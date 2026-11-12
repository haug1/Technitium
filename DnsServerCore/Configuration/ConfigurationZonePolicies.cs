using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using DnsServerCore.Dns.Zones;
using TechnitiumLibrary.Net;
using PolicyMap = System.Collections.Generic.IReadOnlyDictionary<string, System.Collections.Generic.IReadOnlyDictionary<string, System.Collections.Generic.IReadOnlyList<TechnitiumLibrary.Net.Dns.ResourceRecords.DnsResourceRecordType>>>;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationZonePolicies
    {
        internal readonly record struct Changes(
            AuthZoneQueryAccess? QueryAccess, NetworkAccessControl[] QueryAcl,
            AuthZoneTransfer? Transfer, NetworkAccessControl[] TransferAcl, IReadOnlySet<string> TransferKeys,
            AuthZoneNotify? Notify, IPAddress[] NotifyServers,
            AuthZoneUpdate? Update, NetworkAccessControl[] UpdateAcl, PolicyMap UpdatePolicies)
        {
            internal void Apply(AuthZoneInfo zone)
            {
                if (QueryAcl is not null)
                    zone.QueryAccessNetworkACL = QueryAcl;
                if (QueryAccess.HasValue)
                    zone.QueryAccess = QueryAccess.Value;
                if (TransferAcl is not null)
                    zone.ZoneTransferNetworkACL = TransferAcl;
                if (Transfer.HasValue)
                    zone.ZoneTransfer = Transfer.Value;
                if (TransferKeys is not null)
                    zone.ZoneTransferTsigKeyNames = TransferKeys;
                if (NotifyServers is not null)
                    zone.NotifyNameServers = NotifyServers;
                if (Notify.HasValue)
                    zone.Notify = Notify.Value;
                if (UpdateAcl is not null)
                    zone.UpdateNetworkACL = UpdateAcl;
                if (Update.HasValue)
                    zone.Update = Update.Value;
                if (UpdatePolicies is not null)
                    zone.UpdateSecurityPolicies = UpdatePolicies.Count == 0 ? null : UpdatePolicies;
            }
        }

        internal static Changes Prepare(JsonElement declaration, string zone, string path, AuthZoneInfo current)
        {
            declaration.TryGetProperty("query", out JsonElement query);
            declaration.TryGetProperty("transfer", out JsonElement transfer);
            declaration.TryGetProperty("notify", out JsonElement notify);
            declaration.TryGetProperty("updates", out JsonElement updates);
            AuthZoneNotify? notifyMode = ReadMode(notify, "notify", current?.Notify);
            if (notifyMode == AuthZoneNotify.SeparateNameServersForCatalogAndMemberZones)
                throw new InvalidDataException($"{path}/notify/mode: This notification mode requires a catalog zone.");

            IPAddress[] notifyServers = null;
            if (notify.ValueKind == JsonValueKind.Object && notify.TryGetProperty("nameServers", out JsonElement names))
            {
                IPAddress[] addresses = names.ValueKind == JsonValueKind.Null ? [] :
                    names.EnumerateArray().Select(value => IPAddress.Parse(value.GetString())).ToArray();
                if (!(current?.NotifyNameServers ?? []).SequenceEqual(addresses))
                    notifyServers = addresses;
            }

            IReadOnlySet<string> transferKeys = ReadTransferKeys(declaration, path);
            if (transferKeys is not null && transferKeys.SetEquals(current?.ZoneTransferTsigKeyNames ?? Enumerable.Empty<string>()))
                transferKeys = null;

            PolicyMap policies = ConfigurationZoneUpdatePolicies.Prepare(declaration, zone, path, current?.UpdateSecurityPolicies);
            if (ConfigurationZoneUpdatePolicies.Same(policies, current?.UpdateSecurityPolicies))
                policies = null;

            return new Changes(
                ReadMode(query, "query", current?.QueryAccess), ReadAcl(query, "query", current?.QueryAccessNetworkACL),
                ReadMode(transfer, "transfer", current?.ZoneTransfer), ReadAcl(transfer, "transfer", current?.ZoneTransferNetworkACL), transferKeys,
                notifyMode, notifyServers,
                ReadMode(updates, "updates", current?.Update), ReadAcl(updates, "updates", current?.UpdateNetworkACL), policies);

            static T? ReadMode<T>(JsonElement policy, string name, T? previous) where T : struct, Enum
            {
                if (policy.ValueKind != JsonValueKind.Object || !policy.TryGetProperty("mode", out JsonElement value))
                    return null;

                T mode = Enum.Parse<T>(value.GetString() ?? GetDefaultMode(name));
                return previous.HasValue && EqualityComparer<T>.Default.Equals(previous.Value, mode) ? null : mode;
            }

            NetworkAccessControl[] ReadAcl(JsonElement policy, string name, IReadOnlyCollection<NetworkAccessControl> previous)
            {
                if (policy.ValueKind != JsonValueKind.Object || !policy.TryGetProperty("networkAcl", out JsonElement value))
                    return null;

                NetworkAccessControl[] acl = ConfigurationManifest.ReadNetworkAcl(value, path + "/" + name + "/networkAcl");
                return (previous ?? []).Select(rule => rule.ToString()).SequenceEqual(acl.Select(rule => rule.ToString()), StringComparer.Ordinal)
                    ? null : acl;
            }
        }

        internal static void CheckRestoreOwnership(string path, IEnumerable<string> fields, AuthZoneInfo current, AuthZoneInfo candidate)
        {
            foreach (string field in fields)
            {
                bool changed = field switch
                {
                    "query/mode" => current.QueryAccess != candidate.QueryAccess,
                    "query/networkAcl" => !Equal(current.QueryAccessNetworkACL, candidate.QueryAccessNetworkACL),
                    "transfer/mode" => current.ZoneTransfer != candidate.ZoneTransfer,
                    "transfer/networkAcl" => !Equal(current.ZoneTransferNetworkACL, candidate.ZoneTransferNetworkACL),
                    "transfer/tsigKeys" => !new HashSet<string>(current.ZoneTransferTsigKeyNames ?? Enumerable.Empty<string>(), StringComparer.OrdinalIgnoreCase)
                        .SetEquals(candidate.ZoneTransferTsigKeyNames ?? Enumerable.Empty<string>()),
                    "notify/mode" => current.Notify != candidate.Notify,
                    "notify/nameServers" => !Equal(current.NotifyNameServers, candidate.NotifyNameServers),
                    "updates/mode" => current.Update != candidate.Update,
                    "updates/networkAcl" => !Equal(current.UpdateNetworkACL, candidate.UpdateNetworkACL),
                    _ => ConfigurationZoneUpdatePolicies.OwnedValueChanged(field, current.UpdateSecurityPolicies, candidate.UpdateSecurityPolicies)
                };
                if (changed)
                    throw new InvalidDataException($"{path}/{field}: Zone policy is managed by the configuration manifest.");
            }

            static bool Equal<T>(IReadOnlyCollection<T> before, IReadOnlyCollection<T> after) =>
                (before ?? []).Select(value => value.ToString()).SequenceEqual((after ?? []).Select(value => value.ToString()), StringComparer.Ordinal);
        }

        internal static IReadOnlySet<string> ReadTransferKeys(JsonElement declaration, string path)
        {
            if (!declaration.TryGetProperty("transfer", out JsonElement transfer) || !transfer.TryGetProperty("tsigKeys", out JsonElement value))
                return null;

            var names = new SortedSet<string>(StringComparer.Ordinal);
            if (value.ValueKind != JsonValueKind.Null)
            {
                foreach (JsonElement name in value.EnumerateArray())
                    names.Add(ConfigurationManifest.CanonicalDnsName(name.GetString(), path + "/transfer/tsigKeys", allowRoot: false));
            }
            return names;
        }

        internal static void ValidateKeyReferences(JsonElement declaration, string zone, string path, AuthZoneInfo current, IReadOnlyDictionary<string, TechnitiumLibrary.Net.Dns.TsigKey> keys)
        {
            if (ReadTransferKeys(declaration, path)?.Any(name => keys?.ContainsKey(name) != true) == true)
                throw new InvalidDataException($"{path}/transfer/tsigKeys: A referenced TSIG key is missing from the effective DNS configuration.");
            if (declaration.TryGetProperty("updates", out JsonElement updates) && updates.TryGetProperty("securityPolicies", out _) &&
                ConfigurationZoneUpdatePolicies.Prepare(declaration, zone, path, current?.UpdateSecurityPolicies)
                    .Keys.Any(name => keys?.ContainsKey(name) != true))
                throw new InvalidDataException($"{path}/updates/securityPolicies: A referenced TSIG key is missing from the effective DNS configuration.");
        }

        internal static bool IsPolicy(string name)
        {
            return name is "query" or "transfer" or "notify" or "updates";
        }

        internal static void Validate(JsonElement manifest)
        {
            if (!manifest.TryGetProperty("zones", out JsonElement zones))
                return;

            foreach (JsonProperty zone in zones.EnumerateObject())
            {
                if (zone.Value.ValueKind != JsonValueKind.Object)
                    continue;

                string path = ConfigurationPlan.AppendPath("/zones", zone.Name);
                ReadTransferKeys(zone.Value, path);
                string name = ConfigurationManifest.CanonicalDnsName(zone.Name, path, allowRoot: true);
                ConfigurationZoneUpdatePolicies.Prepare(zone.Value, name, path, null);
                foreach (JsonProperty policy in zone.Value.EnumerateObject())
                {
                    if (IsPolicy(policy.Name) && policy.Value.TryGetProperty("networkAcl", out JsonElement acl))
                        ConfigurationManifest.ReadNetworkAcl(acl, path + "/" + policy.Name + "/networkAcl");
                }
            }
        }

        internal static void WriteSnapshot(Utf8JsonWriter writer, JsonElement declaration, AuthZoneInfo zone)
        {
            writer.WriteStartObject("policies");
            writer.WriteBoolean("catalogMember", zone.CatalogZoneName is not null);
            foreach (JsonProperty policy in declaration.EnumerateObject())
            {
                switch (policy.Name)
                {
                    case "query":
                        WritePolicy("query", zone.QueryAccess.ToString(), zone.QueryAccessNetworkACL);
                        break;
                    case "transfer":
                        WritePolicy("transfer", zone.ZoneTransfer.ToString(), zone.ZoneTransferNetworkACL, zone.ZoneTransferTsigKeyNames);
                        break;
                    case "updates":
                        WritePolicy("updates", zone.Update.ToString(), zone.UpdateNetworkACL);
                        break;
                    case "notify":
                        writer.WriteStartObject("notify");
                        writer.WriteString("mode", zone.Notify.ToString());
                        writer.WriteStartArray("nameServers");
                        foreach (IPAddress address in zone.NotifyNameServers ?? [])
                            writer.WriteStringValue(address.ToString());
                        writer.WriteEndArray();
                        writer.WriteEndObject();
                        break;
                }
            }
            writer.WriteEndObject();

            void WritePolicy(string name, string mode, IReadOnlyCollection<NetworkAccessControl> acl, IReadOnlySet<string> keys = null)
            {
                writer.WriteStartObject(name);
                writer.WriteString("mode", mode);
                writer.WriteStartArray("networkAcl");
                foreach (NetworkAccessControl entry in acl ?? [])
                    writer.WriteStringValue(entry.ToString());
                writer.WriteEndArray();
                if (name == "transfer")
                {
                    writer.WriteStartArray("tsigKeys");
                    foreach (string key in (keys ?? Enumerable.Empty<string>()).OrderBy(key => key, StringComparer.Ordinal))
                        writer.WriteStringValue(key);
                    writer.WriteEndArray();
                }
                if (name == "updates")
                {
                    writer.WritePropertyName("securityPolicies");
                    ConfigurationZoneUpdatePolicies.Write(zone.UpdateSecurityPolicies).WriteTo(writer);
                }
                writer.WriteEndObject();
            }
        }

        internal static void Compare(string zoneName, string zonePath, JsonElement declared, JsonElement current, List<ConfigurationChange> changes)
        {
            bool exists = current.ValueKind == JsonValueKind.Object && current.TryGetProperty("type", out _);
            foreach (JsonProperty policy in declared.EnumerateObject())
            {
                if (!IsPolicy(policy.Name))
                    continue;

                string path = zonePath + "/" + policy.Name;
                JsonElement currentPolicy = default;
                if (exists)
                {
                    JsonElement policies = current.GetProperty("policies");
                    if (!current.GetProperty("type").ValueEquals(nameof(AuthZoneType.Primary)) ||
                        current.GetProperty("clusterProtected").GetBoolean() || policies.GetProperty("catalogMember").GetBoolean())
                        throw new InvalidDataException($"{path}: Policy preview requires a primary zone outside a catalog and the cluster infrastructure.");
                    currentPolicy = policies.GetProperty(policy.Name);
                }

                foreach (JsonProperty field in policy.Value.EnumerateObject())
                {
                    string fieldPath = ConfigurationPlan.AppendPath(path, field.Name);
                    bool changed;
                    if (field.Name == "mode")
                    {
                        string mode = field.Value.GetString() ?? GetDefaultMode(policy.Name);
                        if (policy.Name == "notify" && mode == nameof(AuthZoneNotify.SeparateNameServersForCatalogAndMemberZones))
                            throw new InvalidDataException($"{fieldPath}: This notification mode requires a catalog zone.");
                        changed = exists && !currentPolicy.GetProperty("mode").ValueEquals(mode);
                    }
                    else if (field.Name == "networkAcl" && policy.Name != "notify")
                    {
                        NetworkAccessControl[] acl = ConfigurationManifest.ReadNetworkAcl(field.Value, fieldPath);
                        changed = exists && !EqualList(currentPolicy, field.Name, acl.Select(entry => entry.ToString()));
                    }
                    else if (field.Name == "tsigKeys" && policy.Name == "transfer")
                    {
                        changed = exists && !EqualList(currentPolicy, field.Name, ReadTransferKeys(declared, zonePath));
                    }
                    else if (field.Name == "securityPolicies" && policy.Name == "updates")
                    {
                        PolicyMap previous = exists ? ConfigurationZoneUpdatePolicies.ReadSnapshot(currentPolicy.GetProperty("securityPolicies")) : null;
                        PolicyMap candidate = ConfigurationZoneUpdatePolicies.Prepare(declared, zoneName, zonePath, previous);
                        changed = exists && !ConfigurationZoneUpdatePolicies.Same(previous, candidate);
                    }
                    else if (field.Name == "nameServers" && policy.Name == "notify")
                    {
                        IEnumerable<string> addresses = field.Value.ValueKind == JsonValueKind.Null ? [] :
                            field.Value.EnumerateArray().Select(value => IPAddress.Parse(value.GetString()).ToString());
                        changed = exists && !EqualList(currentPolicy, field.Name, addresses);
                    }
                    else
                    {
                        throw new InvalidDataException($"{fieldPath}: Planning for this zone policy setting is not implemented.");
                    }

                    if (changed)
                        changes.Add(new ConfigurationChange(fieldPath, ConfigurationChangeKind.Update, false));
                }
            }
        }

        private static string GetDefaultMode(string policy)
        {
            return policy switch
            {
                "query" => nameof(AuthZoneQueryAccess.Allow),
                "transfer" => nameof(AuthZoneTransfer.AllowOnlyZoneNameServers),
                "notify" => nameof(AuthZoneNotify.ZoneNameServers),
                "updates" => nameof(AuthZoneUpdate.Deny),
                _ => throw new ArgumentOutOfRangeException(nameof(policy))
            };
        }

        private static bool EqualList(JsonElement current, string field, IEnumerable<string> declared)
        {
            return current.GetProperty(field).EnumerateArray().Select(value => value.GetString())
                .SequenceEqual(declared, StringComparer.Ordinal);
        }
    }
}
