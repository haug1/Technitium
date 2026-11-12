using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using DnsServerCore.Dns.Zones;
using TechnitiumLibrary.Net;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationZonePolicies
    {
        internal readonly record struct Changes(
            AuthZoneQueryAccess? QueryAccess, NetworkAccessControl[] QueryAcl,
            AuthZoneTransfer? Transfer, NetworkAccessControl[] TransferAcl,
            AuthZoneNotify? Notify, IPAddress[] NotifyServers,
            AuthZoneUpdate? Update, NetworkAccessControl[] UpdateAcl)
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
                if (NotifyServers is not null)
                    zone.NotifyNameServers = NotifyServers;
                if (Notify.HasValue)
                    zone.Notify = Notify.Value;
                if (UpdateAcl is not null)
                    zone.UpdateNetworkACL = UpdateAcl;
                if (Update.HasValue)
                    zone.Update = Update.Value;
            }
        }

        internal static Changes Prepare(JsonElement declaration, string path, AuthZoneInfo current)
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

            return new Changes(
                ReadMode(query, "query", current?.QueryAccess), ReadAcl(query, "query", current?.QueryAccessNetworkACL),
                ReadMode(transfer, "transfer", current?.ZoneTransfer), ReadAcl(transfer, "transfer", current?.ZoneTransferNetworkACL),
                notifyMode, notifyServers,
                ReadMode(updates, "updates", current?.Update), ReadAcl(updates, "updates", current?.UpdateNetworkACL));

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
                    "notify/mode" => current.Notify != candidate.Notify,
                    "notify/nameServers" => !Equal(current.NotifyNameServers, candidate.NotifyNameServers),
                    "updates/mode" => current.Update != candidate.Update,
                    "updates/networkAcl" => !Equal(current.UpdateNetworkACL, candidate.UpdateNetworkACL),
                    _ => false
                };
                if (changed)
                    throw new InvalidDataException($"{path}/{field}: Zone policy is managed by the configuration manifest.");
            }

            static bool Equal<T>(IReadOnlyCollection<T> before, IReadOnlyCollection<T> after) =>
                (before ?? []).Select(value => value.ToString()).SequenceEqual((after ?? []).Select(value => value.ToString()), StringComparer.Ordinal);
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
                        WritePolicy("transfer", zone.ZoneTransfer.ToString(), zone.ZoneTransferNetworkACL);
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

            void WritePolicy(string name, string mode, IReadOnlyCollection<NetworkAccessControl> acl)
            {
                writer.WriteStartObject(name);
                writer.WriteString("mode", mode);
                writer.WriteStartArray("networkAcl");
                foreach (NetworkAccessControl entry in acl ?? [])
                    writer.WriteStringValue(entry.ToString());
                writer.WriteEndArray();
                writer.WriteEndObject();
            }
        }

        internal static void Compare(string zonePath, JsonElement declared, JsonElement current, List<ConfigurationChange> changes)
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
