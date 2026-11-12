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
