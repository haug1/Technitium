using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Dns.ZoneManagers;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using PolicyMap = System.Collections.Generic.IReadOnlyDictionary<string, System.Collections.Generic.IReadOnlyDictionary<string, System.Collections.Generic.IReadOnlyList<TechnitiumLibrary.Net.Dns.ResourceRecords.DnsResourceRecordType>>>;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationZoneUpdatePolicies
    {
        internal static PolicyMap Prepare(JsonElement declaration, string zone, string zonePath, PolicyMap current)
        {
            if (!declaration.TryGetProperty("updates", out JsonElement updates) ||
                !updates.TryGetProperty("securityPolicies", out JsonElement policies))
                return current;

            string path = zonePath + "/updates/securityPolicies";
            var result = new SortedDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(StringComparer.Ordinal);
            if (policies.ValueKind == JsonValueKind.Null)
                return result;
            foreach (var (key, entries) in current ?? Empty)
                result.Add(key, entries);

            var seenKeys = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty key in policies.EnumerateObject())
            {
                string keyPath = ConfigurationPlan.AppendPath(path, key.Name);
                string name = ConfigurationManifest.CanonicalDnsName(key.Name, keyPath, allowRoot: false);
                if (!seenKeys.Add(name))
                    throw new InvalidDataException($"{keyPath}: Duplicate TSIG key name.");
                if (key.Value.ValueKind == JsonValueKind.Null)
                {
                    result.Remove(name);
                    continue;
                }

                var owners = new SortedDictionary<string, IReadOnlyList<DnsResourceRecordType>>(StringComparer.Ordinal);
                if (result.TryGetValue(name, out var existing))
                {
                    foreach (var (owner, types) in existing)
                        owners.Add(owner, types);
                }

                var seenOwners = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonProperty entry in key.Value.EnumerateObject())
                {
                    string ownerPath = ConfigurationPlan.AppendPath(keyPath, entry.Name);
                    string owner = entry.Name == "@" ? zone : ConfigurationManifest.CanonicalDnsName(entry.Name, ownerPath, allowRoot: true);
                    if (!AuthZoneManager.DomainBelongsToZone(zone, owner))
                        throw new InvalidDataException($"{ownerPath}: A policy owner must belong to its zone.");
                    if (!seenOwners.Add(owner))
                        throw new InvalidDataException($"{ownerPath}: Duplicate policy owner.");
                    if (entry.Value.ValueKind == JsonValueKind.Null)
                        owners.Remove(owner);
                    else
                    {
                        var types = entry.Value.EnumerateArray().Select(type => type.ValueKind == JsonValueKind.Number
                            ? (DnsResourceRecordType)decimal.ToUInt16(type.GetDecimal())
                            : Enum.TryParse(type.GetString(), out DnsResourceRecordType recordType) ? recordType :
                                throw new InvalidDataException($"{ownerPath}: Unknown record type. Use a numeric code for unrecognized types."))
                            .Distinct().Order().ToArray();
                        if (types.Length > byte.MaxValue)
                            throw new InvalidDataException($"{ownerPath}: At most 255 record types can be stored per owner.");
                        owners[owner] = types;
                    }
                }

                if (owners.Count > byte.MaxValue)
                    throw new InvalidDataException($"{keyPath}: At most 255 owners can be stored per key.");
                result[name] = owners;
            }
            return result;
        }

        private static readonly PolicyMap Empty =
            new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(StringComparer.Ordinal);

        internal static JsonObject Write(PolicyMap policies)
        {
            var result = new JsonObject();
            foreach (var (key, owners) in (policies ?? Empty).OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                var entries = new JsonObject();
                foreach (var (owner, types) in owners.OrderBy(entry => entry.Key, StringComparer.Ordinal))
                    entries.Add(owner.Length == 0 ? "." : owner,
                        JsonSerializer.SerializeToNode(types.Distinct().Order().Select(type => (ushort)type)));
                result.Add(key, entries);
            }
            return result;
        }

        internal static bool Same(PolicyMap first, PolicyMap second) => JsonNode.DeepEquals(Write(first), Write(second));

        internal static void AddOwnedFields(JsonElement policies, string zone, string zonePath, List<string> fields)
        {
            const string field = "updates/securityPolicies";
            if (policies.ValueKind == JsonValueKind.Null)
            {
                fields.Add(field);
                return;
            }

            foreach (JsonProperty key in policies.EnumerateObject())
            {
                string name = ConfigurationManifest.CanonicalDnsName(key.Name, zonePath + "/" + field, allowRoot: false);
                string keyPath = ConfigurationPlan.AppendPath(field, name);
                fields.Add(keyPath);
                if (key.Value.ValueKind != JsonValueKind.Object)
                    continue;

                foreach (JsonProperty entry in key.Value.EnumerateObject())
                {
                    string owner = entry.Name == "@" ? zone : ConfigurationManifest.CanonicalDnsName(entry.Name, zonePath + "/" + keyPath, allowRoot: true);
                    fields.Add(ConfigurationPlan.AppendPath(keyPath, owner.Length == 0 ? "." : owner));
                }
            }
        }

        internal static bool OwnedValueChanged(string field, PolicyMap current, PolicyMap candidate)
        {
            const string root = "updates/securityPolicies";
            if (field == root)
                return !Same(current, candidate);
            if (!field.StartsWith(root + "/", StringComparison.Ordinal))
                return false;

            string[] segments = field[(root.Length + 1)..].Split('/');
            string key = Unescape(segments[0]);
            (current ?? Empty).TryGetValue(key, out var currentOwners);
            (candidate ?? Empty).TryGetValue(key, out var candidateOwners);
            if (segments.Length == 1)
                return (currentOwners is null) != (candidateOwners is null);

            string owner = segments[1] == "." ? string.Empty : Unescape(segments[1]);
            IReadOnlyList<DnsResourceRecordType> before = null;
            IReadOnlyList<DnsResourceRecordType> after = null;
            currentOwners?.TryGetValue(owner, out before);
            candidateOwners?.TryGetValue(owner, out after);
            if (before is null || after is null)
                return (before is null) != (after is null);

            return !before.ToHashSet().SetEquals(after);

            static string Unescape(string value) => value.Replace("~1", "/").Replace("~0", "~");
        }

        internal static PolicyMap ReadSnapshot(JsonElement value)
        {
            var result = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(StringComparer.Ordinal);
            foreach (JsonProperty key in value.EnumerateObject())
            {
                var owners = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>(StringComparer.Ordinal);
                foreach (JsonProperty owner in key.Value.EnumerateObject())
                    owners.Add(owner.Name == "." ? string.Empty : owner.Name,
                        owner.Value.EnumerateArray().Select(type => (DnsResourceRecordType)type.GetUInt16()).ToArray());
                result.Add(key.Name, owners);
            }
            return result;
        }
    }
}
