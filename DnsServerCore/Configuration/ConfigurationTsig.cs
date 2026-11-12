using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationTsig
    {
        internal const string Path = "/dns/tsigKeys";

        internal readonly record struct Candidate(IReadOnlyDictionary<string, TsigKey> Keys, IReadOnlySet<string> OwnedNames, bool OwnsAll);

        internal static bool SameKey(TsigKey first, TsigKey second)
        {
            if (ReferenceEquals(first, second))
                return true;
            if (first is null || second is null || first.Algorithm != second.Algorithm)
                return false;
            if (first.SharedSecret == second.SharedSecret)
                return true;

            Span<byte> firstBytes = stackalloc byte[192];
            Span<byte> secondBytes = stackalloc byte[192];
            return Convert.TryFromBase64String(first.SharedSecret, firstBytes, out int firstLength) &&
                Convert.TryFromBase64String(second.SharedSecret, secondBytes, out int secondLength) &&
                CryptographicOperations.FixedTimeEquals(firstBytes[..firstLength], secondBytes[..secondLength]);
        }

        internal static string GetCatalogKey(string clusterDomain) =>
            string.IsNullOrEmpty(clusterDomain) ? null : "cluster-catalog." + clusterDomain;

        internal static bool TryGetDeclaration(ConfigurationManifest manifest, out JsonElement keys)
        {
            keys = default;
            return manifest is not null && manifest.Settings.TryGetProperty("dns", out JsonElement dns) &&
                dns.TryGetProperty("tsigKeys", out keys);
        }

        internal static void Validate(JsonElement keys)
        {
            if (keys.ValueKind == JsonValueKind.Null)
                return;

            foreach (JsonProperty entry in keys.EnumerateObject())
            {
                if (entry.Value.ValueKind == JsonValueKind.Null)
                    continue;
                string path = ConfigurationPlan.AppendPath(Path, entry.Name);
                if (entry.Value.TryGetProperty("algorithm", out JsonElement algorithm))
                    ReadAlgorithm(algorithm, path);
            }
        }

        internal static Candidate Prepare(ConfigurationManifest manifest, JsonElement declaration,
            IReadOnlyDictionary<string, TsigKey> current, string protectedKey)
        {
            var candidate = new Dictionary<string, TsigKey>(StringComparer.OrdinalIgnoreCase);
            if (declaration.ValueKind == JsonValueKind.Null)
            {
                if (protectedKey is not null && current is not null && current.TryGetValue(protectedKey, out TsigKey clusterKey))
                    candidate.Add(protectedKey, clusterKey);
                return new Candidate(candidate, null, true);
            }

            if (current is not null)
            {
                foreach (var (name, key) in current)
                    candidate.Add(name, key);
            }

            var ownedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (JsonProperty entry in declaration.EnumerateObject())
            {
                string path = ConfigurationPlan.AppendPath(Path, entry.Name);
                string name = ConfigurationManifest.CanonicalDnsName(entry.Name, path, allowRoot: false);
                ownedNames.Add(name);
                if (string.Equals(name, protectedKey, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"{path}: The cluster catalog manages this TSIG key.");

                if (entry.Value.ValueKind == JsonValueKind.Null)
                {
                    candidate.Remove(name);
                    continue;
                }

                candidate.TryGetValue(name, out TsigKey previous);
                TsigAlgorithm algorithm = entry.Value.TryGetProperty("algorithm", out JsonElement algorithmValue)
                    ? ReadAlgorithm(algorithmValue, path) : previous?.Algorithm ??
                        throw new InvalidDataException($"{path}/algorithm: A new TSIG key requires an algorithm.");
                string secret = entry.Value.TryGetProperty("secret", out JsonElement reference)
                    ? ReadSecret(manifest, reference, path + "/secret") : previous?.SharedSecret ??
                        throw new InvalidDataException($"{path}/secret: A new TSIG key requires a secret reference.");
                var key = new TsigKey(name, secret, algorithm);
                candidate[name] = SameKey(previous, key) ? previous : key;
            }

            if (candidate.Count > byte.MaxValue)
                throw new InvalidDataException($"{Path}: At most 255 TSIG keys are supported.");
            if (ownedNames.Count > ushort.MaxValue)
                throw new InvalidDataException($"{Path}: Too many TSIG key declarations.");
            return new Candidate(candidate, ownedNames, false);
        }

        private static TsigAlgorithm ReadAlgorithm(JsonElement value, string path)
        {
            if (value.ValueKind == JsonValueKind.String)
            {
                try
                {
                    var key = new TsigKey("", "", value.GetString().TrimEnd('.'));
                    if (key.Algorithm is not (TsigAlgorithm.GSS_TSIG or TsigAlgorithm.HMAC_SHA224))
                        return key.Algorithm;
                }
                catch (NotSupportedException)
                {
                }
            }

            throw new InvalidDataException($"{path}/algorithm: Unsupported TSIG HMAC algorithm.");
        }

        internal static string ReadSecret(ConfigurationManifest manifest, JsonElement reference, string path)
        {
            string secret = manifest.ResolveReference(reference, path);
            Span<byte> decoded = stackalloc byte[192];
            if (secret.Length <= byte.MaxValue && Convert.TryFromBase64String(secret, decoded, out int length) && length > 0)
                return Convert.ToBase64String(decoded[..length]);

            throw new InvalidDataException($"{path}: The resolved secret must be nonempty base64 and fit in 255 bytes.");
        }

        internal static void WriteSnapshot(Utf8JsonWriter writer, IReadOnlyDictionary<string, TsigKey> current,
            IReadOnlyDictionary<string, TsigKey> candidate, byte[] revisionKey)
        {
            writer.WriteStartObject("manifestTsigKeys");
            WriteKeys("current", current);
            WriteKeys("desired", candidate);
            writer.WriteEndObject();

            void WriteKeys(string property, IReadOnlyDictionary<string, TsigKey> keys)
            {
                writer.WriteStartObject(property);
                if (keys is not null)
                {
                    foreach (var (name, key) in keys.OrderBy(item => item.Key, StringComparer.Ordinal))
                    {
                        writer.WriteStartObject(name.ToLowerInvariant());
                        writer.WriteNumber("algorithm", (byte)key.Algorithm);
                        writer.WriteString("secret", Fingerprint(key.SharedSecret, revisionKey));
                        writer.WriteEndObject();
                    }
                }
                writer.WriteEndObject();
            }
        }

        internal static void Compare(JsonElement snapshot, List<ConfigurationChange> changes)
        {
            if (!snapshot.TryGetProperty("manifestTsigKeys", out JsonElement state))
                throw new InvalidDataException($"{Path}: A server preview is required to resolve the TSIG keys.");

            JsonElement current = state.GetProperty("current");
            JsonElement desired = state.GetProperty("desired");
            foreach (JsonProperty entry in current.EnumerateObject())
            {
                string path = ConfigurationPlan.AppendPath(Path, entry.Name);
                if (!desired.TryGetProperty(entry.Name, out JsonElement key))
                    changes.Add(new ConfigurationChange(path, ConfigurationChangeKind.Remove, false));
                else
                {
                    if (!JsonElement.DeepEquals(entry.Value.GetProperty("algorithm"), key.GetProperty("algorithm")))
                        changes.Add(new ConfigurationChange(path + "/algorithm", ConfigurationChangeKind.Update, false));
                    if (!JsonElement.DeepEquals(entry.Value.GetProperty("secret"), key.GetProperty("secret")))
                        changes.Add(new ConfigurationChange(path + "/secret", ConfigurationChangeKind.Update, false));
                }
            }
            foreach (JsonProperty entry in desired.EnumerateObject())
            {
                if (!current.TryGetProperty(entry.Name, out _))
                    changes.Add(new ConfigurationChange(ConfigurationPlan.AppendPath(Path, entry.Name), ConfigurationChangeKind.Add, false));
            }
        }

        private static string Fingerprint(string secret, byte[] revisionKey)
        {
            Span<byte> decoded = stackalloc byte[192];
            if (Convert.TryFromBase64String(secret, decoded, out int length))
                return Convert.ToHexString(HMACSHA256.HashData(revisionKey, decoded[..length]));
            return Convert.ToHexString(HMACSHA256.HashData(revisionKey, Encoding.UTF8.GetBytes(secret)));
        }

        internal static JsonObject Export(JsonElement keys, string protectedKey)
        {
            var result = new JsonObject();
            foreach (JsonElement key in keys.EnumerateArray().OrderBy(item => item.GetProperty("keyName").GetString(), StringComparer.Ordinal))
            {
                string name = key.GetProperty("keyName").GetString();
                if (!string.Equals(name, protectedKey, StringComparison.OrdinalIgnoreCase))
                    result.Add(name, new JsonObject { ["algorithm"] = key.GetProperty("algorithmName").GetString() });
            }
            return result;
        }
    }
}
