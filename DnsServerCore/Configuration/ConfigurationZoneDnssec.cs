using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Dns;
using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.Zones;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationZoneDnssec
    {
        internal sealed record Key(DnssecPrivateKeyType Role, DnssecAlgorithm Algorithm, int Size, ushort RolloverDays, DnssecPrivateKey Imported, string Path, bool HasRolloverDays, bool PublishOnSign)
        {
            internal DnssecPrivateKey Create()
            {
                try
                {
                    var key = Imported ?? DnssecPrivateKey.Create(Algorithm, Role, Size);
                    if (Role == DnssecPrivateKeyType.ZoneSigningKey)
                        key.RolloverDays = RolloverDays;
                    return key;
                }
                catch (Exception ex) when (ex is ArgumentException or CryptographicException)
                {
                    throw new InvalidDataException($"{Path}: Could not initialize the DNSSEC key.");
                }
            }

            internal bool Matches(DnssecPrivateKey key) =>
                key.KeyType == Role && key.Algorithm == Algorithm &&
                (Size < 0 || key is DnssecRsaPrivateKey rsa && rsa.KeySize == Size) &&
                (Imported is null || Imported.DnsKey.Equals(key.DnsKey));
        }

        internal sealed record Signing(uint Ttl, bool UseNsec3, ushort Iterations, int SaltLength, Key[] Keys,
            bool Disable = false, bool ChangeProof = false, bool ChangeTtl = false, RolloverChange[] Rollovers = null, Key[] Additions = null, KeyRemoval[] Removals = null);

        internal sealed record KeyRemoval(ushort Tag, string Path);

        internal sealed record RolloverChange(ushort Tag, ushort Before, ushort After, string Path);

        internal static IEnumerable<(string Path, ConfigurationChangeKind Kind)> DescribeChanges(Signing signing, string zonePath)
        {
            string path = zonePath + "/dnssec";
            if (signing.Disable || signing.Keys.Length > 0)
                yield return (path + "/enabled", ConfigurationChangeKind.Update);
            if (signing.ChangeProof)
                yield return (path + "/proof", ConfigurationChangeKind.Update);
            if (signing.ChangeTtl)
                yield return (path + "/dnsKeyTtl", ConfigurationChangeKind.Update);
            foreach (Key key in signing.Keys.Concat(signing.Additions ?? []))
                yield return (key.Path, ConfigurationChangeKind.Add);
            foreach (KeyRemoval removal in signing.Removals ?? [])
                yield return (removal.Path, ConfigurationChangeKind.Remove);
            foreach (RolloverChange rollover in signing.Rollovers ?? [])
                yield return (rollover.Path + "/rolloverDays", ConfigurationChangeKind.Update);
        }

        internal static void ValidateDeclarations(JsonElement root)
        {
            if (!root.TryGetProperty("zones", out JsonElement zones))
                return;

            foreach (JsonProperty zone in zones.EnumerateObject())
            {
                if (zone.Value.ValueKind != JsonValueKind.Object || !zone.Value.TryGetProperty("dnssec", out JsonElement dnssec))
                    continue;

                string path = ConfigurationPlan.AppendPath("/zones", zone.Name) + "/dnssec";
                if (Read(zone.Value, "type") is JsonElement type && !type.ValueEquals("Primary"))
                    throw new InvalidDataException($"{path}: DNSSEC signing requires a configurable primary zone.");

                if (dnssec.TryGetProperty("enabled", out _) && Read(dnssec, "enabled")?.GetBoolean() != true &&
                    dnssec.EnumerateObject().Any(field => field.Name != "enabled"))
                    throw new InvalidDataException($"{path}: Enable DNSSEC before declaring signing settings.");

                JsonElement proof = Read(dnssec, "proof") ?? default;
                if (proof.ValueKind == JsonValueKind.Object && proof.TryGetProperty("type", out _) &&
                    Read(proof, "type")?.ValueEquals("NSEC3") != true)
                {
                    if ((Read(proof, "iterations")?.GetDecimal() ?? 0) != 0)
                        throw new InvalidDataException($"{path}/proof/iterations: Iterations require NSEC3.");
                    if ((Read(proof, "saltLength")?.GetDecimal() ?? 0) != 0)
                        throw new InvalidDataException($"{path}/proof/saltLength: Salt length requires NSEC3.");
                }

                ReadKeys(null, dnssec, path);
                ReadKeyRemovals(dnssec, path);
            }
        }

        internal static void ValidateKeyReferences(ConfigurationManifest manifest, JsonElement dnssec, string path)
        {
            ReadKeys(manifest, dnssec, path);
        }

        internal static Signing Prepare(ConfigurationManifest manifest, JsonElement declaration, AuthZoneType type, AuthZoneInfo current, string path)
        {
            if (!declaration.TryGetProperty("dnssec", out JsonElement dnssec))
                return null;
            path += "/dnssec";
            if (type != AuthZoneType.Primary)
                throw new InvalidDataException($"{path}: DNSSEC signing requires a configurable primary zone.");

            bool signed = current?.ApexZone.DnssecStatus is AuthZoneDnssecStatus.SignedWithNSEC or AuthZoneDnssecStatus.SignedWithNSEC3;
            bool enabled = Read(dnssec, "enabled")?.GetBoolean() ?? (dnssec.TryGetProperty("enabled", out _) ? false : signed);
            if (!enabled)
            {
                if (dnssec.EnumerateObject().Any(field => field.Name != "enabled"))
                    throw new InvalidDataException($"{path}: Enable DNSSEC before declaring signing settings.");
                return signed ? new Signing(0, false, 0, 0, [], Disable: true) : null;
            }

            bool currentNsec3 = current?.ApexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3;
            var parameters = currentNsec3
                ? (DnsNSEC3PARAMRecordData)current.ApexZone.GetRecords(DnsResourceRecordType.NSEC3PARAM)[0].RDATA : null;
            uint ttl = dnssec.TryGetProperty("dnsKeyTtl", out _)
                ? decimal.ToUInt32(Read(dnssec, "dnsKeyTtl")?.GetDecimal() ?? 3600)
                : signed ? current.DnsKeyTtl : 3600;
            JsonElement proof = Read(dnssec, "proof") ?? default;
            bool useNsec3 = proof.ValueKind == JsonValueKind.Object && proof.TryGetProperty("type", out _)
                ? Read(proof, "type")?.ValueEquals("NSEC3") == true : currentNsec3;
            int iterations = proof.ValueKind == JsonValueKind.Object && proof.TryGetProperty("iterations", out _)
                ? decimal.ToInt32(Read(proof, "iterations")?.GetDecimal() ?? 0) : useNsec3 ? parameters?.Iterations ?? 0 : 0;
            int saltLength = proof.ValueKind == JsonValueKind.Object && proof.TryGetProperty("saltLength", out _)
                ? decimal.ToInt32(Read(proof, "saltLength")?.GetDecimal() ?? 0) : useNsec3 ? parameters?.Salt.Length ?? 0 : 0;
            if (iterations > 50 || (!useNsec3 && iterations != 0))
                throw new InvalidDataException($"{path}/proof/iterations: NSEC3 iterations must be between 0 and 50.");
            if (saltLength > 32 || (!useNsec3 && saltLength != 0))
                throw new InvalidDataException($"{path}/proof/saltLength: NSEC3 salt length must be between 0 and 32.");

            Key[] parsed = ReadKeys(manifest, dnssec, path);
            KeyRemoval[] requestedRemovals = ReadKeyRemovals(dnssec, path);

            if (signed)
            {
                var existingKeys = (current.DnssecPrivateKeys ?? []).ToArray();
                var additions = new List<Key>();
                var removals = new List<KeyRemoval>();
                foreach (KeyRemoval removal in requestedRemovals)
                {
                    DnssecPrivateKey key = existingKeys.FirstOrDefault(candidate => candidate.KeyTag == removal.Tag);
                    if (key is null)
                        continue;
                    if (key.State != DnssecPrivateKeyState.Generated)
                        throw new InvalidDataException($"{removal.Path}: Only Generated keys can be removed. Use the DNSSEC lifecycle to retire a published key.");
                    removals.Add(removal);
                }
                var removedTags = removals.Select(removal => removal.Tag).ToHashSet();
                var remaining = existingKeys.Where(key => !key.IsRetiring && !removedTags.Contains(key.KeyTag)).ToList();
                var rollovers = new List<RolloverChange>();
                foreach (Key expected in parsed.OrderBy(key => key.Imported is null))
                {
                    var matches = remaining.Where(expected.Matches).ToList();
                    if (matches.Count == 0)
                    {
                        if (expected.Imported is DnssecPrivateKey imported && existingKeys.Any(key => key.KeyTag == imported.KeyTag ||
                            (key.KeyType == imported.KeyType && key.Algorithm == imported.Algorithm &&
                            key.DnsKey.PublicKey.RawPublicKey.AsSpan().SequenceEqual(imported.DnsKey.PublicKey.RawPublicKey))))
                            throw new InvalidDataException($"{expected.Path}/privateKey: The key or its tag is already in use.");
                        additions.Add(expected);
                        continue;
                    }

                    // Keep an already matching interval, or require an unambiguous key for an update.
                    DnssecPrivateKey key = expected.HasRolloverDays
                        ? matches.Find(candidate => candidate.RolloverDays == expected.RolloverDays) : matches[0];
                    if (key is null && matches.Count != 1)
                        throw new InvalidDataException($"{expected.Path}/privateKey: Supply a private-key reference to identify the key to update.");
                    key ??= matches[0];
                    remaining.Remove(key);
                    if (!expected.HasRolloverDays || key.RolloverDays == expected.RolloverDays)
                        continue;
                    try
                    {
                        key.ValidateRolloverDays(expected.RolloverDays);
                    }
                    catch (InvalidOperationException ex)
                    {
                        throw new InvalidDataException($"{expected.Path}/rolloverDays: {ex.Message}");
                    }
                    rollovers.Add(new(key.KeyTag, key.RolloverDays, expected.RolloverDays, expected.Path));
                }

                bool changeTtl = ttl != current.DnsKeyTtl;
                bool changeProof = useNsec3 != currentNsec3 || (useNsec3 &&
                    (iterations != (parameters?.Iterations ?? 0) || saltLength != (parameters?.Salt.Length ?? 0)));
                if (!changeProof && !changeTtl && rollovers.Count == 0 && additions.Count == 0 && removals.Count == 0)
                    return null;
                if (changeTtl)
                {
                    try
                    {
                        PrimaryZone.CheckDnsKeyTtlUpdate(existingKeys.Where(key => !removedTags.Contains(key.KeyTag)));
                    }
                    catch (DnsServerException ex)
                    {
                        throw new InvalidDataException($"{path}/dnsKeyTtl: {ex.Message}");
                    }
                }
                return new Signing(ttl, useNsec3, (ushort)iterations, saltLength, [], ChangeProof: changeProof, ChangeTtl: changeTtl, Rollovers: rollovers.ToArray(), Additions: additions.ToArray(), Removals: removals.ToArray());
            }

            Key[] initialKeys = parsed.Where(key => key.PublishOnSign).ToArray();
            if (!initialKeys.Any(key => key.Role == DnssecPrivateKeyType.KeySigningKey) ||
                !initialKeys.Any(key => key.Role == DnssecPrivateKeyType.ZoneSigningKey))
                throw new InvalidDataException($"{path}/keys: Specify both a key signing key and a zone signing key for initial publication.");
            return new Signing(ttl, useNsec3, (ushort)iterations, saltLength, initialKeys,
                Additions: parsed.Where(key => !key.PublishOnSign).ToArray());
        }

        internal static JsonObject Export(AuthZoneInfo zone, string path, ISet<string> missingInputs)
        {
            var result = new JsonObject { ["enabled"] = true, ["dnsKeyTtl"] = zone.DnsKeyTtl };
            bool useNsec3 = zone.ApexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3;
            var proof = new JsonObject { ["type"] = useNsec3 ? "NSEC3" : "NSEC" };
            if (useNsec3)
            {
                var parameters = (DnsNSEC3PARAMRecordData)zone.ApexZone.GetRecords(DnsResourceRecordType.NSEC3PARAM)[0].RDATA;
                proof["iterations"] = parameters.Iterations;
                proof["saltLength"] = parameters.Salt.Length;
            }
            result["proof"] = proof;

            var keys = new JsonObject();
            string zoneHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(zone.Name)));
            foreach (var key in (zone.DnssecPrivateKeys ?? []).Where(key => !key.IsRetiring &&
                key.State is DnssecPrivateKeyState.Generated or DnssecPrivateKeyState.Published or DnssecPrivateKeyState.Ready or DnssecPrivateKeyState.Active).OrderBy(key => key.KeyTag))
            {
                (string Family, string Hash, string Curve) algorithm = key.Algorithm switch
                {
                    DnssecAlgorithm.RSAMD5 => ("RSA", "MD5", null),
                    DnssecAlgorithm.RSASHA1 => ("RSA", "SHA1", null),
                    DnssecAlgorithm.RSASHA1_NSEC3_SHA1 => ("RSA", "SHA1-NSEC3", null),
                    DnssecAlgorithm.RSASHA256 => ("RSA", "SHA256", null),
                    DnssecAlgorithm.RSASHA512 => ("RSA", "SHA512", null),
                    DnssecAlgorithm.ECDSAP256SHA256 => ("ECDSA", null, "P256"),
                    DnssecAlgorithm.ECDSAP384SHA384 => ("ECDSA", null, "P384"),
                    DnssecAlgorithm.ED25519 => ("EDDSA", null, "ED25519"),
                    DnssecAlgorithm.ED448 => ("EDDSA", null, "ED448"),
                    _ => throw new InvalidDataException($"{path}/dnssec: The zone uses an unsupported signing algorithm.")
                };
                string name = key.KeyTag.ToString(System.Globalization.CultureInfo.InvariantCulture);
                var entry = new JsonObject
                {
                    ["role"] = key.KeyType.ToString(),
                    ["algorithm"] = algorithm.Family,
                    ["dnsKeySha256"] = GetDnsKeyDigest(key),
                    ["privateKey"] = new JsonObject { ["environment"] = $"TECHNITIUM_DNSSEC_{zoneHash}_{name}" }
                };
                if (key.State == DnssecPrivateKeyState.Generated)
                    entry["publishOnSign"] = false;
                if (algorithm.Hash is not null)
                    entry["hashAlgorithm"] = algorithm.Hash;
                if (algorithm.Curve is not null)
                    entry["curve"] = algorithm.Curve;
                if (key is DnssecRsaPrivateKey rsa)
                    entry["keySize"] = rsa.KeySize;
                if (key.KeyType == DnssecPrivateKeyType.ZoneSigningKey)
                    entry["rolloverDays"] = key.RolloverDays;
                keys.Add(name, entry);
                missingInputs.Add($"{path}/dnssec/keys/{name}/privateKey");
            }
            if (keys.Count == 0)
                missingInputs.Add(path + "/dnssec/keys");
            result["keys"] = keys;
            return result;
        }

        private static Key[] ReadKeys(ConfigurationManifest manifest, JsonElement dnssec, string path)
        {
            JsonElement keys = Read(dnssec, "keys") ?? default;
            Key[] parsed = keys.ValueKind == JsonValueKind.Object
                ? keys.EnumerateObject().Where(key => key.Value.ValueKind != JsonValueKind.Null).Select(key => ReadKey(manifest, key.Value, ConfigurationPlan.AppendPath(path + "/keys", key.Name))).ToArray()
                : [];
            if (parsed.Where(key => key.Imported is not null).GroupBy(key => key.Imported.KeyTag).Any(group => group.Count() > 1))
                throw new InvalidDataException($"{path}/keys: Imported DNSSEC key tags must be distinct.");
            return parsed;
        }

        private static KeyRemoval[] ReadKeyRemovals(JsonElement dnssec, string path)
        {
            if (Read(dnssec, "keys") is not JsonElement keys)
                return [];

            var removals = new List<KeyRemoval>();
            foreach (JsonProperty key in keys.EnumerateObject())
            {
                if (key.Value.ValueKind != JsonValueKind.Null)
                    continue;
                string keyPath = ConfigurationPlan.AppendPath(path + "/keys", key.Name);
                if (!ushort.TryParse(key.Name, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out ushort tag) ||
                    key.Name != tag.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    throw new InvalidDataException($"{keyPath}: Use the numeric DNSSEC key tag to remove a Generated key.");
                removals.Add(new(tag, keyPath));
            }
            return removals.ToArray();
        }

        private static Key ReadKey(ConfigurationManifest manifest, JsonElement value, string path)
        {
            if (value.ValueKind != JsonValueKind.Object || Read(value, "role") is not JsonElement roleValue)
                throw new InvalidDataException($"{path}/role: Specify a DNSSEC key role.");
            var role = Enum.Parse<DnssecPrivateKeyType>(roleValue.GetString());
            string family = Read(value, "algorithm")?.GetString()?.ToUpperInvariant();
            string hash = Read(value, "hashAlgorithm")?.GetString()?.ToUpperInvariant();
            string curve = Read(value, "curve")?.GetString()?.ToUpperInvariant();
            DnssecAlgorithm algorithm = (family, hash, curve) switch
            {
                ("RSA", "MD5", null) => DnssecAlgorithm.RSAMD5,
                ("RSA", "SHA1", null) => DnssecAlgorithm.RSASHA1,
                ("RSA", "SHA1-NSEC3", null) => DnssecAlgorithm.RSASHA1_NSEC3_SHA1,
                ("RSA", "SHA256", null) => DnssecAlgorithm.RSASHA256,
                ("RSA", "SHA512", null) => DnssecAlgorithm.RSASHA512,
                ("ECDSA", null, "P256") => DnssecAlgorithm.ECDSAP256SHA256,
                ("ECDSA", null, "P384") => DnssecAlgorithm.ECDSAP384SHA384,
                ("EDDSA", null, "ED25519") => DnssecAlgorithm.ED25519,
                ("EDDSA", null, "ED448") => DnssecAlgorithm.ED448,
                _ => throw new InvalidDataException($"{path}/algorithm: Specify a supported DNSSEC algorithm and hash or curve.")
            };
            int size = decimal.ToInt32(Read(value, "keySize")?.GetDecimal() ?? -1);
            JsonElement? reference = Read(value, "privateKey");
            string digest = Read(value, "dnsKeySha256")?.GetString();
            if (digest is not null && !reference.HasValue)
                throw new InvalidDataException($"{path}/privateKey: A private-key reference is required for dnsKeySha256.");
            if (family == "RSA" ? ((size != -1 || !reference.HasValue) && (size is < 1024 or > 4096)) : size != -1)
                throw new InvalidDataException($"{path}/keySize: Key size applies only to RSA and must be between 1024 and 4096 bits.");
            ushort rollover = decimal.ToUInt16(Read(value, "rolloverDays")?.GetDecimal() ??
                (role == DnssecPrivateKeyType.ZoneSigningKey && !reference.HasValue ? 30 : 0));
            if (role != DnssecPrivateKeyType.ZoneSigningKey && rollover != 0)
                throw new InvalidDataException($"{path}/rolloverDays: Rollover days apply only to zone signing keys.");

            DnssecPrivateKey imported = null;
            if (manifest is not null && reference.HasValue)
            {
                if (reference.Value.TryGetProperty("zoneFile", out JsonElement zoneFile))
                {
                    imported = ReadZoneFileKey(manifest, zoneFile.GetString(), reference.Value.GetProperty("keyTag").GetUInt16(), path + "/privateKey");
                    if (imported.Algorithm != algorithm || imported.KeyType != role)
                        throw new InvalidDataException($"{path}/privateKey: The referenced key has a different algorithm or role.");
                }
                else
                {
                    string pem = manifest.ResolveReference(reference.Value, path + "/privateKey");
                    try
                    {
                        imported = DnssecPrivateKey.Create(algorithm, role, pem);
                    }
                    catch (Exception ex) when (ex is ArgumentException or CryptographicException or FormatException or IOException or InvalidOperationException)
                    {
                        throw new InvalidDataException($"{path}/privateKey: The referenced DNSSEC key could not be read.");
                    }
                }
                if (size != -1 && ((DnssecRsaPrivateKey)imported).KeySize != size)
                    throw new InvalidDataException($"{path}/keySize: The referenced RSA key has a different size.");
                if (digest is not null && !digest.Equals(GetDnsKeyDigest(imported), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"{path}/dnsKeySha256: The referenced private key does not match the declared DNSKEY digest.");
            }

            return new Key(role, algorithm, size, rollover, imported, path, value.TryGetProperty("rolloverDays", out _), Read(value, "publishOnSign")?.GetBoolean() ?? true);
        }

        private static DnssecPrivateKey ReadZoneFileKey(ConfigurationManifest manifest, string file, ushort tag, string path)
        {
            if (manifest.FilePath is null)
                throw new InvalidDataException($"{path}: Zone-file key references require a local manifest.");

            DnssecPrivateKey key;
            try
            {
                string localPath = System.IO.Path.GetFullPath(file, System.IO.Path.GetDirectoryName(manifest.FilePath));
                using var input = File.OpenRead(localPath);
                using var reader = new BinaryReader(input);
                if (reader.ReadByte() != 'D' || reader.ReadByte() != 'Z' || reader.ReadByte() != 4)
                    throw new InvalidDataException();
                var info = new AuthZoneInfo(reader, DateTime.UnixEpoch);
                key = info.Type == AuthZoneType.Primary ? info.DnssecPrivateKeys?.FirstOrDefault(candidate => candidate.KeyTag == tag) : null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException or CryptographicException or NotSupportedException or DnsServerException)
            {
                throw new InvalidDataException($"{path}: The referenced primary zone file could not be read.");
            }

            if (key is null)
                throw new InvalidDataException($"{path}: The specified DNSSEC key tag was not found in the referenced primary zone file.");
            key.ResetForImport();
            return key;
        }

        private static string GetDnsKeyDigest(DnssecPrivateKey key)
        {
            using var wire = new MemoryStream();
            key.DnsKey.WriteTo(wire);
            // WriteTo prefixes the DNSKEY RDATA with its two-byte wire length.
            return Convert.ToHexString(SHA256.HashData(wire.GetBuffer().AsSpan(2, checked((int)wire.Length - 2))));
        }

        private static JsonElement? Read(JsonElement value, string property) =>
            value.ValueKind == JsonValueKind.Object && value.TryGetProperty(property, out JsonElement item) &&
            item.ValueKind != JsonValueKind.Null ? item : null;
    }
}
