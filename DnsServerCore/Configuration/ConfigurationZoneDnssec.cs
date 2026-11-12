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
        internal sealed record Key(DnssecPrivateKeyType Role, DnssecAlgorithm Algorithm, int Size, ushort RolloverDays, DnssecPrivateKey Imported, string Path, bool HasRolloverDays)
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
            bool Disable = false, bool ChangeProof = false, bool ChangeTtl = false, RolloverChange[] Rollovers = null);

        internal sealed record RolloverChange(ushort Tag, ushort Before, ushort After);

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

            JsonElement keys = Read(dnssec, "keys") ?? default;
            Key[] parsed = keys.ValueKind == JsonValueKind.Object
                ? keys.EnumerateObject().Select(key => ReadKey(manifest, key.Value, ConfigurationPlan.AppendPath(path + "/keys", key.Name))).ToArray()
                : [];
            if (signed)
            {
                var remaining = (current.DnssecPrivateKeys ?? []).Where(key => !key.IsRetiring).ToList();
                var rollovers = new List<RolloverChange>();
                foreach (Key expected in parsed.OrderBy(key => key.Imported is null))
                {
                    var matches = remaining.Where(expected.Matches).ToList();
                    if (matches.Count == 0)
                        throw new InvalidDataException($"{expected.Path}: No existing signing key matches the declaration.");

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
                    rollovers.Add(new(key.KeyTag, key.RolloverDays, expected.RolloverDays));
                }

                bool changeTtl = ttl != current.DnsKeyTtl;
                bool changeProof = useNsec3 != currentNsec3 || (useNsec3 &&
                    (iterations != (parameters?.Iterations ?? 0) || saltLength != (parameters?.Salt.Length ?? 0)));
                if (!changeProof && !changeTtl && rollovers.Count == 0)
                    return null;
                if (changeTtl)
                {
                    try
                    {
                        ((PrimaryZone)current.ApexZone).CheckDnsKeyTtlUpdate();
                    }
                    catch (DnsServerException ex)
                    {
                        throw new InvalidDataException($"{path}/dnsKeyTtl: {ex.Message}");
                    }
                }
                return new Signing(ttl, useNsec3, (ushort)iterations, saltLength, [], ChangeProof: changeProof, ChangeTtl: changeTtl, Rollovers: rollovers.ToArray());
            }

            if (!parsed.Any(key => key.Role == DnssecPrivateKeyType.KeySigningKey) ||
                !parsed.Any(key => key.Role == DnssecPrivateKeyType.ZoneSigningKey))
                throw new InvalidDataException($"{path}/keys: Specify both a key signing key and a zone signing key.");
            if (parsed.Where(key => key.Imported is not null).GroupBy(key => key.Imported.KeyTag).Any(group => group.Count() > 1))
                throw new InvalidDataException($"{path}/keys: Imported DNSSEC key tags must be distinct.");
            return new Signing(ttl, useNsec3, (ushort)iterations, saltLength, parsed);
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
                key.State is DnssecPrivateKeyState.Published or DnssecPrivateKeyState.Ready or DnssecPrivateKeyState.Active).OrderBy(key => key.KeyTag))
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
                    ["privateKey"] = new JsonObject { ["environment"] = $"TECHNITIUM_DNSSEC_{zoneHash}_{name}" }
                };
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
            if (family == "RSA" ? ((size != -1 || !reference.HasValue) && (size is < 1024 or > 4096)) : size != -1)
                throw new InvalidDataException($"{path}/keySize: Key size applies only to RSA and must be between 1024 and 4096 bits.");
            ushort rollover = decimal.ToUInt16(Read(value, "rolloverDays")?.GetDecimal() ??
                (role == DnssecPrivateKeyType.ZoneSigningKey && !reference.HasValue ? 30 : 0));
            if (role != DnssecPrivateKeyType.ZoneSigningKey && rollover != 0)
                throw new InvalidDataException($"{path}/rolloverDays: Rollover days apply only to zone signing keys.");

            DnssecPrivateKey imported = null;
            if (reference.HasValue)
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
                if (size != -1 && ((DnssecRsaPrivateKey)imported).KeySize != size)
                    throw new InvalidDataException($"{path}/keySize: The referenced RSA key has a different size.");
            }

            return new Key(role, algorithm, size, rollover, imported, path, value.TryGetProperty("rolloverDays", out _));
        }

        private static JsonElement? Read(JsonElement value, string property) =>
            value.ValueKind == JsonValueKind.Object && value.TryGetProperty(property, out JsonElement item) &&
            item.ValueKind != JsonValueKind.Null ? item : null;
    }
}
