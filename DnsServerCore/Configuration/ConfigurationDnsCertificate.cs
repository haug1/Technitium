using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DnsServerCore.Dns;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationDnsCertificate
    {
        internal const string Path = "/dns/listeners/certificate";

        internal readonly record struct Candidate(bool OwnsPath, bool OwnsPassword, DnsServer.DnsCertificate Certificate);

        internal static bool TryGetDeclaration(ConfigurationManifest manifest, out JsonElement declaration)
        {
            declaration = default;
            return manifest is not null && manifest.Settings.TryGetProperty("dns", out JsonElement dns) &&
                dns.TryGetProperty("listeners", out JsonElement listeners) && listeners.TryGetProperty("certificate", out declaration);
        }

        internal static Candidate Prepare(ConfigurationManifest manifest, DnsServer dns, bool preview = false)
        {
            if (!TryGetDeclaration(manifest, out JsonElement declaration))
                return default;

            bool reset = declaration.ValueKind == JsonValueKind.Null;
            JsonElement pathValue = default, reference = default;
            bool ownsPath = reset || declaration.TryGetProperty("path", out pathValue);
            bool ownsPassword = reset || declaration.TryGetProperty("password", out reference);
            if (!ownsPath && !ownsPassword)
                return default;

            DnsServer.DnsCertificate current = dns.CaptureDnsCertificate();
            string path;
            try
            {
                path = ownsPath ? dns.NormalizeDnsCertificatePath(reset ? null : pathValue.GetString()) : current.Path;
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or NotSupportedException)
            {
                throw new InvalidDataException($"{Path}/path: Invalid DNS certificate path.");
            }
            if (path is not null && Encoding.UTF8.GetByteCount(path) > byte.MaxValue)
                throw new InvalidDataException($"{Path}/path: The DNS certificate path exceeds 255 UTF-8 bytes.");

            string password = ownsPassword
                ? reset || reference.ValueKind == JsonValueKind.Null ? null : manifest.ResolveReference(reference, Path + "/password")
                : path is null ? null : current.Password;
            if (password is not null && Encoding.UTF8.GetByteCount(password) > byte.MaxValue)
                throw new InvalidDataException($"{Path}/password: The resolved password exceeds 255 UTF-8 bytes.");
            if (path is null && !string.IsNullOrEmpty(password))
                throw new InvalidDataException($"{Path}/password: A password requires a DNS certificate path.");

            try
            {
                return new Candidate(ownsPath, ownsPassword, dns.ReadManifestDnsCertificate(path, password, preview));
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or CryptographicException or NotSupportedException)
            {
                throw new InvalidDataException($"{Path}: Could not load the PKCS #12 certificate and private key.");
            }
        }

        internal static bool HasSecureBindings(DnsServer.DnsBindings candidate, DnsServer.DnsBindings current)
        {
            return (candidate.TlsEnabled ?? current.TlsEnabled) == true ||
                (candidate.HttpsEnabled ?? current.HttpsEnabled) == true ||
                (candidate.HttpsSocketEnabled ?? current.HttpsSocketEnabled) == true ||
                (candidate.QuicEnabled ?? current.QuicEnabled) == true;
        }

        internal static void WriteSnapshot(Utf8JsonWriter writer, DnsServer.DnsCertificate current, Candidate candidate, byte[] key)
        {
            if (candidate.Certificate is not DnsServer.DnsCertificate desired)
                return;

            writer.WriteStartObject("manifestDnsCertificate");
            writer.WriteString("currentFile", current.FileHash);
            writer.WriteString("desiredFile", desired.FileHash);
            writer.WriteString("currentPassword", Fingerprint(current.Password));
            writer.WriteString("desiredPassword", Fingerprint(desired.Password));
            writer.WriteString("desiredPath", desired.Path);
            writer.WriteEndObject();

            string Fingerprint(string value) => string.IsNullOrEmpty(value)
                ? null : Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));
        }

        internal static void Compare(JsonElement declaration, JsonElement snapshot, bool restart, List<ConfigurationChange> changes)
        {
            if (!snapshot.TryGetProperty("manifestDnsCertificate", out JsonElement candidate))
            {
                if (declaration.ValueKind == JsonValueKind.Object && !declaration.TryGetProperty("password", out _) &&
                    (!declaration.TryGetProperty("path", out JsonElement path) || path.ValueKind == JsonValueKind.Null &&
                        snapshot.TryGetProperty("dnsTlsCertificatePath", out JsonElement current) && current.ValueKind == JsonValueKind.Null))
                    return;
                throw new InvalidDataException($"{Path}: A server preview is required to load the DNS certificate.");
            }
            string currentPath = snapshot.GetProperty("dnsTlsCertificatePath").GetString();
            string desiredPath = candidate.GetProperty("desiredPath").GetString();
            if (currentPath != desiredPath || !JsonElement.DeepEquals(candidate.GetProperty("currentFile"), candidate.GetProperty("desiredFile")))
            {
                ConfigurationChangeKind kind = currentPath is null ? ConfigurationChangeKind.Add :
                    desiredPath is null ? ConfigurationChangeKind.Remove : ConfigurationChangeKind.Update;
                changes.Add(new ConfigurationChange(Path + "/path", kind, false, restart));
            }
            if (!JsonElement.DeepEquals(candidate.GetProperty("currentPassword"), candidate.GetProperty("desiredPassword")))
                changes.Add(new ConfigurationChange(Path + "/password", ConfigurationChangeKind.Update, false, restart));
        }
    }
}
