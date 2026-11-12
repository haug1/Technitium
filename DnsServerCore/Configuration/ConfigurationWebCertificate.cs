using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationWebCertificate
    {
        internal const string Path = "/web/certificate";
        internal readonly record struct State(bool SelfSigned, string Path, string Password, string FileHash);
        internal readonly record struct Preview(State Current, State Desired)
        {
            internal bool HasCertificate => Desired.SelfSigned || Desired.FileHash is not null;
        }

        internal static bool IsDeclared(ConfigurationManifest manifest)
        {
            return manifest.Settings.TryGetProperty("web", out JsonElement web) &&
                (web.TryGetProperty("useSelfSignedCertificate", out _) ||
                 web.TryGetProperty("certificate", out JsonElement certificate) &&
                 (certificate.ValueKind == JsonValueKind.Null || certificate.TryGetProperty("path", out _) ||
                  certificate.TryGetProperty("password", out _)));
        }

        internal static Preview PreparePreview(ConfigurationManifest manifest, State current, LogManager log)
        {
            JsonElement web = manifest.Settings.GetProperty("web");
            bool selfSigned = web.TryGetProperty("useSelfSignedCertificate", out JsonElement selfSignedValue)
                ? selfSignedValue.ValueKind == JsonValueKind.True : current.SelfSigned;

            bool hasCertificate = web.TryGetProperty("certificate", out JsonElement certificate);
            bool reset = hasCertificate && certificate.ValueKind == JsonValueKind.Null;
            JsonElement declaredPath = default, reference = default;
            bool hasPath = hasCertificate && !reset && certificate.TryGetProperty("path", out declaredPath);
            bool hasPassword = hasCertificate && !reset && certificate.TryGetProperty("password", out reference);
            string path = reset ? null : hasPath ? declaredPath.GetString() : current.Path;

            try
            {
                path = string.IsNullOrWhiteSpace(path) ? null : log.ConvertToRelativePath(log.ConvertToAbsolutePath(path));
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or NotSupportedException)
            {
                throw new InvalidDataException($"{Path}/path: Invalid web certificate path.");
            }
            if (path is not null && Encoding.UTF8.GetByteCount(path) > byte.MaxValue)
                throw new InvalidDataException($"{Path}/path: The web certificate path exceeds 255 UTF-8 bytes.");

            string password = hasPassword && reference.ValueKind != JsonValueKind.Null
                ? manifest.ResolveReference(reference, Path + "/password")
                : reset || hasPassword || path is null ? null : current.Password;
            if (password is not null && Encoding.UTF8.GetByteCount(password) > byte.MaxValue)
                throw new InvalidDataException($"{Path}/password: The resolved password exceeds 255 UTF-8 bytes.");
            if (path is null && !string.IsNullOrEmpty(password))
                throw new InvalidDataException($"{Path}/password: A password requires a web certificate path.");

            string fileHash = null;
            if (path is not null)
            {
                try
                {
                    fileHash = Pkcs12Certificate.Read(log.ConvertToAbsolutePath(path), password, X509KeyStorageFlags.EphemeralKeySet).FileHash;
                }
                catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or CryptographicException or NotSupportedException)
                {
                    throw new InvalidDataException($"{Path}: Could not load the PKCS #12 certificate and private key.");
                }
            }

            return new Preview(current, new State(selfSigned, path, password, fileHash));
        }

        internal static void WriteSnapshot(Utf8JsonWriter writer, Preview preview, byte[] key)
        {
            writer.WriteStartObject("manifestWebCertificate");
            writer.WriteString("currentFile", preview.Current.Path is null ? null : preview.Current.FileHash);
            writer.WriteString("desiredFile", preview.Desired.FileHash);
            writer.WriteString("currentPassword", Fingerprint(preview.Current.Password));
            writer.WriteString("desiredPassword", Fingerprint(preview.Desired.Password));
            writer.WriteString("desiredPath", preview.Desired.Path);
            writer.WriteEndObject();

            string Fingerprint(string value) => string.IsNullOrEmpty(value)
                ? null : Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));
        }

        internal static void Compare(JsonElement declaration, JsonElement snapshot, List<ConfigurationChange> changes)
        {
            if (!snapshot.TryGetProperty("manifestWebCertificate", out JsonElement certificate))
            {
                if (declaration.ValueKind == JsonValueKind.Object && !declaration.TryGetProperty("password", out _) &&
                    (!declaration.TryGetProperty("path", out JsonElement path) || path.ValueKind == JsonValueKind.Null &&
                        snapshot.TryGetProperty("webServiceTlsCertificatePath", out JsonElement current) && current.ValueKind == JsonValueKind.Null))
                    return;
                throw new InvalidDataException($"{Path}: A server preview is required to load the web certificate.");
            }

            string currentPath = snapshot.GetProperty("webServiceTlsCertificatePath").GetString();
            string desiredPath = certificate.GetProperty("desiredPath").GetString();
            if (currentPath != desiredPath || !JsonElement.DeepEquals(certificate.GetProperty("currentFile"), certificate.GetProperty("desiredFile")))
            {
                ConfigurationChangeKind kind = currentPath is null ? ConfigurationChangeKind.Add :
                    desiredPath is null ? ConfigurationChangeKind.Remove : ConfigurationChangeKind.Update;
                changes.Add(new ConfigurationChange(Path + "/path", kind, true));
            }
            if (!JsonElement.DeepEquals(certificate.GetProperty("currentPassword"), certificate.GetProperty("desiredPassword")))
                changes.Add(new ConfigurationChange(Path + "/password", ConfigurationChangeKind.Update, true));
        }
    }
}
