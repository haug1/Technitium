using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Auth;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationSso
    {
        internal const string Path = "/auth/sso";
        private static readonly SortedSet<string> _defaultScopes = new(["openid", "profile", "email"], StringComparer.Ordinal);

        internal sealed record Settings(bool Enabled, Uri Authority, string ClientId, string ClientSecret, Uri MetadataAddress,
            IReadOnlySet<string> Scopes, bool AllowSignup, bool AllowSignupOnlyForMappedUsers, IReadOnlyDictionary<string, string> GroupMap);

        internal static readonly Settings Default = new(false, null, null, null, null, _defaultScopes, false, true, null);

        internal static bool IsDeclared(ConfigurationManifest manifest) => manifest is not null &&
            manifest.Settings.TryGetProperty("auth", out JsonElement auth) && auth.TryGetProperty("sso", out _);

        internal static Settings Prepare(ConfigurationManifest manifest, AuthManager auth)
        {
            if (!IsDeclared(manifest))
                return null;

            JsonElement sso = manifest.Settings.GetProperty("auth").GetProperty("sso");
            Settings current = auth.GetManifestSsoSettings();
            IReadOnlySet<string> scopes = current.Scopes;
            if (sso.TryGetProperty("scopes", out JsonElement scopeList))
            {
                var desired = new SortedSet<string>(StringComparer.Ordinal);
                if (scopeList.ValueKind != JsonValueKind.Null)
                {
                    foreach (JsonElement item in scopeList.EnumerateArray())
                    {
                        string scope = item.GetString();
                        CheckLength(scope, "scopes");
                        if (string.IsNullOrWhiteSpace(scope) || scope.Any(char.IsWhiteSpace))
                            throw new InvalidDataException($"{Path}/scopes: Scope names must be nonempty and contain no whitespace.");
                        desired.Add(scope);
                    }
                }
                scopes = NormalizeScopes(desired);
                if (scopes.Count > byte.MaxValue)
                    throw new InvalidDataException($"{Path}/scopes: At most 255 scopes can be stored.");
            }

            var groups = new SortedDictionary<string, string>(StringComparer.Ordinal);
            if (current.GroupMap is not null)
                foreach (var (name, group) in current.GroupMap)
                    groups.Add(name, group);

            if (sso.TryGetProperty("groupMap", out JsonElement mappings))
            {
                if (mappings.ValueKind == JsonValueKind.Null)
                    groups.Clear();
                else
                {
                    foreach (JsonProperty mapping in mappings.EnumerateObject())
                    {
                        string path = ConfigurationPlan.AppendPath("groupMap", mapping.Name);
                        if (mapping.Value.ValueKind == JsonValueKind.Null)
                        {
                            groups.Remove(mapping.Name);
                            continue;
                        }
                        string group = mapping.Value.GetString();
                        CheckLength(mapping.Name, path);
                        CheckLength(group, path);
                        if (string.IsNullOrWhiteSpace(mapping.Name) || !ConfigurationGroups.ExistsAfterApply(manifest, auth, group))
                            throw new InvalidDataException($"{Path}/{path}: An external group must map to an existing local group.");
                        groups[mapping.Name] = group;
                    }
                }
                if (groups.Count > byte.MaxValue)
                    throw new InvalidDataException($"{Path}/groupMap: At most 255 mappings can be stored.");
            }

            string secret = current.ClientSecret;
            if (sso.TryGetProperty("clientSecret", out JsonElement reference))
            {
                secret = reference.ValueKind == JsonValueKind.Null ? null : manifest.ResolveReference(reference, Path + "/clientSecret");
                CheckLength(secret, "clientSecret");
                if (secret?.Length == 0)
                    secret = null;
            }

            string clientId = sso.TryGetProperty("clientId", out JsonElement id) ? id.GetString() : current.ClientId;
            CheckLength(clientId, "clientId");
            if (string.IsNullOrEmpty(clientId))
                clientId = null;
            var desiredSettings = new Settings(Flag("enabled", current.Enabled, false), ReadUri("authority", current.Authority),
                clientId, secret, ReadUri("metadataAddress", current.MetadataAddress), scopes,
                Flag("allowSignup", current.AllowSignup, false), Flag("allowSignupOnlyForMappedUsers", current.AllowSignupOnlyForMappedUsers, true), groups);
            if (desiredSettings.Enabled && (desiredSettings.Authority is null || string.IsNullOrWhiteSpace(desiredSettings.ClientId) ||
                string.IsNullOrWhiteSpace(desiredSettings.ClientSecret)))
                throw new InvalidDataException($"{Path}: Enabling SSO requires an authority, client ID, and client secret.");
            return desiredSettings;

            bool Flag(string field, bool previous, bool reset) => sso.TryGetProperty(field, out JsonElement value)
                ? value.ValueKind == JsonValueKind.Null ? reset : value.GetBoolean() : previous;

            Uri ReadUri(string field, Uri previous)
            {
                if (!sso.TryGetProperty(field, out JsonElement value))
                    return previous;
                string text = value.GetString();
                CheckLength(text, field);
                if (string.IsNullOrEmpty(text))
                    return null;
                if (!Uri.TryCreate(text, UriKind.Absolute, out Uri uri) || uri.Scheme is not ("http" or "https") || uri.Host.Length == 0)
                    throw new InvalidDataException($"{Path}/{field}: Expected an absolute HTTP or HTTPS URI.");
                return uri;
            }
        }

        private static void CheckLength(string value, string field)
        {
            if (value is not null && Encoding.UTF8.GetByteCount(value) > byte.MaxValue)
                throw new InvalidDataException($"{Path}/{field}: The configured value exceeds 255 UTF-8 bytes.");
        }

        internal static JsonObject Export(Settings settings) => JsonSerializer.SerializeToNode(new
        {
            enabled = settings.Enabled, authority = settings.Authority?.OriginalString, clientId = settings.ClientId,
            metadataAddress = settings.MetadataAddress?.OriginalString, scopes = settings.Scopes.Order(StringComparer.Ordinal),
            allowSignup = settings.AllowSignup, allowSignupOnlyForMappedUsers = settings.AllowSignupOnlyForMappedUsers,
            groupMap = settings.GroupMap?.OrderBy(entry => entry.Key, StringComparer.Ordinal).ToDictionary() ?? []
        }).AsObject();

        internal static string[] GetOwnedFields(ConfigurationManifest manifest)
        {
            if (!IsDeclared(manifest))
                return [];
            var fields = new SortedSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty field in manifest.Settings.GetProperty("auth").GetProperty("sso").EnumerateObject())
            {
                if (field.NameEquals("groupMap") && field.Value.ValueKind == JsonValueKind.Object)
                {
                    foreach (JsonProperty mapping in field.Value.EnumerateObject())
                        fields.Add(ConfigurationPlan.AppendPath("groupMap", mapping.Name));
                }
                else
                {
                    fields.Add(field.Name);
                }
            }
            if (fields.Count > ushort.MaxValue)
                throw new InvalidDataException($"{Path}: Too many SSO ownership declarations.");
            return fields.ToArray();
        }

        internal static IReadOnlySet<string> NormalizeScopes(IEnumerable<string> scopes)
        {
            var result = new SortedSet<string>(scopes, StringComparer.Ordinal);
            if (result.Count == 0)
                result.UnionWith(_defaultScopes);
            else
                result.UnionWith(["openid", "profile"]);
            return result;
        }

        internal static void CheckOwnership(Settings current, Settings desired, IReadOnlyList<string> fields)
        {
            if (fields.Count == 0)
                return;
            JsonObject before = Export(current);
            JsonObject after = Export(desired);
            foreach (string field in fields)
            {
                bool changed;
                if (field == "clientSecret")
                    changed = current.ClientSecret != desired.ClientSecret;
                else if (field.StartsWith("groupMap/", StringComparison.Ordinal))
                {
                    string key = field["groupMap/".Length..].Replace("~1", "/").Replace("~0", "~");
                    changed = !JsonNode.DeepEquals(before["groupMap"]?[key], after["groupMap"]?[key]);
                }
                else
                    changed = !JsonNode.DeepEquals(before[field], after[field]);
                if (changed)
                    throw new InvalidDataException($"{Path}/{field}: SSO setting is managed by the configuration manifest.");
            }
        }

        internal static void CheckGroupReference(Settings settings, IReadOnlyList<string> fields, string group)
        {
            if (fields.Count == 0 || settings.GroupMap is null)
                return;
            foreach (var (key, target) in settings.GroupMap)
            {
                string field = ConfigurationPlan.AppendPath("groupMap", key);
                if (target.Equals(group, StringComparison.OrdinalIgnoreCase) &&
                    (fields.Contains("groupMap") || fields.Contains(field)))
                    throw new InvalidDataException($"{Path}/{field}: The managed SSO mapping references this group.");
            }
        }

        internal static bool Same(Settings current, Settings desired) =>
            current.ClientSecret == desired.ClientSecret && JsonNode.DeepEquals(Export(current), Export(desired));

        internal static bool NeedsRestart(Settings current, Settings desired) => desired is not null &&
            (current.Enabled != desired.Enabled || desired.Enabled &&
                (current.Authority != desired.Authority || current.ClientId != desired.ClientId || current.ClientSecret != desired.ClientSecret ||
                    current.MetadataAddress != desired.MetadataAddress || !current.Scopes.SetEquals(desired.Scopes)));

        internal static void WriteSnapshot(Utf8JsonWriter writer, Settings current, Settings desired, byte[] key)
        {
            writer.WriteStartObject("manifestSso");
            Write("current", current);
            Write("desired", desired);
            writer.WriteBoolean("restart", NeedsRestart(current, desired));
            writer.WriteEndObject();

            void Write(string property, Settings value)
            {
                JsonObject settings = Export(value);
                settings["clientSecret"] = value.ClientSecret is null ? null :
                    Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value.ClientSecret)));
                writer.WritePropertyName(property);
                settings.WriteTo(writer);
            }
        }

        internal static void Compare(JsonElement snapshot, List<ConfigurationChange> changes)
        {
            JsonElement before = snapshot.GetProperty("current");
            bool restart = snapshot.GetProperty("restart").GetBoolean();
            foreach (JsonProperty field in snapshot.GetProperty("desired").EnumerateObject())
            {
                if (!JsonElement.DeepEquals(field.Value, before.GetProperty(field.Name)))
                    changes.Add(new ConfigurationChange(ConfigurationPlan.AppendPath(Path, field.Name), ConfigurationChangeKind.Update,
                        restart && field.Name is "enabled" or "authority" or "clientId" or "clientSecret" or "metadataAddress" or "scopes"));
            }
        }
    }
}
