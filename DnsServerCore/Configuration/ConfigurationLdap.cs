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
    internal static class ConfigurationLdap
    {
        internal const string Path = "/auth/ldap";

        internal sealed record Settings(bool Enabled, string Server, int Port, LdapAuthSslOption SslOption, bool IgnoreSslErrors,
            string BindUsername, string BindPassword, string SearchBase, string UserSearchFilter, string GroupAttribute,
            bool AllowSignup, bool AllowSignupOnlyForMappedUsers, IReadOnlyDictionary<string, string> GroupMap);

        internal static readonly Settings Default = new(false, null, 389, default, false, null, null, null, null, null, false, true, null);

        internal static bool IsDeclared(ConfigurationManifest manifest) =>
            manifest.Settings.TryGetProperty("auth", out JsonElement auth) && auth.TryGetProperty("ldap", out _);

        internal static Settings Prepare(ConfigurationManifest manifest, AuthManager auth)
        {
            if (!IsDeclared(manifest))
                return null;

            JsonElement ldap = manifest.Settings.GetProperty("auth").GetProperty("ldap");
            Settings current = auth.GetManifestLdapSettings();
            var groups = new SortedDictionary<string, string>(StringComparer.Ordinal);
            if (current.GroupMap is not null)
                foreach (var (name, group) in current.GroupMap)
                    groups.Add(name, group);

            if (ldap.TryGetProperty("groupMap", out JsonElement groupMap))
            {
                if (groupMap.ValueKind == JsonValueKind.Null)
                    groups.Clear();
                else
                {
                    foreach (JsonProperty entry in groupMap.EnumerateObject())
                    {
                        if (entry.Value.ValueKind == JsonValueKind.Null)
                            groups.Remove(entry.Name);
                        else
                        {
                            string path = ConfigurationPlan.AppendPath(Path + "/groupMap", entry.Name);
                            string group = entry.Value.GetString();
                            CheckLength(entry.Name, path);
                            CheckLength(group, path);
                            if (!auth.Groups.Any(candidate => candidate.Name.Equals(group, StringComparison.OrdinalIgnoreCase)))
                                throw new InvalidDataException($"{path}: The mapped local group does not exist.");
                            groups[entry.Name] = group;
                        }
                    }
                }
                if (groups.Count > byte.MaxValue)
                    throw new InvalidDataException($"{Path}/groupMap: At most 255 mappings can be stored.");
            }

            string password = current.BindPassword;
            if (ldap.TryGetProperty("bindPassword", out JsonElement reference))
            {
                password = reference.ValueKind == JsonValueKind.Null ? null : manifest.ResolveReference(reference, Path + "/bindPassword");
                CheckLength(password, Path + "/bindPassword");
                if (password?.Length == 0)
                    password = null;
            }

            var desired = new Settings(
                Flag("enabled", current.Enabled, false), Read("server", current.Server),
                ldap.TryGetProperty("port", out JsonElement port) ? port.ValueKind == JsonValueKind.Null ? 389 : port.GetInt32() : current.Port,
                ldap.TryGetProperty("sslOption", out JsonElement ssl) ? ssl.ValueKind == JsonValueKind.Null ? default : Enum.Parse<LdapAuthSslOption>(ssl.GetString()) : current.SslOption,
                Flag("ignoreSslErrors", current.IgnoreSslErrors, false), Read("bindUsername", current.BindUsername), password,
                Read("searchBase", current.SearchBase), Read("userSearchFilter", current.UserSearchFilter), Read("groupAttribute", current.GroupAttribute),
                Flag("allowSignup", current.AllowSignup, false), Flag("allowSignupOnlyForMappedUsers", current.AllowSignupOnlyForMappedUsers, true), groups);
            if (desired.Enabled && string.IsNullOrEmpty(desired.Server))
                throw new InvalidDataException($"{Path}/server: Enabling LDAP requires a server.");

            return desired;

            bool Flag(string name, bool previous, bool reset) => ldap.TryGetProperty(name, out JsonElement value)
                ? value.ValueKind == JsonValueKind.Null ? reset : value.GetBoolean() : previous;

            string Read(string name, string previous)
            {
                if (!ldap.TryGetProperty(name, out JsonElement value))
                    return previous;
                string text = value.GetString();
                CheckLength(text, Path + "/" + name);
                return string.IsNullOrEmpty(text) ? null : text;
            }
        }

        private static void CheckLength(string value, string path)
        {
            if (value is not null && Encoding.UTF8.GetByteCount(value) > byte.MaxValue)
                throw new InvalidDataException($"{path}: The configured value exceeds 255 UTF-8 bytes.");
        }

        internal static JsonObject Export(Settings settings) => JsonSerializer.SerializeToNode(new
        {
            enabled = settings.Enabled, server = settings.Server, port = settings.Port, sslOption = settings.SslOption.ToString(),
            ignoreSslErrors = settings.IgnoreSslErrors, bindUsername = settings.BindUsername, searchBase = settings.SearchBase,
            userSearchFilter = settings.UserSearchFilter, groupAttribute = settings.GroupAttribute, allowSignup = settings.AllowSignup,
            allowSignupOnlyForMappedUsers = settings.AllowSignupOnlyForMappedUsers,
            groupMap = settings.GroupMap?.OrderBy(entry => entry.Key, StringComparer.Ordinal).ToDictionary() ?? []
        }).AsObject();

        internal static bool Same(Settings first, Settings second) =>
            first.BindPassword == second.BindPassword && JsonNode.DeepEquals(Export(first), Export(second));

        internal static void WriteSnapshot(Utf8JsonWriter writer, Settings current, Settings desired, byte[] key)
        {
            writer.WriteStartObject("manifestLdap");
            Write("current", current);
            Write("desired", desired);
            writer.WriteEndObject();

            void Write(string property, Settings value)
            {
                JsonObject settings = Export(value);
                settings["bindPassword"] = value.BindPassword is null ? null :
                    Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value.BindPassword)));
                writer.WritePropertyName(property);
                settings.WriteTo(writer);
            }
        }

        internal static void Compare(JsonElement auth, JsonElement snapshot, List<ConfigurationChange> changes)
        {
            foreach (JsonProperty section in auth.EnumerateObject())
            {
                if (section.Name != "ldap")
                    throw new InvalidDataException($"{ConfigurationPlan.AppendPath("/auth", section.Name)}: Planning for this setting is not implemented.");
            }
            JsonElement before = snapshot.GetProperty("current");
            foreach (JsonProperty field in snapshot.GetProperty("desired").EnumerateObject())
            {
                if (!JsonElement.DeepEquals(field.Value, before.GetProperty(field.Name)))
                    changes.Add(new ConfigurationChange(ConfigurationPlan.AppendPath(Path, field.Name), ConfigurationChangeKind.Update, false));
            }
        }
    }
}
