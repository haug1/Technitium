using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Auth;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationGroups
    {
        internal const string Path = "/auth/groups";

        internal static bool TryGetDeclaration(ConfigurationManifest manifest, out JsonElement groups)
        {
            groups = default;
            return manifest is not null && manifest.Settings.TryGetProperty("auth", out JsonElement auth) &&
                auth.TryGetProperty("groups", out groups);
        }

        internal static SortedDictionary<string, Group> Prepare(ConfigurationManifest manifest, AuthManager auth,
            ConfigurationLdap.Settings ldap)
        {
            var changes = new SortedDictionary<string, Group>(StringComparer.Ordinal);
            if (!TryGetDeclaration(manifest, out JsonElement groups))
                return changes;

            if (groups.ValueKind == JsonValueKind.Null)
            {
                foreach (Group group in auth.Groups.Where(group => !IsReserved(group.Name)))
                    Remove(group.Name.ToLowerInvariant(), group, ConfigurationPlan.AppendPath(Path, group.Name));
                return changes;
            }

            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (JsonProperty declaration in groups.EnumerateObject())
            {
                string path = ConfigurationPlan.AppendPath(Path, declaration.Name);
                if (string.IsNullOrWhiteSpace(declaration.Name) || Encoding.UTF8.GetByteCount(declaration.Name) > byte.MaxValue)
                    throw new InvalidDataException($"{path}: Group names must fit in 255 UTF-8 bytes and contain a non-whitespace character.");
                if (!names.Add(declaration.Name))
                    throw new InvalidDataException($"{path}: Duplicate group name.");

                string name = declaration.Name.ToLowerInvariant();
                Group current = auth.GetGroup(name);
                if (declaration.Value.ValueKind == JsonValueKind.Null)
                {
                    if (IsReserved(name))
                        throw new InvalidDataException($"{path}: A built-in group cannot be removed.");
                    if (current is not null)
                        Remove(name, current, path);
                    continue;
                }

                string description = declaration.Value.TryGetProperty("description", out JsonElement value)
                    ? value.GetString() : current?.Description;
                if (Encoding.UTF8.GetByteCount(description ?? "") > byte.MaxValue)
                    throw new InvalidDataException($"{path}/description: A group description must fit in 255 UTF-8 bytes.");
                var candidate = new Group(current?.Name ?? declaration.Name, description);
                if (current is null || candidate.Description != current.Description)
                    changes.Add(name, candidate);
            }

            int count = auth.Groups.Count + changes.Count(entry => entry.Value is not null && auth.GetGroup(entry.Key) is null)
                - changes.Count(entry => entry.Value is null);
            if (count > byte.MaxValue)
                throw new InvalidDataException($"{Path}: At most 255 groups can be stored.");
            return changes;

            void Remove(string name, Group group, string path)
            {
                ValidateRemoval(auth, group, ldap, path);
                changes.Add(name, null);
            }
        }

        internal static void ValidateRemoval(AuthManager auth, Group group, ConfigurationLdap.Settings ldap, string path)
        {
            if (auth.GetGroupMembers(group).Count > 0 ||
                auth.Permissions.Any(permission => permission.GroupPermissions.ContainsKey(group) ||
                    permission.SubItemPermissions.Values.Any(item => item.GroupPermissions.ContainsKey(group))) ||
                (ldap ?? auth.GetManifestLdapSettings()).GroupMap?.Values.Any(IsMapping) == true ||
                auth.SsoGroupMap?.Values.Any(IsMapping) == true)
                throw new InvalidDataException($"{path}: The group is still referenced by authentication settings.");

            bool IsMapping(string mapped) => mapped.Equals(group.Name, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsReserved(string name) => name.ToLowerInvariant() is
            "everyone" or "administrators" or "dns administrators" or "dhcp administrators";

        internal static bool ExistsAfterApply(ConfigurationManifest manifest, AuthManager auth, string name)
        {
            if (TryGetDeclaration(manifest, out JsonElement groups))
            {
                if (groups.ValueKind == JsonValueKind.Null && !IsReserved(name))
                    return false;
                if (groups.ValueKind == JsonValueKind.Object)
                {
                    foreach (JsonProperty group in groups.EnumerateObject())
                    {
                        if (group.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                            return group.Value.ValueKind != JsonValueKind.Null;
                    }
                }
            }
            return name.Length <= 255 && auth.GetGroup(name) is not null;
        }

        internal static JsonObject Export(AuthManager auth)
        {
            var result = new JsonObject();
            foreach (Group group in auth.Groups.OrderBy(group => group.Name, StringComparer.OrdinalIgnoreCase))
                result.Add(group.Name, new JsonObject { ["description"] = group.Description });
            return result;
        }

        internal static void WriteSnapshot(Utf8JsonWriter writer, ConfigurationManifest manifest, AuthManager auth, ConfigurationLdap.Settings ldap)
        {
            var changes = Prepare(manifest, auth, ldap);
            writer.WriteStartObject("manifestGroups");
            writer.WritePropertyName("current");
            Export(auth).WriteTo(writer);
            writer.WriteStartObject("changes");
            foreach (var (name, candidate) in changes)
            {
                Group current = auth.GetGroup(name);
                string path = ConfigurationPlan.AppendPath(Path, candidate?.Name ?? current.Name);
                ConfigurationChangeKind kind = candidate is null ? ConfigurationChangeKind.Remove :
                    current is null ? ConfigurationChangeKind.Add : ConfigurationChangeKind.Update;
                writer.WriteNumber(kind == ConfigurationChangeKind.Update ? path + "/description" : path, (int)kind);
            }
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
    }
}
