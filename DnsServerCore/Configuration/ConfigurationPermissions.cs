using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Auth;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationPermissions
    {
        internal const string Path = "/auth/permissions";

        private static readonly PermissionSection[] _sections = Enum.GetValues<PermissionSection>()
            .Where(section => section != PermissionSection.Unknown).ToArray();

        internal static string GrantPath(PermissionSection section, bool group, string name) =>
            ConfigurationPlan.AppendPath($"{Path}/{section}/{(group ? "groups" : "users")}", name.ToLowerInvariant());

        internal static string[] GetOwnedPaths(ConfigurationManifest manifest)
        {
            if (!TryGetDeclaration(manifest, out JsonElement permissions))
                return [];
            if (permissions.ValueKind == JsonValueKind.Null)
                return [Path];

            var paths = new SortedSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty entry in permissions.EnumerateObject())
            {
                var section = Enum.Parse<PermissionSection>(entry.Name, ignoreCase: true);
                if (entry.Value.ValueKind == JsonValueKind.Null)
                {
                    paths.Add($"{Path}/{section}");
                    continue;
                }
                foreach (JsonProperty map in entry.Value.EnumerateObject())
                    foreach (JsonProperty grant in map.Value.EnumerateObject())
                        paths.Add(GrantPath(section, map.NameEquals("groups"), grant.Name));
            }
            return paths.ToArray();
        }

        internal static bool OwnsGrant(IReadOnlyList<string> paths, PermissionSection section, string path) =>
            paths.Contains(Path) || paths.Contains($"{Path}/{section}") || paths.Contains(path);

        internal static void CheckGrant(IReadOnlyList<string> paths, PermissionSection section, bool group, string name)
        {
            string path = GrantPath(section, group, name);
            if (OwnsGrant(paths, section, path))
                throw new InvalidDataException($"{path}: This permission grant is managed by the manifest.");
        }

        internal static void CheckWrite(IReadOnlyList<string> paths, Permission current,
            IReadOnlyDictionary<User, PermissionFlag> users, IReadOnlyDictionary<Group, PermissionFlag> groups)
        {
            if (paths.Count == 0 || current.SubItemName is not null)
                return;
            if (users is not null)
                CheckMap(current.Section, false, current.UserPermissions, users, user => user.Username, paths);
            if (groups is not null)
                CheckMap(current.Section, true, current.GroupPermissions, groups, group => group.Name, paths);
        }

        internal static void CheckRestore(AuthManager auth, IReadOnlyDictionary<PermissionSection, Permission> restored)
        {
            foreach (PermissionSection section in _sections)
            {
                Permission current = auth.GetPermission(section);
                restored.TryGetValue(section, out Permission candidate);
                CheckMap(section, false, current?.UserPermissions, candidate?.UserPermissions, user => user.Username, auth.ManagedPermissionPaths);
                CheckMap(section, true, current?.GroupPermissions, candidate?.GroupPermissions, group => group.Name, auth.ManagedPermissionPaths);
            }
        }

        private static void CheckMap<T>(PermissionSection section, bool group, IReadOnlyDictionary<T, PermissionFlag> current,
            IReadOnlyDictionary<T, PermissionFlag> candidate, Func<T, string> name, IReadOnlyList<string> paths)
        {
            var before = ToMap(current);
            var after = ToMap(candidate);
            foreach (string principal in before.Keys.Union(after.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
            {
                if (before.GetValueOrDefault(principal) != after.GetValueOrDefault(principal) ||
                    before.ContainsKey(principal) != after.ContainsKey(principal))
                    CheckGrant(paths, section, group, principal);
            }

            Dictionary<string, PermissionFlag> ToMap(IReadOnlyDictionary<T, PermissionFlag> source) =>
                source?.ToDictionary(entry => name(entry.Key).ToLowerInvariant(), entry => entry.Value) ?? [];
        }

        internal sealed record Grant(PermissionSection Section, bool Group, string Name, PermissionFlag? Before, PermissionFlag? After)
        {
            internal string SettingPath => GrantPath(Section, Group, Name);
        }

        internal static bool TryGetDeclaration(ConfigurationManifest manifest, out JsonElement permissions)
        {
            permissions = default;
            return manifest is not null && manifest.Settings.TryGetProperty("auth", out JsonElement auth) &&
                auth.TryGetProperty("permissions", out permissions);
        }

        internal static IReadOnlyList<Grant> Prepare(ConfigurationManifest manifest, AuthManager auth,
            IReadOnlyDictionary<string, Group> groups, IReadOnlyDictionary<string, ConfigurationUsers.Change> users, User actor)
        {
            var changes = new List<Grant>();
            if (!TryGetDeclaration(manifest, out JsonElement declaration))
                return changes;

            if (declaration.ValueKind == JsonValueKind.Null)
            {
                foreach (PermissionSection section in _sections)
                    PrepareSection(section, declaration);
            }
            else
            {
                var sections = new HashSet<PermissionSection>();
                foreach (JsonProperty item in declaration.EnumerateObject())
                {
                    if (!Enum.TryParse(item.Name, ignoreCase: true, out PermissionSection section) ||
                        !_sections.Contains(section) || !section.ToString().Equals(item.Name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException($"{ConfigurationPlan.AppendPath(Path, item.Name)}: Unknown permission section.");
                    if (!sections.Add(section))
                        throw new InvalidDataException($"{Path}/{section}: Duplicate permission section.");
                    PrepareSection(section, item.Value);
                }
            }
            if (actor is not null && changes.Count > 0)
            {
                ValidateActor(PermissionSection.Administration, PermissionFlag.Delete);
                ValidateActor(PermissionSection.Settings, PermissionFlag.Modify);
                ValidateActor(PermissionSection.Settings, PermissionFlag.View);
            }
            return changes;

            void PrepareSection(PermissionSection section, JsonElement value)
            {
                Permission current = auth.GetPermission(section);
                var currentUsers = current?.UserPermissions.ToDictionary(grant => grant.Key.Username, grant => grant.Value) ?? [];
                var currentGroups = current?.GroupPermissions.ToDictionary(grant => grant.Key.Name.ToLowerInvariant(), grant => grant.Value) ?? [];
                if (value.ValueKind == JsonValueKind.Null)
                {
                    foreach (var (name, flags) in currentUsers)
                        changes.Add(new Grant(section, false, name, flags, null));
                    var defaults = Defaults(section);
                    foreach (string name in currentGroups.Keys.Union(defaults.Keys, StringComparer.Ordinal))
                        AddChange(section, true, name, currentGroups, defaults.TryGetValue(name, out var flags) ? flags : null);
                    return;
                }

                if (value.TryGetProperty("users", out JsonElement userMap))
                    ReadMap(section, false, userMap, currentUsers);
                if (value.TryGetProperty("groups", out JsonElement groupMap))
                    ReadMap(section, true, groupMap, currentGroups);
            }

            void ReadMap(PermissionSection section, bool group, JsonElement map, Dictionary<string, PermissionFlag> current)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonProperty entry in map.EnumerateObject())
                {
                    string name = entry.Name.ToLowerInvariant();
                    string path = ConfigurationPlan.AppendPath($"{Path}/{section}/{(group ? "groups" : "users")}", name);
                    if (group ? string.IsNullOrWhiteSpace(name) || name.Length > 255 : !User.IsUsernameValid(name))
                        throw new InvalidDataException($"{path}: Invalid principal name.");
                    if (!names.Add(name))
                        throw new InvalidDataException($"{path}: Duplicate principal.");

                    PermissionFlag? desired = null;
                    if (entry.Value.ValueKind != JsonValueKind.Null)
                    {
                        PermissionFlag flags = PermissionFlag.None;
                        foreach (JsonElement item in entry.Value.EnumerateArray())
                            flags |= Enum.Parse<PermissionFlag>(item.GetString());
                        desired = flags;
                    }

                    if (group && IsRequiredGrant(section, name) && desired != PermissionFlag.ViewModifyDelete)
                        throw new InvalidDataException($"{path}: The built-in administrative grant must retain View, Modify, and Delete.");

                    if (desired is not null &&
                        (group
                            ? groups.TryGetValue(name, out Group candidate) ? candidate is null : auth.GetGroup(name) is null
                            : users?.TryGetValue(name, out var candidateUser) == true ? candidateUser.Remove : auth.GetUser(name) is null))
                        throw new InvalidDataException($"{path}: The principal does not exist in the effective configuration.");

                    AddChange(section, group, name, current, desired);
                }
            }

            void AddChange(PermissionSection section, bool group, string name, Dictionary<string, PermissionFlag> current, PermissionFlag? after)
            {
                PermissionFlag? before = current.TryGetValue(name, out PermissionFlag flags) ? flags : null;
                if (before != after)
                    changes.Add(new Grant(section, group, name, before, after));
            }

            void ValidateActor(PermissionSection section, PermissionFlag flag)
            {
                var relevant = changes.Where(change => change.Section == section).ToArray();
                if (relevant.Length == 0 || !auth.IsPermitted(section, actor, flag))
                    return;

                var current = auth.GetPermission(section);
                string[] memberships = users?.TryGetValue(actor.Username, out var actorChange) == true
                    ? actorChange.Groups : actor.MemberOfGroups.Select(group => group.Name.ToLowerInvariant()).ToArray();
                var direct = relevant.FirstOrDefault(change => !change.Group && change.Name == actor.Username);
                bool retained = direct is not null
                    ? direct.After?.HasFlag(flag) == true
                    : current?.UserPermissions.TryGetValue(actor, out var flags) == true && flags.HasFlag(flag);
                foreach (string name in memberships)
                {
                    var groupChange = relevant.FirstOrDefault(change => change.Group && change.Name == name);
                    retained |= groupChange is not null ? groupChange.After?.HasFlag(flag) == true :
                        auth.GetGroup(name) is Group group && current?.GroupPermissions.TryGetValue(group, out var granted) == true && granted.HasFlag(flag);
                }
                if (!retained)
                    throw new InvalidDataException($"{Path}/{section}: The applying administrator must retain access.");
            }
        }

        private static bool IsRequiredGrant(PermissionSection section, string group) =>
            group == Group.ADMINISTRATORS.ToLowerInvariant() ||
            (section == PermissionSection.Zones && group == Group.DNS_ADMINISTRATORS.ToLowerInvariant()) ||
            (section == PermissionSection.DhcpServer && group == Group.DHCP_ADMINISTRATORS.ToLowerInvariant());

        internal static Dictionary<string, PermissionFlag> Defaults(PermissionSection section)
        {
            var grants = new Dictionary<string, PermissionFlag>(StringComparer.Ordinal)
            {
                [Group.ADMINISTRATORS.ToLowerInvariant()] = PermissionFlag.ViewModifyDelete
            };
            PermissionFlag dns = section switch
            {
                PermissionSection.Zones or PermissionSection.Cache or PermissionSection.Allowed or PermissionSection.Blocked => PermissionFlag.ViewModifyDelete,
                PermissionSection.Apps or PermissionSection.Settings => PermissionFlag.ViewModify,
                PermissionSection.DnsClient => PermissionFlag.View,
                _ => PermissionFlag.None
            };
            if (dns != PermissionFlag.None)
                grants.Add(Group.DNS_ADMINISTRATORS.ToLowerInvariant(), dns);
            if (section == PermissionSection.DhcpServer)
                grants.Add(Group.DHCP_ADMINISTRATORS.ToLowerInvariant(), PermissionFlag.ViewModifyDelete);
            if (section is not (PermissionSection.Settings or PermissionSection.Administration))
                grants.Add(Group.EVERYONE.ToLowerInvariant(), PermissionFlag.View);
            return grants;
        }

        internal static void InstallDefaults(AuthManager auth)
        {
            foreach (PermissionSection section in _sections)
                foreach (var (group, flags) in Defaults(section))
                    auth.SetPermission(section, auth.GetGroup(group), flags);
        }

        internal static JsonObject Export(AuthManager auth)
        {
            var result = new JsonObject();
            foreach (Permission permission in auth.Permissions.Where(permission => permission.Section != PermissionSection.Unknown)
                .OrderBy(permission => permission.Section.ToString(), StringComparer.Ordinal))
            {
                result[permission.Section.ToString()] = new JsonObject
                {
                    ["users"] = WriteGrants(permission.UserPermissions.Select(entry => (entry.Key.Username, entry.Value))),
                    ["groups"] = WriteGrants(permission.GroupPermissions.Select(entry => (entry.Key.Name, entry.Value)))
                };
            }
            return result;

            static JsonObject WriteGrants(IEnumerable<(string Name, PermissionFlag Flags)> grants)
            {
                var result = new JsonObject();
                foreach (var (name, flags) in grants.OrderBy(entry => entry.Name, StringComparer.Ordinal))
                {
                    var values = new JsonArray();
                    foreach (PermissionFlag bit in new[] { PermissionFlag.View, PermissionFlag.Modify, PermissionFlag.Delete })
                        if (flags.HasFlag(bit))
                            values.Add(bit.ToString());
                    result[name] = values;
                }
                return result;
            }
        }

        internal static void WriteSnapshot(Utf8JsonWriter writer, AuthManager auth, IReadOnlyList<Grant> changes)
        {
            writer.WriteStartObject("manifestPermissions");
            writer.WritePropertyName("current");
            Export(auth).WriteTo(writer);
            writer.WriteStartObject("changes");
            foreach (Grant change in changes.OrderBy(change => change.SettingPath, StringComparer.Ordinal))
            {
                var kind = change.Before is null ? ConfigurationChangeKind.Add :
                    change.After is null ? ConfigurationChangeKind.Remove : ConfigurationChangeKind.Update;
                writer.WriteNumber(change.SettingPath, (int)kind);
            }
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
    }
}
