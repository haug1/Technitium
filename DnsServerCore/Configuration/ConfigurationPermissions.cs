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

        internal static string GrantPath(PermissionSection section, bool group, string name, string zone = null) =>
            ConfigurationPlan.AppendPath($"{(zone is null ? $"{Path}/{section}" : ZonePath(zone))}/{(group ? "groups" : "users")}",
                name.ToLowerInvariant());

        internal static string[] GetOwnedPaths(ConfigurationManifest manifest)
        {
            var paths = new SortedSet<string>(StringComparer.Ordinal);
            if (TryGetDeclaration(manifest, out JsonElement permissions))
            {
                if (permissions.ValueKind == JsonValueKind.Null)
                    paths.Add(Path);
                else
                {
                    foreach (JsonProperty entry in permissions.EnumerateObject())
                        AddScope(Enum.Parse<PermissionSection>(entry.Name, ignoreCase: true), entry.Value);
                }
            }
            if (manifest.Settings.TryGetProperty("zones", out JsonElement zones))
            {
                foreach (JsonProperty entry in zones.EnumerateObject())
                {
                    if (entry.Value.ValueKind == JsonValueKind.Object && entry.Value.TryGetProperty("permissions", out JsonElement value))
                        AddScope(PermissionSection.Zones, value,
                            ConfigurationManifest.CanonicalDnsName(entry.Name, "/zones", allowRoot: true));
                }
            }
            return paths.ToArray();

            void AddScope(PermissionSection section, JsonElement value, string zone = null)
            {
                if (value.ValueKind == JsonValueKind.Null)
                {
                    paths.Add(zone is null ? $"{Path}/{section}" : ZonePath(zone));
                    return;
                }
                foreach (JsonProperty map in value.EnumerateObject())
                    foreach (JsonProperty grant in map.Value.EnumerateObject())
                        paths.Add(GrantPath(section, map.NameEquals("groups"), grant.Name, zone));
            }
        }

        internal static void CheckGrant(IReadOnlyList<string> paths, PermissionSection section, bool group, string name, string zone = null)
        {
            string path = GrantPath(section, group, name, zone);
            bool ownsScope = zone is null ? paths.Contains(Path) || paths.Contains($"{Path}/{section}") : paths.Contains(ZonePath(zone));
            if (ownsScope || paths.Contains(path))
                throw new InvalidDataException($"{path}: This permission grant is managed by the manifest.");
        }

        internal static void CheckWrite(IReadOnlyList<string> paths, Permission current,
            IReadOnlyDictionary<User, PermissionFlag> users, IReadOnlyDictionary<Group, PermissionFlag> groups)
        {
            if (paths.Count == 0)
                return;
            if (users is not null)
                CheckMap(current.Section, false, current.UserPermissions, users, user => user.Username, paths, current.SubItemName);
            if (groups is not null)
                CheckMap(current.Section, true, current.GroupPermissions, groups, group => group.Name, paths, current.SubItemName);
        }

        internal static void CheckRestore(AuthManager auth, IReadOnlyDictionary<PermissionSection, Permission> restored)
        {
            foreach (PermissionSection section in _sections)
            {
                Permission current = auth.GetPermission(section);
                restored.TryGetValue(section, out Permission candidate);
                CheckScope(section, current, candidate);
                if (section != PermissionSection.Zones)
                    continue;

                foreach (string zone in (current?.SubItemPermissions.Keys ?? []).Union(candidate?.SubItemPermissions.Keys ?? [], StringComparer.Ordinal))
                    CheckScope(section, current?.GetSubItemPermission(zone), candidate?.GetSubItemPermission(zone), zone);
            }

            void CheckScope(PermissionSection section, Permission current, Permission candidate, string zone = null)
            {
                CheckMap(section, false, current?.UserPermissions, candidate?.UserPermissions, user => user.Username, auth.ManagedPermissionPaths, zone);
                CheckMap(section, true, current?.GroupPermissions, candidate?.GroupPermissions, group => group.Name, auth.ManagedPermissionPaths, zone);
            }
        }

        private static void CheckMap<T>(PermissionSection section, bool group, IReadOnlyDictionary<T, PermissionFlag> current,
            IReadOnlyDictionary<T, PermissionFlag> candidate, Func<T, string> name, IReadOnlyList<string> paths, string zone)
        {
            var before = ToMap(current);
            var after = ToMap(candidate);
            foreach (string principal in before.Keys.Union(after.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
            {
                if (before.GetValueOrDefault(principal) != after.GetValueOrDefault(principal) ||
                    before.ContainsKey(principal) != after.ContainsKey(principal))
                    CheckGrant(paths, section, group, principal, zone);
            }

            Dictionary<string, PermissionFlag> ToMap(IReadOnlyDictionary<T, PermissionFlag> source) =>
                source?.ToDictionary(entry => name(entry.Key).ToLowerInvariant(), entry => entry.Value) ?? [];
        }

        internal sealed record Grant(PermissionSection Section, bool Group, string Name, PermissionFlag? Before, PermissionFlag? After, string Zone = null)
        {
            internal string SettingPath => GrantPath(Section, Group, Name, Zone);
        }

        internal static string ZonePath(string zone) =>
            ConfigurationPlan.AppendPath("/zones", zone.Length == 0 ? "." : zone) + "/permissions";

        internal static bool DeclaresZonePermissions(JsonElement zones) => zones.EnumerateObject().Any(entry =>
            entry.Value.ValueKind == JsonValueKind.Object && entry.Value.TryGetProperty("permissions", out _));

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
            if (manifest is null)
                return changes;
            if (manifest.Settings.TryGetProperty("zones", out JsonElement zones))
            {
                foreach (JsonProperty entry in zones.EnumerateObject())
                {
                    if (entry.Value.ValueKind != JsonValueKind.Object || !entry.Value.TryGetProperty("permissions", out JsonElement value))
                        continue;
                    string zone = ConfigurationManifest.CanonicalDnsName(entry.Name, "/zones", allowRoot: true);
                    PrepareSection(PermissionSection.Zones, value, zone);
                    ValidateActor(PermissionSection.Zones, PermissionFlag.View, zone);
                    ValidateActor(PermissionSection.Zones, PermissionFlag.Delete, zone);
                }
            }
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

            void PrepareSection(PermissionSection section, JsonElement value, string zone = null)
            {
                Permission current = zone is null ? auth.GetPermission(section) : auth.GetPermission(section, zone);
                var currentUsers = current?.UserPermissions.ToDictionary(grant => grant.Key.Username, grant => grant.Value) ?? [];
                var currentGroups = current?.GroupPermissions.ToDictionary(grant => grant.Key.Name.ToLowerInvariant(), grant => grant.Value) ?? [];
                if (zone is not null && current is null)
                {
                    currentGroups[Group.ADMINISTRATORS.ToLowerInvariant()] = PermissionFlag.ViewModifyDelete;
                    currentGroups[Group.DNS_ADMINISTRATORS.ToLowerInvariant()] = PermissionFlag.ViewModifyDelete;
                    if (actor is not null)
                        currentUsers[actor.Username] = PermissionFlag.ViewModifyDelete;
                }
                if (value.ValueKind == JsonValueKind.Null)
                {
                    foreach (var (name, flags) in currentUsers)
                        changes.Add(new Grant(section, false, name, flags, null, zone));
                    var defaults = zone is null ? Defaults(section) : new Dictionary<string, PermissionFlag>
                    {
                        [Group.ADMINISTRATORS.ToLowerInvariant()] = PermissionFlag.ViewModifyDelete,
                        [Group.DNS_ADMINISTRATORS.ToLowerInvariant()] = PermissionFlag.ViewModifyDelete
                    };
                    foreach (string name in currentGroups.Keys.Union(defaults.Keys, StringComparer.Ordinal))
                        AddChange(section, true, name, currentGroups, defaults.TryGetValue(name, out var flags) ? flags : null, zone);
                    return;
                }

                if (value.TryGetProperty("users", out JsonElement userMap))
                    ReadMap(section, false, userMap, currentUsers, zone);
                if (value.TryGetProperty("groups", out JsonElement groupMap))
                    ReadMap(section, true, groupMap, currentGroups, zone);
            }

            void ReadMap(PermissionSection section, bool group, JsonElement map, Dictionary<string, PermissionFlag> current, string zone)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonProperty entry in map.EnumerateObject())
                {
                    string name = entry.Name.ToLowerInvariant();
                    string path = GrantPath(section, group, name, zone);
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

                    AddChange(section, group, name, current, desired, zone);
                }
            }

            void AddChange(PermissionSection section, bool group, string name, Dictionary<string, PermissionFlag> current, PermissionFlag? after, string zone)
            {
                PermissionFlag? before = current.TryGetValue(name, out PermissionFlag flags) ? flags : null;
                if (before != after)
                    changes.Add(new Grant(section, group, name, before, after, zone));
            }

            void ValidateActor(PermissionSection section, PermissionFlag flag, string zone = null)
            {
                var relevant = changes.Where(change => change.Section == section && change.Zone == zone).ToArray();
                if (actor is null || relevant.Length == 0 ||
                    (zone is null ? !auth.IsPermitted(section, actor, flag) : !auth.IsPermitted(section, zone, actor, flag)))
                    return;

                var current = zone is null ? auth.GetPermission(section) : auth.GetPermission(section, zone);
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
                    throw new InvalidDataException($"{(zone is null ? $"{Path}/{section}" : ZonePath(zone))}: The applying administrator must retain access.");
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
                result[permission.Section.ToString()] = ExportGrants(permission);
            }
            return result;
        }

        internal static JsonObject ExportGrants(Permission permission)
        {
            return new JsonObject
            {
                ["users"] = WriteGrants(permission?.UserPermissions.Select(entry => (entry.Key.Username, entry.Value)) ?? []),
                ["groups"] = WriteGrants(permission?.GroupPermissions.Select(entry => (entry.Key.Name, entry.Value)) ?? [])
            };

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

        internal static void WriteSnapshot(Utf8JsonWriter writer, AuthManager auth, IReadOnlyList<Grant> changes, JsonElement declaredZones, bool declaresSections)
        {
            writer.WriteStartObject("manifestPermissions");
            if (declaresSections)
            {
                writer.WritePropertyName("current");
                Export(auth).WriteTo(writer);
            }
            writer.WriteStartObject("zones");
            if (declaredZones.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty entry in declaredZones.EnumerateObject().OrderBy(entry => entry.Name, StringComparer.Ordinal))
                {
                    if (entry.Value.ValueKind != JsonValueKind.Object || !entry.Value.TryGetProperty("permissions", out _))
                        continue;
                    string zone = ConfigurationManifest.CanonicalDnsName(entry.Name, "/zones", allowRoot: true);
                    writer.WritePropertyName(zone);
                    ExportGrants(auth.GetPermission(PermissionSection.Zones, zone)).WriteTo(writer);
                }
            }
            writer.WriteEndObject();
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
