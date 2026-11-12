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
    internal static class ConfigurationUsers
    {
        internal const string Path = "/auth/users";

        internal sealed record Change(User Current, string Name, string DisplayName, bool Disabled, int Timeout,
            string[] Groups, string Password, int Iterations, string[] Fields)
        {
            internal User Stage(AuthManager auth, IReadOnlyDictionary<string, Group> groupChanges)
            {
                User user = Current?.CopyForManifest() ?? User.CreateLocalUser(DisplayName, Name, Password, Iterations);
                user.DisplayName = DisplayName;
                user.Disabled = Disabled;
                user.SessionTimeoutSeconds = Timeout;
                var groups = new Dictionary<string, Group>(StringComparer.Ordinal);
                foreach (string name in Groups)
                    groups.Add(name, auth.GetGroup(name) ?? groupChanges[name]);
                user.SyncGroups(groups);
                if (Current is not null && Fields.Contains("password"))
                    user.ChangePassword(Password, Iterations);
                return user;
            }
        }

        internal static bool TryGetDeclaration(ConfigurationManifest manifest, out JsonElement users)
        {
            users = default;
            return manifest is not null && manifest.Settings.TryGetProperty("auth", out JsonElement auth) &&
                auth.TryGetProperty("users", out users);
        }

        internal static SortedDictionary<string, Change> Prepare(ConfigurationManifest manifest, AuthManager auth,
            IReadOnlyDictionary<string, Group> groupChanges, bool includeUnchanged = false, User actor = null)
        {
            var changes = new SortedDictionary<string, Change>(StringComparer.Ordinal);
            if (!TryGetDeclaration(manifest, out JsonElement users))
                return changes;
            if (users.ValueKind == JsonValueKind.Null)
                throw new InvalidDataException($"{Path}: Removing users through the manifest is not implemented.");

            var names = new HashSet<string>(StringComparer.Ordinal);
            int additions = 0;
            foreach (JsonProperty entry in users.EnumerateObject())
            {
                string path = ConfigurationPlan.AppendPath(Path, entry.Name);
                if (!User.IsUsernameValid(entry.Name))
                    throw new InvalidDataException($"{path}: Invalid username.");
                string name = entry.Name.ToLowerInvariant();
                if (!names.Add(name))
                    throw new InvalidDataException($"{path}: Duplicate username.");

                JsonElement declaration = entry.Value;
                if (declaration.ValueKind == JsonValueKind.Null)
                    throw new InvalidDataException($"{path}: Removing users through the manifest is not implemented.");
                User current = auth.GetUser(name);
                if (current is not null && current.Type != UserType.Local ||
                    declaration.TryGetProperty("type", out JsonElement type) && type.ValueKind != JsonValueKind.Null && !type.ValueEquals("Local"))
                    throw new InvalidDataException($"{path}/type: Only local accounts can be reconciled.");
                if (declaration.TryGetProperty("externalIdentifier", out _))
                    throw new InvalidDataException($"{path}/externalIdentifier: Local users have no external identifier.");
                if (declaration.TryGetProperty("totp", out _))
                    throw new InvalidDataException($"{path}/totp: Reconciling enrollment is not implemented.");

                string password = null;
                if (declaration.TryGetProperty("password", out JsonElement reference))
                {
                    if (reference.ValueKind == JsonValueKind.Null)
                        throw new InvalidDataException($"{path}/password: A local password requires a secret reference.");
                    password = manifest.ResolveReference(reference, path + "/password");
                    if (string.IsNullOrEmpty(password))
                        throw new InvalidDataException($"{path}/password: A local password cannot be empty.");
                }
                if (current is null && password is null)
                    throw new InvalidDataException($"{path}/password: Creating a local user requires a secret reference.");

                int iterations = User.DEFAULT_ITERATIONS;
                if (declaration.TryGetProperty("passwordIterations", out JsonElement configured))
                {
                    if (configured.ValueKind != JsonValueKind.Null)
                        iterations = configured.GetInt32();
                    if (password is null && current?.PasswordIterations != iterations)
                        throw new InvalidDataException($"{path}/passwordIterations: Changing iterations requires a password reference.");
                }

                string displayName = declaration.TryGetProperty("displayName", out JsonElement display)
                    ? display.GetString() : current?.DisplayName;
                if (string.IsNullOrWhiteSpace(displayName))
                    displayName = name;
                if (Encoding.UTF8.GetByteCount(displayName) > byte.MaxValue)
                    throw new InvalidDataException($"{path}/displayName: Display names must fit in 255 UTF-8 bytes.");
                bool disabled = declaration.TryGetProperty("disabled", out JsonElement disabledValue)
                    ? disabledValue.ValueKind == JsonValueKind.True : current?.Disabled ?? false;
                int timeout = declaration.TryGetProperty("sessionTimeoutSeconds", out JsonElement seconds)
                    ? seconds.ValueKind == JsonValueKind.Null ? 1800 : seconds.GetInt32() : current?.SessionTimeoutSeconds ?? 1800;
                if (timeout is > 0 and < 60)
                    timeout = 60;

                var groups = new SortedDictionary<string, Group>(StringComparer.Ordinal);
                if (declaration.TryGetProperty("groups", out JsonElement groupList))
                {
                    if (groupList.ValueKind != JsonValueKind.Null)
                    {
                        foreach (JsonElement item in groupList.EnumerateArray())
                        {
                            string groupName = item.GetString().ToLowerInvariant();
                            if (groupName.Length > 255)
                                throw new InvalidDataException($"{path}/groups: Invalid group name.");
                            Group group = auth.GetGroup(groupName);
                            if (groupChanges.TryGetValue(groupName, out Group candidate))
                                group = candidate is null ? null : group ?? candidate;
                            if (group is null || !groups.TryAdd(groupName, group))
                                throw new InvalidDataException($"{path}/groups: A group is unknown or duplicated.");
                        }
                    }
                }
                else if (current is not null)
                {
                    foreach (Group group in current.MemberOfGroups)
                        groups.Add(group.Name.ToLowerInvariant(), group);
                }
                groups[Group.EVERYONE.ToLowerInvariant()] = auth.GetGroup(Group.EVERYONE);
                bool retainsAdminGroup = groups.ContainsKey(Group.ADMINISTRATORS.ToLowerInvariant());
                if (name == "admin" && (disabled || !retainsAdminGroup))
                    throw new InvalidDataException($"{path}: The built-in administrator must remain enabled in the Administrators group.");
                if (actor is not null && ReferenceEquals(current, actor) &&
                    (disabled || actor.IsMemberOfGroup(auth.GetGroup(Group.ADMINISTRATORS)) && !retainsAdminGroup))
                    throw new InvalidDataException($"{path}: The applying administrator must retain access.");

                if (current is null)
                    additions++;
                var fields = new List<string>();
                if (current is not null)
                {
                    if (current.DisplayName != displayName)
                        fields.Add("displayName");
                    if (current.Disabled != disabled)
                        fields.Add("disabled");
                    if (current.SessionTimeoutSeconds != timeout)
                        fields.Add("sessionTimeoutSeconds");
                    if (!groups.Keys.SequenceEqual(current.MemberOfGroups.Select(group => group.Name.ToLowerInvariant()).Order(StringComparer.Ordinal)))
                        fields.Add("groups");
                    if (password is not null && (current.PasswordIterations != iterations || current.GetPasswordHashFor(password) != current.PasswordHash))
                        fields.Add("password");
                }
                if (current is null || fields.Count > 0 || includeUnchanged)
                    changes.Add(name, new Change(current, name, displayName, disabled, timeout, groups.Keys.ToArray(), password, iterations, fields.ToArray()));
            }
            if (auth.Users.Count + additions > byte.MaxValue)
                throw new InvalidDataException($"{Path}: At most 255 users can be stored.");
            return changes;
        }

        private static JsonObject Profile(User user) => new()
        {
            ["type"] = "Local",
            ["displayName"] = user.DisplayName,
            ["disabled"] = user.Disabled,
            ["sessionTimeoutSeconds"] = user.SessionTimeoutSeconds,
            ["groups"] = new JsonArray(user.MemberOfGroups.Select(group => group.Name).Order(StringComparer.Ordinal).Select(name => (JsonNode)JsonValue.Create(name)).ToArray())
        };

        internal static JsonObject Export(AuthManager auth, ICollection<string> missingInputs)
        {
            var users = new JsonObject();
            foreach (User user in auth.Users.OrderBy(user => user.Username, StringComparer.Ordinal))
            {
                string path = ConfigurationPlan.AppendPath(Path, user.Username);
                if (user.Type != UserType.Local)
                {
                    missingInputs.Add(path);
                    continue;
                }
                JsonObject profile = Profile(user);
                if (user.PasswordIterations >= User.DEFAULT_ITERATIONS)
                    profile["passwordIterations"] = user.PasswordIterations;
                users.Add(user.Username, profile);
                missingInputs.Add(path + "/password");
                if (user.TOTPEnabled || user.TOTPKeyUri is not null)
                    missingInputs.Add(path + "/totp/enrollment");
            }
            return users;
        }

        internal static void WriteSnapshot(Utf8JsonWriter writer, IReadOnlyDictionary<string, Change> candidates, byte[] key)
        {
            writer.WriteStartObject("manifestUsers");
            writer.WriteStartObject("current");
            foreach (var (name, change) in candidates)
            {
                writer.WriteStartObject(name);
                if (change.Current is User current)
                {
                    writer.WritePropertyName("profile");
                    Profile(current).WriteTo(writer);
                    writer.WriteNumber("iterations", current.PasswordIterations);
                    writer.WriteString("passwordRevision", Fingerprint(current.PasswordHash));
                }
                if (change.Password is not null)
                    writer.WriteString("desiredPasswordRevision", Fingerprint(change.Password));
                writer.WriteEndObject();
            }
            writer.WriteEndObject();
            writer.WriteStartObject("changes");
            foreach (var (name, change) in candidates)
            {
                string path = ConfigurationPlan.AppendPath(Path, name);
                if (change.Current is null)
                    writer.WriteNumber(path, (int)ConfigurationChangeKind.Add);
                else
                    foreach (string field in change.Fields)
                        writer.WriteNumber(path + "/" + field, (int)ConfigurationChangeKind.Update);
            }
            writer.WriteEndObject();
            writer.WriteEndObject();

            string Fingerprint(string value) => Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));
        }
    }
}
