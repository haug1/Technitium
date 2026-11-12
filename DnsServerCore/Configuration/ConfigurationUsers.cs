using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Auth;
using TechnitiumLibrary;
using TechnitiumLibrary.Security.OTP;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationUsers
    {
        internal const string Path = "/auth/users";

        internal static string UserPath(string name) => ConfigurationPlan.AppendPath(Path, name.ToLowerInvariant());

        internal static string[] GetOwnedPaths(ConfigurationManifest manifest)
        {
            if (!TryGetDeclaration(manifest, out JsonElement users))
                return [];
            if (users.ValueKind == JsonValueKind.Null)
                return [Path];

            var paths = new SortedSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty entry in users.EnumerateObject())
            {
                string path = UserPath(entry.Name);
                paths.Add(path);
                if (entry.Value.ValueKind == JsonValueKind.Object)
                {
                    foreach (JsonProperty field in entry.Value.EnumerateObject())
                    {
                        if (field.NameEquals("totp"))
                        {
                            foreach (JsonProperty setting in field.Value.EnumerateObject())
                                paths.Add(path + "/totp/" + setting.Name);
                        }
                        else
                        {
                            paths.Add(path + "/" + field.Name);
                        }
                    }
                }
            }
            return paths.ToArray();
        }

        internal static bool OwnsMembership(IReadOnlyList<string> paths, string name, UserType type) =>
            paths.Contains(UserPath(name)) ||
            (type == UserType.Local && !name.Equals("admin", StringComparison.OrdinalIgnoreCase) && paths.Contains(Path));

        internal static void CheckMembership(IReadOnlyList<string> paths, string name, UserType type)
        {
            if (OwnsMembership(paths, name, type))
                throw Conflict(UserPath(name));
        }

        internal static bool OwnsField(IReadOnlyList<string> paths, User user, string field) =>
            paths.Contains(UserPath(user.Username) + "/" + field);

        internal static void CheckField(IReadOnlyList<string> paths, User user, string field, bool changes)
        {
            if (changes && OwnsField(paths, user, field))
                throw Conflict(UserPath(user.Username) + "/" + field);
        }

        internal static bool CheckPassword(IReadOnlyList<string> paths, User user, string password, int iterations)
        {
            CheckField(paths, user, "passwordIterations", user.PasswordIterations != iterations);
            if (!OwnsField(paths, user, "password"))
                return true;
            if (user.PasswordIterations != iterations || user.GetPasswordHashFor(password) != user.PasswordHash)
                throw Conflict(UserPath(user.Username) + "/password");
            return false;
        }

        internal static bool SameGroups(User user, IEnumerable<string> names) =>
            user.MemberOfGroups.Select(group => group.Name.ToLowerInvariant()).ToHashSet(StringComparer.Ordinal).SetEquals(names);

        private static InvalidDataException Conflict(string path) => new($"{path}: This account setting is managed by the manifest.");

        internal static void CheckRestore(AuthManager auth, IReadOnlyDictionary<string, User> candidate)
        {
            var paths = auth.ManagedUserPaths;
            var names = new SortedSet<string>(candidate.Keys, StringComparer.Ordinal);
            names.UnionWith(auth.Users.Select(user => user.Username));
            foreach (string name in names)
            {
                User current = auth.GetUser(name);
                candidate.TryGetValue(name, out User restored);
                if (current?.Type != restored?.Type)
                {
                    CheckMembership(paths, name, current?.Type ?? restored.Type);
                    if (current is not null && restored is not null)
                        CheckMembership(paths, name, restored.Type);
                }
                if (current is null || restored is null)
                    continue;

                CheckField(paths, current, "displayName", current.DisplayName != restored.DisplayName);
                CheckField(paths, current, "disabled", current.Disabled != restored.Disabled);
                CheckField(paths, current, "sessionTimeoutSeconds", current.SessionTimeoutSeconds != restored.SessionTimeoutSeconds);
                CheckField(paths, current, "groups", !SameGroups(current, restored.MemberOfGroups.Select(group => group.Name.ToLowerInvariant())));
                CheckField(paths, current, "passwordIterations", current.PasswordIterations != restored.PasswordIterations);
                CheckField(paths, current, "password", !current.HasSamePasswordState(restored));
                CheckField(paths, current, "externalIdentifier", current.SsoIdentifier != restored.SsoIdentifier);
                CheckField(paths, current, "totp/enabled", current.TOTPEnabled != restored.TOTPEnabled);
                CheckField(paths, current, "totp/enrollment", !SameEnrollment(current.TOTPKeyUri, restored.TOTPKeyUri));
            }
        }

        internal static bool SameEnrollment(AuthenticatorKeyUri current, AuthenticatorKeyUri desired) =>
            current?.ToString() == desired?.ToString();

        internal static bool CheckTotpDisable(IReadOnlyList<string> paths, User user)
        {
            CheckField(paths, user, "totp/enabled", user.TOTPEnabled);
            CheckField(paths, user, "totp/enrollment", user.TOTPEnabled && user.TOTPKeyUri is not null);
            return user.TOTPEnabled ||
                (!OwnsField(paths, user, "totp/enabled") && !OwnsField(paths, user, "totp/enrollment"));
        }

        private static AuthenticatorKeyUri ParseEnrollment(ConfigurationManifest manifest, JsonElement reference, string path)
        {
            string value = manifest.ResolveReference(reference, path);
            try
            {
                AuthenticatorKeyUri key = AuthenticatorKeyUri.Parse(value.Trim());
                byte[] decoded = Base32.FromBase32String(key.Secret);
                if (key.Period is < 1 or > int.MaxValue / 10 ||
                    string.IsNullOrWhiteSpace(key.AccountName) || string.IsNullOrWhiteSpace(key.Issuer) ||
                    decoded.Length == 0 || !Base32.ToBase32String(decoded, skipPadding: true)
                        .Equals(key.Secret.TrimEnd('='), StringComparison.OrdinalIgnoreCase))
                    throw new FormatException();

                // Exercise the same algorithm and key parsing used at sign-in.
                _ = new Authenticator(key).GetTOTP();
                return key;
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or IndexOutOfRangeException or NotSupportedException or OverflowException or CryptographicException)
            {
                throw new InvalidDataException($"{path}: The reference must contain a valid otpauth TOTP enrollment URI.");
            }
        }

        internal sealed record Change(User Current, string Name, string DisplayName, bool Disabled, int Timeout,
            string[] Groups, string Password, int Iterations, string[] Fields, bool Remove = false, bool TotpEnabled = false, AuthenticatorKeyUri Enrollment = null, UserType Type = UserType.Local, string ExternalIdentifier = null)
        {
            internal User Stage(AuthManager auth, IReadOnlyDictionary<string, Group> groupChanges)
            {
                User user = Current?.CopyForManifest() ?? (Type switch
                {
                    UserType.RemoteSSO => User.CreateSsoUser(DisplayName, Name, ExternalIdentifier),
                    UserType.RemoteLDAP => User.CreateLdapUser(DisplayName, Name),
                    _ => User.CreateLocalUser(DisplayName, Name, Password, Iterations)
                });
                user.DisplayName = DisplayName;
                user.Disabled = Disabled;
                user.SessionTimeoutSeconds = Timeout;
                var groups = new Dictionary<string, Group>(StringComparer.Ordinal);
                foreach (string name in Groups)
                    groups.Add(name, auth.GetGroup(name) ?? groupChanges[name]);
                user.SyncGroups(groups);
                if (Current is null || Fields.Contains("totp/enabled") || Fields.Contains("totp/enrollment"))
                    user.SetManifestTotp(TotpEnabled, Enrollment);
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
            IReadOnlyDictionary<string, Group> groupChanges, bool includeUnchanged = false, User actor = null, ConfigurationLdap.Settings ldap = null, ConfigurationSso.Settings sso = null)
        {
            var changes = new SortedDictionary<string, Change>(StringComparer.Ordinal);
            if (!TryGetDeclaration(manifest, out JsonElement users))
                return changes;
            if (users.ValueKind == JsonValueKind.Null)
            {
                foreach (User user in auth.Users.Where(user => user.Type == UserType.Local && user.Username != "admin"))
                    Remove(user);
                return changes;
            }

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
                User current = auth.GetUser(name);
                if (declaration.ValueKind == JsonValueKind.Null)
                {
                    if (name == "admin")
                        throw new InvalidDataException($"{path}: The built-in administrator cannot be removed.");
                    if (current is not null)
                        Remove(current);
                    continue;
                }
                UserType type = current?.Type ?? UserType.Local;
                if (declaration.TryGetProperty("type", out JsonElement typeValue))
                    type = typeValue.ValueKind == JsonValueKind.Null ? UserType.Local : Enum.Parse<UserType>(typeValue.GetString());
                if (current is not null && current.Type != type)
                    throw new InvalidDataException($"{path}/type: Changing an existing account type is not supported.");
                if (name == "admin" && type != UserType.Local)
                    throw new InvalidDataException($"{path}/type: The built-in administrator must remain a local account.");

                string identifier = current?.SsoIdentifier;
                if (declaration.TryGetProperty("externalIdentifier", out JsonElement external))
                {
                    if (type != UserType.RemoteSSO)
                        throw new InvalidDataException($"{path}/externalIdentifier: Only SSO accounts use an external identifier.");
                    identifier = external.GetString();
                    if (current is not null && current.SsoIdentifier != identifier)
                        throw new InvalidDataException($"{path}/externalIdentifier: Changing an existing SSO identity is not supported.");
                }
                if (type == UserType.RemoteSSO && (string.IsNullOrWhiteSpace(identifier) || Encoding.UTF8.GetByteCount(identifier) > byte.MaxValue))
                    throw new InvalidDataException($"{path}/externalIdentifier: An SSO account requires an external identifier within 255 UTF-8 bytes.");
                bool totpEnabled = current?.TOTPEnabled ?? false;
                AuthenticatorKeyUri enrollment = current?.TOTPKeyUri;
                if (declaration.TryGetProperty("totp", out JsonElement totp))
                {
                    if (type == UserType.RemoteSSO)
                        throw new InvalidDataException($"{path}/totp: The identity provider manages SSO authentication.");
                    if (totp.TryGetProperty("enabled", out JsonElement enabled))
                        totpEnabled = enabled.ValueKind == JsonValueKind.True;
                    if (totp.TryGetProperty("enrollment", out JsonElement enrollmentRef))
                        enrollment = enrollmentRef.ValueKind == JsonValueKind.Null ? null : ParseEnrollment(manifest, enrollmentRef, path + "/totp/enrollment");
                    if (totpEnabled && enrollment is null)
                        throw new InvalidDataException($"{path}/totp/enrollment: Enabling TOTP requires valid enrollment material.");
                }

                string password = null;
                if (declaration.TryGetProperty("password", out JsonElement reference))
                {
                    if (type != UserType.Local)
                        throw new InvalidDataException($"{path}/password: Only local accounts accept a password.");
                    if (reference.ValueKind == JsonValueKind.Null)
                        throw new InvalidDataException($"{path}/password: A local password requires a secret reference.");
                    password = manifest.ResolveReference(reference, path + "/password");
                    if (string.IsNullOrEmpty(password))
                        throw new InvalidDataException($"{path}/password: A local password cannot be empty.");
                }
                if (current is null && type == UserType.Local && password is null)
                    throw new InvalidDataException($"{path}/password: Creating a local user requires a secret reference.");

                int iterations = User.DEFAULT_ITERATIONS;
                if (declaration.TryGetProperty("passwordIterations", out JsonElement configured))
                {
                    if (type != UserType.Local)
                        throw new InvalidDataException($"{path}/passwordIterations: Only local accounts use password iterations.");
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
                    bool providerManagesGroups = type == UserType.RemoteSSO && (sso is null ? auth.SsoManagedGroups : sso.GroupMap?.Count > 0) ||
                        type == UserType.RemoteLDAP && (ldap is null ? auth.LdapManagedGroups : ldap.GroupMap?.Count > 0);
                    if (providerManagesGroups)
                        throw new InvalidDataException($"{path}/groups: The identity provider manages this account's groups.");
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
                    if (!SameGroups(current, groups.Keys))
                        fields.Add("groups");
                    if (password is not null && (current.PasswordIterations != iterations || current.GetPasswordHashFor(password) != current.PasswordHash))
                        fields.Add("password");
                    if (current.TOTPEnabled != totpEnabled)
                        fields.Add("totp/enabled");
                    if (!SameEnrollment(current.TOTPKeyUri, enrollment))
                        fields.Add("totp/enrollment");
                }
                if (current is null || fields.Count > 0 || includeUnchanged)
                    changes.Add(name, new Change(current, name, displayName, disabled, timeout, groups.Keys.ToArray(), password, iterations, fields.ToArray(), TotpEnabled: totpEnabled, Enrollment: enrollment, Type: type, ExternalIdentifier: identifier));
            }
            if (auth.Users.Count + additions - changes.Values.Count(change => change.Remove) > byte.MaxValue)
                throw new InvalidDataException($"{Path}: At most 255 users can be stored.");
            CheckSsoIdentities(auth, changes);
            return changes;

            void Remove(User user)
            {
                CheckRemoval(auth, user, actor);
                changes.Add(user.Username, new Change(user, user.Username, null, false, 0, [], null, 0, [], Remove: true));
            }
        }

        internal static void CheckRemoval(AuthManager auth, User user, User actor)
        {
            string path = ConfigurationPlan.AppendPath(Path, user.Username);
            if (user.Username == "admin" || ReferenceEquals(actor, user))
                throw new InvalidDataException($"{path}: The built-in or applying administrator cannot be removed.");
            if (auth.HasLegacyStaticSession(user) || auth.GetSessions(user).Any(session => session.Type == UserSessionType.ClusterApiToken))
                throw new InvalidDataException($"{path}: An account with a legacy static or cluster session cannot be removed.");
        }

        internal static void CheckSsoIdentities(AuthManager auth, IReadOnlyDictionary<string, Change> changes)
        {
            var identifiers = auth.Users.Where(user => user.Type == UserType.RemoteSSO &&
                (!changes.TryGetValue(user.Username, out Change change) || !change.Remove))
                .Select(user => user.SsoIdentifier).ToHashSet(StringComparer.Ordinal);
            foreach (Change change in changes.Values)
            {
                if (change.Current is null && change.Type == UserType.RemoteSSO && !identifiers.Add(change.ExternalIdentifier))
                    throw new InvalidDataException($"{UserPath(change.Name)}/externalIdentifier: The SSO identifier is already in use.");
            }
        }

        private static JsonObject Profile(User user) => new()
        {
            ["type"] = user.Type.ToString(),
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
                JsonObject profile = Profile(user);
                if (user.Type == UserType.Local)
                {
                    if (user.PasswordIterations >= User.DEFAULT_ITERATIONS)
                        profile["passwordIterations"] = user.PasswordIterations;
                    missingInputs.Add(path + "/password");
                }
                else if (user.Type == UserType.RemoteSSO)
                {
                    profile["externalIdentifier"] = user.SsoIdentifier;
                }
                if (user.Type == UserType.RemoteSSO && auth.SsoManagedGroups || user.Type == UserType.RemoteLDAP && auth.LdapManagedGroups)
                    profile.Remove("groups");
                users.Add(user.Username, profile);
                if (user.TOTPKeyUri is not null)
                {
                    profile["totp"] = new JsonObject { ["enabled"] = user.TOTPEnabled };
                    missingInputs.Add(path + "/totp/enrollment");
                }
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
                    if (current.Type == UserType.Local)
                        writer.WriteString("passwordRevision", Fingerprint(current.PasswordHash));
                    if (current.Type == UserType.RemoteSSO)
                        writer.WriteString("externalIdentifier", current.SsoIdentifier);
                    writer.WriteBoolean("totpEnabled", current.TOTPEnabled);
                    if (current.TOTPKeyUri is not null)
                        writer.WriteString("totpEnrollmentRevision", Fingerprint(current.TOTPKeyUri.ToString()));
                }
                if (change.Enrollment is not null)
                    writer.WriteString("desiredTotpEnrollmentRevision", Fingerprint(change.Enrollment.ToString()));
                if (change.Password is not null)
                    writer.WriteString("desiredPasswordRevision", Fingerprint(change.Password));
                writer.WriteEndObject();
            }
            writer.WriteEndObject();
            writer.WriteStartObject("changes");
            foreach (var (name, change) in candidates)
            {
                string path = ConfigurationPlan.AppendPath(Path, name);
                if (change.Remove)
                    writer.WriteNumber(path, (int)ConfigurationChangeKind.Remove);
                else if (change.Current is null)
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
