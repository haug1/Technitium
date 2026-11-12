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
    internal static class ConfigurationStaticSessions
    {
        internal const string Path = "/auth/staticSessions";
        internal const string FileName = "static-sessions.config";

        internal sealed record Definition(string User, JsonElement Token);
        internal sealed record Entry(Definition Definition, string Token);
        internal sealed record Candidate(SortedDictionary<string, Entry> Entries, SortedDictionary<string, ConfigurationChangeKind> Changes);

        internal static bool TryGetDeclaration(ConfigurationManifest manifest, out JsonElement declaration)
        {
            declaration = default;
            return manifest is not null && manifest.Settings.TryGetProperty("auth", out JsonElement auth) &&
                auth.TryGetProperty("staticSessions", out declaration);
        }

        internal static Candidate Prepare(ConfigurationManifest manifest, AuthManager auth,
            IReadOnlyDictionary<string, ConfigurationUsers.Change> users = null, bool loading = false)
        {
            bool declared = TryGetDeclaration(manifest, out JsonElement declaration);
            if (!declared && !loading)
                return null;

            var definitions = new SortedDictionary<string, Definition>(auth.ManifestStaticSessionDefinitions, StringComparer.Ordinal);
            var refresh = new HashSet<string>(StringComparer.Ordinal);
            if (declared)
            {
                if (declaration.ValueKind == JsonValueKind.Null)
                    definitions.Clear();
                else
                {
                    foreach (JsonProperty item in declaration.EnumerateObject())
                    {
                        string path = ConfigurationPlan.AppendPath(Path, item.Name);
                        if (string.IsNullOrWhiteSpace(item.Name))
                            throw new InvalidDataException($"{path}: A session name is required.");
                        if (item.Value.ValueKind == JsonValueKind.Null)
                        {
                            definitions.Remove(item.Name);
                            continue;
                        }
                        string user = item.Value.GetProperty("user").GetString();
                        if (!User.IsUsernameValid(user))
                            throw new InvalidDataException($"{path}/user: Invalid username.");
                        definitions[item.Name] = new Definition(user.ToLowerInvariant(), item.Value.GetProperty("token").Clone());
                        refresh.Add(item.Name);
                    }
                }
            }

            var entries = new SortedDictionary<string, Entry>(StringComparer.Ordinal);
            var changes = new SortedDictionary<string, ConfigurationChangeKind>(StringComparer.Ordinal);
            var tokens = new HashSet<string>(StringComparer.Ordinal);
            foreach (var (name, definition) in definitions)
            {
                string path = ConfigurationPlan.AppendPath(Path, name);
                if (users?.TryGetValue(definition.User, out var candidate) == true ? candidate.Remove : auth.GetUser(definition.User) is null)
                    throw new InvalidDataException($"{path}/user: The account does not exist in the effective configuration.");

                auth.ManifestStaticSessionEntries.TryGetValue(name, out Entry previous);
                string token = previous is not null && !refresh.Contains(name) ? previous.Token :
                    (manifest ?? auth.StaticSessionReferenceContext).ResolveReference(definition.Token, path + "/token");
                if (token.Length != 64 || token.Any(char.IsWhiteSpace))
                    throw new InvalidDataException($"{path}/token: A static session token must contain 64 characters without whitespace.");
                token = token.ToLowerInvariant();
                if (!tokens.Add(token) || auth.StaticTokenConflicts(token))
                    throw new InvalidDataException($"{path}/token: The static session token is already in use.");
                entries.Add(name, new Entry(definition, token));

                if (previous is null)
                    changes.Add(path, ConfigurationChangeKind.Add);
                else if (previous.Token != token || previous.Definition.User != definition.User ||
                    !JsonElement.DeepEquals(previous.Definition.Token, definition.Token))
                    changes.Add(path, ConfigurationChangeKind.Update);
            }
            foreach (string name in auth.ManifestStaticSessionEntries.Keys.Concat(auth.ManifestStaticSessionDefinitions.Keys).Distinct())
            {
                if (!entries.ContainsKey(name))
                    changes.Add(ConfigurationPlan.AppendPath(Path, name), ConfigurationChangeKind.Remove);
            }
            return new Candidate(entries, changes);
        }

        internal static void CheckAccountRemovals(AuthManager auth, IReadOnlyDictionary<string, ConfigurationUsers.Change> users, Candidate candidate)
        {
            if (users is null || users.Count == 0)
                return;

            var definitions = candidate is null ? auth.ManifestStaticSessionDefinitions :
                candidate.Entries.Select(entry => new KeyValuePair<string, Definition>(entry.Key, entry.Value.Definition));
            foreach (var (name, definition) in definitions)
            {
                if (users.TryGetValue(definition.User, out var user) && user.Remove)
                    throw new InvalidDataException($"{ConfigurationPlan.AppendPath(Path, name)}/user: The static session still references an account being removed.");
            }
        }

        internal static void WriteSnapshot(Utf8JsonWriter writer, AuthManager auth, Candidate candidate, byte[] key)
        {
            writer.WriteStartObject("manifestStaticSessions");
            WriteEntries("current", auth.ManifestStaticSessionEntries);
            WriteEntries("desired", candidate.Entries);
            writer.WriteStartObject("changes");
            foreach (var (path, kind) in candidate.Changes)
                writer.WriteNumber(path, (int)kind);
            writer.WriteEndObject();
            writer.WriteEndObject();

            void WriteEntries(string property, IReadOnlyDictionary<string, Entry> entries)
            {
                writer.WriteStartObject(property);
                foreach (var (name, entry) in entries)
                {
                    writer.WriteStartObject(name);
                    writer.WriteString("user", entry.Definition.User);
                    writer.WriteString("revision", Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(entry.Token))));
                    writer.WriteEndObject();
                }
                writer.WriteEndObject();
            }
        }

        internal static JsonObject Export(AuthManager auth, ICollection<string> missingInputs)
        {
            var sessions = new JsonObject();
            foreach (var (name, definition) in auth.ManifestStaticSessionDefinitions.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                sessions[name] = new JsonObject { ["user"] = definition.User };
                missingInputs.Add(ConfigurationPlan.AppendPath(Path, name) + "/token");
            }
            return sessions;
        }
    }
}
