using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using DnsServerCore.Dns.Applications;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationApplications
    {
        internal const string Path = "/apps/packages";
        internal const string OwnershipFile = "app-ownership.config";

        internal static string AppPath(string name) => ConfigurationPlan.AppendPath(Path, name);

        internal static string[] GetOwnedPaths(ConfigurationManifest manifest)
        {
            if (!IsDeclared(manifest))
                return [];
            JsonElement packages = manifest.Settings.GetProperty("apps").GetProperty("packages");
            if (packages.ValueKind == JsonValueKind.Null)
                return [Path];
            var paths = new SortedSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty item in packages.EnumerateObject())
            {
                string path = AppPath(item.Name);
                paths.Add(path);
                if (item.Value.ValueKind == JsonValueKind.Null)
                    continue;
                if (item.Value.TryGetProperty("configuration", out _))
                    paths.Add(path + "/configuration");
                if (item.Value.TryGetProperty("version", out JsonElement version) && version.ValueKind != JsonValueKind.Null)
                    paths.Add(path + "/version");
            }
            return paths.ToArray();
        }

        internal sealed record Entry(DnsApplication Application, string Before, string After, bool Remove = false, string InstallName = null, byte[] Package = null, string Version = null, bool HasConfig = false)
        {
            internal string Name => InstallName ?? Application.Name;
            internal string SettingPath => AppPath(Name) + (Remove || InstallName is not null ? "" : "/configuration");
            internal string FileName => Remove ? ConfigurationJournal.AppRemovalPath(Application.Name) :
                System.IO.Path.Combine("apps", Application.Name, DnsApplication.ConfigurationFileName);
        }

        internal static bool IsDeclared(ConfigurationManifest manifest) => manifest is not null &&
            manifest.Settings.TryGetProperty("apps", out JsonElement apps) && apps.TryGetProperty("packages", out _);

        internal static Entry[] Prepare(ConfigurationManifest manifest, DnsApplicationManager manager)
        {
            if (!IsDeclared(manifest))
                return null;
            JsonElement packages = manifest.Settings.GetProperty("apps").GetProperty("packages");
            if (packages.ValueKind == JsonValueKind.Null)
                return manager.Applications.Values.OrderBy(app => app.Name, StringComparer.Ordinal).Select(Removal).ToArray();

            var entries = new List<Entry>();
            foreach (JsonProperty item in packages.EnumerateObject().OrderBy(entry => entry.Name, StringComparer.Ordinal))
            {
                string path = ConfigurationPlan.AppendPath(Path, item.Name);
                if (!IsSafeName(item.Name))
                    throw new InvalidDataException($"{path}: Invalid app name.");
                if (OperatingSystem.IsWindows() && !manager.Applications.ContainsKey(item.Name) &&
                    manager.Applications.Keys.Contains(item.Name, StringComparer.OrdinalIgnoreCase))
                    throw new InvalidDataException($"{path}: Use the installed app name with its original casing.");
                if (item.Value.ValueKind == JsonValueKind.Null)
                {
                    if (manager.Applications.TryGetValue(item.Name, out DnsApplication installed))
                        entries.Add(Removal(installed));
                    continue;
                }
                if (item.Value.TryGetProperty("source", out JsonElement source) && source.ValueKind != JsonValueKind.Null &&
                    (!source.TryGetProperty("file", out _) || manifest.FilePath is null))
                    throw new InvalidDataException($"{path}/source: A local package requires a file reference in the startup manifest.");
                if (!manager.Applications.TryGetValue(item.Name, out DnsApplication app))
                {
                    if (source.ValueKind != JsonValueKind.Object)
                        throw new InvalidDataException($"{path}: The DNS app is not installed and needs a package source.");
                    byte[] package;
                    try
                    {
                        using FileStream input = OpenLocalSource(manifest, source, path + "/source");
                        using var copy = new MemoryStream();
                        input.CopyTo(copy);
                        package = copy.ToArray();
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException)
                    {
                        throw new InvalidDataException($"{path}/source: Could not read the app package.");
                    }

                    string pin = item.Value.TryGetProperty("version", out JsonElement requested) ? requested.GetString() : null;
                    if (pin is not null && !System.Version.TryParse(pin, out _))
                        throw new InvalidDataException($"{path}/version: Invalid app version.");
                    entries.Add(new Entry(null, null, ReadConfig(item.Value, null, path), InstallName: item.Name,
                        Package: package, Version: pin, HasConfig: item.Value.TryGetProperty("configuration", out _)));
                    continue;
                }
                if (item.Value.TryGetProperty("version", out JsonElement version) && version.ValueKind != JsonValueKind.Null &&
                    version.GetString() != DnsWebService.GetCleanVersion(app.Version) &&
                    (!Version.TryParse(version.GetString(), out Version desired) || app.Version != desired))
                    throw new InvalidDataException($"{path}/version: The installed version does not match.");

                string before = app.ReadManifestConfig();
                string after = ReadConfig(item.Value, before, path);
                entries.Add(new Entry(app, before, after));
            }
            return entries.ToArray();

            string ReadConfig(JsonElement value, string before, string path)
            {
                    string after = before;
                    if (value.TryGetProperty("configuration", out JsonElement config))
                    {
                        after = config.ValueKind == JsonValueKind.Null ? null :
                            config.TryGetProperty("text", out JsonElement text) ? text.GetString() :
                            config.TryGetProperty("secret", out JsonElement secret) ? manifest.ResolveReference(secret, path + "/configuration") :
                            manifest.ResolveReference(config, path + "/configuration");
                        if (after?.Length == 0)
                            after = null;
                    }
                return after;
            }

            static Entry Removal(DnsApplication app) => new(app, app.ReadManifestConfig(), null, Remove: true);
        }

        internal static void ValidateLocalSource(ConfigurationManifest manifest, JsonElement source, string path)
        {
            try
            {
                using FileStream input = OpenLocalSource(manifest, source, path);
                using var archive = new ZipArchive(input, ZipArchiveMode.Read);
                if (archive.Entries.Count == 0)
                    throw new InvalidDataException();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException)
            {
                throw new InvalidDataException($"{path}: Expected a readable, nonempty ZIP package.");
            }
        }

        private static FileStream OpenLocalSource(ConfigurationManifest manifest, JsonElement source, string path)
        {
            if (manifest.FilePath is null)
                throw new InvalidDataException($"{path}: A local package requires a file reference in the startup manifest.");
            return File.OpenRead(System.IO.Path.GetFullPath(source.GetProperty("file").GetString(),
                System.IO.Path.GetDirectoryName(manifest.FilePath)));
        }

        internal static bool DeclaresRemovals(ConfigurationManifest manifest)
        {
            JsonElement packages = manifest.Settings.GetProperty("apps").GetProperty("packages");
            return packages.ValueKind == JsonValueKind.Null || packages.EnumerateObject().Any(entry => entry.Value.ValueKind == JsonValueKind.Null);
        }

        internal static bool IsSafeName(string name) => !string.IsNullOrWhiteSpace(name) && name is not ("." or "..") &&
            name.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) < 0 && !name.Contains('/') && !name.Contains('\\');

        internal static void WriteSnapshot(Utf8JsonWriter writer, Entry[] entries, byte[] key)
        {
            writer.WriteStartObject("manifestApplications");
            foreach (Entry entry in entries)
            {
                writer.WriteStartObject(entry.SettingPath);
                writer.WriteString("version", entry.Application?.Version.ToString() ?? entry.Version);
                writer.WriteBoolean("install", entry.InstallName is not null);
                if (entry.Package is not null)
                    writer.WriteString("package", Convert.ToHexString(HMACSHA256.HashData(key, entry.Package)));
                writer.WriteBoolean("remove", entry.Remove);
                writer.WriteString("before", Fingerprint(entry.Before));
                writer.WriteString("after", Fingerprint(entry.After));
                writer.WriteEndObject();
            }
            writer.WriteEndObject();

            string Fingerprint(string value) => value is null ? null :
                Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));
        }

        internal static void Compare(JsonElement snapshot, List<ConfigurationChange> changes)
        {
            foreach (JsonProperty entry in snapshot.EnumerateObject())
            {
                if (entry.Value.GetProperty("install").GetBoolean())
                {
                    changes.Add(new ConfigurationChange(entry.Name, ConfigurationChangeKind.Add, false));
                    continue;
                }
                if (entry.Value.GetProperty("remove").GetBoolean())
                {
                    changes.Add(new ConfigurationChange(entry.Name, ConfigurationChangeKind.Remove, false));
                    continue;
                }
                JsonElement before = entry.Value.GetProperty("before");
                JsonElement after = entry.Value.GetProperty("after");
                if (!JsonElement.DeepEquals(before, after))
                    changes.Add(new ConfigurationChange(entry.Name, before.ValueKind == JsonValueKind.Null ? ConfigurationChangeKind.Add :
                        after.ValueKind == JsonValueKind.Null ? ConfigurationChangeKind.Remove : ConfigurationChangeKind.Update, false));
            }
        }

        internal static JsonObject Export(DnsApplicationManager manager, ISet<string> missingInputs)
        {
            var result = new JsonObject();
            foreach (DnsApplication app in manager.Applications.Values.OrderBy(app => app.Name, StringComparer.Ordinal))
            {
                string path = ConfigurationPlan.AppendPath(Path, app.Name);
                result[app.Name] = new JsonObject { ["version"] = app.Version.ToString() };
                missingInputs.Add(path + "/source");
                if (app.ReadManifestConfig() is not null)
                    missingInputs.Add(path + "/configuration");
            }
            return result;
        }

        internal static async Task ApplyAsync(DnsApplicationManager manager, Entry[] entries, string[] ownership, Func<Action, string[], Task> commit)
        {
            if ((entries is null || entries.Length == 0) && manager.ManagedPaths.SequenceEqual(ownership))
            {
                await commit(null, []);
                return;
            }

            await manager.EnterManifestGateAsync();
            var activated = new List<Entry>();
            var removed = new List<DnsApplication>();
            var installed = new List<DnsApplication>();
            try
            {
                bool ownershipChanged = !manager.ManagedPaths.SequenceEqual(ownership);
                entries ??= [];
                foreach (Entry entry in entries)
                {
                    manager.Applications.TryGetValue(entry.Name, out DnsApplication current);
                    if (!ReferenceEquals(current, entry.Application) || (current is not null && current.ReadManifestConfig() != entry.Before))
                        throw new InvalidDataException($"{entry.SettingPath}: The app changed during apply. Create a new preview.");
                }
                Entry[] changed = entries.Where(entry => entry.InstallName is null && !entry.Remove && entry.Before != entry.After).ToArray();
                Entry[] removals = entries.Where(entry => entry.Remove).ToArray();
                string[] files = changed.Select(entry => entry.FileName).ToArray();
                await ConfigurationJournal.ActivateAppsAsync(manager.ConfigurationFolder, files, async () =>
                {
                    foreach (Entry entry in changed)
                    {
                        activated.Add(entry);
                        try
                        {
                            await entry.Application.ActivateConfigAsync(entry.After);
                            entry.Application.NotifyManifestConfigUpdated();
                        }
                        catch (Exception)
                        {
                            throw new InvalidDataException($"{entry.SettingPath}: The app rejected its configuration.");
                        }
                    }
                });

                foreach (Entry entry in entries.Where(entry => entry.InstallName is not null))
                {
                    DnsApplication app = await manager.InstallManifestAppAsync(entry.Name, entry.Package, entry.Version,
                        entry.After, entry.HasConfig);
                    installed.Add(app);
                }

                foreach (Entry entry in removals)
                {
                    manager.DetachManifestApp(entry.Application);
                    removed.Add(entry.Application);
                }
                string[] resources = [.. files, .. removals.Select(entry => entry.FileName),
                    .. installed.Select(app => ConfigurationJournal.AppInstallPath(app.Name))];
                await commit(resources.Length > 0 || ownershipChanged ? Write : null,
                    ownershipChanged ? [.. resources, OwnershipFile] : resources);
                if (ownershipChanged)
                    manager.PublishManifestOwnership(ownership);
                foreach (DnsApplication app in removed)
                    manager.DisposeManifestApp(app);

                void Write()
                {
                    foreach (Entry entry in changed)
                        entry.Application.WriteManifestConfig(entry.After);
                    foreach (Entry entry in removals)
                        ConfigurationJournal.StageAppRemoval(manager.ConfigurationFolder, entry.Application.Name);
                    if (ownershipChanged)
                        manager.WriteManifestOwnership(ownership);
                    foreach (DnsApplication app in installed)
                        ConfigurationJournal.FinishAppInstall(manager.ConfigurationFolder, app.Name);
                }
            }
            catch
            {
                foreach (DnsApplication app in installed)
                {
                    manager.DetachManifestApp(app);
                    manager.DisposeManifestApp(app);
                    ConfigurationJournal.CancelAppInstall(manager.ConfigurationFolder, app.Name);
                }
                foreach (DnsApplication app in removed)
                    manager.ReattachManifestApp(app);
                string failedRollbackPath = null;
                await ConfigurationJournal.ActivateAppsAsync(manager.ConfigurationFolder,
                    activated.Select(entry => entry.FileName).ToArray(), async () =>
                    {
                        for (int i = activated.Count - 1; i >= 0; i--)
                        {
                            Entry entry = activated[i];
                            try
                            {
                                await entry.Application.ActivateConfigAsync(entry.Before);
                                entry.Application.NotifyManifestConfigUpdated();
                            }
                            catch (Exception)
                            {
                                failedRollbackPath ??= entry.SettingPath;
                            }
                        }
                    });
                if (failedRollbackPath is not null)
                    throw new InvalidDataException($"{failedRollbackPath}: The app could not reactivate its previous configuration.");
                throw;
            }
            finally
            {
                manager.ExitManifestGate();
            }

        }
    }
}
