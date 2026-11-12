using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
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
        internal const string PrimaryOwnershipFile = "app-primary-ownership.config";

        internal static string AppPath(string name) => ConfigurationPlan.AppendPath(Path, name);

        internal static bool HasPackageDigestPins(IEnumerable<string> paths) =>
            paths.Any(path => path.LastIndexOf('/') > Path.Length && path.EndsWith("/packageSha256", StringComparison.Ordinal));

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
                if (item.Value.TryGetProperty("packageSha256", out _))
                    paths.Add(path + "/packageSha256");
            }
            return paths.ToArray();
        }

        internal sealed record Entry(DnsApplication Application, string Before, string After, bool Remove = false, string InstallName = null, byte[] Package = null, string Version = null, bool HasConfig = false, Uri RemoteSource = null, string PackageSha256 = null)
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
                Uri remoteSource = null;
                if (item.Value.TryGetProperty("source", out JsonElement source) && source.ValueKind == JsonValueKind.Object)
                {
                    if (source.TryGetProperty("url", out JsonElement url))
                    {
                        remoteSource = ReadRemoteSource(url, path);
                    }
                    else if (manifest.FilePath is null)
                    {
                        throw new InvalidDataException($"{path}/source: A local package requires a file reference in the startup manifest.");
                    }
                }
                manager.Applications.TryGetValue(item.Name, out DnsApplication app);
                string pin = ReadVersionPin(item.Value, path);
                var (packageDigest, sourceDigest) = ReadPackagePins(item.Value, source, path);
                string before = app?.ReadManifestConfig();
                bool versionDiffers = app is not null && pin is not null && pin != DnsWebService.GetCleanVersion(app.Version) &&
                    new System.Version(pin) != app.Version;
                bool digestDiffers = app is not null && packageDigest is not null &&
                    !packageDigest.Equals(ReadInstalledPackageHash(app), StringComparison.OrdinalIgnoreCase);
                bool replace = versionDiffers || digestDiffers;
                if (app is null || replace)
                {
                    if (replace && source.ValueKind != JsonValueKind.Object)
                    {
                        if (versionDiffers)
                            throw new InvalidDataException($"{path}/version: The installed version does not match and needs a replacement package.");
                        throw new InvalidDataException($"{path}/packageSha256: The stored package digest does not match. Supply a replacement package.");
                    }
                    if (source.ValueKind != JsonValueKind.Object)
                        throw new InvalidDataException($"{path}: The DNS app is not installed and needs a package source.");
                    byte[] package = null;
                    if (remoteSource is null)
                    {
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
                    }

                    string sha256 = packageDigest ?? sourceDigest;
                    if (package is not null && sha256 is not null)
                        CheckPackageHash(sha256, SHA256.HashData(package), path + "/source/sha256");

                    entries.Add(new Entry(app, before, ReadConfig(item.Value, before, path), InstallName: item.Name,
                        Package: package, Version: pin, HasConfig: item.Value.TryGetProperty("configuration", out _), RemoteSource: remoteSource,
                        PackageSha256: sha256));
                    continue;
                }
                string after = ReadConfig(item.Value, before, path);
                entries.Add(new Entry(app, before, after, PackageSha256: packageDigest));
            }
            return entries.ToArray();

            string ReadConfig(JsonElement value, string before, string path)
            {
                    string after = before;
                    if (value.TryGetProperty("configuration", out JsonElement config))
                    {
                    after = config.ValueKind == JsonValueKind.Null ? null : ReadConfiguration(manifest, config, path + "/configuration");
                        if (after?.Length == 0)
                            after = null;
                    }
                return after;
            }

            static Entry Removal(DnsApplication app) => new(app, app.ReadManifestConfig(), null, Remove: true);
        }

        internal static string ReadConfiguration(ConfigurationManifest manifest, JsonElement config, string path) =>
            config.TryGetProperty("text", out JsonElement text) ? text.GetString() :
            manifest.ResolveReference(config.TryGetProperty("secret", out JsonElement secret) ? secret : config, path);

        internal static void ValidatePackageReferences(ConfigurationManifest manifest, JsonElement declaration, string path)
        {
            ReadVersionPin(declaration, path);
            declaration.TryGetProperty("source", out JsonElement source);
            var (packageDigest, sourceDigest) = ReadPackagePins(declaration, source, path);
            if (source.ValueKind != JsonValueKind.Object)
                return;

            if (source.TryGetProperty("url", out JsonElement url))
                ReadRemoteSource(url, path);
            else if (source.TryGetProperty("file", out _))
                ValidateLocalSource(manifest, source, path, packageDigest, sourceDigest);
        }

        private static string ReadVersionPin(JsonElement declaration, string path)
        {
            string pin = declaration.TryGetProperty("version", out JsonElement version) ? version.GetString() : null;
            if (pin is not null && !System.Version.TryParse(pin, out _))
                throw new InvalidDataException($"{path}/version: Invalid app version.");

            return pin;
        }

        private static Uri ReadRemoteSource(JsonElement url, string path)
        {
            if (!Uri.TryCreate(url.GetString(), UriKind.Absolute, out Uri remoteSource) ||
                remoteSource.Scheme != Uri.UriSchemeHttps || remoteSource.Host.Length == 0 ||
                remoteSource.UserInfo.Length != 0 || remoteSource.Fragment.Length != 0)
                throw new InvalidDataException($"{path}/source/url: Expected an HTTPS URL without credentials or a fragment.");

            return remoteSource;
        }

        private static void ValidateLocalSource(ConfigurationManifest manifest, JsonElement source, string path, string packageDigest, string sourceDigest)
        {
            string sha256 = packageDigest ?? sourceDigest;
            byte[] hash = null;
            try
            {
                using FileStream input = OpenLocalSource(manifest, source, path + "/source");
                if (sha256 is not null)
                {
                    hash = SHA256.HashData(input);
                    input.Position = 0;
                }
                using var archive = new ZipArchive(input, ZipArchiveMode.Read);
                if (archive.Entries.Count == 0)
                    throw new InvalidDataException();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException)
            {
                throw new InvalidDataException($"{path}/source: Expected a readable, nonempty ZIP package.");
            }

            if (hash is not null)
                CheckPackageHash(sha256, hash, path + (packageDigest is null ? "/source/sha256" : "/packageSha256"));
        }

        private static (string Package, string Source) ReadPackagePins(JsonElement declaration, JsonElement source, string path)
        {
            string packageDigest = declaration.TryGetProperty("packageSha256", out JsonElement digest) ? digest.GetString() : null;
            string sourceDigest = source.ValueKind == JsonValueKind.Object && source.TryGetProperty("sha256", out JsonElement hash) ? hash.GetString() : null;
            if (sourceDigest is not null && packageDigest is not null && !sourceDigest.Equals(packageDigest, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"{path}/source/sha256: The source digest differs from packageSha256.");
            return (packageDigest, sourceDigest);
        }

        private static void CheckPackageHash(string expected, byte[] actual, string path)
        {
            if (!Convert.ToHexString(actual).Equals(expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"{path}: The package does not match the declared SHA-256 digest.");
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
                writer.WriteBoolean("upgrade", entry.InstallName is not null && entry.Application is not null);
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
                    changes.Add(new ConfigurationChange(entry.Name, entry.Value.GetProperty("upgrade").GetBoolean()
                        ? ConfigurationChangeKind.Update : ConfigurationChangeKind.Add, false));
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
                var declaration = new JsonObject { ["version"] = app.Version.ToString() };
                if (ReadInstalledPackageHash(app) is string digest)
                    declaration["packageSha256"] = digest;
                result[app.Name] = declaration;
                missingInputs.Add(path + "/source");
                if (app.ReadManifestConfig() is not null)
                    missingInputs.Add(path + "/configuration");
                else
                    declaration["configuration"] = null;
            }
            return result;
        }

        private static string ReadInstalledPackageHash(DnsApplication app)
        {
            try
            {
                using var package = File.OpenRead(System.IO.Path.Combine(app.DnsServer.ApplicationFolder, app.Name + ".zip"));
                return Convert.ToHexString(SHA256.HashData(package));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }

        internal static async Task ApplyAsync(DnsApplicationManager manager, Entry[] entries, string[] ownership, Func<Action, string[], Task> commit,
            bool fromPrimary = false)
        {
            if ((entries is null || entries.Length == 0) && (ownership is null ||
                manager.ManagedPaths.SequenceEqual(ownership) && manager.OwnershipFromPrimary == (fromPrimary && ownership.Length > 0)))
            {
                await commit(null, []);
                return;
            }

            await manager.EnterManifestGateAsync();
            var activated = new List<Entry>();
            var removed = new List<DnsApplication>();
            var installed = new List<(DnsApplication App, DnsApplication Previous)>();
            try
            {
                bool ownershipChanged = ownership is not null && (!manager.ManagedPaths.SequenceEqual(ownership) ||
                    manager.OwnershipFromPrimary != (fromPrimary && ownership.Length > 0));
                entries ??= [];
                foreach (Entry entry in entries)
                {
                    manager.Applications.TryGetValue(entry.Name, out DnsApplication current);
                    if (!ReferenceEquals(current, entry.Application) || (current is not null && current.ReadManifestConfig() != entry.Before) ||
                        (entry.InstallName is null && entry.PackageSha256 is not null &&
                        !entry.PackageSha256.Equals(ReadInstalledPackageHash(current), StringComparison.OrdinalIgnoreCase)))
                        throw new InvalidDataException($"{entry.SettingPath}: The app changed during apply. Create a new preview.");
                }
                var packages = new Dictionary<string, byte[]>(StringComparer.Ordinal);
                foreach (Entry entry in entries.Where(entry => entry.InstallName is not null))
                {
                    if (entry.RemoteSource is null)
                    {
                        packages.Add(entry.Name, entry.Package);
                        continue;
                    }
                    byte[] downloaded;
                    try
                    {
                        downloaded = await manager.DownloadManifestPackageAsync(entry.RemoteSource);
                    }
                    catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or OperationCanceledException)
                    {
                        throw new InvalidDataException($"{entry.SettingPath}/source: Could not download the app package.");
                    }
                    if (entry.PackageSha256 is not null)
                        CheckPackageHash(entry.PackageSha256, SHA256.HashData(downloaded), entry.SettingPath + "/source/sha256");
                    packages.Add(entry.Name, downloaded);
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
                    DnsApplication app = await manager.InstallManifestAppAsync(entry.Name, packages[entry.Name], entry.Version,
                        entry.After, entry.HasConfig, entry.Application);
                    installed.Add((app, entry.Application));
                }

                foreach (Entry entry in removals)
                {
                    manager.DetachManifestApp(entry.Application);
                    removed.Add(entry.Application);
                }
                string[] resources = [.. files, .. removals.Select(entry => entry.FileName),
                    .. installed.Select(entry => entry.Previous is null ? ConfigurationJournal.AppInstallPath(entry.App.Name) :
                        ConfigurationJournal.AppUpgradePath(entry.App.Name))];
                await commit(resources.Length > 0 || ownershipChanged ? Write : null,
                    ownershipChanged ? [.. resources, OwnershipFile, PrimaryOwnershipFile] : resources);
                if (ownershipChanged)
                    manager.PublishManifestOwnership(ownership, fromPrimary);
                foreach (DnsApplication app in removed)
                    manager.DisposeManifestApp(app);
                foreach (var (_, previous) in installed)
                    if (previous is not null)
                        manager.DisposeManifestApp(previous);

                void Write()
                {
                    foreach (Entry entry in changed)
                        entry.Application.WriteManifestConfig(entry.After);
                    foreach (Entry entry in removals)
                        ConfigurationJournal.StageAppRemoval(manager.ConfigurationFolder, entry.Application.Name);
                    if (ownershipChanged)
                        manager.WriteManifestOwnership(ownership, fromPrimary);
                    foreach (var (app, previous) in installed)
                    {
                        if (previous is null)
                            ConfigurationJournal.FinishAppInstall(manager.ConfigurationFolder, app.Name);
                        else
                            ConfigurationJournal.FinishAppUpgrade(manager.ConfigurationFolder, app.Name);
                    }
                }
            }
            catch
            {
                foreach (var (app, previous) in installed)
                {
                    manager.DetachManifestApp(app);
                    manager.DisposeManifestApp(app);
                    if (previous is null)
                        ConfigurationJournal.CancelAppInstall(manager.ConfigurationFolder, app.Name);
                    else
                    {
                        ConfigurationJournal.CancelAppUpgrade(manager.ConfigurationFolder, app.Name);
                        manager.ReattachManifestApp(previous);
                    }
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
