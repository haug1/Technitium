/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using DnsServerCore.ApplicationCommon;
using DnsServerCore.Configuration;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Http.Client;

namespace DnsServerCore.Dns.Applications
{
    public sealed class DnsApplicationManager : IDisposable
    {
        #region variables

        readonly static Uri APP_STORE_URI = new Uri("https://go.technitium.com/?id=44");

        readonly DnsServer _dnsServer;

        readonly string _appsPath;

        readonly ConcurrentDictionary<string, DnsApplication> _applications = new ConcurrentDictionary<string, DnsApplication>();

        IReadOnlyList<IDnsRequestController> _dnsRequestControllers = [];
        IReadOnlyList<IDnsAuthoritativeRequestHandler> _dnsAuthoritativeRequestHandlers = [];
        IReadOnlyList<IDnsRequestBlockingHandler> _dnsRequestBlockingHandlers = [];
        IReadOnlyList<IDnsQueryLogger> _dnsQueryLoggers = [];
        IReadOnlyList<IDnsPostProcessor> _dnsPostProcessors = [];

        string _storeAppsJsonData;
        DateTime _storeAppsJsonDataUpdatedOn;
        const int STORE_APPS_JSON_DATA_CACHE_TIME_SECONDS = 900;

        Timer _appUpdateTimer;
        const int APP_UPDATE_TIMER_INITIAL_INTERVAL = 10000;
        const int APP_UPDATE_TIMER_PERIODIC_INTERVAL = 86400000;

        private const string ClusterConfigAbsentEntry = ".config-absent";
        private const string ClusterAppExistsEntry = ".exists";

        private string[] _manifestOwnedPaths = [];
        internal IReadOnlyList<string> ManagedPaths => _manifestOwnedPaths;
        internal bool OwnershipFromPrimary { get; private set; }

        SemaphoreSlim _opsLock = new SemaphoreSlim(1, 1);

        #endregion

        #region constructor

        public DnsApplicationManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _appsPath = Path.Combine(_dnsServer.ConfigFolder, "apps");
            string ownershipFile = Path.Combine(dnsServer.ConfigFolder, ConfigurationApplications.PrimaryOwnershipFile);
            OwnershipFromPrimary = File.Exists(ownershipFile);
            if (!OwnershipFromPrimary)
                ownershipFile = Path.Combine(dnsServer.ConfigFolder, ConfigurationApplications.OwnershipFile);
            if (File.Exists(ownershipFile))
                _manifestOwnedPaths = JsonSerializer.Deserialize<string[]>(File.ReadAllBytes(ownershipFile))
                    ?? throw new InvalidDataException("Invalid app manifest ownership file.");

            if (!Directory.Exists(_appsPath))
                Directory.CreateDirectory(_appsPath);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _appUpdateTimer?.Dispose();

                if (_applications != null)
                    UnloadAllApplicationsAsync().Sync();

                if (_opsLock is not null)
                {
                    _opsLock.Dispose();
                    _opsLock = null;
                }
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private async Task<DnsApplication> LoadApplicationAsync(string applicationFolder, bool refreshAppObjectList)
        {
            string applicationName = Path.GetFileName(applicationFolder);

            DnsApplication application = new DnsApplication(new InternalDnsServer(_dnsServer, applicationName, applicationFolder), applicationName);

            await application.InitializeAsync();

            if (!_applications.TryAdd(application.Name, application))
            {
                application.Dispose();
                throw new DnsServerException("DNS application already exists: " + application.Name);
            }

            application.ConfigUpdated += Application_ConfigUpdated;

            if (refreshAppObjectList)
                RefreshAppObjectLists();

            return application;
        }

        private void UnloadApplication(string applicationName)
        {
            if (!_applications.TryRemove(applicationName, out DnsApplication removedApp))
                throw new DnsServerException("DNS application does not exists: " + applicationName);

            RefreshAppObjectLists();

            removedApp.ConfigUpdated -= Application_ConfigUpdated;
            removedApp.Dispose();
        }

        private void Application_ConfigUpdated(object sender, EventArgs e)
        {
            //refresh app objects to allow sorting them as per app preference
            RefreshAppObjectLists();
        }

        private void RefreshAppObjectLists()
        {
            List<IDnsRequestController> dnsRequestControllers = new List<IDnsRequestController>(1);
            List<IDnsAuthoritativeRequestHandler> dnsAuthoritativeRequestHandlers = new List<IDnsAuthoritativeRequestHandler>(1);
            List<IDnsRequestBlockingHandler> dnsRequestBlockingHandlers = new List<IDnsRequestBlockingHandler>(1);
            List<IDnsQueryLogger> dnsQueryLoggers = new List<IDnsQueryLogger>(1);
            List<IDnsPostProcessor> dnsPostProcessors = new List<IDnsPostProcessor>(1);

            foreach (KeyValuePair<string, DnsApplication> application in _applications)
            {
                foreach (KeyValuePair<string, IDnsRequestController> controller in application.Value.DnsRequestControllers)
                    dnsRequestControllers.Add(controller.Value);

                foreach (KeyValuePair<string, IDnsAuthoritativeRequestHandler> handler in application.Value.DnsAuthoritativeRequestHandlers)
                    dnsAuthoritativeRequestHandlers.Add(handler.Value);

                foreach (KeyValuePair<string, IDnsRequestBlockingHandler> blocker in application.Value.DnsRequestBlockingHandler)
                    dnsRequestBlockingHandlers.Add(blocker.Value);

                foreach (KeyValuePair<string, IDnsQueryLogger> logger in application.Value.DnsQueryLoggers)
                    dnsQueryLoggers.Add(logger.Value);

                foreach (KeyValuePair<string, IDnsPostProcessor> processor in application.Value.DnsPostProcessors)
                    dnsPostProcessors.Add(processor.Value);
            }

            //sort app objects by preference
            dnsRequestControllers.Sort(CompareApps);
            dnsAuthoritativeRequestHandlers.Sort(CompareApps);
            dnsRequestBlockingHandlers.Sort(CompareApps);
            dnsQueryLoggers.Sort(CompareApps);
            dnsPostProcessors.Sort(CompareApps);

            _dnsRequestControllers = dnsRequestControllers;
            _dnsAuthoritativeRequestHandlers = dnsAuthoritativeRequestHandlers;
            _dnsRequestBlockingHandlers = dnsRequestBlockingHandlers;
            _dnsQueryLoggers = dnsQueryLoggers;
            _dnsPostProcessors = dnsPostProcessors;
        }

        private static int CompareApps<T>(T x, T y)
        {
            int xp;
            int yp;

            if (x is IDnsApplicationPreference xpref)
                xp = xpref.Preference;
            else
                xp = 100;

            if (y is IDnsApplicationPreference ypref)
                yp = ypref.Preference;
            else
                yp = 100;

            return xp.CompareTo(yp);
        }

        private void StartAutomaticUpdate()
        {
            async Task DownloadAndUpdateAsync(DnsApplication application, string url)
            {
                try
                {
                    await DownloadAndUpdateAppAsync(application.Name, new Uri(url));

                    _dnsServer.LogManager.Write("DNS application '" + application.Name + "' was automatically updated successfully from: " + url);
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write("Failed to automatically download and update DNS application '" + application.Name + "'.", ex);
                }
            }

            if (_appUpdateTimer is null)
            {
                _appUpdateTimer = new Timer(async delegate (object state)
                {
                    try
                    {
                        if (_applications.IsEmpty)
                            return;

                        _dnsServer.LogManager.Write("DNS Server has started automatic update check for DNS Apps.");

                        string storeAppsJsonData = await GetStoreAppsJsonData();
                        using JsonDocument jsonDocument = JsonDocument.Parse(storeAppsJsonData);
                        JsonElement jsonStoreAppsArray = jsonDocument.RootElement;

                        Version currentVersion = Assembly.GetExecutingAssembly().GetName().Version;
                        List<Task> tasks = new List<Task>();

                        foreach (DnsApplication application in _applications.Values)
                        {
                            if (IsPackageUpdateManaged(application.Name))
                                continue;
                            foreach (JsonElement jsonStoreApp in jsonStoreAppsArray.EnumerateArray())
                            {
                                string name = jsonStoreApp.GetProperty("name").GetString();
                                if (name.Equals(application.Name, StringComparison.Ordinal))
                                {
                                    string url = null;
                                    Version storeAppVersion = null;
                                    Version lastServerVersion = null;

                                    foreach (JsonElement jsonVersion in jsonStoreApp.GetProperty("versions").EnumerateArray())
                                    {
                                        string strServerVersion = jsonVersion.GetProperty("serverVersion").GetString();
                                        Version requiredServerVersion = new Version(strServerVersion);

                                        if (currentVersion < requiredServerVersion)
                                            continue;

                                        if ((lastServerVersion is not null) && (lastServerVersion > requiredServerVersion))
                                            continue;

                                        string version = jsonVersion.GetProperty("version").GetString();
                                        url = jsonVersion.GetProperty("url").GetString();

                                        storeAppVersion = new Version(version);
                                        lastServerVersion = requiredServerVersion;
                                    }

                                    if ((storeAppVersion is not null) && (storeAppVersion > application.Version))
                                        tasks.Add(DownloadAndUpdateAsync(application, url));

                                    break;
                                }
                            }
                        }

                        await Task.WhenAll(tasks);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                });

                _appUpdateTimer.Change(APP_UPDATE_TIMER_INITIAL_INTERVAL, APP_UPDATE_TIMER_PERIODIC_INTERVAL);
            }
        }

        private void StopAutomaticUpdate()
        {
            if (_appUpdateTimer is not null)
            {
                _appUpdateTimer.Dispose();
                _appUpdateTimer = null;
            }
        }

        internal async Task<string> GetStoreAppsJsonData()
        {
            if ((_storeAppsJsonData is null) || (DateTime.UtcNow > _storeAppsJsonDataUpdatedOn.AddSeconds(STORE_APPS_JSON_DATA_CACHE_TIME_SECONDS)))
            {
                HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                handler.Proxy = _dnsServer.Proxy;
                handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode);
                handler.DnsClient = _dnsServer;

                using (HttpClient http = new HttpClient(handler))
                {
                    _storeAppsJsonData = await http.GetStringAsync(APP_STORE_URI);
                    _storeAppsJsonDataUpdatedOn = DateTime.UtcNow;
                }
            }

            return _storeAppsJsonData;
        }

        #endregion

        #region public

        public async Task UnloadAllApplicationsAsync()
        {
            await _opsLock.WaitAsync();
            try
            {
                foreach (KeyValuePair<string, DnsApplication> application in _applications)
                {
                    try
                    {
                        application.Value.Dispose();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                }

                _applications.Clear();
                _dnsRequestControllers = Array.Empty<IDnsRequestController>();
                _dnsAuthoritativeRequestHandlers = Array.Empty<IDnsAuthoritativeRequestHandler>();
                _dnsRequestBlockingHandlers = Array.Empty<IDnsRequestBlockingHandler>();
                _dnsQueryLoggers = Array.Empty<IDnsQueryLogger>();
                _dnsPostProcessors = Array.Empty<IDnsPostProcessor>();
            }
            finally
            {
                _opsLock.Release();
            }
        }

        public async Task LoadAllApplicationsAsync()
        {
            await UnloadAllApplicationsAsync();

            await _opsLock.WaitAsync();
            try
            {
                List<Task> tasks = new List<Task>();

                foreach (string applicationFolder in Directory.GetDirectories(_appsPath))
                {
                    tasks.Add(Task.Run(async delegate ()
                    {
                        try
                        {
                            _dnsServer.LogManager.Write("DNS Server is loading DNS application: " + Path.GetFileName(applicationFolder));

                            _ = await LoadApplicationAsync(applicationFolder, false);

                            _dnsServer.LogManager.Write("DNS Server successfully loaded DNS application: " + Path.GetFileName(applicationFolder));
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.LogManager.Write("DNS Server failed to load DNS application: " + Path.GetFileName(applicationFolder), ex);
                        }
                    }));
                }

                await Task.WhenAll(tasks);

                RefreshAppObjectLists();
            }
            finally
            {
                _opsLock.Release();
            }
        }

        internal bool IsPackageUpdateManaged(string name)
        {
            string path = ConfigurationApplications.AppPath(name);
            var paths = _manifestOwnedPaths;
            return paths.Contains(path + "/version") || paths.Contains(path + "/configuration");
        }

        internal void CheckPackageUpdate(string name)
        {
            if (IsPackageUpdateManaged(name))
                throw new InvalidDataException($"{ConfigurationApplications.AppPath(name)}: The package version or configuration is managed by the manifest.");
        }

        internal async Task SetApplicationConfigAsync(DnsApplication app, string config, bool skipUnchanged = false)
        {
            await _opsLock.WaitAsync();
            try
            {
                string path = ConfigurationApplications.AppPath(app.Name) + "/configuration";
                if (!_applications.TryGetValue(app.Name, out DnsApplication current) || !ReferenceEquals(current, app))
                    throw new InvalidDataException($"{path}: The installed app changed before its configuration could be saved.");

                bool managed = _manifestOwnedPaths.Contains(path);
                if ((managed || skipUnchanged) && app.ReadManifestConfig() == config)
                    return;
                if (!managed)
                    await app.SetConfigAsync(config);
                else
                    throw new InvalidDataException($"{path}: App configuration is managed by the manifest.");
            }
            finally
            {
                _opsLock.Release();
            }
        }

        private bool OwnsAppAbsence(string name)
        {
            StringComparer comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
            return _manifestOwnedPaths.Contains(ConfigurationApplications.Path) ||
                (_manifestOwnedPaths.Contains(ConfigurationApplications.AppPath(name), comparer) && !_applications.Keys.Contains(name, comparer));
        }

        internal async Task WriteClusterTransferAsync(ZipArchive backupZip, DateTime ifModifiedSince)
        {
            await _opsLock.WaitAsync();
            try
            {
                using (Stream stream = backupZip.CreateEntry(ConfigurationApplications.OwnershipFile).Open())
                    JsonSerializer.Serialize(stream, _manifestOwnedPaths);

                string[] appDirectories = Directory.GetDirectories(_appsPath);
                foreach (string appDirectory in appDirectories)
                {
                    string applicationName = Path.GetFileName(appDirectory);
                    string path = ConfigurationApplications.AppPath(applicationName);
                    string applicationZipFile = Path.Combine(appDirectory, applicationName + ".zip");
                    string configFile = Path.Combine(appDirectory, DnsApplication.ConfigurationFileName);
                    bool fileAdded = false;

                    if (File.Exists(applicationZipFile) && (_manifestOwnedPaths.Contains(path) || File.GetLastWriteTimeUtc(applicationZipFile) > ifModifiedSince))
                    {
                        string entryName = "apps/" + applicationName + "/" + applicationName + ".zip";
                        backupZip.CreateEntryFromFile(applicationZipFile, entryName);
                        fileAdded = true;
                    }

                    if (!File.Exists(configFile))
                    {
                        _ = backupZip.CreateEntry("apps/" + applicationName + "/" + ClusterConfigAbsentEntry);
                        fileAdded = true;
                    }
                    else if (_manifestOwnedPaths.Contains(path + "/configuration") || File.GetLastWriteTimeUtc(configFile) > ifModifiedSince)
                    {
                        string entryName = "apps/" + applicationName + "/" + DnsApplication.ConfigurationFileName;
                        backupZip.CreateEntryFromFile(configFile, entryName);
                        fileAdded = true;
                    }

                    if (!fileAdded)
                        _ = backupZip.CreateEntry("apps/" + applicationName + "/" + ClusterAppExistsEntry, CompressionLevel.Optimal);
                }
            }
            finally
            {
                _opsLock.Release();
            }
        }

        internal sealed class ClusterAppTransfer
        {
            internal ZipArchiveEntry Package;
            internal ZipArchiveEntry Configuration;
            internal bool ClearConfiguration;
            internal bool ExistsOnly;
        }

        internal static Dictionary<string, ClusterAppTransfer> ReadClusterTransfer(ZipArchive archive)
        {
            var transfers = new Dictionary<string, ClusterAppTransfer>(StringComparer.Ordinal);
            var comparison = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
            var spellings = new HashSet<string>(comparison);
            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                if (!entry.FullName.StartsWith("apps/", StringComparison.Ordinal))
                    continue;

                string[] parts = entry.FullName.Split('/');
                if (parts.Length != 3 || !ConfigurationApplications.IsSafeName(parts[1]))
                    throw new InvalidDataException("Invalid app entry in the cluster configuration transfer.");

                string name = parts[1];
                if (!transfers.TryGetValue(name, out ClusterAppTransfer transfer))
                {
                    if (!spellings.Add(name))
                        throw new InvalidDataException("Conflicting app names in the cluster configuration transfer.");
                    transfer = new ClusterAppTransfer();
                    transfers.Add(name, transfer);
                }

                string path = ConfigurationApplications.AppPath(name);
                string file = parts[2];
                if (file == name + ".zip" && !transfer.ExistsOnly && transfer.Package is null)
                    transfer.Package = entry;
                else if (file == DnsApplication.ConfigurationFileName && !transfer.ExistsOnly && transfer.Configuration is null && !transfer.ClearConfiguration)
                    transfer.Configuration = entry;
                else if (file == ClusterConfigAbsentEntry && entry.Length == 0 && !transfer.ExistsOnly && transfer.Configuration is null && !transfer.ClearConfiguration)
                    transfer.ClearConfiguration = true;
                else if (file == ClusterAppExistsEntry && entry.Length == 0 && !transfer.ExistsOnly && transfer.Package is null && transfer.Configuration is null && !transfer.ClearConfiguration)
                    transfer.ExistsOnly = true;
                else
                    throw new InvalidDataException($"{path}: Unexpected or duplicate entry in the cluster configuration transfer.");
            }
            return transfers;
        }

        internal string[] ReadClusterOwnership(ZipArchive archive, IReadOnlyDictionary<string, ClusterAppTransfer> transfers)
        {
            ZipArchiveEntry entry = null;
            foreach (ZipArchiveEntry candidate in archive.Entries)
            {
                if (candidate.FullName != ConfigurationApplications.OwnershipFile)
                    continue;
                if (entry is not null)
                    throw new InvalidDataException("/apps/packages: Duplicate cluster ownership entry.");
                entry = candidate;
            }
            if (entry is null)
            {
                if (OwnershipFromPrimary)
                    throw new InvalidDataException("/apps/packages: The Primary did not send app ownership.");
                return null;
            }

            using Stream stream = entry.Open();
            string[] paths = JsonSerializer.Deserialize<string[]>(stream) ??
                throw new InvalidDataException("/apps/packages: Invalid cluster app ownership.");
            var declared = new HashSet<string>(paths, StringComparer.Ordinal);
            if (declared.Count != paths.Length)
                throw new InvalidDataException("/apps/packages: Duplicate cluster app ownership path.");

            const string prefix = ConfigurationApplications.Path + "/";
            foreach (string path in paths)
            {
                if (path == ConfigurationApplications.Path && paths.Length == 1 && transfers.Count == 0)
                    continue;
                if (path is null || !path.StartsWith(prefix, StringComparison.Ordinal))
                    throw new InvalidDataException("/apps/packages: Invalid cluster app ownership path.");
                string[] segments = path[prefix.Length..].Split('/');
                string name = segments[0].Replace("~1", "/").Replace("~0", "~");
                string appPath = ConfigurationApplications.AppPath(name);
                if (!ConfigurationApplications.IsSafeName(name) || !declared.Contains(appPath) ||
                    (segments.Length != 1 || path != appPath) &&
                    (segments.Length != 2 || segments[1] is not ("configuration" or "version") || path != appPath + "/" + segments[1]))
                    throw new InvalidDataException("/apps/packages: Invalid cluster app ownership path.");
                if (!transfers.TryGetValue(name, out ClusterAppTransfer transfer))
                {
                    if (segments.Length == 1)
                        continue; // owned absence
                    throw new InvalidDataException($"{appPath}: Cluster transfer omitted the managed app.");
                }
                if (transfer.Package is null || segments.Length == 2 && segments[1] == "configuration" &&
                    transfer.Configuration is null && !transfer.ClearConfiguration)
                    throw new InvalidDataException($"{appPath}: Cluster transfer omitted managed app files.");
            }
            if (paths.Length != 0 && !OwnershipFromPrimary && ManagedPaths.Count != 0)
                throw new InvalidDataException("/apps/packages: Release local app ownership before accepting Primary ownership.");
            return paths;
        }

        internal async Task ApplyClusterTransferAsync(Dictionary<string, ClusterAppTransfer> transfers, string[] ownership)
        {
            if (ownership is { Length: > 0 } || OwnershipFromPrimary)
            {
                await ApplyManagedClusterTransferAsync(transfers, ownership);
                return;
            }
            await ApplyLegacyClusterTransferAsync(transfers);
        }

        private async Task ApplyManagedClusterTransferAsync(Dictionary<string, ClusterAppTransfer> transfers, string[] ownership)
        {
            var changes = new List<ConfigurationApplications.Entry>();
            foreach (var (name, transfer) in transfers)
            {
                _applications.TryGetValue(name, out DnsApplication app);
                string before = app?.ReadManifestConfig();
                string after = transfer.ClearConfiguration ? null : before;
                if (transfer.Configuration is not null)
                {
                    using var reader = new StreamReader(transfer.Configuration.Open(), true);
                    after = await reader.ReadToEndAsync();
                }
                bool hasConfig = transfer.ClearConfiguration || transfer.Configuration is not null;
                if (transfer.Package is not null && (app is null ||
                    !MatchesFile(Path.Combine(app.DnsServer.ApplicationFolder, name + ".zip"), transfer.Package)))
                {
                    using Stream source = transfer.Package.Open();
                    using var package = new MemoryStream();
                    await source.CopyToAsync(package);
                    changes.Add(new(app, before, after, InstallName: name, Package: package.ToArray(), HasConfig: hasConfig));
                }
                else if (app is not null && before != after)
                {
                    changes.Add(new(app, before, after));
                }
            }
            foreach (DnsApplication app in _applications.Values)
            {
                if (!transfers.ContainsKey(app.Name))
                    changes.Add(new(app, app.ReadManifestConfig(), null, Remove: true));
            }
            await ConfigurationApplications.ApplyAsync(this, changes.ToArray(), ownership, (write, files) =>
            {
                if (write is not null)
                    ConfigurationJournal.Persist(ConfigurationFolder, write, files);
                return Task.CompletedTask;
            }, fromPrimary: true);
        }

        private async Task ApplyLegacyClusterTransferAsync(Dictionary<string, ClusterAppTransfer> transfers)
        {
            foreach (var (name, transfer) in transfers)
            {
                if (transfer.Package is null)
                    continue;
                await using Stream stream = transfer.Package.Open();
                if (_applications.ContainsKey(name))
                    await UpdateApplicationAsync(name, stream);
                else
                    await InstallApplicationAsync(name, stream);
            }

            foreach (var (name, transfer) in transfers)
            {
                if (!_applications.TryGetValue(name, out DnsApplication app))
                    continue;
                if (transfer.ClearConfiguration)
                {
                    await SetApplicationConfigAsync(app, null, skipUnchanged: true);
                    continue;
                }
                if (transfer.Configuration is null)
                    continue;

                using var reader = new StreamReader(transfer.Configuration.Open(), true);
                string config = await reader.ReadToEndAsync();
                try
                {
                    await SetApplicationConfigAsync(app, config);
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            }

            foreach (string name in _applications.Keys)
            {
                if (!transfers.ContainsKey(name))
                    await UninstallApplicationAsync(name);
            }
        }

        internal void CheckClusterTransfer(IReadOnlyDictionary<string, ClusterAppTransfer> transfers)
        {
            var paths = _manifestOwnedPaths;
            if (paths.Length == 0 || OwnershipFromPrimary)
                return;

            foreach (string name in transfers.Keys)
            {
                if (OwnsAppAbsence(name))
                    throw new InvalidDataException($"{ConfigurationApplications.AppPath(name)}: Cluster transfer would recreate a manifest-managed absent app.");
            }

            foreach (DnsApplication app in _applications.Values.OrderBy(app => app.Name, StringComparer.Ordinal))
            {
                string path = ConfigurationApplications.AppPath(app.Name);
                if (!paths.Contains(path))
                    continue;
                if (!transfers.TryGetValue(app.Name, out ClusterAppTransfer transfer))
                    throw new InvalidDataException($"{path}: Cluster transfer would replace manifest-managed app membership.");
                if (transfer.Package is not null && IsPackageUpdateManaged(app.Name))
                    throw new InvalidDataException($"{path}: Cluster transfer would update a managed package.");
                if (!paths.Contains(path + "/configuration"))
                    continue;
                if (transfer.ClearConfiguration && app.ReadManifestConfig() is not null)
                    throw new InvalidDataException($"{path}/configuration: Cluster transfer would clear a managed app configuration.");
                if (transfer.Configuration is not null &&
                    !MatchesFile(Path.Combine(app.DnsServer.ApplicationFolder, DnsApplication.ConfigurationFileName), transfer.Configuration))
                    throw new InvalidDataException($"{path}/configuration: Cluster transfer would change a managed app configuration.");
            }
        }

        internal void CheckManifestRestore(ZipArchive archive, bool deleteExistingFiles)
        {
            var paths = _manifestOwnedPaths;
            if (paths.Length == 0)
                return;

            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            string root = Path.GetFullPath(_appsPath) + Path.DirectorySeparatorChar;
            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                if (!entry.FullName.StartsWith("apps/", StringComparison.Ordinal) || entry.FullName == "apps/")
                    continue;
                string target = Path.GetFullPath(Path.Combine(_dnsServer.ConfigFolder, entry.FullName));
                if (!target.StartsWith(root, comparison))
                    throw new InvalidDataException("App backup paths must stay inside the apps directory.");
                string name = target[root.Length..].Split(Path.DirectorySeparatorChar, 2)[0];
                if (OwnsAppAbsence(name))
                    throw new InvalidDataException($"{ConfigurationApplications.AppPath(name)}: Restore would recreate a manifest-managed absent app.");
            }

            foreach (DnsApplication app in _applications.Values.OrderBy(app => app.Name, StringComparer.Ordinal))
            {
                string path = ConfigurationApplications.AppPath(app.Name);
                if (!paths.Contains(path))
                    continue;
                if (deleteExistingFiles)
                    throw new InvalidDataException($"{path}: Restore would replace manifest-managed app membership.");

                if (!IsPackageUpdateManaged(app.Name))
                    continue;
                string folder = Path.GetFullPath(app.DnsServer.ApplicationFolder) + Path.DirectorySeparatorChar;
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (!entry.FullName.StartsWith("apps/", StringComparison.Ordinal) || entry.Name.Length == 0)
                        continue;
                    string target = Path.GetFullPath(Path.Combine(_dnsServer.ConfigFolder, entry.FullName));
                    if (!target.StartsWith(folder, comparison))
                        continue;
                    bool config = Path.GetFileName(target).Equals(DnsApplication.ConfigurationFileName, comparison);
                    if (config && !paths.Contains(path + "/configuration"))
                        continue;
                    if (MatchesFile(target, entry))
                        continue;
                    throw new InvalidDataException($"{path}/{(config ? "configuration" : "version")}: Restore would change a managed app.");
                }
            }
        }

        private static bool MatchesFile(string file, ZipArchiveEntry entry)
        {
            if (!File.Exists(file))
                return false;
            using Stream current = File.OpenRead(file);
            using Stream candidate = entry.Open();
            return SHA256.HashData(current).AsSpan().SequenceEqual(SHA256.HashData(candidate));
        }

        internal void WriteManifestOwnership(string[] paths, bool fromPrimary)
        {
            string local = Path.Combine(_dnsServer.ConfigFolder, ConfigurationApplications.OwnershipFile);
            string primary = Path.Combine(_dnsServer.ConfigFolder, ConfigurationApplications.PrimaryOwnershipFile);
            string file = fromPrimary ? primary : local;
            File.Delete(fromPrimary ? local : primary);
            if (paths.Length == 0)
            {
                File.Delete(file);
                return;
            }
            string temporary = file + ".tmp";
            using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write))
            {
                JsonSerializer.Serialize(stream, paths);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, file, true);
        }

        internal void PublishManifestOwnership(string[] paths, bool fromPrimary)
        {
            _manifestOwnedPaths = paths;
            OwnershipFromPrimary = fromPrimary && paths.Length > 0;
        }

        internal async Task<byte[]> DownloadManifestPackageAsync(Uri uri)
        {
            using var handler = new HttpClientNetworkHandler
            {
                Proxy = _dnsServer.Proxy,
                NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode),
                DnsClient = _dnsServer
            };
            handler.InnerHandler.AllowAutoRedirect = false;
            using var client = new HttpClient(handler, disposeHandler: false);
            return await DownloadManifestPackageAsync(client, uri);
        }

        internal static async Task<byte[]> DownloadManifestPackageAsync(HttpClient client, Uri uri)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            for (int redirects = 0; redirects <= 10; redirects++)
            {
                if (uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
                    throw new InvalidDataException("An app package must use HTTPS without credentials or a fragment.");

                using HttpResponseMessage response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                if ((int)response.StatusCode is 301 or 302 or 303 or 307 or 308 &&
                    response.Headers.Location is Uri location)
                {
                    uri = location.IsAbsoluteUri ? location : new Uri(uri, location);
                    continue;
                }

                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsByteArrayAsync(timeout.Token);
            }
            throw new InvalidDataException("The app package download exceeded the redirect limit.");
        }

        internal async Task<DnsApplication> InstallManifestAppAsync(string name, byte[] package, string version, string config, bool hasConfig, DnsApplication previous)
        {
            string path = ConfigurationApplications.AppPath(name);
            string folder = Path.Combine(_appsPath, name);
            if (previous is null && Directory.Exists(folder))
                throw new InvalidDataException($"{path}: The application folder already exists.");
            if (previous is not null)
                DetachManifestApp(previous);

            if (previous is null)
                ConfigurationJournal.BeginAppInstall(ConfigurationFolder, name);
            DnsApplication app = null;
            bool attached = false;
            try
            {
                string priorFolder = previous is null ? null : ConfigurationJournal.BeginAppUpgrade(ConfigurationFolder, name);
                Directory.CreateDirectory(folder);
                if (priorFolder is not null)
                {
                    var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint };
                    foreach (string file in Directory.EnumerateFiles(priorFolder, "*", options))
                    {
                        string target = Path.Combine(folder, Path.GetRelativePath(priorFolder, file));
                        Directory.CreateDirectory(Path.GetDirectoryName(target));
                        File.Copy(file, target);
                    }
                }
                using var stream = new MemoryStream(package, writable: false);
                using (var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true))
                    await archive.ExtractToDirectoryAsync(folder, overwriteFiles: previous is not null);
                await File.WriteAllBytesAsync(Path.Combine(folder, name + ".zip"), package);

                app = new DnsApplication(new InternalDnsServer(_dnsServer, name, folder), name);
                if (version is not null && version != DnsWebService.GetCleanVersion(app.Version) && new Version(version) != app.Version)
                    throw new InvalidDataException($"{path}/version: The package version does not match.");
                string effectiveConfig = hasConfig || previous is not null && config is not null ? config : app.ReadManifestConfig();
                try
                {
                    await app.ActivateConfigAsync(effectiveConfig);
                }
                catch (Exception)
                {
                    throw new InvalidDataException($"{path}/configuration: The app rejected its configuration.");
                }
                if (hasConfig || previous is not null && config is not null)
                    app.WriteManifestConfig(effectiveConfig);

                attached = _applications.TryAdd(name, app);
                if (!attached)
                    throw new InvalidDataException($"{path}: The app is already installed.");
                app.ConfigUpdated += Application_ConfigUpdated;
                RefreshAppObjectLists();
                return app;
            }
            catch
            {
                if (attached)
                    DetachManifestApp(app);
                if (app is not null)
                    DisposeManifestApp(app);
                if (previous is null)
                    ConfigurationJournal.CancelAppInstall(ConfigurationFolder, name);
                else
                {
                    ConfigurationJournal.CancelAppUpgrade(ConfigurationFolder, name);
                    ReattachManifestApp(previous);
                }
                throw;
            }
        }

        internal void DetachManifestApp(DnsApplication app)
        {
            if (!_applications.TryRemove(app.Name, out _))
                throw new InvalidOperationException("The app is no longer installed.");
            app.ConfigUpdated -= Application_ConfigUpdated;
            try
            {
                RefreshAppObjectLists();
            }
            catch
            {
                ReattachManifestApp(app);
                throw;
            }
        }

        internal void ReattachManifestApp(DnsApplication app)
        {
            _applications[app.Name] = app;
            app.ConfigUpdated += Application_ConfigUpdated;
            RefreshAppObjectLists();
        }

        internal void DisposeManifestApp(DnsApplication app)
        {
            try
            {
                app.Dispose();
            }
            catch (Exception)
            {
                _dnsServer.LogManager.Write("Could not dispose the removed DNS application '" + app.Name + "'.");
            }
        }

        internal string ConfigurationFolder => _dnsServer.ConfigFolder;

        internal Task EnterManifestGateAsync() => _opsLock.WaitAsync();

        internal void ExitManifestGate() => _opsLock.Release();

        public async Task<DnsApplication> InstallApplicationAsync(string applicationName, Stream appZipStream)
        {
            await _opsLock.WaitAsync();
            try
            {
                foreach (char invalidChar in Path.GetInvalidFileNameChars())
                {
                    if (applicationName.Contains(invalidChar))
                        throw new DnsServerException("The application name contains an invalid character: " + invalidChar);
                }

                if (OwnsAppAbsence(applicationName))
                    throw new InvalidDataException($"{ConfigurationApplications.AppPath(applicationName)}: App absence is managed by the manifest.");

                if (_applications.ContainsKey(applicationName))
                    throw new DnsServerException("DNS application already exists: " + applicationName);

                string applicationFolder = Path.GetFullPath(Path.Combine(_appsPath, applicationName));
                if (!applicationFolder.StartsWith(_appsPath + Path.DirectorySeparatorChar, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                    throw new DnsServerException("The application name is invalid: " + applicationName);

                if (Directory.Exists(applicationFolder))
                    Directory.Delete(applicationFolder, true);

                Directory.CreateDirectory(applicationFolder);

                //keep a copy of the zip file in the application folder for transferring to other nodes
                await using (FileStream zipCopyStream = new FileStream(Path.Combine(applicationFolder, applicationName + ".zip"), FileMode.Create, FileAccess.ReadWrite))
                {
                    await appZipStream.CopyToAsync(zipCopyStream);

                    zipCopyStream.Position = 0;

                    await using (ZipArchive appZip = new ZipArchive(zipCopyStream, ZipArchiveMode.Read, false, Encoding.UTF8))
                    {
                        try
                        {
                            await appZip.ExtractToDirectoryAsync(applicationFolder, true);

                            return await LoadApplicationAsync(applicationFolder, true);
                        }
                        catch
                        {
                            await appZip.DisposeAsync();

                            if (Directory.Exists(applicationFolder))
                                Directory.Delete(applicationFolder, true);

                            throw;
                        }
                    }
                }
            }
            finally
            {
                _opsLock.Release();
            }
        }

        public async Task<DnsApplication> UpdateApplicationAsync(string applicationName, Stream appZipStream)
        {
            await _opsLock.WaitAsync();
            try
            {
                CheckPackageUpdate(applicationName);
                if (!_applications.ContainsKey(applicationName))
                    throw new DnsServerException("DNS application does not exists: " + applicationName);

                string applicationFolder = Path.Combine(_appsPath, applicationName);

                //keep a copy of the zip file in the application folder for transferring to other nodes
                await using (FileStream zipCopyStream = new FileStream(Path.Combine(applicationFolder, applicationName + ".zip"), FileMode.Create, FileAccess.ReadWrite))
                {
                    await appZipStream.CopyToAsync(zipCopyStream);

                    zipCopyStream.Position = 0;

                    await using (ZipArchive appZip = new ZipArchive(zipCopyStream, ZipArchiveMode.Read, false, Encoding.UTF8))
                    {
                        UnloadApplication(applicationName);

                        foreach (ZipArchiveEntry entry in appZip.Entries)
                        {
                            string filePath = Path.GetFullPath(Path.Combine(applicationFolder, entry.FullName));
                            if (!filePath.StartsWith(applicationFolder + Path.DirectorySeparatorChar, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                                throw new IOException("Extracting Zip entry would have resulted in a file outside the specified destination directory.");

                            if ((entry.Name == "dnsApp.config") && File.Exists(filePath))
                                continue; //avoid overwriting existing config file

                            if ((entry.Length == 0) && (entry.Name.Length == 0) && entry.FullName.EndsWith('/'))
                            {
                                //directory entry
                                Directory.CreateDirectory(filePath);
                            }
                            else
                            {
                                //file entry
                                Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                                await entry.ExtractToFileAsync(filePath, true);
                            }
                        }

                        return await LoadApplicationAsync(applicationFolder, true);
                    }
                }
            }
            finally
            {
                _opsLock.Release();
            }
        }

        public async Task UninstallApplicationAsync(string applicationName)
        {
            await _opsLock.WaitAsync();
            try
            {
                string path = ConfigurationApplications.AppPath(applicationName);
                if (_manifestOwnedPaths.Contains(path))
                    throw new InvalidDataException($"{path}: App membership is managed by the manifest.");
                if (_applications.TryRemove(applicationName, out DnsApplication removedApp))
                {
                    RefreshAppObjectLists();

                    removedApp.ConfigUpdated -= Application_ConfigUpdated;
                    removedApp.Dispose();

                    if (Directory.Exists(removedApp.DnsServer.ApplicationFolder))
                    {
                        try
                        {
                            Directory.Delete(removedApp.DnsServer.ApplicationFolder, true);
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.LogManager.Write(ex);
                        }
                    }
                }
            }
            finally
            {
                _opsLock.Release();
            }
        }

        public async Task<DnsApplication> DownloadAndInstallAppAsync(string applicationName, Uri uri)
        {
            string tmpFile = Path.GetTempFileName();
            try
            {
                await using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //download to temp file
                    HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                    handler.Proxy = _dnsServer.Proxy;
                    handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode);
                    handler.DnsClient = _dnsServer;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        HttpResponseMessage httpResponse = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead);

                        httpResponse.EnsureSuccessStatusCode();

                        await using (Stream httpStream = await httpResponse.Content.ReadAsStreamAsync())
                        {
                            //copy stream with idle timeout
                            await httpStream.CopyToAsync(fS, TimeSpan.FromSeconds(60));
                        }
                    }

                    //install app
                    fS.Position = 0;
                    return await InstallApplicationAsync(applicationName, fS);
                }
            }
            finally
            {
                try
                {
                    File.Delete(tmpFile);
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            }
        }

        public async Task<DnsApplication> DownloadAndUpdateAppAsync(string applicationName, Uri uri)
        {
            string tmpFile = Path.GetTempFileName();
            try
            {
                await using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //download to temp file
                    HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                    handler.Proxy = _dnsServer.Proxy;
                    handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode);
                    handler.DnsClient = _dnsServer;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        HttpResponseMessage httpResponse = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead);

                        httpResponse.EnsureSuccessStatusCode();

                        await using (Stream httpStream = await httpResponse.Content.ReadAsStreamAsync())
                        {
                            //copy stream with idle timeout
                            await httpStream.CopyToAsync(fS, TimeSpan.FromSeconds(60));
                        }
                    }

                    //update app
                    fS.Position = 0;
                    return await UpdateApplicationAsync(applicationName, fS);
                }
            }
            finally
            {
                try
                {
                    File.Delete(tmpFile);
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            }
        }

        #endregion

        #region properties

        public IReadOnlyDictionary<string, DnsApplication> Applications
        { get { return _applications; } }

        public IReadOnlyList<IDnsRequestController> DnsRequestControllers
        { get { return _dnsRequestControllers; } }

        public IReadOnlyList<IDnsAuthoritativeRequestHandler> DnsAuthoritativeRequestHandlers
        { get { return _dnsAuthoritativeRequestHandlers; } }

        public IReadOnlyList<IDnsRequestBlockingHandler> DnsRequestBlockingHandlers
        { get { return _dnsRequestBlockingHandlers; } }

        public IReadOnlyList<IDnsQueryLogger> DnsQueryLoggers
        { get { return _dnsQueryLoggers; } }

        public IReadOnlyList<IDnsPostProcessor> DnsPostProcessors
        { get { return _dnsPostProcessors; } }

        public bool EnableAutomaticUpdate
        {
            get { return _appUpdateTimer is not null; }
            set
            {
                if (value)
                    StartAutomaticUpdate();
                else
                    StopAutomaticUpdate();
            }
        }

        #endregion
    }
}
