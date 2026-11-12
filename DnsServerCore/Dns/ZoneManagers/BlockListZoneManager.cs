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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class BlockListZoneManager : IDisposable
    {
        #region variables

        readonly static char[] _popWordSeperator = new char[] { ' ', '\t' };
        readonly static char[] _trimSeperator = new char[] { ' ', '\t', '*', '.' };

        readonly DnsServer _dnsServer;
        readonly string _localCacheFolder;

        IReadOnlyList<string> _blockListUrls = [];

        Dictionary<string, object> _allowListZone = new Dictionary<string, object>();
        Dictionary<string, List<Uri>> _blockListZone = new Dictionary<string, List<Uri>>();

        DnsSOARecordData _soaRecord;
        DnsNSRecordData _nsRecord;

        readonly IReadOnlyCollection<DnsARecordData> _aRecords = [new DnsARecordData(IPAddress.Any)];
        readonly IReadOnlyCollection<DnsAAAARecordData> _aaaaRecords = [new DnsAAAARecordData(IPAddress.IPv6Any)];

        Timer _blockListUpdateTimer;
        DateTime _blockListLastUpdatedOn;
        int _blockListUpdateIntervalHours = 24;
        bool _manifestOwnsUpdateInterval;
        bool _manifestOwnsSources;
        const int BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL = 5000;
        const int BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL = 900000;

        Timer _temporaryDisableBlockingTimer;
        DateTime _temporaryDisableBlockingTill;

        readonly Lock _saveLock = new Lock();
        bool _pendingSave;
        bool _pendingLazySave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        public BlockListZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _localCacheFolder = Path.Combine(_dnsServer.ConfigFolder, "blocklists");

            if (!Directory.Exists(_localCacheFolder))
                Directory.CreateDirectory(_localCacheFolder);

            UpdateServerDomain();

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveConfigFileInternal();
                            _pendingSave = false;
                            _pendingLazySave = false;
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.LogManager.Write(ex);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _blockListUpdateTimer?.Dispose();
            _temporaryDisableBlockingTimer?.Dispose();

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave || _pendingLazySave)
                {
                    try
                    {
                        SaveConfigFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                        _pendingLazySave = false;
                    }
                }
            }

            _disposed = true;
        }

        #endregion

        #region config

        public void LoadConfigFile()
        {
            string blockListConfigFile = Path.Combine(_dnsServer.ConfigFolder, "blocklist.config");

            try
            {
                using (FileStream fS = new FileStream(blockListConfigFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS, false, readOwnership: true);
                }

                _dnsServer.LogManager.Write("DNS Server block list config file was loaded: " + blockListConfigFile);
            }
            catch (FileNotFoundException)
            {
                lock (_saveLock)
                {
                    SaveConfigFileInternal();
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server encountered an error while loading block list config file: " + blockListConfigFile, ex);
            }
        }

        public void LoadConfig(Stream s, bool isConfigTransfer)
        {
            lock (_saveLock)
            {
                ReadConfigFrom(s, isConfigTransfer);

                SaveConfigFileInternal();
                _pendingSave = false;
                _pendingLazySave = false;
            }
        }

        private void SaveConfigFileInternal(IReadOnlyList<string> sources = null)
        {
            string tmpBlockListConfigFile = Path.Combine(_dnsServer.ConfigFolder, "blocklist.tmp");
            string blockListConfigFile = Path.Combine(_dnsServer.ConfigFolder, "blocklist.config");

            using (FileStream fS = new FileStream(tmpBlockListConfigFile, FileMode.Create, FileAccess.Write))
            {
                WriteConfigTo(fS, sources ?? _blockListUrls);
                fS.Flush(flushToDisk: true);
            }

            File.Move(tmpBlockListConfigFile, blockListConfigFile, true);

            _dnsServer.LogManager.Write("DNS Server block list config file was saved: " + blockListConfigFile);
        }

        public void SaveConfigFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void LazySaveConfigFile()
        {
            lock (_saveLock)
            {
                _pendingLazySave = true;
            }
        }

        internal bool HasManagedSettings => _manifestOwnsUpdateInterval || _manifestOwnsSources;
        internal bool ManifestOwnsUpdateInterval => _manifestOwnsUpdateInterval;
        internal bool ManifestOwnsSources => _manifestOwnsSources;

        internal void CheckManifestSources(IReadOnlyList<string> sources)
        {
            if (_manifestOwnsSources && sources is not null && !sources.SequenceEqual(_blockListUrls, StringComparer.Ordinal))
                throw new DnsWebServiceException("/blocklists/sources: Setting is managed by the configuration manifest.");
        }

        internal void CheckManifestUpdateInterval(int interval)
        {
            if (_manifestOwnsUpdateInterval && interval != _blockListUpdateIntervalHours)
                throw new DnsWebServiceException("/blocklists/updateIntervalHours: Setting is managed by the configuration manifest.");
        }

        internal void CheckRestoreManifestOwnership(Stream stream)
        {
            var reader = new BinaryReader(stream);
            var (sources, interval) = ReadConfigPrefix(reader);
            CheckManifestSources(sources);
            CheckManifestUpdateInterval(interval);
        }

        internal void ApplyManifestSettings(int? interval, IReadOnlyList<string> sources, Action<Action> persist)
        {
            lock (_saveLock)
            {
                int previous = _blockListUpdateIntervalHours;
                bool previouslyOwned = _manifestOwnsUpdateInterval;
                bool previouslyOwnedSources = _manifestOwnsSources;
                int effective = interval ?? previous;
                bool sourcesChanged = sources is not null && !sources.SequenceEqual(_blockListUrls, StringComparer.Ordinal);
                if (effective == previous && interval.HasValue == previouslyOwned &&
                    !sourcesChanged && (sources is not null) == previouslyOwnedSources)
                {
                    persist(null);
                    return;
                }

                _blockListUpdateIntervalHours = effective;
                _manifestOwnsUpdateInterval = interval.HasValue;
                _manifestOwnsSources = sources is not null;
                try
                {
                    persist(() => SaveConfigFileInternal(sourcesChanged ? sources : null));
                    _pendingSave = false;
                    _pendingLazySave = false;
                }
                catch
                {
                    _blockListUpdateIntervalHours = previous;
                    _manifestOwnsUpdateInterval = previouslyOwned;
                    _manifestOwnsSources = previouslyOwnedSources;
                    throw;
                }

                if (sourcesChanged)
                {
                    ApplyBlockListUrls(sources);
                    if (sources.Count > 0)
                        QueueLoadBlockLists();
                }
                else if (effective != previous)
                {
                    ApplyBlockListUpdateInterval();
                }
            }
        }

        private static (string[] Urls, int Interval) ReadConfigPrefix(BinaryReader reader)
        {
            Stream stream = reader.BaseStream;
            if (Encoding.ASCII.GetString(stream.ReadExactly(2)) != "BL")
                throw new InvalidDataException("DnsServer block list zone file format is invalid.");
            if (reader.ReadByte() != 1)
                throw new InvalidDataException("DnsServer block list zone file version not supported.");

            var urls = new string[reader.ReadByte()];
            for (int i = 0; i < urls.Length; i++)
                urls[i] = stream.ReadShortString();

            return (urls, reader.ReadInt32());
        }

        private void ReadConfigFrom(Stream s, bool isConfigTransfer, bool readOwnership = false)
        {
            var (blockListUrls, interval) = ReadConfigPrefix(new BinaryReader(s));
            _blockListUpdateIntervalHours = interval;
            DateTime blockListLastUpdatedOn = s.ReadDateTime();
            if (readOwnership)
            {
                int ownership = s.ReadByte();
                _manifestOwnsUpdateInterval = ownership >= 0 && (ownership & 1) != 0;
                _manifestOwnsSources = ownership >= 0 && (ownership & 2) != 0;
            }

            if (!isConfigTransfer)
                _blockListLastUpdatedOn = blockListLastUpdatedOn;

            ApplyBlockListUrls(blockListUrls);
            ApplyBlockListUpdateInterval();
            if (!isConfigTransfer && blockListUrls.Length > 0)
                QueueLoadBlockLists();
        }

        private void WriteConfigTo(Stream s, IReadOnlyList<string> sources)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("BL")); //format
            bW.Write((byte)1); //version

            bW.Write(Convert.ToByte(sources.Count));
            foreach (string source in sources)
                s.WriteShortString(source);

            bW.Write(_blockListUpdateIntervalHours);
            s.WriteDateTime(_blockListLastUpdatedOn);
            // Existing version 1 readers stop after the timestamp.
            if (HasManagedSettings)
                bW.Write((byte)((_manifestOwnsUpdateInterval ? 1 : 0) | (_manifestOwnsSources ? 2 : 0)));
        }

        #endregion

        #region private

        internal void UpdateServerDomain()
        {
            _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, _dnsServer.BlockingAnswerTtl);
            _nsRecord = new DnsNSRecordData(_dnsServer.ServerDomain);
        }

        private string GetSourceDisplayName(Uri source)
        {
            return _manifestOwnsSources ? (source.IsFile ? "local file" : source.Host) : source.AbsoluteUri;
        }

        private void WriteSourceError(string message, Exception error)
        {
            if (_manifestOwnsSources)
                _dnsServer.LogManager.Write(message + " (" + error.GetType().Name + ")");
            else
                _dnsServer.LogManager.Write(message, error);
        }

        private string GetBlockListFilePath(Uri blockListUrl)
        {
            return Path.Combine(_localCacheFolder, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(blockListUrl.AbsoluteUri))).ToLowerInvariant());
        }

        private static string PopWord(ref string line)
        {
            if (line.Length == 0)
                return line;

            line = line.TrimStart(_popWordSeperator);

            int i = line.IndexOfAny(_popWordSeperator);
            string word;

            if (i < 0)
            {
                word = line;
                line = "";
            }
            else
            {
                word = line.Substring(0, i);
                line = line.Substring(i + 1);
            }

            return word;
        }

        private Queue<string> ReadListFile(Uri listUrl, bool isAllowList, out Queue<string> exceptionDomains)
        {
            Queue<string> domains = new Queue<string>();
            exceptionDomains = new Queue<string>();

            try
            {
                _dnsServer.LogManager.Write("DNS Server is reading " + (isAllowList ? "allow" : "block") + " list from: " + GetSourceDisplayName(listUrl));

                string listFilePath;

                if (listUrl.IsFile)
                    listFilePath = listUrl.LocalPath;
                else
                    listFilePath = GetBlockListFilePath(listUrl);

                using (FileStream fS = new FileStream(listFilePath, FileMode.Open, FileAccess.Read))
                {
                    //parse hosts file and populate block zone
                    StreamReader sR = new StreamReader(fS, true);

                    string line;
                    string firstWord;
                    string secondWord;
                    string hostname;
                    string domain;
                    string options;
                    int i;

                    while (true)
                    {
                        line = sR.ReadLine();
                        if (line is null)
                            break; //eof

                        line = line.TrimStart(_trimSeperator);

                        if (line.Length == 0)
                            continue; //skip empty line

                        if (line.StartsWith('#') || line.StartsWith('!'))
                            continue; //skip comment line

                        if (line.StartsWith("||", StringComparison.Ordinal))
                        {
                            //adblock format
                            i = line.IndexOf('^');
                            if (i > -1)
                            {
                                domain = line.Substring(2, i - 2);
                                options = line.Substring(i + 1);

                                if (((options.Length == 0) || (options.StartsWith('$') && (options.Contains("doc") || options.Contains("all")))) && DnsClient.IsDomainNameValid(domain))
                                    domains.Enqueue(domain.ToLowerInvariant());
                            }
                            else
                            {
                                domain = line.Substring(2);

                                if (DnsClient.IsDomainNameValid(domain))
                                    domains.Enqueue(domain.ToLowerInvariant());
                            }
                        }
                        else if (line.StartsWith("@@||", StringComparison.Ordinal))
                        {
                            //adblock format - exception syntax
                            i = line.IndexOf('^');
                            if (i > -1)
                            {
                                domain = line.Substring(4, i - 4);
                                options = line.Substring(i + 1);

                                if (((options.Length == 0) || (options.StartsWith('$') && (options.Contains("doc") || options.Contains("all")))) && DnsClient.IsDomainNameValid(domain))
                                    exceptionDomains.Enqueue(domain.ToLowerInvariant());
                            }
                            else
                            {
                                domain = line.Substring(4);

                                if (DnsClient.IsDomainNameValid(domain))
                                    exceptionDomains.Enqueue(domain.ToLowerInvariant());
                            }
                        }
                        else
                        {
                            //hosts file format
                            firstWord = PopWord(ref line);

                            if (line.Length == 0)
                            {
                                hostname = firstWord;
                            }
                            else
                            {
                                secondWord = PopWord(ref line);

                                if ((secondWord.Length == 0) || secondWord.StartsWith('#'))
                                {
                                    hostname = firstWord;
                                }
                                else
                                {
                                    if (!IPAddress.TryParse(firstWord, out _))
                                        continue; //first word must be an IP address for using second word as hostname as per hosts file format

                                    hostname = secondWord;
                                }
                            }

                            hostname = hostname.Trim('.').ToLowerInvariant();

                            switch (hostname)
                            {
                                case "":
                                case "localhost":
                                case "localhost.localdomain":
                                case "local":
                                case "broadcasthost":
                                case "ip6-localhost":
                                case "ip6-loopback":
                                case "ip6-localnet":
                                case "ip6-mcastprefix":
                                case "ip6-allnodes":
                                case "ip6-allrouters":
                                case "ip6-allhosts":
                                    continue; //skip these hostnames
                            }

                            if (!DnsClient.IsDomainNameValid(hostname))
                                continue;

                            if (IPAddress.TryParse(hostname, out _))
                                continue; //skip line when hostname is IP address

                            domains.Enqueue(hostname);
                        }
                    }
                }

                _dnsServer.LogManager.Write("DNS Server read " + (isAllowList ? "allow" : "block") + " list file (" + domains.Count + " domain(s) blocked" + (exceptionDomains.Count > 0 ? ", " + exceptionDomains.Count + " domain(s) allowed" : "") + ") from: " + GetSourceDisplayName(listUrl));
            }
            catch (Exception ex)
            {
                WriteSourceError("DNS Server failed to read " + (isAllowList ? "allow" : "block") + " list from: " + GetSourceDisplayName(listUrl), ex);
            }

            return domains;
        }

        private List<Uri> IsZoneBlocked(string domain, out string blockedDomain)
        {
            domain = domain.ToLowerInvariant();

            do
            {
                if (_blockListZone.TryGetValue(domain, out List<Uri> blockLists))
                {
                    //found zone blocked
                    blockedDomain = domain;
                    return blockLists;
                }

                domain = AuthZoneManager.GetParentZone(domain);
            }
            while (domain is not null);

            blockedDomain = null;
            return null;
        }

        private bool IsZoneAllowed(string domain)
        {
            domain = domain.ToLowerInvariant();

            do
            {
                if (_allowListZone.TryGetValue(domain, out _))
                    return true;

                domain = AuthZoneManager.GetParentZone(domain);
            }
            while (domain is not null);

            return false;
        }

        private void ApplyBlockListUrls(IReadOnlyList<string> blockListUrls)
        {
            bool blockListUrlsUpdated = !blockListUrls.HasSameItems(_blockListUrls);

            _blockListUrls = blockListUrls;

            if ((_blockListUpdateIntervalHours > 0) && (_blockListUrls.Count > 0))
            {
                if (_blockListUpdateTimer is null)
                    StartBlockListUpdateTimer(blockListUrlsUpdated);
                else if (blockListUrlsUpdated)
                    ForceUpdateBlockLists(true);
            }
            else
            {
                StopBlockListUpdateTimer();
            }

            if (_blockListUrls.Count < 1)
                Flush();
        }

        private void ApplyBlockListUpdateInterval()
        {
            if ((_blockListUpdateIntervalHours > 0) && (_blockListUrls.Count > 0))
            {
                if (_blockListUpdateTimer is null)
                    StartBlockListUpdateTimer(false);
            }
            else
            {
                StopBlockListUpdateTimer();
            }
        }

        private void Flush()
        {
            _allowListZone = new Dictionary<string, object>();
            _blockListZone = new Dictionary<string, List<Uri>>();
        }

        private async Task<bool> UpdateBlockListsAsync(bool forceReload)
        {
            bool downloaded = false;
            bool notModified = false;

            async Task DownloadListUrlAsync(Uri listUrl, bool isAllowList)
            {
                try
                {
                    _dnsServer.LogManager.Write("DNS Server is downloading " + (isAllowList ? "allow" : "block") + " list: " + GetSourceDisplayName(listUrl));

                    string listFilePath = GetBlockListFilePath(listUrl);

                    if (listUrl.IsFile)
                    {
                        if (!File.Exists(listUrl.LocalPath))
                        {
                            _dnsServer.LogManager.Write("DNS Server did not find the " + (isAllowList ? "allow" : "block") + " list: " + GetSourceDisplayName(listUrl));
                            return;
                        }

                        if (File.Exists(listFilePath))
                        {
                            if (File.GetLastWriteTimeUtc(listUrl.LocalPath) <= File.GetLastWriteTimeUtc(listFilePath))
                            {
                                notModified = true;
                                _dnsServer.LogManager.Write("DNS Server successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + GetSourceDisplayName(listUrl));
                                return;
                            }
                        }

                        //create dummy file
                        await File.Create(listFilePath).DisposeAsync();

                        downloaded = true;
                        _dnsServer.LogManager.Write("DNS Server found new update for the " + (isAllowList ? "allow" : "block") + " list: " + GetSourceDisplayName(listUrl));
                    }
                    else
                    {
                        HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                        handler.Proxy = _dnsServer.Proxy;
                        handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode);
                        handler.DnsClient = _dnsServer;

                        using (HttpClient http = new HttpClient(handler))
                        {
                            if (File.Exists(listFilePath))
                                http.DefaultRequestHeaders.IfModifiedSince = File.GetLastWriteTimeUtc(listFilePath);

                            http.DefaultRequestHeaders.UserAgent.TryParseAdd("Technitium DNS Server");

                            HttpResponseMessage httpResponse = await http.GetAsync(listUrl, HttpCompletionOption.ResponseHeadersRead);
                            switch (httpResponse.StatusCode)
                            {
                                case HttpStatusCode.OK:
                                    {
                                        string listDownloadFilePath = listFilePath + ".downloading";

                                        await using (FileStream fS = new FileStream(listDownloadFilePath, FileMode.Create, FileAccess.Write))
                                        {
                                            await using (Stream httpStream = await httpResponse.Content.ReadAsStreamAsync())
                                            {
                                                //copy stream with idle timeout
                                                await httpStream.CopyToAsync(fS, TimeSpan.FromSeconds(60));
                                            }
                                        }

                                        File.Move(listDownloadFilePath, listFilePath, true);

                                        if (httpResponse.Content.Headers.LastModified != null)
                                            File.SetLastWriteTimeUtc(listFilePath, httpResponse.Content.Headers.LastModified.Value.UtcDateTime);

                                        downloaded = true;
                                        _dnsServer.LogManager.Write("DNS Server successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + GetSourceDisplayName(listUrl));
                                    }
                                    break;

                                case HttpStatusCode.NotModified:
                                    {
                                        notModified = true;
                                        _dnsServer.LogManager.Write("DNS Server successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + GetSourceDisplayName(listUrl));
                                    }
                                    break;

                                default:
                                    throw new HttpRequestException((int)httpResponse.StatusCode + " " + httpResponse.ReasonPhrase);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    WriteSourceError("DNS Server failed to download " + (isAllowList ? "allow" : "block") + " list and will use previously downloaded file (if available): " + GetSourceDisplayName(listUrl), ex);
                }
            }

            List<Task> tasks = new List<Task>();

            foreach (string blockListUrl in _blockListUrls)
            {
                if (blockListUrl.TrimStart().StartsWith('#'))
                    continue; //skip comment line

                if (blockListUrl.StartsWith('!'))
                    tasks.Add(DownloadListUrlAsync(new Uri(blockListUrl.Substring(1)), true));
                else
                    tasks.Add(DownloadListUrlAsync(new Uri(blockListUrl), false));
            }

            await Task.WhenAll(tasks);

            if (downloaded || forceReload)
            {
                LoadBlockLists();

                GC.Collect(2, GCCollectionMode.Optimized, false); //do GC collection to remove old block list data from memory quickly
            }

            return downloaded || notModified;
        }

        private void ForceUpdateBlockLists(bool forceReload)
        {
            ThreadPool.QueueUserWorkItem(async delegate (object state)
            {
                try
                {
                    if (await UpdateBlockListsAsync(forceReload))
                    {
                        //block lists were updated
                        _blockListLastUpdatedOn = DateTime.UtcNow;

                        //lazy save last updated on time
                        LazySaveConfigFile();
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            });
        }

        private void StartBlockListUpdateTimer(bool forceUpdateAndReload)
        {
            if (_blockListUpdateTimer is null)
            {
                if (forceUpdateAndReload)
                    _blockListLastUpdatedOn = default;

                _blockListUpdateTimer = new Timer(async delegate (object state)
                {
                    try
                    {
                        if (DateTime.UtcNow > _blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours))
                        {
                            if (await UpdateBlockListsAsync(_blockListLastUpdatedOn == default))
                            {
                                //block lists were updated
                                _blockListLastUpdatedOn = DateTime.UtcNow;

                                //lazy save last updated on time
                                LazySaveConfigFile();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write("DNS Server encountered an error while updating block lists.", ex);
                    }
                    finally
                    {
                        try
                        {
                            _blockListUpdateTimer?.Change(BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL, Timeout.Infinite);
                        }
                        catch (ObjectDisposedException)
                        { }
                    }
                }, null, BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void StopBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer is not null)
            {
                _blockListUpdateTimer.Dispose();
                _blockListUpdateTimer = null;
            }
        }

        private void QueueLoadBlockLists()
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    LoadBlockLists();
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            });
        }

        private void LoadBlockLists()
        {
            _dnsServer.LogManager.Write("DNS Server is loading block list zone...");

            List<Uri> allowListUrls = new List<Uri>();
            List<Uri> blockListUrls = new List<Uri>();

            IReadOnlyList<string> sources = _blockListUrls;
            foreach (string listUri in sources)
            {
                if (listUri.TrimStart().StartsWith('#'))
                    continue; //skip comment line

                if (listUri.StartsWith('!'))
                    allowListUrls.Add(new Uri(listUri.Substring(1)));
                else
                    blockListUrls.Add(new Uri(listUri));
            }

            Dictionary<Uri, Queue<string>> allowListQueues = new Dictionary<Uri, Queue<string>>(allowListUrls.Count);
            Dictionary<Uri, Queue<string>> blockListQueues = new Dictionary<Uri, Queue<string>>(blockListUrls.Count);
            int totalAllowedDomains = 0;
            int totalBlockedDomains = 0;

            //read all allow lists in a queue
            foreach (Uri allowListUrl in allowListUrls)
            {
                if (!allowListQueues.ContainsKey(allowListUrl))
                {
                    Queue<string> allowListQueue = ReadListFile(allowListUrl, true, out Queue<string> blockListQueue);

                    totalAllowedDomains += allowListQueue.Count;
                    allowListQueues.Add(allowListUrl, allowListQueue);

                    totalBlockedDomains += blockListQueue.Count;
                    blockListQueues.Add(allowListUrl, blockListQueue);
                }
            }

            //read all block lists in a queue
            foreach (Uri blockListUrl in blockListUrls)
            {
                if (!blockListQueues.ContainsKey(blockListUrl))
                {
                    Queue<string> blockListQueue = ReadListFile(blockListUrl, false, out Queue<string> allowListQueue);

                    totalBlockedDomains += blockListQueue.Count;
                    blockListQueues.Add(blockListUrl, blockListQueue);

                    totalAllowedDomains += allowListQueue.Count;
                    allowListQueues.Add(blockListUrl, allowListQueue);
                }
            }

            //load block list zone
            Dictionary<string, object> allowListZone = new Dictionary<string, object>(totalAllowedDomains);

            foreach (KeyValuePair<Uri, Queue<string>> allowListQueue in allowListQueues)
            {
                Queue<string> queue = allowListQueue.Value;

                while (queue.Count > 0)
                {
                    string domain = queue.Dequeue();

                    allowListZone.TryAdd(domain, null);
                }
            }

            Dictionary<string, List<Uri>> blockListZone = new Dictionary<string, List<Uri>>(totalBlockedDomains);

            foreach (KeyValuePair<Uri, Queue<string>> blockListQueue in blockListQueues)
            {
                Queue<string> queue = blockListQueue.Value;

                while (queue.Count > 0)
                {
                    string domain = queue.Dequeue();

                    if (!blockListZone.TryGetValue(domain, out List<Uri> blockLists))
                    {
                        blockLists = new List<Uri>(2);
                        blockListZone.Add(domain, blockLists);
                    }

                    if (!blockLists.Contains(blockListQueue.Key))
                        blockLists.Add(blockListQueue.Key);
                }
            }

            //set new allowed and blocked zones
            lock (_saveLock)
            {
                if (!ReferenceEquals(sources, _blockListUrls))
                    return;
                _allowListZone = allowListZone;
                _blockListZone = blockListZone;
            }

            _dnsServer.LogManager.Write("DNS Server block list zone was loaded successfully.");
        }

        #endregion

        #region public

        public bool IsAllowed(DnsDatagram request)
        {
            if (_allowListZone.Count < 1)
                return false;

            return IsZoneAllowed(request.Question[0].Name);
        }

        public DnsDatagram Query(DnsDatagram request)
        {
            if (_blockListZone.Count < 1)
                return null;

            DnsQuestionRecord question = request.Question[0];

            List<Uri> blockLists = IsZoneBlocked(question.Name, out string blockedDomain);
            if (blockLists is null)
                return null; //zone not blocked

            //zone is blocked
            if (_dnsServer.AllowTxtBlockingReport && (question.Type == DnsResourceRecordType.TXT))
            {
                //return meta data
                DnsResourceRecord[] answer = new DnsResourceRecord[blockLists.Count];

                for (int i = 0; i < answer.Length; i++)
                    answer[i] = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, _dnsServer.BlockingAnswerTtl, new DnsTXTRecordData("source=block-list-zone; blockListUrl=" + GetSourceDisplayName(blockLists[i]) + "; domain=" + blockedDomain));

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer);
            }
            else
            {
                EDnsOption[] options = null;

                if (_dnsServer.AllowTxtBlockingReport && (request.EDNS is not null))
                {
                    options = new EDnsOption[blockLists.Count];

                    for (int i = 0; i < options.Length; i++)
                        options[i] = new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, "source=block-list-zone; blockListUrl=" + GetSourceDisplayName(blockLists[i]) + "; domain=" + blockedDomain));
                }

                IReadOnlyCollection<DnsARecordData> aRecords;
                IReadOnlyCollection<DnsAAAARecordData> aaaaRecords;

                switch (_dnsServer.BlockingType)
                {
                    case DnsServerBlockingType.AnyAddress:
                        aRecords = _aRecords;
                        aaaaRecords = _aaaaRecords;
                        break;

                    case DnsServerBlockingType.CustomAddress:
                        aRecords = _dnsServer.CustomBlockingARecords;
                        aaaaRecords = _dnsServer.CustomBlockingAAAARecords;
                        break;

                    case DnsServerBlockingType.NxDomain:
                        string parentDomain = AuthZoneManager.GetParentZone(blockedDomain);
                        if (parentDomain is null)
                            parentDomain = string.Empty;

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, !_dnsServer.AllowTxtBlockingReport, false, false, DnsResponseCode.NxDomain, request.Question, null, [new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)], null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options);

                    default:
                        throw new InvalidOperationException();
                }

                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                switch (question.Type)
                {
                    case DnsResourceRecordType.A:
                        {
                            if (aRecords.Count > 0)
                            {
                                DnsResourceRecord[] rrList = new DnsResourceRecord[aRecords.Count];
                                int i = 0;

                                foreach (DnsARecordData record in aRecords)
                                    rrList[i++] = new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, _dnsServer.BlockingAnswerTtl, record);

                                answer = rrList;
                            }
                            else
                            {
                                authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)];
                            }
                        }
                        break;

                    case DnsResourceRecordType.AAAA:
                        {
                            if (aaaaRecords.Count > 0)
                            {
                                DnsResourceRecord[] rrList = new DnsResourceRecord[aaaaRecords.Count];
                                int i = 0;

                                foreach (DnsAAAARecordData record in aaaaRecords)
                                    rrList[i++] = new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, _dnsServer.BlockingAnswerTtl, record);

                                answer = rrList;
                            }
                            else
                            {
                                authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)];
                            }
                        }
                        break;

                    case DnsResourceRecordType.NS:
                        if (question.Name.Equals(blockedDomain, StringComparison.OrdinalIgnoreCase))
                            answer = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.NS, question.Class, _dnsServer.BlockingAnswerTtl, _nsRecord)];
                        else
                            authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)];

                        break;

                    case DnsResourceRecordType.SOA:
                        answer = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)];
                        break;

                    default:
                        authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)];
                        break;
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, !_dnsServer.AllowTxtBlockingReport, false, false, DnsResponseCode.NoError, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options);
            }
        }

        public void ForceUpdateBlockLists()
        {
            ForceUpdateBlockLists(false);
        }

        public void TemporaryDisableBlocking(int minutes, IPEndPoint userEP, string username)
        {
            Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
            if (temporaryDisableBlockingTimer is not null)
                temporaryDisableBlockingTimer.Dispose();

            Timer newTemporaryDisableBlockingTimer = new Timer(delegate (object state)
            {
                try
                {
                    _dnsServer.EnableBlocking = true;
                    _dnsServer.LogManager.Write(userEP, "[" + username + "] Blocking was enabled after " + minutes + " minute(s) being temporarily disabled.");
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            });

            Timer originalTimer = Interlocked.CompareExchange(ref _temporaryDisableBlockingTimer, newTemporaryDisableBlockingTimer, temporaryDisableBlockingTimer);
            if (ReferenceEquals(originalTimer, temporaryDisableBlockingTimer))
            {
                newTemporaryDisableBlockingTimer.Change(minutes * 60 * 1000, Timeout.Infinite);
                _dnsServer.EnableBlocking = false;
                _temporaryDisableBlockingTill = DateTime.UtcNow.AddMinutes(minutes);

                _dnsServer.LogManager.Write(userEP, "[" + username + "] Blocking was temporarily disabled for " + minutes + " minute(s).");
            }
            else
            {
                newTemporaryDisableBlockingTimer.Dispose();
            }
        }

        public void StopTemporaryDisableBlockingTimer()
        {
            Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
            if (temporaryDisableBlockingTimer is not null)
                temporaryDisableBlockingTimer.Dispose();
        }

        #endregion

        #region properties

        public IReadOnlyList<string> BlockListUrls
        {
            get { return _blockListUrls; }
            set
            {
                lock (_saveLock)
                    ApplyBlockListUrls(NormalizeBlockListUrls(value));
            }
        }

        internal static IReadOnlyList<string> NormalizeBlockListUrls(IReadOnlyList<string> urls)
        {
            if (urls is null)
                return [];

            if (urls.Count > 255)
                throw new ArgumentException("Cannot configure more than 255 block list URLs.", nameof(BlockListUrls));

            List<string> uniqueList = new List<string>(urls.Count);
            int commentCount = 0;

            foreach (string url in urls)
            {
                if (Encoding.UTF8.GetByteCount(url) > 255)
                    throw new ArgumentException("Block list URL (or comment line) length cannot exceed 255 UTF-8 bytes.", nameof(BlockListUrls));

                if (url.TrimStart().StartsWith('#'))
                {
                    uniqueList.Add(url);
                    commentCount++;
                    continue;
                }

                try
                {
                    _ = new Uri(url.StartsWith('!') ? url.Substring(1) : url);
                }
                catch (UriFormatException ex)
                {
                    throw new ArgumentException(ex.Message, nameof(BlockListUrls));
                }

                if (!uniqueList.Contains(url))
                    uniqueList.Add(url);
            }

            return uniqueList.Count == commentCount ? [] : uniqueList;
        }

        public int BlockListUpdateIntervalHours
        {
            get { return _blockListUpdateIntervalHours; }
            set
            {
                if ((value < 0) || (value > 168))
                    throw new ArgumentOutOfRangeException(nameof(BlockListUpdateIntervalHours), "Value must be between 1 hour and 168 hours (7 days) or 0 to disable automatic update.");

                _blockListUpdateIntervalHours = value;

                ApplyBlockListUpdateInterval();
            }
        }

        public bool BlockListUpdateEnabled
        { get { return _blockListUpdateTimer is not null; } }

        public DateTime BlockListLastUpdatedOn
        {
            get { return _blockListLastUpdatedOn; }
            internal set
            {
                _blockListLastUpdatedOn = value;
            }
        }

        public DateTime TemporaryDisableBlockingTill
        { get { return _temporaryDisableBlockingTill; } }

        public int TotalZonesAllowed
        { get { return _allowListZone.Count; } }

        public int TotalZonesBlocked
        { get { return _blockListZone.Count; } }

        #endregion
    }
}
