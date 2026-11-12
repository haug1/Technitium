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

using DnsServerCore.Auth;
using DnsServerCore.Configuration;
using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Trees;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class AuthZoneManager : IDisposable
    {
        #region events

        public event EventHandler<SecondaryCatalogEventArgs> SecondaryCatalogZoneAdded;
        public event EventHandler<SecondaryCatalogEventArgs> SecondaryCatalogZoneRemoved;

        #endregion

        #region variables

        readonly DnsServer _dnsServer;

        string _serverDomain;
        uint _defaultRecordTtl = 3600;
        uint _defaultNsRecordTtl = 14400;
        uint _defaultSoaRecordTtl = 900;
        bool _useSoaSerialDateScheme;
        uint _minSoaRefresh = 300;
        uint _minSoaRetry = 300;

        readonly AuthZoneTree _root = new AuthZoneTree();

        readonly List<AuthZoneInfo> _zoneIndex = new List<AuthZoneInfo>(10);
        readonly List<AuthZoneInfo> _catalogZoneIndex = new List<AuthZoneInfo>(2);
        readonly ReaderWriterLockSlim _zoneIndexLock = new ReaderWriterLockSlim();

        internal const string ManifestOwnershipFile = "zone-ownership.config";
        private SortedDictionary<string, string[]> _manifestOwnedZones = new(StringComparer.Ordinal);
        internal IReadOnlyDictionary<string, string[]> ManifestOwnedZones => _manifestOwnedZones;

        readonly Lock _saveLock = new Lock();
        readonly Dictionary<string, object> _pendingSaveZones = new Dictionary<string, object>();
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        volatile int _updateServerDomainId;

        #endregion

        #region constructor

        public AuthZoneManager(DnsServer dnsServer) : this(dnsServer, loadManifestOwnership: false)
        {
        }

        internal AuthZoneManager(DnsServer dnsServer, bool loadManifestOwnership)
        {
            _dnsServer = dnsServer;

            string ownershipFile = Path.Combine(_dnsServer.ConfigFolder, ManifestOwnershipFile);
            if (loadManifestOwnership && File.Exists(ownershipFile))
            {
                using JsonDocument ownership = JsonDocument.Parse(File.ReadAllBytes(ownershipFile));
                foreach (JsonProperty zone in ownership.RootElement.EnumerateObject())
                {
                    _manifestOwnedZones.Add(zone.Name, zone.Value.ValueKind switch
                    {
                        JsonValueKind.True => ["enabled"],
                        JsonValueKind.False => [],
                        _ => zone.Value.Deserialize<string[]>() ?? throw new InvalidDataException("Invalid zone manifest ownership file.")
                    });
                }
            }

            _serverDomain = _dnsServer.ServerDomain;

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    List<string> failedZones = new List<string>();

                    foreach (KeyValuePair<string, object> pendingSaveZone in _pendingSaveZones)
                    {
                        try
                        {
                            SaveZoneFileInternal(pendingSaveZone.Key);
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.LogManager.Write(ex);

                            failedZones.Add(pendingSaveZone.Key);
                        }
                    }

                    _pendingSaveZones.Clear();

                    foreach (string zoneName in failedZones)
                        _pendingSaveZones.TryAdd(zoneName, null);

                    if (_pendingSaveZones.Count > 0)
                        _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                }
            });
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
                lock (_saveLock)
                {
                    _saveTimer?.Dispose();

                    try
                    {
                        foreach (KeyValuePair<string, object> pendingSaveZone in _pendingSaveZones)
                        {
                            try
                            {
                                SaveZoneFileInternal(pendingSaveZone.Key);
                            }
                            catch (Exception ex)
                            {
                                _dnsServer.LogManager.Write(ex);
                            }
                        }
                    }
                    finally
                    {
                        _pendingSaveZones.Clear();
                    }
                }

                foreach (AuthZoneNode zoneNode in _root)
                    zoneNode.Dispose();

                _zoneIndexLock.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region zone file serialization and loading

        public void LoadAllZoneFiles()
        {
            string zonesFolder = Path.Combine(_dnsServer.ConfigFolder, "zones");
            if (!Directory.Exists(zonesFolder))
                Directory.CreateDirectory(zonesFolder);

            //move zone files to new folder
            {
                string[] oldZoneFiles = Directory.GetFiles(_dnsServer.ConfigFolder, "*.zone", SearchOption.TopDirectoryOnly);

                foreach (string oldZoneFile in oldZoneFiles)
                    File.Move(oldZoneFile, Path.Combine(zonesFolder, Path.GetFileName(oldZoneFile)));
            }

            //remove old internal zones files
            {
                string[] oldZoneFiles = ["localhost.zone", "1.0.0.127.in-addr.arpa.zone", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.zone"];

                foreach (string oldZoneFile in oldZoneFiles)
                {
                    string filePath = Path.Combine(zonesFolder, oldZoneFile);

                    if (File.Exists(filePath))
                    {
                        try
                        {
                            File.Delete(filePath);
                        }
                        catch
                        { }
                    }
                }
            }

            //flush existing zones
            Flush();

            //load zone files
            _zoneIndexLock.EnterWriteLock();
            try
            {
                string[] zoneFiles = Directory.GetFiles(zonesFolder, "*.zone", SearchOption.TopDirectoryOnly);

                foreach (string zoneFile in zoneFiles)
                {
                    try
                    {
                        using (FileStream fS = new FileStream(zoneFile, FileMode.Open, FileAccess.Read))
                        {
                            AuthZoneInfo zoneInfo = LoadZoneFrom(fS, File.GetLastWriteTimeUtc(fS.SafeFileHandle));
                            _zoneIndex.Add(zoneInfo);

                            if (zoneInfo.Type == AuthZoneType.Catalog)
                                _catalogZoneIndex.Add(zoneInfo);
                        }

                        _dnsServer.LogManager.Write("DNS Server successfully loaded zone file: " + zoneFile);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write("DNS Server failed to load zone file: " + zoneFile, ex);
                    }
                }

                _zoneIndex.Sort();
                _catalogZoneIndex.Sort();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        private void SaveZoneFileInternal(string zoneName, bool? disabled = null, ConfigurationZonePolicies.Changes policies = default, ConfigurationZonePrimary.Changes primary = default, string catalog = null)
        {
            zoneName = zoneName.ToLowerInvariant();

            string tmpZoneFile = Path.Combine(_dnsServer.ConfigFolder, "zones", zoneName + ".tmp");
            string zoneFile = Path.Combine(_dnsServer.ConfigFolder, "zones", zoneName + ".zone");

            using (FileStream fS = new FileStream(tmpZoneFile, FileMode.Create, FileAccess.Write))
            {
                WriteZoneTo(zoneName, fS, disabled, policies, primary, catalog);

                if (fS.Position == 0)
                {
                    //zone was not found
                    fS.Dispose();

                    try
                    {
                        File.Delete(tmpZoneFile);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }

                    return;
                }

                if (disabled.HasValue || policies != default || primary != default || catalog is not null)
                    fS.Flush(flushToDisk: true);
            }

            File.Move(tmpZoneFile, zoneFile, true);

            _dnsServer.LogManager.Write("Saved zone file for domain: " + (zoneName == "" ? "<root>" : zoneName));
        }

        public void SaveZoneFile(string zoneName)
        {
            zoneName = zoneName.ToLowerInvariant();

            lock (_saveLock)
            {
                if (!_pendingSaveZones.TryAdd(zoneName, null))
                    return;

                if (_pendingSaveZones.Count == 1)
                    _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        internal void FlushZoneSaves(params string[] names)
        {
            lock (_saveLock)
            {
                foreach (string name in names)
                {
                    SaveZoneFileInternal(name);
                    _pendingSaveZones.Remove(name);
                }
            }
        }

        internal void ClearClusterBootstrapSaves(params string[] names)
        {
            lock (_saveLock)
            {
                foreach (string name in names)
                    _pendingSaveZones.Remove(name);
            }
        }

        private static uint GetMinExpiryTtlFor(IReadOnlyList<DnsResourceRecord> records)
        {
            uint minExpiryTtl = 0u;

            foreach (DnsResourceRecord record in records)
            {
                GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                if (recordInfo.ExpiryTtl > 0u)
                {
                    uint pendingExpiryTtl = recordInfo.GetPendingExpiryTtl();
                    if (pendingExpiryTtl == 0)
                    {
                        //expired record found; set 10 sec ttl for timer to delete it
                        minExpiryTtl = 10;
                    }
                    else
                    {
                        if (minExpiryTtl == 0u)
                            minExpiryTtl = pendingExpiryTtl;
                        else
                            minExpiryTtl = Math.Min(minExpiryTtl, pendingExpiryTtl);
                    }
                }
            }

            return minExpiryTtl;
        }

        private void LoadAndInitZone(AuthZoneInfo zoneInfo, IReadOnlyList<DnsResourceRecord> records)
        {
            ApexZone apexZone = zoneInfo.ApexZone;

            //load records
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> zoneEntry in DnsResourceRecord.GroupRecords(records))
            {
                if (apexZone.Name.Equals(zoneEntry.Key, StringComparison.OrdinalIgnoreCase))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                        apexZone.LoadRecords(rrsetEntry.Key, rrsetEntry.Value);
                }
                else
                {
                    ValidateIfDomainBelongsToZone(apexZone.Name, zoneEntry.Key);

                    AuthZone authZone = GetOrAddSubDomainZone(apexZone.Name, zoneEntry.Key);

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                        authZone.LoadRecords(rrsetEntry.Key, rrsetEntry.Value);

                    if (authZone is SubDomainZone subDomainZone)
                        subDomainZone.AutoUpdateState();
                }
            }

            //update dnssec status
            apexZone.UpdateDnssecStatus();

            //init zone
            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    {
                        apexZone.TriggerNotify();

                        uint minExpiryTtl = GetMinExpiryTtlFor(records);
                        if (minExpiryTtl > 0u)
                            apexZone.StartRecordExpiryTimer(minExpiryTtl);
                    }
                    break;

                case AuthZoneType.Secondary:
                    {
                        SecondaryZone secondary = apexZone as SecondaryZone;

                        DnsResourceRecord soaRecord = secondary.GetRecords(DnsResourceRecordType.SOA)[0];
                        SOARecordInfo soaInfo = soaRecord.GetAuthSOARecordInfo();
                        if (soaInfo.Version == 1)
                        {
                            secondary.PrimaryNameServerAddresses = soaInfo.PrimaryNameServers;
                            secondary.PrimaryZoneTransferProtocol = soaInfo.ZoneTransferProtocol;
                            secondary.PrimaryZoneTransferTsigKeyName = soaInfo.TsigKeyName;
                        }

                        secondary.TriggerNotify();
                        secondary.TriggerRefresh();
                    }
                    break;

                case AuthZoneType.Stub:
                    {
                        StubZone stub = apexZone as StubZone;

                        DnsResourceRecord soaRecord = stub.GetRecords(DnsResourceRecordType.SOA)[0];
                        SOARecordInfo soaInfo = soaRecord.GetAuthSOARecordInfo();
                        if (soaInfo.Version == 1)
                            stub.PrimaryNameServerAddresses = soaInfo.PrimaryNameServers;

                        stub.TriggerRefresh();
                    }
                    break;

                case AuthZoneType.Forwarder:
                    {
                        IReadOnlyList<DnsResourceRecord> soaRecords = apexZone.GetRecords(DnsResourceRecordType.SOA);
                        if (soaRecords.Count == 0)
                            (apexZone as ForwarderZone).InitZone();

                        apexZone.TriggerNotify();

                        uint minExpiryTtl = GetMinExpiryTtlFor(records);
                        if (minExpiryTtl > 0u)
                            apexZone.StartRecordExpiryTimer(minExpiryTtl);
                    }
                    break;

                case AuthZoneType.SecondaryForwarder:
                    {
                        (apexZone as SecondaryZone).TriggerRefresh();
                    }
                    break;

                case AuthZoneType.Catalog:
                    {
                        (apexZone as CatalogZone).BuildMembersIndex();
                        apexZone.TriggerNotify();

                        uint minExpiryTtl = GetMinExpiryTtlFor(records);
                        if (minExpiryTtl > 0u)
                            apexZone.StartRecordExpiryTimer(minExpiryTtl);
                    }
                    break;

                case AuthZoneType.SecondaryCatalog:
                    {
                        (apexZone as SecondaryZone).TriggerRefresh();
                        (apexZone as SecondaryCatalogZone).BuildMembersIndex();
                    }
                    break;
            }
        }

        public AuthZoneInfo LoadZoneFrom(Stream s, DateTime lastModified)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) != "DZ")
                throw new InvalidDataException("DnsServer zone file format is invalid.");

            BinaryReader bR = new BinaryReader(s);

            switch (bR.ReadByte())
            {
                case 2:
                    {
                        DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                        if (records.Length == 0)
                            throw new InvalidDataException("Zone does not contain SOA record.");

                        DnsResourceRecord soaRecord = null;

                        for (int i = 0; i < records.Length; i++)
                        {
                            records[i] = new DnsResourceRecord(s);

                            if (records[i].Type == DnsResourceRecordType.SOA)
                                soaRecord = records[i];
                        }

                        if (soaRecord == null)
                            throw new InvalidDataException("Zone does not contain SOA record.");

                        //make zone info
                        AuthZoneType zoneType;
                        if (_dnsServer.ServerDomain.Equals((soaRecord.RDATA as DnsSOARecordData).PrimaryNameServer, StringComparison.OrdinalIgnoreCase))
                            zoneType = AuthZoneType.Primary;
                        else
                            zoneType = AuthZoneType.Stub;

                        AuthZoneInfo zoneInfo = new AuthZoneInfo(records[0].Name, zoneType, false);

                        //create zone
                        ApexZone apexZone = CreateEmptyApexZone(zoneInfo);
                        zoneInfo = new AuthZoneInfo(apexZone);

                        try
                        {
                            //load and init zone
                            LoadAndInitZone(zoneInfo, records);
                        }
                        catch
                        {
                            DeleteZone(zoneInfo);
                            throw;
                        }

                        return zoneInfo;
                    }

                case 3:
                    {
                        bool zoneDisabled = bR.ReadBoolean();
                        DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                        if (records.Length == 0)
                            throw new InvalidDataException("Zone does not contain SOA record.");

                        DnsResourceRecord soaRecord = null;

                        for (int i = 0; i < records.Length; i++)
                        {
                            records[i] = new DnsResourceRecord(s);
                            records[i].Tag = AuthRecordInfo.ReadGenericRecordInfoFrom(bR, records[i].Type);

                            if (records[i].Type == DnsResourceRecordType.SOA)
                                soaRecord = records[i];
                        }

                        if (soaRecord == null)
                            throw new InvalidDataException("Zone does not contain SOA record.");

                        //make zone info
                        AuthZoneType zoneType;
                        if (_dnsServer.ServerDomain.Equals((soaRecord.RDATA as DnsSOARecordData).PrimaryNameServer, StringComparison.OrdinalIgnoreCase))
                            zoneType = AuthZoneType.Primary;
                        else
                            zoneType = AuthZoneType.Stub;

                        AuthZoneInfo zoneInfo = new AuthZoneInfo(records[0].Name, zoneType, zoneDisabled);

                        //create zone
                        ApexZone apexZone = CreateEmptyApexZone(zoneInfo);
                        zoneInfo = new AuthZoneInfo(apexZone);

                        try
                        {
                            //load and init zone
                            LoadAndInitZone(zoneInfo, records);
                        }
                        catch
                        {
                            DeleteZone(zoneInfo);
                            throw;
                        }

                        return zoneInfo;
                    }

                case 4:
                    {
                        //read zone info
                        AuthZoneInfo zoneInfo = new AuthZoneInfo(bR, lastModified);

                        //create zone
                        ApexZone apexZone = CreateEmptyApexZone(zoneInfo);
                        zoneInfo = new AuthZoneInfo(apexZone);

                        try
                        {
                            //read all zone records
                            DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                            if (records.Length < 1)
                                throw new InvalidDataException("Failed to load DNS zone file: the zone file does not contain any records.");

                            for (int i = 0; i < records.Length; i++)
                            {
                                records[i] = new DnsResourceRecord(s);
                                records[i].Tag = AuthRecordInfo.ReadGenericRecordInfoFrom(bR, records[i].Type);
                            }

                            //load and init zone
                            LoadAndInitZone(zoneInfo, records);
                        }
                        catch
                        {
                            DeleteZone(zoneInfo);
                            throw;
                        }

                        return zoneInfo;
                    }

                default:
                    throw new InvalidDataException("DNS Zone file version not supported.");
            }
        }

        public void WriteZoneTo(string zoneName, Stream s) => WriteZoneTo(zoneName, s, disabled: null);

        private void WriteZoneTo(string zoneName, Stream s, bool? disabled, ConfigurationZonePolicies.Changes policies = default, ConfigurationZonePrimary.Changes primary = default, string catalog = null)
        {
            AuthZoneInfo zoneInfo = GetAuthZoneInfo(zoneName, true);
            if (zoneInfo is null)
                return;

            var records = new List<DnsResourceRecord>();
            ListAllZoneRecords(zoneInfo.Name, records);
            WriteZoneTo(zoneInfo, records, s, disabled, policies, primary, catalog);
        }

        private static void WriteZoneTo(AuthZoneInfo zoneInfo, List<DnsResourceRecord> records, Stream s, bool? disabled, ConfigurationZonePolicies.Changes policies = default, ConfigurationZonePrimary.Changes primary = default, string catalog = null)
        {
            //serialize zone
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("DZ")); //format
            bW.Write((byte)4); //version

            //write zone info
            zoneInfo.WriteTo(bW, disabled, policies, primary, catalog);

            bW.Write(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                record.WriteTo(s);
                record.GetAuthGenericRecordInfo().WriteTo(bW);
            }
        }

        #endregion

        #region internal

        internal static string GetManifestZonePath(string name) =>
            ConfigurationPlan.AppendPath("/zones", name.Length == 0 ? "." : name);

        internal void CheckManifestZoneMembership(string name)
        {
            name = name.ToLowerInvariant();
            if (_manifestOwnedZones.ContainsKey(name))
                throw new DnsWebServiceException($"{GetManifestZonePath(name)}: Zone membership is managed by the configuration manifest.");
            if (GetAuthZoneInfo(name)?.Type == AuthZoneType.Catalog)
            {
                foreach (AuthZoneInfo member in _zoneIndexLock.IsWriteLockHeld ? _zoneIndex : GetAllZones())
                {
                    if (member.CatalogZoneName == name && OwnsManifestZoneField(member.Name, "catalog/name"))
                        throw new DnsWebServiceException($"{GetManifestZonePath(member.Name)}/catalog/name: Catalog membership is managed by the configuration manifest.");
                }
            }
        }

        internal void CheckManifestZoneEnabled(AuthZoneInfo zone, bool disabled)
        {
            if (zone.Disabled != disabled && OwnsManifestZoneField(zone.Name, "enabled"))
                throw new DnsWebServiceException($"{GetManifestZonePath(zone.Name)}/enabled: Zone enabled state is managed by the configuration manifest.");
        }

        internal static IEnumerable<ZipArchiveEntry> GetZoneBackupEntries(ZipArchive archive) =>
            archive.Entries.Where(entry => entry.FullName == "zones/" + entry.Name &&
                entry.Name.EndsWith(".zone", OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
                entry.Name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0);

        internal void CheckManifestZoneRestore(ZipArchive archive, bool deleteExistingFiles)
        {
            var incoming = new HashSet<string>(StringComparer.Ordinal);
            foreach (ZipArchiveEntry entry in GetZoneBackupEntries(archive))
            {
                string name = Path.GetFileNameWithoutExtension(entry.Name).ToLowerInvariant();
                string path = GetManifestZonePath(name);
                if (!incoming.Add(name))
                    throw new InvalidDataException($"{path}: The backup contains duplicate zone files.");
                if (_manifestOwnedZones.ContainsKey(name) && !entry.Name.Equals(name + ".zone",
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                    throw new InvalidDataException($"{path}: The managed zone backup filename must use the canonical zone name.");

                using Stream stream = entry.Open();
                CheckZoneFile(stream, name);
            }

            foreach (string name in _manifestOwnedZones.Keys)
            {
                if (incoming.Contains(name) || GetAuthZoneInfo(name) is null)
                    continue;

                string file = Path.Combine(_dnsServer.ConfigFolder, "zones", name + ".zone");
                if (deleteExistingFiles || !File.Exists(file))
                    CheckManifestZoneMembership(name);

                using Stream stream = File.OpenRead(file);
                CheckZoneFile(stream, name);
            }

            void CheckZoneFile(Stream stream, string name)
            {
                string path = GetManifestZonePath(name);
                var reader = new BinaryReader(stream);
                if (reader.ReadByte() != 'D' || reader.ReadByte() != 'Z')
                    throw new InvalidDataException($"{path}: Invalid zone backup file.");
                byte version = reader.ReadByte();
                bool owned = _manifestOwnedZones.TryGetValue(name, out string[] fields);
                if (version is 2 or 3)
                {
                    if (owned)
                        throw new InvalidDataException($"{path}: Managed settings cannot be verified in this legacy zone backup format.");
                    if (version == 3)
                        reader.ReadBoolean();
                    int legacyCount = reader.ReadInt32();
                    using var legacyRecords = new MemoryStream();
                    stream.CopyTo(legacyRecords);
                    legacyRecords.Position = 0;
                    if (legacyCount < 1 || !new DnsResourceRecord(legacyRecords).Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException($"{path}: The zone backup filename does not match its content.");
                    return;
                }
                if (version != 4)
                    throw new InvalidDataException($"{path}: Unsupported zone backup format.");

                if (!owned)
                {
                    reader.ReadByte(); // Zone information format version.
                    if (!stream.ReadShortString().Equals(name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException($"{path}: The zone backup filename does not match its content.");
                    return;
                }

                using var records = new MemoryStream();
                stream.CopyTo(records);
                records.Position = 0;
                var recordReader = new BinaryReader(records);
                var candidate = new AuthZoneInfo(recordReader, DateTime.UnixEpoch);
                if (!candidate.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"{path}: The zone backup filename does not match its content.");

                AuthZoneInfo current = GetAuthZoneInfo(name);
                if (current is null || candidate.Type != current.Type || candidate.CatalogZoneName != current.CatalogZoneName)
                    CheckManifestZoneMembership(name);

                CheckManifestZoneEnabled(current, candidate.Disabled);
                ConfigurationZonePolicies.CheckRestoreOwnership(path, fields, current, candidate);
                ConfigurationZonePrimary.CheckRestoreOwnership(path, fields, current, candidate);
                bool ownsRecords = fields.Contains("records", StringComparer.Ordinal);
                var candidateRecords = new List<DnsResourceRecord>();
                bool hasSoa = false;
                int count = recordReader.ReadInt32();
                for (int index = 0; index < count; index++)
                {
                    var record = new DnsResourceRecord(records);
                    record.Tag = AuthRecordInfo.ReadGenericRecordInfoFrom(recordReader, record.Type);
                    if (ownsRecords)
                        candidateRecords.Add(record);
                    ValidateIfDomainBelongsToZone(name, record.Name);
                    hasSoa |= record.Type == DnsResourceRecordType.SOA && record.Name.Equals(name, StringComparison.OrdinalIgnoreCase);
                }
                if (!hasSoa)
                    throw new InvalidDataException($"{path}: The zone backup is missing the apex SOA record.");
                if (ownsRecords)
                {
                    var currentRecords = new List<DnsResourceRecord>();
                    ListAllZoneRecords(name, currentRecords);
                    var expected = OperatorRecordKeys(currentRecords);
                    if (!expected.SetEquals(OperatorRecordKeys(candidateRecords)))
                        CheckManifestZoneRecords(name);
                }

                HashSet<(string Owner, DnsResourceRecordType Type, DnsClass Class, DnsResourceRecordData Data,
                    uint Ttl, bool Disabled, string Comments, uint ExpiryTtl, string Glue)> OperatorRecordKeys(List<DnsResourceRecord> source) =>
                    source.Where(record => !ConfigurationPlan.IsLeaseRecord(record) &&
                        !ConfigurationPlan.IsGeneratedRecord(name, _dnsServer.ServerDomain, record.Name, record.Type, record.RDATA))
                        .Select(record =>
                        {
                            var metadata = record.Tag as GenericRecordInfo;
                            return (record.Name.ToLowerInvariant(), record.Type, record.Class, record.RDATA,
                                record.OriginalTtlValue, metadata?.Disabled ?? false, metadata?.Comments ?? string.Empty, metadata?.ExpiryTtl ?? 0u,
                                string.Join('|', (metadata as NSRecordInfo)?.GlueRecords?.Select(glue => glue.ToString()) ?? []));
                        }).ToHashSet();

            }
        }

        internal void CheckManifestZoneRecords(string name)
        {
            if (OwnsManifestZoneField(name, "records"))
                throw new DnsWebServiceException($"{GetManifestZonePath(name)}/records: Zone records are managed by the configuration manifest.");
        }

        internal bool OwnsManifestZoneField(string name, string field) =>
            _manifestOwnedZones.TryGetValue(name, out string[] fields) && fields.Contains(field, StringComparer.Ordinal);

        internal string PrepareManifestCatalogMembership(JsonElement zones, JsonElement declaration, AuthZoneInfo member, AuthZoneType type, string path)
        {
            if (!declaration.TryGetProperty("catalog", out JsonElement catalog))
            {
                if (member?.CatalogZoneName is not null)
                    throw new InvalidDataException($"{path}: Declare catalog.name when applying a local catalog member.");
                return null;
            }
            if (type is not (AuthZoneType.Primary or AuthZoneType.Forwarder) ||
                !catalog.TryGetProperty("name", out JsonElement value) ||
                catalog.EnumerateObject().Any(field => field.Name is not ("name" or "overrideNotify" or "overrideQueryAccess" or "overrideZoneTransfer")))
                throw new InvalidDataException($"{path}/catalog: Specify a catalog name and optional overrides for a primary or forwarder zone.");
            string before = member?.CatalogZoneName;
            if (before is not null && GetAuthZoneInfo(before)?.Type != AuthZoneType.Catalog)
                throw new InvalidDataException($"{path}/catalog/name: This membership is maintained by a secondary catalog.");

            string after = value.ValueKind == JsonValueKind.Null ? "" :
                ConfigurationManifest.CanonicalDnsName(value.GetString(), path + "/catalog/name", allowRoot: false);
            if (before is not null && after.Length != 0 && before != after)
                throw new InvalidDataException($"{path}/catalog/name: Detach the zone before assigning another catalog.");
            if (after.Length != 0)
            {
                bool declaredCatalog = false;
                foreach (JsonProperty target in zones.EnumerateObject())
                {
                    if (ConfigurationManifest.CanonicalDnsName(target.Name, "/zones", allowRoot: true) != after)
                        continue;
                    if (target.Value.ValueKind == JsonValueKind.Null)
                        throw new InvalidDataException($"{path}/catalog/name: The target catalog is being removed.");
                    declaredCatalog = target.Value.TryGetProperty("type", out JsonElement declaredType) && declaredType.ValueEquals("Catalog");
                    break;
                }
                AuthZoneInfo targetZone = GetAuthZoneInfo(after);
                if (targetZone is null ? !declaredCatalog : targetZone.Type != AuthZoneType.Catalog)
                    throw new InvalidDataException($"{path}/catalog/name: The target must be a local primary catalog.");
            }
            return after;
        }

        internal (Action<Action> Commit, Action Write, string[] Files) PrepareManifestZoneAndAuthChanges(ConfigurationManifest manifest, AuthManager auth, User creator,
            IReadOnlyDictionary<string, TsigKey> tsigKeys, ConfigurationLdap.Settings ldap, IReadOnlyDictionary<string, ConfigurationUsers.Change> preparedUsers, ConfigurationStaticSessions.Candidate preparedSessions, ConfigurationSso.Settings sso, bool isClusterSecondary)
        {
            if (ldap is not null && ConfigurationLdap.Same(ldap, auth.GetManifestLdapSettings()))
                ldap = null;

            string[] ldapOwnership = ConfigurationLdap.GetOwnedFields(manifest);
            if (auth.LdapOwnershipFromPrimary ? isClusterSecondary : auth.ManagedLdapFields.SequenceEqual(ldapOwnership))
                ldapOwnership = null;

            string[] ssoOwnership = ConfigurationSso.GetOwnedFields(manifest);
            if (auth.SsoOwnershipFromPrimary ? isClusterSecondary : auth.ManagedSsoFields.SequenceEqual(ssoOwnership))
                ssoOwnership = null;

            var groupChanges = ConfigurationGroups.Prepare(manifest, auth);
            var userChanges = preparedUsers ?? ConfigurationUsers.Prepare(manifest, auth, groupChanges, actor: creator, ldap: ldap, sso: sso);
            var staticSessions = preparedSessions ?? ConfigurationStaticSessions.Prepare(manifest, auth, userChanges);
            ConfigurationStaticSessions.CheckAccountRemovals(auth, userChanges, staticSessions);
            if (staticSessions?.Changes.Count == 0)
                staticSessions = null;
            var grants = ConfigurationPermissions.Prepare(manifest, auth, groupChanges, userChanges, creator);
            string[] groupOwnership = ConfigurationGroups.GetOwnedPaths(manifest);
            if (auth.GroupOwnershipFromPrimary ? isClusterSecondary : auth.ManagedGroupPaths.SequenceEqual(groupOwnership))
                groupOwnership = null;
            string[] userOwnership = ConfigurationUsers.GetOwnedPaths(manifest);
            if (auth.UserOwnershipFromPrimary ? isClusterSecondary : auth.ManagedUserPaths.SequenceEqual(userOwnership))
                userOwnership = null;
            string[] permissionOwnership = ConfigurationPermissions.GetOwnedPaths(manifest);
            if (auth.PermissionOwnershipFromPrimary ? isClusterSecondary : auth.ManagedPermissionPaths.SequenceEqual(permissionOwnership))
                permissionOwnership = null;
            var changed = new List<(string Name, AuthZoneInfo Current, bool Remove, bool? Disabled, ConfigurationZonePolicies.Changes Policies, JsonElement Records, AuthZoneType Type, ConfigurationZonePrimary.Changes Primary)>();
            var membership = new Dictionary<string, bool>(StringComparer.Ordinal);
            var desiredCatalogs = new Dictionary<string, string>(StringComparer.Ordinal);
            var catalogEdits = new Dictionary<string, List<ManifestCatalogMemberEdit>>(StringComparer.Ordinal);
            var recordRevisions = new Dictionary<string, DateTime>(StringComparer.Ordinal);
            var ownedZones = new SortedDictionary<string, string[]>(StringComparer.Ordinal);
            string serverDomain = _dnsServer.ServerDomain;
            if (manifest.Settings.TryGetProperty("zones", out JsonElement zones))
            {
                foreach (JsonProperty declaration in zones.EnumerateObject())
                {
                    string path = ConfigurationPlan.AppendPath("/zones", declaration.Name);
                    string name = ConfigurationManifest.CanonicalDnsName(declaration.Name, path, allowRoot: true);
                    ownedZones.Add(name, GetOwnedZoneFields(name, path, declaration.Value));
                    AuthZoneInfo zone = GetAuthZoneInfo(name);
                    if (zone is not null && zone.Type is not (AuthZoneType.Primary or AuthZoneType.Forwarder or AuthZoneType.Catalog) &&
                        !ConfigurationZonePrimary.IsReplicated(zone.Type))
                        throw new InvalidDataException($"{path}: Apply requires a supported zone outside catalogs.");

                    if (declaration.Value.ValueKind == JsonValueKind.Null)
                    {
                        if (zone is not null)
                        {
                            if (zone.CatalogZoneName is not null)
                                throw new InvalidDataException($"{path}: Detach the zone before removing it.");
                            CheckManifestZoneRemoval(zone, path);
                            changed.Add((name, zone, true, null, default, default, zone.Type, default));
                            membership.Add(name, false);
                        }
                        continue;
                    }

                    AuthZoneType type = zone?.Type ?? AuthZoneType.Primary;
                    if (declaration.Value.TryGetProperty("type", out JsonElement declaredType))
                    {
                        AuthZoneType requested = Enum.Parse<AuthZoneType>(declaredType.GetString());
                        if (zone is not null && requested != type)
                            throw new InvalidDataException($"{path}/type: The declared type differs from the existing zone type.");
                        type = requested;
                    }

                    bool? disabled = declaration.Value.TryGetProperty("enabled", out JsonElement enabled)
                        ? enabled.ValueKind == JsonValueKind.False : null;
                    ConfigurationZonePolicies.ValidateKeyReferences(declaration.Value, name, path, zone, tsigKeys);
                    var primary = ConfigurationZonePrimary.Prepare(declaration.Value, type, zone, tsigKeys, path);
                    string catalog = PrepareManifestCatalogMembership(zones, declaration.Value, zone, type, path);
                    ConfigurationZonePolicies.Changes policies = ConfigurationZonePolicies.Prepare(declaration.Value, name, path, zone);
                    if (catalog is not null)
                    {
                        string before = zone?.CatalogZoneName ?? "";
                        if (catalog != before)
                            desiredCatalogs.Add(name, catalog);
                        bool wasActive = before.Length != 0 && !zone.Disabled;
                        bool isActive = catalog.Length != 0 && !(disabled ?? zone?.Disabled ?? false);
                        if (wasActive && (!isActive || catalog != before))
                            AddCatalogEdit(before, new(name, type, false, null, null, null));
                        if (isActive && (!wasActive || catalog != before || CatalogPoliciesChanged(policies)))
                        {
                            bool queryOverride = policies.OverrideCatalogQuery ?? zone?.OverrideCatalogQueryAccess ?? false;
                            bool transferOverride = type == AuthZoneType.Primary &&
                                (policies.OverrideCatalogTransfer ?? zone?.OverrideCatalogZoneTransfer ?? false);
                            var query = queryOverride ? ApexZone.GetQueryAccessACL(policies.QueryAccess ?? zone?.QueryAccess ?? AuthZoneQueryAccess.Allow,
                                policies.QueryAcl ?? zone?.QueryAccessNetworkACL) : null;
                            var transfer = transferOverride ? ApexZone.GetZoneTranferACL(policies.Transfer ?? zone?.ZoneTransfer ?? AuthZoneTransfer.AllowOnlyZoneNameServers,
                                policies.TransferAcl ?? zone?.ZoneTransferNetworkACL) : null;
                            AddCatalogEdit(catalog, new(name, type, !wasActive || catalog != before ? true : null, query, transfer,
                                transferOverride ? policies.TransferKeys ?? zone?.ZoneTransferTsigKeyNames : null));
                        }
                    }
                    bool editRecords = declaration.Value.TryGetProperty("records", out JsonElement records);
                    if (editRecords && zone is not null)
                    {
                        DateTime revision = zone.LastModified;
                        var currentRecords = new List<DnsResourceRecord>();
                        ListAllZoneRecords(name, currentRecords);
                        editRecords = ConfigurationPlan.PrepareZoneRecordEdits(manifest, name, name, serverDomain, records, currentRecords, OwnsManifestZoneField(name, "records"), type == AuthZoneType.Forwarder)
                            .Any(edit => edit.Kind.HasValue);
                        if (editRecords)
                            recordRevisions.Add(name, revision);
                    }
                    if (!editRecords)
                        records = default;
                    if (zone is null)
                    {
                        if (!declaration.Value.TryGetProperty("type", out _))
                            throw new InvalidDataException($"{path}/type: A zone type is required to create a zone.");
                        ValidateZoneName(name);
                        changed.Add((name, null, false, disabled ?? false, policies, records, type, primary));
                        membership.Add(name, true);
                    }
                    else if ((disabled.HasValue && zone.Disabled != disabled.Value) || policies != default || primary != default || editRecords || desiredCatalogs.ContainsKey(name))
                    {
                        changed.Add((name, zone, false, disabled, policies, records, type, primary));
                    }
                }
            }

            foreach (string catalog in catalogEdits.Keys)
            {
                if (changed.Any(entry => entry.Name == catalog))
                    continue;
                AuthZoneInfo existing = GetAuthZoneInfo(catalog);
                changed.Add((catalog, existing, false, null, default, default, AuthZoneType.Catalog, default));
            }

            void AddCatalogEdit(string catalog, ManifestCatalogMemberEdit edit)
            {
                if (!catalogEdits.TryGetValue(catalog, out var edits))
                    catalogEdits.Add(catalog, edits = []);
                edits.Add(edit);
            }

            ConfigurationGroups.ValidateRemovals(auth, groupChanges, ldap, userChanges, grants, sso,
                membership.Where(entry => !entry.Value).Select(entry => entry.Key).ToHashSet(StringComparer.Ordinal));
            bool ownershipChanged = _manifestOwnedZones.Count != ownedZones.Count || ownedZones.Any(entry =>
                !_manifestOwnedZones.TryGetValue(entry.Key, out string[] previous) || !previous.SequenceEqual(entry.Value));
            if (changed.Count == 0 && !ownershipChanged && ldap is null && ldapOwnership is null && groupChanges.Count == 0 && groupOwnership is null && userChanges.Count == 0 && userOwnership is null && grants.Count == 0 && permissionOwnership is null && staticSessions is null && sso is null && ssoOwnership is null)
                return (persist => persist(), null, []);

            var files = changed.Select(entry => Path.Combine("zones", entry.Name + ".zone")).ToList();
            if (membership.Count > 0 || ldap is not null || ldapOwnership is not null || groupChanges.Count > 0 || userChanges.Count > 0 || grants.Count > 0 || sso is not null || ssoOwnership is not null || groupOwnership is not null || userOwnership is not null || permissionOwnership is not null)
                files.Add("auth.config");
            if (ownershipChanged)
                files.Add(ManifestOwnershipFile);
            if (ldapOwnership is not null)
                files.Add(AuthManager.LdapOwnershipFile);
            if (ssoOwnership is not null)
                files.Add(AuthManager.SsoOwnershipFile);
            if (groupOwnership is not null)
                files.Add(AuthManager.GroupOwnershipFile);
            if (userOwnership is not null)
                files.Add(AuthManager.UserOwnershipFile);
            if (permissionOwnership is not null)
                files.Add(AuthManager.PermissionOwnershipFile);
            if (staticSessions is not null)
                files.Add(ConfigurationStaticSessions.FileName);
            var created = new Dictionary<string, ApexZone>(StringComparer.Ordinal);
            var stagedRecords = new Dictionary<string, (ApexZone Zone, List<DnsResourceRecord> Records,
                HashSet<(string Owner, DnsResourceRecordType Type)> ChangedSets)>(StringComparer.Ordinal);
            Action writeAuth = null;
            return (Commit, Write, files.ToArray());

            void Write()
            {
                foreach (var (name, current, remove, disabled, policies, records, type, primary) in changed)
                {
                    string path = Path.Combine(_dnsServer.ConfigFolder, "zones", name + ".zone");
                    if (remove)
                    {
                        File.Delete(path);
                    }
                    else if (current is not null && records.ValueKind == JsonValueKind.Undefined && type != AuthZoneType.Catalog)
                    {
                        SaveZoneFileInternal(name, disabled, policies, primary, desiredCatalogs.GetValueOrDefault(name));
                    }
                    else
                    {
                        ApexZone zone;
                        var allRecords = new List<DnsResourceRecord>();
                        if (current is null)
                        {
                            zone = type switch
                            {
                                AuthZoneType.Forwarder => new ForwarderZone(_dnsServer, name, initializeTimers: false),
                                AuthZoneType.Catalog => new CatalogZone(_dnsServer, name, initializeTimers: false),
                                AuthZoneType.Secondary => SecondaryZone.CreateUnrefreshed(_dnsServer, name),
                                AuthZoneType.SecondaryForwarder => new SecondaryForwarderZone(_dnsServer, name, primary.Servers,
                                    primary.Protocol ?? DnsTransportProtocol.Tcp, primary.TsigKey),
                                AuthZoneType.SecondaryCatalog => new SecondaryCatalogZone(_dnsServer, name, primary.Servers,
                                    primary.Protocol ?? DnsTransportProtocol.Tcp, primary.TsigKey),
                                AuthZoneType.Stub => StubZone.CreateUnrefreshed(_dnsServer, name),
                                _ => new PrimaryZone(_dnsServer, name, _useSoaSerialDateScheme, initializeExpiryTimer: false)
                            };
                            created.Add(name, zone);
                            zone.Disabled = disabled.Value;
                            var info = new AuthZoneInfo(zone);
                            if (type != AuthZoneType.Catalog)
                                policies.Apply(info);
                            primary.Apply(info);
                            zone.ListAllRecords(allRecords);
                        }
                        else
                        {
                            if (current.ApexZone is PrimaryZone { DnssecStatus: not AuthZoneDnssecStatus.Unsigned })
                                throw new InvalidDataException($"{ConfigurationPlan.AppendPath("/zones", name)}/records: Applying records requires an unsigned primary zone.");
                            AuthZoneInfo previous = GetAuthZoneInfo(name, loadHistory: true);
                            zone = type switch
                            {
                                AuthZoneType.Catalog => new CatalogZone(_dnsServer, previous, initializeTimers: false),
                                AuthZoneType.Forwarder => new ForwarderZone(_dnsServer, previous, initializeTimers: false),
                                _ => new PrimaryZone(_dnsServer, previous, initializeTimers: false)
                            };
                            stagedRecords.Add(name, (zone, allRecords, null));
                            ListAllZoneRecords(name, allRecords);
                        }

                        if (zone is CatalogZone catalog)
                        {
                            var changedSets = StageManifestCatalogRecords(catalog, allRecords, policies, current is null, catalogEdits.GetValueOrDefault(name));
                            stagedRecords[name] = (catalog, allRecords, changedSets);
                        }
                        else if (records.ValueKind != JsonValueKind.Undefined)
                        {
                            var changedSets = StageManifestRecords(manifest, zone, records, allRecords, membership, current is null ? _dnsServer.ServerDomain : serverDomain);
                            stagedRecords[name] = (zone, allRecords, changedSets);
                        }

                        string temporary = Path.ChangeExtension(path, ".tmp");
                        using (var output = new FileStream(temporary, FileMode.Create, FileAccess.Write))
                        {
                            WriteZoneTo(new AuthZoneInfo(zone, loadHistory: true), allRecords, output, disabled, policies,
                                catalog: desiredCatalogs.GetValueOrDefault(name));
                            output.Flush(flushToDisk: true);
                        }
                        File.Move(temporary, path, true);
                    }
                }

                writeAuth?.Invoke();
                if (ownershipChanged)
                    WriteManifestZoneOwnership(ownedZones);
            }

            void Commit(Action persist)
            {
                _zoneIndexLock.EnterWriteLock();
                try
                {
                    lock (_saveLock)
                    {
                        foreach (var (name, current, remove, _, _, _, _, _) in changed)
                        {
                            AuthZoneInfo live = GetAuthZoneInfo(name);
                            if (!ReferenceEquals(live?.ApexZone, current?.ApexZone) || live?.CatalogZoneName != current?.CatalogZoneName ||
                                (recordRevisions.TryGetValue(name, out DateTime revision) && live?.LastModified != revision))
                                throw new InvalidDataException($"{ConfigurationPlan.AppendPath("/zones", name)}: The zone changed during apply.");
                            if (remove)
                                CheckManifestZoneRemoval(current, GetManifestZonePath(name));
                        }

                        try
                        {
                            auth.ApplyManifestAuth(membership, creator, ldap, ldapOwnership, groupChanges, groupOwnership, userChanges, userOwnership, grants, permissionOwnership, staticSessions, sso, ssoOwnership, write =>
                            {
                                writeAuth = write;
                                persist();
                            });
                        }
                        catch
                        {
                            foreach (ApexZone zone in created.Values)
                                zone.Dispose();
                            foreach (var (name, stage) in stagedRecords)
                            {
                                if (!created.ContainsKey(name))
                                    stage.Zone.Dispose();
                            }
                            throw;
                        }

                        _manifestOwnedZones = ownedZones;
                        foreach (var (name, current, remove, disabled, policies, _, _, primary) in changed)
                        {
                            if (remove)
                            {
                                RemoveZoneFromIndex(current, deleteZoneFile: false);
                                _pendingSaveZones.Remove(name);
                            }
                            else if (current is not null)
                            {
                                if (current.ApexZone is CatalogZone primaryCatalog)
                                    primaryCatalog.ApplyManifestPolicies(policies, initialize: false, (_, _, _) => { });
                                else
                                {
                                    string oldCatalog = current.CatalogZoneName;
                                    if (oldCatalog is not null)
                                        current.ApexZone.CatalogZoneName = null;
                                    try
                                    {
                                        policies.Apply(current);
                                    }
                                    finally
                                    {
                                        if (oldCatalog is not null)
                                            current.ApexZone.CatalogZoneName = oldCatalog;
                                    }
                                }
                                primary.Apply(current);
                                if (desiredCatalogs.TryGetValue(name, out string catalog))
                                    current.ApexZone.CatalogZoneName = catalog.Length == 0 ? null : catalog;
                                if (disabled.HasValue)
                                {
                                    if (current.ApexZone.CatalogZoneName is not null)
                                        current.ApexZone.SetManifestCatalogMemberDisabled(disabled.Value);
                                    else
                                        current.Disabled = disabled.Value;
                                }
                            }
                            else
                            {
                                ApexZone zone = created[name];
                                if (zone is ForwarderZone forwarder)
                                    forwarder.InitializeManifestZoneExpiry();
                                else if (zone is PrimaryZone primaryZone)
                                    primaryZone.InitializeManifestZoneExpiry();
                                if (desiredCatalogs.TryGetValue(name, out string catalogName) && catalogName.Length != 0)
                                    zone.CatalogZoneName = catalogName;
                                if (!_root.TryAdd(zone))
                                    throw new InvalidOperationException("The zone already exists.");
                                var info = new AuthZoneInfo(zone);
                                _zoneIndex.Add(info);
                                if (zone is CatalogZone)
                                    _catalogZoneIndex.Add(info);
                                if (zone is SecondaryCatalogZone catalog)
                                {
                                    catalog.ZoneAdded += SecondaryCatalogZoneAdded;
                                    catalog.ZoneRemoved += SecondaryCatalogZoneRemoved;
                                }
                            }

                            if (stagedRecords.TryGetValue(name, out var stage))
                            {
                                ApexZone live = current?.ApexZone ?? stage.Zone;
                                List<DnsResourceRecord> recordsToPublish = current is null ? stage.Records : stage.Records
                                    .Where(record => stage.ChangedSets.Contains((record.Name.ToLowerInvariant(), record.Type))).ToList();
                                if (current is not null)
                                {
                                    var retained = recordsToPublish.Select(record => (record.Name.ToLowerInvariant(), record.Type)).ToHashSet();
                                    foreach (var (owner, type) in stage.ChangedSets)
                                    {
                                        if (!retained.Contains((owner, type)) && TryGetAuthZone(name, owner, out AuthZone node))
                                        {
                                            node.RemoveManifestRecordSet(type);
                                            if (node is SubDomainZone subdomain)
                                                subdomain.AutoUpdateState();
                                        }
                                    }
                                }
                                foreach (var owner in DnsResourceRecord.GroupRecords(recordsToPublish))
                                {
                                    AuthZone node = owner.Key.Equals(name, StringComparison.OrdinalIgnoreCase)
                                        ? live : GetOrAddSubDomainZone(name, owner.Key);
                                    foreach (var rrset in owner.Value)
                                        node.LoadRecords(rrset.Key, rrset.Value);
                                    if (node is SubDomainZone subdomain)
                                        subdomain.AutoUpdateState();
                                }
                                if (current is not null)
                                {
                                    live.ApplyManifestRecordHistory(stage.Zone);
                                    stage.Zone.Dispose();
                                }
                                uint minExpiryTtl = GetMinExpiryTtlFor(recordsToPublish);
                                if (minExpiryTtl > 0)
                                    live.StartRecordExpiryTimer(minExpiryTtl);
                                live.TriggerNotify();
                            }
                            if (!remove && (current is null || primary != default))
                            {
                                switch (current?.ApexZone ?? created.GetValueOrDefault(name))
                                {
                                    case SecondaryZone { Disabled: false } secondary:
                                        secondary.TriggerRefresh(0);
                                        break;
                                    case StubZone { Disabled: false } stub:
                                        stub.TriggerRefresh(0);
                                        break;
                                }
                            }

                            _dnsServer.CacheZoneManager.DeleteZone(name);
                        }
                        foreach (string catalog in catalogEdits.Keys)
                            ((CatalogZone)_root.GetApexZone(catalog)).RebuildManifestMembersIndex();
                        _zoneIndex.Sort();
                        _catalogZoneIndex.Sort();
                    }
                }
                finally
                {
                    _zoneIndexLock.ExitWriteLock();
                }
            }
        }

        internal void CheckManifestZoneRemoval(AuthZoneInfo zone, string path)
        {
            if (zone.ApexZone is CatalogZone &&
                (_zoneIndexLock.IsWriteLockHeld ? _zoneIndex : GetAllZones())
                    .Any(member => string.Equals(member.CatalogZoneName, zone.Name, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException($"{path}: Remove the catalog's memberships before manifest removal.");
            if (zone.ApexZone is SecondaryCatalogZone catalog &&
                (!zone.Disabled || catalog.GetAllMemberZoneNames().Count != 0))
                throw new InvalidDataException($"{path}: A secondary catalog must be disabled and have no members before manifest removal.");
        }

        private sealed record ManifestCatalogMemberEdit(string Member, AuthZoneType Type, bool? Add,
            IReadOnlyCollection<NetworkAccessControl> Query, IReadOnlyCollection<NetworkAccessControl> Transfer, IReadOnlySet<string> Keys);

        private static bool CatalogPoliciesChanged(ConfigurationZonePolicies.Changes policies) =>
            policies.OverrideCatalogQuery.HasValue || policies.OverrideCatalogTransfer.HasValue ||
            policies.QueryAccess.HasValue || policies.QueryAcl is not null ||
            policies.Transfer.HasValue || policies.TransferAcl is not null || policies.TransferKeys is not null;

        private static HashSet<(string Owner, DnsResourceRecordType Type)> StageManifestCatalogRecords(
            CatalogZone zone, List<DnsResourceRecord> records, ConfigurationZonePolicies.Changes policies, bool initialize,
            List<ManifestCatalogMemberEdit> membership)
        {
            var currentSoa = records.Single(record => record.Type == DnsResourceRecordType.SOA && record.Name == zone.Name);
            zone.LoadRecords(DnsResourceRecordType.SOA, [CopyRecord(currentSoa, currentSoa.OriginalTtlValue)]);
            var desired = new Dictionary<(string Owner, DnsResourceRecordType Type), IReadOnlyList<DnsResourceRecord>>();
            zone.ApplyManifestPolicies(policies, initialize, (name, type, rrset) => desired[(name, type)] = rrset);
            if (membership is not null)
            {
                string suffix = ".zones." + zone.Name;
                foreach (var edit in membership)
                {
                    var pointers = records.Where(record => record.Name.EndsWith(suffix, StringComparison.Ordinal) &&
                        record.RDATA is DnsPTRRecordData ptr && ptr.Domain.Equals(edit.Member, StringComparison.OrdinalIgnoreCase)).ToArray();
                    if (edit.Add == false)
                    {
                        foreach (DnsResourceRecord pointer in pointers)
                        {
                            foreach (DnsResourceRecord record in records.Where(record => record.Name == pointer.Name ||
                                record.Name.EndsWith("." + pointer.Name, StringComparison.Ordinal)))
                                desired[(record.Name, record.Type)] = [];
                        }
                        continue;
                    }

                    string domain;
                    if (edit.Add == true)
                    {
                        var created = zone.CreateMemberRecords(edit.Member, edit.Type);
                        domain = created.Domain;
                        foreach (DnsResourceRecord record in created.Records)
                            desired[(record.Name, record.Type)] = [record];
                    }
                    else
                    {
                        domain = pointers.SingleOrDefault()?.Name ??
                            throw new InvalidDataException($"{GetManifestZonePath(edit.Member)}/catalog: The catalog member record is missing.");
                    }
                    zone.StageManifestMemberPolicies(domain, edit.Query, edit.Transfer, edit.Keys,
                        (name, type, rrset) => desired[(name, type)] = rrset);
                }
            }
            var changed = new HashSet<(string Owner, DnsResourceRecordType Type)>();
            var deleted = new List<DnsResourceRecord>();
            var added = new List<DnsResourceRecord>();
            foreach (var (key, candidate) in desired)
            {
                var previous = records.Where(record => record.Name == key.Owner && record.Type == key.Type).ToArray();
                if (previous.SequenceEqual(candidate))
                    continue;
                changed.Add(key);
                deleted.AddRange(previous);
                added.AddRange(candidate);
            }
            if (changed.Count != 0)
            {
                records.RemoveAll(record => changed.Contains((record.Name, record.Type)));
                records.AddRange(added);
                zone.CommitAndIncrementSerial(deleted, added);
                records.Remove(currentSoa);
                records.AddRange(zone.GetRecords(DnsResourceRecordType.SOA));
                changed.Add((zone.Name, DnsResourceRecordType.SOA));
            }
            return changed;
        }

        private static string[] GetOwnedZoneFields(string name, string path, JsonElement declaration)
        {
            if (declaration.ValueKind != JsonValueKind.Object)
                return [];

            var fields = new List<string>();
            foreach (JsonProperty field in declaration.EnumerateObject())
            {
                if (field.Name is "enabled" or "records")
                    fields.Add(field.Name);
                else if (field.Name == "catalog")
                    fields.AddRange(field.Value.EnumerateObject().Select(option => "catalog/" + option.Name));
                else if (field.Name == "primary")
                    fields.AddRange(field.Value.EnumerateObject().Select(option => "primary/" + option.Name));
                else if (ConfigurationZonePolicies.IsPolicy(field.Name))
                {
                    foreach (JsonProperty option in field.Value.EnumerateObject())
                    {
                        if (field.Name == "updates" && option.Name == "securityPolicies")
                            ConfigurationZoneUpdatePolicies.AddOwnedFields(option.Value, name, path, fields);
                        else
                            fields.Add(field.Name + "/" + option.Name);
                    }
                }
            }
            fields.Sort(StringComparer.Ordinal);
            return fields.ToArray();
        }

        private void WriteManifestZoneOwnership(SortedDictionary<string, string[]> ownership)
        {
            string path = Path.Combine(_dnsServer.ConfigFolder, ManifestOwnershipFile);
            if (ownership.Count == 0)
            {
                File.Delete(path);
                return;
            }

            string temporary = path + ".tmp";
            using (var output = new FileStream(temporary, FileMode.Create, FileAccess.Write))
            {
                JsonSerializer.Serialize(output, ownership);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, true);
        }

        private HashSet<(string Owner, DnsResourceRecordType Type)> StageManifestRecords(ConfigurationManifest manifest, ApexZone zone, JsonElement declaration, List<DnsResourceRecord> records,
            IReadOnlyDictionary<string, bool> membership, string serverDomain)
        {
            string path = ConfigurationPlan.AppendPath("/zones", zone.Name) + "/records";
            var edits = ConfigurationPlan.PrepareZoneRecordEdits(manifest, zone.Name, zone.Name, serverDomain, declaration, records, OwnsManifestZoneField(zone.Name, "records"), zone is ForwarderZone);
            var owners = DnsResourceRecord.GroupRecords(records);
            var changed = new HashSet<(string Owner, DnsResourceRecordType Type)>();
            // The staging zone uses the normal record setters and SOA history, with notifications disabled.
            bool disabled = zone.Disabled;
            zone.Disabled = true;
            DnsResourceRecord soa = owners[zone.Name][DnsResourceRecordType.SOA][0];
            zone.LoadRecords(DnsResourceRecordType.SOA, [CopyRecord(soa, soa.OriginalTtlValue)]);
            foreach (var group in edits.GroupBy(edit => edit.Owner, StringComparer.OrdinalIgnoreCase).OrderBy(group => group.Key != zone.Name))
            {
                if (!group.Any(edit => edit.Kind.HasValue))
                    continue;

                bool apex = group.Key.Equals(zone.Name, StringComparison.OrdinalIgnoreCase);
                if (!apex)
                {
                    string relative = zone.Name.Length == 0 ? group.Key : group.Key[..^(zone.Name.Length + 1)];
                    AuthZoneInfo closest = FindAuthZoneInfo(group.Key);
                    bool delegated = closest is not null && closest.Name != zone.Name &&
                        closest.Name.Length > zone.Name.Length && !membership.TryGetValue(closest.Name, out _);
                    bool newDelegation = membership.Any(entry => entry.Value && entry.Key != zone.Name &&
                        (group.Key == entry.Key || group.Key.EndsWith("." + entry.Key, StringComparison.Ordinal)));
                    if (relative.Contains('.') && (delegated || newDelegation))
                        throw new InvalidDataException($"{path}: A record belongs to a child zone.");
                }

                AuthZone node = apex ? zone : zone is ForwarderZone forwarder
                    ? new ForwarderSubDomainZone(forwarder, group.Key) : new PrimarySubDomainZone((PrimaryZone)zone, group.Key);
                if (!owners.TryGetValue(group.Key, out var rrsets))
                    owners.Add(group.Key, rrsets = new Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>());
                foreach (var (type, existing) in rrsets)
                {
                    if (!apex || type != DnsResourceRecordType.SOA)
                        node.LoadRecords(type, existing);
                }

                foreach (var rrset in group.GroupBy(edit => edit.Type)
                    .OrderBy(set => set.Key == DnsResourceRecordType.SOA ? 0 : set.All(edit => edit.Kind == ConfigurationChangeKind.Remove) ? 1 : 2))
                {
                    if (!rrset.Any(edit => edit.Kind.HasValue))
                        continue;
                    rrsets.TryGetValue(rrset.Key, out List<DnsResourceRecord> previous);
                    uint[] explicitTtls = rrset.Where(edit => edit.Ttl.HasValue).Select(edit => edit.Ttl.Value).Distinct().ToArray();
                    if (explicitTtls.Length > 1)
                        throw new InvalidDataException($"{path}: Records in an RRset must have the same TTL.");
                    uint defaultTtl = rrset.Key == DnsResourceRecordType.NS ? DefaultNsRecordTtl : DefaultRecordTtl;
                    uint ttl = explicitTtls.Length == 1 ? explicitTtls[0] :
                        previous?.FirstOrDefault()?.OriginalTtlValue ?? defaultTtl;
                    var replacement = new List<DnsResourceRecord>();
                    foreach (DnsResourceRecord record in previous ?? [])
                    {
                        if (!rrset.Any(edit => ReferenceEquals(edit.Existing, record)))
                        {
                            if (record.OriginalTtlValue != ttl)
                                throw new InvalidDataException($"{path}: The TTL would change a server-maintained record.");
                            replacement.Add(record);
                        }
                    }
                    foreach (var edit in rrset.Where(edit => edit.Kind != ConfigurationChangeKind.Remove))
                    {
                        DnsResourceRecord record = edit.Existing is null
                            ? new DnsResourceRecord(edit.Owner, edit.Type, DnsClass.IN, ttl, edit.Data)
                            : CopyRecord(edit.Existing, ttl, edit.Data is DnsSOARecordData or DnsSVCBRecordData or DnsApplicationRecordData ? edit.Data : null);
                        GenericRecordInfo info = record.GetAuthGenericRecordInfo();
                        if (edit.Disabled.HasValue)
                            info.Disabled = edit.Disabled.Value;
                        if (edit.Comments is not null)
                            info.Comments = edit.Comments;
                        if (edit.Existing is null || (edit.ExpiryTtl.HasValue && edit.ExpiryTtl.Value != info.ExpiryTtl) ||
                            (edit.Kind.HasValue && info.ExpiryTtl == 0))
                            info.LastModified = DateTime.UtcNow;
                        if (edit.ExpiryTtl.HasValue)
                            info.ExpiryTtl = edit.ExpiryTtl.Value;
                        if (edit.Glue is not null)
                            record.SetGlueRecords(edit.Glue);
                        if (edit.UseSerialDateScheme.HasValue)
                            record.GetAuthSOARecordInfo().UseSoaSerialDateScheme = edit.UseSerialDateScheme.Value;
                        if (edit.Data is DnsSVCBRecordData)
                        {
                            SVCBRecordInfo hints = record.GetAuthSVCBRecordInfo();
                            hints.AutoIpv4Hint = edit.AutoIpv4Hint;
                            hints.AutoIpv6Hint = edit.AutoIpv6Hint;
                        }
                        replacement.Add(record);
                    }
                    if (rrset.Key is DnsResourceRecordType.CNAME or DnsResourceRecordType.DNAME or DnsResourceRecordType.APP && replacement.Count > 1)
                        throw new InvalidDataException($"{path}: This record type requires a single record at the owner name.");

                    try
                    {
                        if (replacement.Count == 0)
                            node.DeleteRecords(rrset.Key);
                        else
                            node.SetRecords(rrset.Key, replacement);
                    }
                    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or DnsServerException)
                    {
                        throw new InvalidDataException($"{path}: The record set is invalid for this primary zone.");
                    }
                    if (replacement.Count == 0)
                        rrsets.Remove(rrset.Key);
                    else
                        rrsets[rrset.Key] = replacement;
                    changed.Add((group.Key.ToLowerInvariant(), rrset.Key));
                }
            }

            owners[zone.Name][DnsResourceRecordType.SOA] = zone.GetRecords(DnsResourceRecordType.SOA).ToList();
            records.Clear();
            foreach (var owner in owners.Values)
                foreach (var rrset in owner.Values)
                    records.AddRange(rrset);
            // New zones are still detached here. Existing zones use a staging instance without timers.
            zone.SetManifestStagingDisabled(disabled);
            if (changed.Count > 0)
                changed.Add((zone.Name, DnsResourceRecordType.SOA));
            return changed;
        }

        private static DnsResourceRecord CopyRecord(DnsResourceRecord record, uint ttl, DnsResourceRecordData dataOverride = null)
        {
            using var data = new MemoryStream();
            var writer = new BinaryWriter(data);
            record.GetAuthGenericRecordInfo().WriteTo(writer);
            data.Position = 0;
            return new DnsResourceRecord(record.Name, record.Type, record.Class, ttl, dataOverride ?? record.RDATA)
            {
                Tag = AuthRecordInfo.ReadGenericRecordInfoFrom(new BinaryReader(data), record.Type)
            };
        }

        internal void TriggerUpdateServerDomain(bool useBlockingAnswerTtl = false)
        {
            int id = RandomNumberGenerator.GetInt32(int.MaxValue);
            _updateServerDomainId = id;

            ThreadPool.QueueUserWorkItem(delegate (object state)
            {
                string serverDomain = _dnsServer.ServerDomain;

                //update authoritative zone SOA and NS records
                try
                {
                    IReadOnlyList<AuthZoneInfo> zones = GetAllZones();

                    foreach (AuthZoneInfo zone in zones)
                    {
                        if (_updateServerDomainId != id)
                            return; //stop current update since another update has been triggerred

                        if (zone.Type != AuthZoneType.Primary)
                            continue;

                        DnsResourceRecord record = zone.ApexZone.GetRecords(DnsResourceRecordType.SOA)[0];
                        DnsSOARecordData soa = record.RDATA as DnsSOARecordData;

                        uint ttl;
                        uint minimum;

                        if (useBlockingAnswerTtl)
                        {
                            ttl = _dnsServer.BlockingAnswerTtl;
                            minimum = ttl;
                        }
                        else
                        {
                            ttl = record.TTL;
                            minimum = soa.Minimum;
                        }

                        if (soa.PrimaryNameServer.Equals(_serverDomain, StringComparison.OrdinalIgnoreCase))
                        {
                            SetRecord(zone.Name, new DnsResourceRecord(record.Name, record.Type, DnsClass.IN, ttl, new DnsSOARecordData(serverDomain, soa.ResponsiblePerson, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, minimum)));

                            //update NS records
                            IReadOnlyList<DnsResourceRecord> nsResourceRecords = zone.ApexZone.GetRecords(DnsResourceRecordType.NS);

                            foreach (DnsResourceRecord nsResourceRecord in nsResourceRecords)
                            {
                                if ((nsResourceRecord.RDATA as DnsNSRecordData).NameServer.Equals(_serverDomain, StringComparison.OrdinalIgnoreCase))
                                {
                                    UpdateRecord(zone.Name, nsResourceRecord, new DnsResourceRecord(nsResourceRecord.Name, nsResourceRecord.Type, nsResourceRecord.Class, nsResourceRecord.TTL, new DnsNSRecordData(serverDomain)) { Tag = nsResourceRecord.Tag });
                                    break;
                                }
                            }

                            //save zone file
                            SaveZoneFile(zone.Name);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }

                //update server domain
                _serverDomain = serverDomain;
            });
        }

        internal static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        internal static bool DomainBelongsToZone(string zoneName, string domain)
        {
            return domain.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase) || (zoneName.Length == 0);
        }

        internal static void ValidateIfDomainBelongsToZone(string zoneName, string domain)
        {
            if (!DomainBelongsToZone(zoneName, domain))
                throw new DnsServerException("The domain name '" + domain + "' does not belong to the zone: " + zoneName);
        }

        #endregion

        #region auth zone tree methods

        private ApexZone CreateEmptyApexZone(AuthZoneInfo zoneInfo)
        {
            ApexZone apexZone;

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    apexZone = new PrimaryZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Secondary:
                    apexZone = new SecondaryZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Stub:
                    apexZone = new StubZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Forwarder:
                    apexZone = new ForwarderZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.SecondaryForwarder:
                    apexZone = new SecondaryForwarderZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Catalog:
                    apexZone = new CatalogZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.SecondaryCatalog:
                    SecondaryCatalogZone secondaryCatalogZone = new SecondaryCatalogZone(_dnsServer, zoneInfo);
                    secondaryCatalogZone.ZoneAdded += SecondaryCatalogZoneAdded;
                    secondaryCatalogZone.ZoneRemoved += SecondaryCatalogZoneRemoved;

                    apexZone = secondaryCatalogZone;
                    break;

                default:
                    throw new InvalidDataException("DNS zone type not supported.");
            }

            if (_root.TryAdd(apexZone))
                return apexZone;

            throw new DnsServerException("Zone already exists: " + zoneInfo.DisplayName);
        }

        internal AuthZone GetOrAddSubDomainZone(string zoneName, string domain)
        {
            AuthZone authZone = _root.GetOrAddSubDomainZone(zoneName, domain, delegate ()
            {
                //ensure domain name is in zone's bailiwick before adding
                _ = _root.FindZone(domain, out _, out _, out ApexZone apexZone, out _);

                if (apexZone is null)
                    throw new DnsServerException("No such zone was found for: " + domain);

                if (!zoneName.Equals(apexZone.Name, StringComparison.OrdinalIgnoreCase))
                {
                    if (!_root.TryGet(zoneName, out apexZone))
                        throw new DnsServerException("No such zone was found for: " + domain);

                    string subdomain;

                    if (zoneName.Length == 0)
                        subdomain = domain;
                    else
                        subdomain = domain.Substring(0, domain.Length - zoneName.Length - 1);

                    if (subdomain.Contains('.', StringComparison.Ordinal))
                        throw new DnsServerException("The domain name '" + domain + "' does not belong to the zone: " + zoneName); //domain name falls into child zone's bailiwick
                }

                if (apexZone is PrimaryZone primaryZone)
                    return new PrimarySubDomainZone(primaryZone, domain);
                else if (apexZone is SecondaryCatalogZone secondaryCatalogZone)
                    return new SecondaryCatalogSubDomainZone(secondaryCatalogZone, domain);
                else if (apexZone is SecondaryZone secondaryZone)
                    return new SecondarySubDomainZone(secondaryZone, domain);
                else if (apexZone is CatalogZone catalogZone)
                    return new CatalogSubDomainZone(catalogZone, domain);
                else if (apexZone is ForwarderZone forwarderZone)
                    return new ForwarderSubDomainZone(forwarderZone, domain);

                throw new DnsServerException("Zone cannot have sub domains.");
            });

            if (authZone is SubDomainZone subDomainZone && !subDomainZone.AuthoritativeZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                throw new DnsServerException("The domain name '" + domain + "' does not belong to the zone: " + zoneName); //domain name falls into child zone's bailiwick

            return authZone;
        }

        internal IReadOnlyList<AuthZone> GetApexZoneWithSubDomainZones(string zoneName)
        {
            return _root.GetApexZoneWithSubDomainZones(zoneName);
        }

        public AuthZoneInfo GetAuthZoneInfo(string zoneName, bool loadHistory = false)
        {
            if (!DnsClient.IsDomainNameValid(zoneName))
                throw new ArgumentException("Invalid domain name was specified.", nameof(zoneName));

            if (_root.TryGet(zoneName, out AuthZoneNode authZoneNode) && (authZoneNode.ApexZone is not null))
                return new AuthZoneInfo(authZoneNode.ApexZone, loadHistory);

            return null;
        }

        public AuthZoneInfo FindAuthZoneInfo(string domain, bool loadHistory = false)
        {
            if (!DnsClient.IsDomainNameValid(domain))
                throw new ArgumentException("Invalid domain name was specified.", nameof(domain));

            _ = _root.FindZone(domain, out _, out _, out ApexZone apexZone, out _);
            if (apexZone is null)
                return null;

            return new AuthZoneInfo(apexZone, loadHistory);
        }

        internal ApexZone FindApexZone(string domain)
        {
            _ = _root.FindZone(domain, out _, out _, out ApexZone apexZone, out _);
            return apexZone;
        }

        internal AuthZone GetAuthZone(string zoneName, string domain)
        {
            AuthZone authZone = _root.GetAuthZone(zoneName, domain);

            if (authZone is not SubDomainZone subDomainZone || subDomainZone.AuthoritativeZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                return authZone;

            return null;
        }

        private bool TryGetAuthZone(string zoneName, string domain, out AuthZone authZone)
        {
            return _root.TryGet(zoneName, domain, out authZone) && (authZone is not SubDomainZone subDomainZone || subDomainZone.AuthoritativeZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase));
        }

        internal ApexZone GetApexZone(string zoneName)
        {
            return _root.GetApexZone(zoneName);
        }

        public bool NameExists(string zoneName, string domain)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            return TryGetAuthZone(zoneName, domain, out _);
        }

        internal AuthZone FindPreviousSubDomainZone(string zoneName, string domain)
        {
            return _root.FindPreviousSubDomainZone(zoneName, domain);
        }

        internal AuthZone FindNextSubDomainZone(string zoneName, string domain)
        {
            return _root.FindNextSubDomainZone(zoneName, domain);
        }

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            _root.ListSubDomains(domain, subDomains);
        }

        internal bool SubDomainExistsFor(string zoneName, string domain)
        {
            return _root.SubDomainExistsFor(zoneName, domain);
        }

        internal void RemoveSubDomainZone(string domain, bool removeAllSubDomains = false)
        {
            _root.TryRemove(domain, out SubDomainZone _, removeAllSubDomains);
        }

        internal void Flush()
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                foreach (AuthZoneNode zoneNode in _root)
                    zoneNode.Dispose();

                _root.Clear();
                _zoneIndex.Clear();
                _catalogZoneIndex.Clear();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        #endregion

        #region zone create / delete / convert / clone

        internal static void ValidateZoneName(string zoneName)
        {
            if (zoneName.Contains('*'))
                throw new DnsWebServiceException("Domain name for a zone cannot contain wildcard character.");

            foreach (char invalidChar in Path.GetInvalidFileNameChars())
            {
                if (zoneName.Contains(invalidChar))
                    throw new DnsWebServiceException("The zone name contains an invalid character: " + invalidChar);
            }
        }

        internal AuthZoneInfo CreateSpecialPrimaryZone(string zoneName, DnsSOARecordData soaRecord, DnsNSRecordData ns)
        {
            PrimaryZone apexZone = new PrimaryZone(_dnsServer, zoneName, soaRecord, ns);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        internal void LoadSpecialPrimaryZones(IReadOnlyList<string> zoneNames, DnsSOARecordData soaRecord, DnsNSRecordData ns)
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                foreach (string zoneName in zoneNames)
                {
                    PrimaryZone apexZone = new PrimaryZone(_dnsServer, zoneName, soaRecord, ns);

                    if (_root.TryAdd(apexZone))
                    {
                        AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                        _zoneIndex.Add(zoneInfo);
                    }
                }

                _zoneIndex.Sort();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        internal void LoadSpecialPrimaryZones(Func<string> getZoneName, DnsSOARecordData soaRecord, DnsNSRecordData ns)
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                string zoneName;

                while (true)
                {
                    zoneName = getZoneName();
                    if (zoneName is null)
                        break;

                    PrimaryZone apexZone = new PrimaryZone(_dnsServer, zoneName, soaRecord, ns);

                    if (_root.TryAdd(apexZone))
                    {
                        AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                        _zoneIndex.Add(zoneInfo);
                    }
                }

                _zoneIndex.Sort();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        public AuthZoneInfo CreatePrimaryZone(string zoneName)
        {
            return CreatePrimaryZone(zoneName, _useSoaSerialDateScheme);
        }

        public AuthZoneInfo CreatePrimaryZone(string zoneName, bool useSoaSerialDateScheme)
        {
            ValidateZoneName(zoneName);

            PrimaryZone apexZone = new PrimaryZone(_dnsServer, zoneName, useSoaSerialDateScheme);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public Task<AuthZoneInfo> CreateSecondaryZoneAsync(string zoneName, string primaryNameServerAddresses = null, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null, bool validateZone = false, bool ignoreSoaFailure = false)
        {
            NameServerAddress[] primaryNameServers;

            if (string.IsNullOrEmpty(primaryNameServerAddresses))
                primaryNameServers = null;
            else
                primaryNameServers = primaryNameServerAddresses.Split(NameServerAddress.Parse, ',');

            return CreateSecondaryZoneAsync(zoneName, primaryNameServers, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName, validateZone, ignoreSoaFailure);
        }

        public async Task<AuthZoneInfo> CreateSecondaryZoneAsync(string zoneName, IReadOnlyList<NameServerAddress> primaryNameServerAddresses = null, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null, bool validateZone = false, bool ignoreSoaFailure = false)
        {
            ValidateZoneName(zoneName);

            SecondaryZone apexZone = await SecondaryZone.CreateAsync(_dnsServer, zoneName, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName, validateZone, ignoreSoaFailure);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    apexZone.TriggerRefresh(0);

                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public Task<AuthZoneInfo> CreateStubZoneAsync(string zoneName, string primaryNameServerAddresses = null, bool ignoreSoaFailure = false)
        {
            NameServerAddress[] primaryNameServers;

            if (string.IsNullOrEmpty(primaryNameServerAddresses))
                primaryNameServers = null;
            else
                primaryNameServers = primaryNameServerAddresses.Split(NameServerAddress.Parse, ',');

            return CreateStubZoneAsync(zoneName, primaryNameServers, ignoreSoaFailure);
        }

        public async Task<AuthZoneInfo> CreateStubZoneAsync(string zoneName, IReadOnlyList<NameServerAddress> primaryNameServerAddresses = null, bool ignoreSoaFailure = false)
        {
            ValidateZoneName(zoneName);

            StubZone apexZone = await StubZone.CreateAsync(_dnsServer, zoneName, primaryNameServerAddresses, ignoreSoaFailure);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    apexZone.TriggerRefresh(0);

                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public AuthZoneInfo CreateForwarderZone(string zoneName)
        {
            ValidateZoneName(zoneName);

            ForwarderZone apexZone = new ForwarderZone(_dnsServer, zoneName);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public AuthZoneInfo CreateForwarderZone(string zoneName, DnsTransportProtocol forwarderProtocol, string forwarder, bool dnssecValidation, DnsForwarderRecordProxyType proxyType, string proxyAddress, ushort proxyPort, string proxyUsername, string proxyPassword, string fwdRecordComments)
        {
            ValidateZoneName(zoneName);

            ForwarderZone apexZone = new ForwarderZone(_dnsServer, zoneName, forwarderProtocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, fwdRecordComments);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public AuthZoneInfo CreateSecondaryForwarderZone(string zoneName, string primaryNameServerAddresses = null, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null)
        {
            NameServerAddress[] primaryNameServers;

            if (string.IsNullOrEmpty(primaryNameServerAddresses))
                primaryNameServers = null;
            else
                primaryNameServers = primaryNameServerAddresses.Split(NameServerAddress.Parse, ',');

            return CreateSecondaryForwarderZone(zoneName, primaryNameServers, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName);
        }

        public AuthZoneInfo CreateSecondaryForwarderZone(string zoneName, IReadOnlyList<NameServerAddress> primaryNameServerAddresses = null, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null)
        {
            ValidateZoneName(zoneName);

            SecondaryForwarderZone apexZone = new SecondaryForwarderZone(_dnsServer, zoneName, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    apexZone.TriggerRefresh(0);

                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public AuthZoneInfo CreateCatalogZone(string zoneName)
        {
            ValidateZoneName(zoneName);

            CatalogZone apexZone = new CatalogZone(_dnsServer, zoneName);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    _catalogZoneIndex.Add(zoneInfo);
                    _catalogZoneIndex.Sort();

                    apexZone.InitZoneProperties();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public AuthZoneInfo CreateSecondaryCatalogZone(string zoneName, string primaryNameServerAddresses, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null)
        {
            NameServerAddress[] primaryNameServers;

            if (string.IsNullOrEmpty(primaryNameServerAddresses))
                primaryNameServers = null;
            else
                primaryNameServers = primaryNameServerAddresses.Split(NameServerAddress.Parse, ',');

            return CreateSecondaryCatalogZone(zoneName, primaryNameServers, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName);
        }

        public AuthZoneInfo CreateSecondaryCatalogZone(string zoneName, IReadOnlyList<NameServerAddress> primaryNameServerAddresses, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null)
        {
            ValidateZoneName(zoneName);

            SecondaryCatalogZone apexZone = new SecondaryCatalogZone(_dnsServer, zoneName, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    apexZone.ZoneAdded += SecondaryCatalogZoneAdded;
                    apexZone.ZoneRemoved += SecondaryCatalogZoneRemoved;
                    apexZone.TriggerRefresh(0);

                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public bool DeleteZone(string zoneName, bool deleteZoneFile = false)
        {
            AuthZoneInfo zoneInfo = GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                return false;

            return DeleteZone(zoneInfo, deleteZoneFile);
        }

        public bool DeleteZone(AuthZoneInfo zoneInfo, bool deleteZoneFile = false)
        {
            return DeleteZone(zoneInfo, deleteZoneFile, false);
        }

        private bool DeleteZone(AuthZoneInfo zoneInfo, bool deleteZoneFile, bool skipCatalogMemberZoneProcessing)
        {
            if (!skipCatalogMemberZoneProcessing)
            {
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Catalog:
                        //update all zone memberships for catalog zone to be deleted
                        foreach (string memberZoneName in (zoneInfo.ApexZone as CatalogZone).GetAllMemberZoneNames())
                        {
                            AuthZoneInfo memberZoneInfo = GetAuthZoneInfo(memberZoneName);
                            if (memberZoneInfo is null)
                                continue;

                            if (zoneInfo.Name.Equals(memberZoneInfo.CatalogZoneName, StringComparison.OrdinalIgnoreCase))
                            {
                                memberZoneInfo.ApexZone.CatalogZoneName = null;
                                SaveZoneFile(memberZoneInfo.Name);
                            }
                        }
                        break;

                    case AuthZoneType.SecondaryCatalog:
                        //delete all member zones for secondary catalog zone to be deleted
                        foreach (string memberZoneName in (zoneInfo.ApexZone as SecondaryCatalogZone).GetAllMemberZoneNames())
                        {
                            AuthZoneInfo memberZoneInfo = GetAuthZoneInfo(memberZoneName);
                            if (memberZoneInfo is null)
                                continue;

                            if (zoneInfo.Name.Equals(memberZoneInfo.CatalogZoneName, StringComparison.OrdinalIgnoreCase))
                                DeleteZone(memberZoneInfo, true);
                        }
                        break;
                }
            }

            _zoneIndexLock.EnterWriteLock();
            try
            {
                return RemoveZoneFromIndex(zoneInfo, deleteZoneFile);
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        private bool RemoveZoneFromIndex(AuthZoneInfo zoneInfo, bool deleteZoneFile)
        {
            if (!_root.TryRemove(zoneInfo.Name, out ApexZone removedApexZone))
                return false;

            removedApexZone.Dispose();
            _zoneIndex.Remove(zoneInfo);

            if (zoneInfo.Type == AuthZoneType.Catalog)
                _catalogZoneIndex.Remove(zoneInfo);

            if (zoneInfo.CatalogZoneName is not null)
                RemoveCatalogMemberZone(zoneInfo);

            if (deleteZoneFile)
            {
                File.Delete(Path.Combine(_dnsServer.ConfigFolder, "zones", zoneInfo.Name + ".zone"));
                _dnsServer.LogManager.Write("Deleted zone file for domain: " + zoneInfo.DisplayName);
            }

            return true;
        }

        public AuthZoneInfo CloneZone(string zoneName, string sourceZoneName)
        {
            AuthZoneInfo sourceZoneInfo = GetAuthZoneInfo(sourceZoneName);
            if (sourceZoneInfo is null)
                throw new DnsServerException("No such zone was found: " + (sourceZoneName.Length == 0 ? "." : sourceZoneName));

            AuthZoneInfo zoneInfo;

            switch (sourceZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    zoneInfo = CreatePrimaryZone(zoneName);
                    break;

                case AuthZoneType.Forwarder:
                    zoneInfo = CreateForwarderZone(zoneName);
                    break;

                default:
                    throw new DnsServerException("Cannot clone the zone: source zone must be a Primary or Conditional Forwarder zone.");
            }

            if (zoneInfo is null)
                throw new DnsServerException("Failed to clone the zone: zone already exists.");

            //copy zone options
            zoneInfo.Disabled = sourceZoneInfo.Disabled;

            if (zoneInfo.Type == AuthZoneType.Primary)
            {
                zoneInfo.ZoneTransfer = sourceZoneInfo.ZoneTransfer;
                zoneInfo.ZoneTransferNetworkACL = sourceZoneInfo.ZoneTransferNetworkACL;
                zoneInfo.ZoneTransferTsigKeyNames = sourceZoneInfo.ZoneTransferTsigKeyNames;

                zoneInfo.Notify = sourceZoneInfo.Notify;
                zoneInfo.NotifyNameServers = sourceZoneInfo.NotifyNameServers;

                zoneInfo.Update = sourceZoneInfo.Update;
                zoneInfo.UpdateNetworkACL = sourceZoneInfo.UpdateNetworkACL;

                if (sourceZoneInfo.UpdateSecurityPolicies is not null)
                {
                    Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicies = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(sourceZoneInfo.UpdateSecurityPolicies.Count);

                    foreach (KeyValuePair<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> sourceSecurityPolicy in sourceZoneInfo.UpdateSecurityPolicies)
                    {
                        Dictionary<string, IReadOnlyList<DnsResourceRecordType>> policyMap = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>();

                        foreach (KeyValuePair<string, IReadOnlyList<DnsResourceRecordType>> sourcePolicyMap in sourceSecurityPolicy.Value)
                            policyMap.Add(string.Concat(sourcePolicyMap.Key.AsSpan(0, sourcePolicyMap.Key.Length - sourceZoneName.Length), zoneName), sourcePolicyMap.Value);

                        updateSecurityPolicies.Add(sourceSecurityPolicy.Key, policyMap);
                    }

                    zoneInfo.UpdateSecurityPolicies = updateSecurityPolicies;
                }
            }

            //copy records
            List<DnsResourceRecord> sourceRecords = new List<DnsResourceRecord>();
            ListAllZoneRecords(sourceZoneName, sourceRecords);

            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(sourceRecords.Count);

            foreach (DnsResourceRecord sourceRecord in sourceRecords)
            {
                switch (sourceRecord.Type)
                {
                    case DnsResourceRecordType.DNSKEY:
                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.NSEC:
                    case DnsResourceRecordType.NSEC3:
                    case DnsResourceRecordType.NSEC3PARAM:
                    case DnsResourceRecordType.DS:
                        continue; //skip DNSSEC records

                    default:
                        DnsResourceRecord newRecord = new DnsResourceRecord(string.Concat(sourceRecord.Name.AsSpan(0, sourceRecord.Name.Length - sourceZoneName.Length), zoneName), sourceRecord.Type, sourceRecord.Class, sourceRecord.TTL, sourceRecord.RDATA);

                        if (sourceRecord.Tag is NSRecordInfo nsInfo)
                        {
                            NSRecordInfo nrInfo = new NSRecordInfo();

                            nrInfo.Disabled = nsInfo.Disabled;
                            nrInfo.Comments = nsInfo.Comments;
                            nrInfo.GlueRecords = nsInfo.GlueRecords;

                            newRecord.Tag = nrInfo;
                        }
                        else if (sourceRecord.Tag is SOARecordInfo soaInfo)
                        {
                            SOARecordInfo nrInfo = new SOARecordInfo();

                            nrInfo.Disabled = soaInfo.Disabled;
                            nrInfo.Comments = soaInfo.Comments;
                            nrInfo.UseSoaSerialDateScheme = soaInfo.UseSoaSerialDateScheme;

                            newRecord.Tag = nrInfo;
                        }
                        else if (sourceRecord.Tag is SVCBRecordInfo svcbInfo)
                        {
                            SVCBRecordInfo nrInfo = new SVCBRecordInfo();

                            nrInfo.Disabled = svcbInfo.Disabled;
                            nrInfo.Comments = svcbInfo.Comments;
                            nrInfo.AutoIpv4Hint = svcbInfo.AutoIpv4Hint;
                            nrInfo.AutoIpv6Hint = svcbInfo.AutoIpv6Hint;

                            newRecord.Tag = nrInfo;
                        }
                        else if (sourceRecord.Tag is GenericRecordInfo srInfo)
                        {
                            GenericRecordInfo nrInfo = new GenericRecordInfo();

                            nrInfo.Disabled = srInfo.Disabled;
                            nrInfo.Comments = srInfo.Comments;

                            newRecord.Tag = nrInfo;
                        }

                        newRecords.Add(newRecord);
                        break;
                }
            }

            //load and init zone
            LoadAndInitZone(zoneInfo, newRecords);

            //save zone file
            SaveZoneFile(zoneInfo.Name);

            return zoneInfo;
        }

        public AuthZoneInfo ConvertZoneTypeTo(string zoneName, AuthZoneType newType)
        {
            AuthZoneInfo currentZoneInfo = GetAuthZoneInfo(zoneName);
            if (currentZoneInfo is null)
                throw new DnsServerException("No such zone was found: " + (zoneName.Length == 0 ? "." : zoneName));

            //validate conversion type
            if (currentZoneInfo.Type == newType)
                throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: the zone is already of the same type.");

            switch (currentZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    switch (newType)
                    {
                        case AuthZoneType.Forwarder:
                            if (currentZoneInfo.ApexZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned)
                                throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: converting the zone will cause lose of DNSSEC private keys.");

                            break;

                        default:
                            throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: not supported.");
                    }

                    break;

                case AuthZoneType.Secondary:
                case AuthZoneType.SecondaryForwarder:
                case AuthZoneType.SecondaryCatalog:
                    switch (newType)
                    {
                        case AuthZoneType.Primary:
                        case AuthZoneType.Forwarder:
                        case AuthZoneType.Catalog:
                            break;

                        default:
                            throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: not supported.");
                    }

                    break;

                case AuthZoneType.Forwarder:
                    switch (newType)
                    {
                        case AuthZoneType.Primary:
                            break;

                        default:
                            throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: not supported.");
                    }

                    break;

                default:
                    throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: not supported.");
            }

            return ConvertZoneTypeTo(currentZoneInfo, newType);
        }

        private AuthZoneInfo ConvertZoneTypeTo(AuthZoneInfo currentZoneInfo, AuthZoneType newType)
        {
            //read all current records
            List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();
            ListAllZoneRecords(currentZoneInfo.Name, allRecords);

            try
            {
                //delete current zone from auth tree
                DeleteZone(currentZoneInfo, false, true);

                //create new zone
                AuthZoneInfo newZoneInfo;

                switch (newType)
                {
                    case AuthZoneType.Primary:
                        switch (currentZoneInfo.Type)
                        {
                            case AuthZoneType.Secondary:
                                {
                                    //reset SOA metadata and remove DNSSEC records
                                    List<DnsResourceRecord> updateRecords = new List<DnsResourceRecord>(allRecords.Count);

                                    foreach (DnsResourceRecord record in allRecords)
                                    {
                                        switch (record.Type)
                                        {
                                            case DnsResourceRecordType.SOA:
                                                {
                                                    GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                                                    record.Tag = null;

                                                    GenericRecordInfo newRecordInfo = record.GetAuthGenericRecordInfo();
                                                    newRecordInfo.Comments = recordInfo.Comments;
                                                }
                                                break;

                                            case DnsResourceRecordType.DNSKEY:
                                            case DnsResourceRecordType.RRSIG:
                                            case DnsResourceRecordType.NSEC:
                                            case DnsResourceRecordType.NSEC3:
                                            case DnsResourceRecordType.NSEC3PARAM:
                                                continue;
                                        }

                                        updateRecords.Add(record);
                                    }

                                    allRecords = updateRecords;
                                }
                                break;

                            case AuthZoneType.Forwarder:
                            case AuthZoneType.SecondaryForwarder:
                                {
                                    //remove all FWD records
                                    List<DnsResourceRecord> updateRecords = new List<DnsResourceRecord>(allRecords.Count);

                                    foreach (DnsResourceRecord record in allRecords)
                                    {
                                        if (record.Type == DnsResourceRecordType.FWD)
                                            continue;

                                        updateRecords.Add(record);
                                    }

                                    allRecords = updateRecords;
                                }
                                break;
                        }

                        newZoneInfo = CreatePrimaryZone(currentZoneInfo.Name);
                        break;

                    case AuthZoneType.Forwarder:
                        switch (currentZoneInfo.Type)
                        {
                            case AuthZoneType.Primary:
                            case AuthZoneType.SecondaryForwarder:
                                {
                                    //remove SOA and NS records
                                    List<DnsResourceRecord> updateRecords = new List<DnsResourceRecord>(allRecords.Count);

                                    foreach (DnsResourceRecord record in allRecords)
                                    {
                                        switch (record.Type)
                                        {
                                            case DnsResourceRecordType.SOA:
                                            case DnsResourceRecordType.NS:
                                                continue;
                                        }

                                        updateRecords.Add(record);
                                    }

                                    allRecords = updateRecords;
                                }
                                break;

                            case AuthZoneType.Secondary:
                                {
                                    //remove SOA, NS and DNSSEC records
                                    List<DnsResourceRecord> updateRecords = new List<DnsResourceRecord>(allRecords.Count);

                                    foreach (DnsResourceRecord record in allRecords)
                                    {
                                        switch (record.Type)
                                        {
                                            case DnsResourceRecordType.SOA:
                                            case DnsResourceRecordType.NS:
                                            case DnsResourceRecordType.DNSKEY:
                                            case DnsResourceRecordType.RRSIG:
                                            case DnsResourceRecordType.NSEC:
                                            case DnsResourceRecordType.NSEC3:
                                            case DnsResourceRecordType.NSEC3PARAM:
                                            case DnsResourceRecordType.DS:
                                                continue;
                                        }

                                        updateRecords.Add(record);
                                    }

                                    allRecords = updateRecords;
                                }
                                break;
                        }

                        newZoneInfo = CreateForwarderZone(currentZoneInfo.Name);
                        break;

                    case AuthZoneType.Catalog:
                        newZoneInfo = CreateCatalogZone(currentZoneInfo.Name);
                        break;

                    default:
                        throw new InvalidOperationException();
                }

                //load and init zone
                LoadAndInitZone(newZoneInfo, allRecords);

                //save zone file
                SaveZoneFile(newZoneInfo.Name);

                //post processing for catalog zones
                if (newType == AuthZoneType.Catalog)
                {
                    //convert all member zones too
                    CatalogZone newCatalogZone = newZoneInfo.ApexZone as CatalogZone;

                    foreach (string memberZoneName in newCatalogZone.GetAllMemberZoneNames())
                    {
                        AuthZoneInfo memberZoneInfo = GetAuthZoneInfo(memberZoneName);
                        if (memberZoneInfo is null)
                            continue;

                        switch (memberZoneInfo.Type)
                        {
                            case AuthZoneType.Secondary:
                                try
                                {
                                    AuthZoneType originalMemberZoneType = newCatalogZone.GetZoneTypeProperty(memberZoneInfo.Name);
                                    if (originalMemberZoneType != AuthZoneType.Primary)
                                    {
                                        memberZoneInfo.ApexZone.CatalogZoneName = newZoneInfo.Name; //reset catalog zone object reference
                                        break;
                                    }

                                    AuthZoneInfo newMemberZoneInfo = ConvertZoneTypeTo(memberZoneInfo, AuthZoneType.Primary);
                                    newMemberZoneInfo.ApexZone.CatalogZoneName = newZoneInfo.Name;

                                    AuthZoneDnssecStatus dnssecStatus = memberZoneInfo.ApexZone.DnssecStatus;
                                    if (dnssecStatus != AuthZoneDnssecStatus.Unsigned)
                                    {
                                        //sign the new primary zone if the secondary zone was signed
                                        SecondaryZone secondaryZone = memberZoneInfo.ApexZone as SecondaryZone;

                                        IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys = secondaryZone.DnssecPrivateKeys;
                                        if (dnssecPrivateKeys is not null)
                                        {
                                            try
                                            {
                                                IReadOnlyList<DnsResourceRecord> existingDnsKeyRecords = secondaryZone.GetRecords(DnsResourceRecordType.DNSKEY);

                                                uint dnsKeyTtl = existingDnsKeyRecords[0].OriginalTtlValue;
                                                bool useNSec3 = dnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3;
                                                ushort iterations = 0;
                                                byte[] salt = [];

                                                if (useNSec3)
                                                {
                                                    IReadOnlyList<DnsResourceRecord> existingNsec3ParamRecord = secondaryZone.GetRecords(DnsResourceRecordType.NSEC3PARAM);
                                                    DnsNSEC3PARAMRecordData nsec3Param = existingNsec3ParamRecord[0].RDATA as DnsNSEC3PARAMRecordData;

                                                    iterations = nsec3Param.Iterations;
                                                    salt = nsec3Param.Salt;
                                                }

                                                PrimaryZone newPrimaryZone = newMemberZoneInfo.ApexZone as PrimaryZone;
                                                newPrimaryZone.SignZone(dnssecPrivateKeys, dnsKeyTtl, useNSec3, iterations, salt);
                                            }
                                            catch (Exception ex)
                                            {
                                                _dnsServer.LogManager.Write(ex);
                                            }
                                        }
                                    }

                                    SaveZoneFile(newMemberZoneInfo.Name);
                                }
                                catch
                                {
                                    //ignore errors since they were already logged
                                }
                                break;

                            case AuthZoneType.SecondaryForwarder:
                                try
                                {
                                    AuthZoneInfo newMemberZoneInfo = ConvertZoneTypeTo(memberZoneInfo, AuthZoneType.Forwarder);
                                    newMemberZoneInfo.ApexZone.CatalogZoneName = newZoneInfo.Name;

                                    SaveZoneFile(newMemberZoneInfo.Name);
                                }
                                catch
                                {
                                    //ignore errors since they were already logged
                                }
                                break;

                            default: //stub zone
                                memberZoneInfo.ApexZone.CatalogZoneName = newZoneInfo.Name; //reset catalog zone object reference
                                break;
                        }
                    }
                }

                return newZoneInfo;
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server failed to convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone.", ex);

                //delete the zone if it was created
                DeleteZone(currentZoneInfo);

                //reload old zone file
                string zoneFile = Path.Combine(_dnsServer.ConfigFolder, "zones", currentZoneInfo.Name + ".zone");

                _zoneIndexLock.EnterWriteLock();
                try
                {
                    using (FileStream fS = new FileStream(zoneFile, FileMode.Open, FileAccess.Read))
                    {
                        AuthZoneInfo zoneInfo = LoadZoneFrom(fS, File.GetLastWriteTimeUtc(fS.SafeFileHandle));
                        _zoneIndex.Add(zoneInfo);
                        _zoneIndex.Sort();
                    }

                    _dnsServer.LogManager.Write("DNS Server successfully loaded zone file: " + zoneFile);
                }
                catch (Exception ex2)
                {
                    _dnsServer.LogManager.Write("DNS Server failed to load zone file: " + zoneFile, ex2);
                }
                finally
                {
                    _zoneIndexLock.ExitWriteLock();
                }

                throw;
            }
        }

        #endregion

        #region catalog member zones

        public void AddCatalogMemberZone(string catalogZoneName, AuthZoneInfo memberZoneInfo, bool ignoreValidationErrors = false)
        {
            switch (memberZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Secondary:
                case AuthZoneType.Stub:
                case AuthZoneType.Forwarder:
                    if (!ignoreValidationErrors)
                    {
                        string currentCatalogZoneName = memberZoneInfo.ApexZone.CatalogZoneName;
                        if (currentCatalogZoneName is not null)
                            throw new DnsServerException("The zone '" + memberZoneInfo.DisplayName + "' is already a member of Catalog zone '" + currentCatalogZoneName + "'.");
                    }

                    ApexZone apexZone = _root.GetApexZone(catalogZoneName);
                    if (apexZone is not CatalogZone catalogZone)
                    {
                        if (ignoreValidationErrors)
                            return;

                        throw new DnsServerException("No such Catalog zone was found: " + catalogZoneName);
                    }

                    //set catalog zone name in member zone so that properties can be set below correctly
                    memberZoneInfo.ApexZone.CatalogZoneName = catalogZone.Name;

                    if (!memberZoneInfo.Disabled)
                    {
                        catalogZone.AddMemberZone(memberZoneInfo.Name, memberZoneInfo.Type);

                        //update properties in catalog zone by settings member zone property values again
                        switch (memberZoneInfo.Type)
                        {
                            case AuthZoneType.Primary:
                                memberZoneInfo.QueryAccess = memberZoneInfo.QueryAccess;
                                memberZoneInfo.ZoneTransfer = memberZoneInfo.ZoneTransfer;
                                memberZoneInfo.ZoneTransferTsigKeyNames = memberZoneInfo.ZoneTransferTsigKeyNames;
                                break;

                            case AuthZoneType.Secondary:
                                memberZoneInfo.PrimaryNameServerAddresses = memberZoneInfo.PrimaryNameServerAddresses;
                                memberZoneInfo.PrimaryZoneTransferProtocol = memberZoneInfo.PrimaryZoneTransferProtocol;
                                memberZoneInfo.PrimaryZoneTransferTsigKeyName = memberZoneInfo.PrimaryZoneTransferTsigKeyName;
                                memberZoneInfo.ValidateZone = memberZoneInfo.ValidateZone;
                                memberZoneInfo.QueryAccess = memberZoneInfo.QueryAccess;
                                memberZoneInfo.ZoneTransfer = memberZoneInfo.ZoneTransfer;
                                memberZoneInfo.ZoneTransferTsigKeyNames = memberZoneInfo.ZoneTransferTsigKeyNames;
                                break;

                            case AuthZoneType.Stub:
                                memberZoneInfo.PrimaryNameServerAddresses = memberZoneInfo.PrimaryNameServerAddresses;
                                memberZoneInfo.QueryAccess = memberZoneInfo.QueryAccess;
                                break;

                            case AuthZoneType.Forwarder:
                                memberZoneInfo.QueryAccess = memberZoneInfo.QueryAccess;
                                break;
                        }

                        //save catalog changes
                        SaveZoneFile(catalogZone.Name);
                    }

                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        public void RemoveCatalogMemberZone(AuthZoneInfo memberZoneInfo, bool disableOnly = false)
        {
            switch (memberZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Secondary:
                case AuthZoneType.Stub:
                case AuthZoneType.Forwarder:
                case AuthZoneType.SecondaryForwarder:
                    string catalogZoneName = memberZoneInfo.ApexZone.CatalogZoneName;
                    if (catalogZoneName is null)
                        return;

                    CatalogZone catalogZone = memberZoneInfo.ApexZone.CatalogZone;
                    if (catalogZone is not null)
                    {
                        catalogZone.RemoveMemberZone(memberZoneInfo.Name);

                        //save catalog changes
                        SaveZoneFile(catalogZone.Name);
                    }

                    if (!disableOnly)
                        memberZoneInfo.ApexZone.CatalogZoneName = null;

                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        public void ChangeCatalogMemberZoneOwnership(AuthZoneInfo memberZoneInfo, string newCatalogZoneName)
        {
            switch (memberZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Secondary:
                case AuthZoneType.Stub:
                case AuthZoneType.Forwarder:
                    string currentCatalogZoneName = memberZoneInfo.ApexZone.CatalogZoneName;
                    if (currentCatalogZoneName is null)
                        throw new DnsServerException("The zone '" + memberZoneInfo.DisplayName + "' is not a member of any Catalog zone.");

                    AddCatalogMemberZone(newCatalogZoneName, memberZoneInfo, true);

                    if (!memberZoneInfo.Disabled)
                    {
                        ApexZone apexZone = _root.GetApexZone(currentCatalogZoneName);
                        if (apexZone is CatalogZone currentCatalogZone)
                        {
                            currentCatalogZone.ChangeMemberZoneOwnership(memberZoneInfo.Name, newCatalogZoneName);

                            //save catalog changes
                            SaveZoneFile(currentCatalogZone.Name);
                        }
                    }

                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        #endregion

        #region DNSSEC

        public void SignPrimaryZone(string zoneName, DnssecPrivateKey kskPrivateKey, DnssecPrivateKey zskPrivateKey, uint dnsKeyTtl, bool useNSec3, ushort iterations = 0, byte saltLength = 0)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.SignZone(kskPrivateKey, zskPrivateKey, dnsKeyTtl, useNSec3, iterations, saltLength);

            SaveZoneFile(primaryZone.Name);
        }

        public void UnsignPrimaryZone(string zoneName)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.UnsignZone();

            SaveZoneFile(primaryZone.Name);
        }

        public void ConvertPrimaryZoneToNSEC(string zoneName)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.ConvertToNSec();

            SaveZoneFile(primaryZone.Name);
        }

        public void ConvertPrimaryZoneToNSEC3(string zoneName, ushort iterations, byte saltLength)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.ConvertToNSec3(iterations, saltLength);

            SaveZoneFile(primaryZone.Name);
        }

        public void UpdatePrimaryZoneNSEC3Parameters(string zoneName, ushort iterations, byte saltLength)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.UpdateNSec3Parameters(iterations, saltLength);

            SaveZoneFile(primaryZone.Name);
        }

        public void UpdatePrimaryZoneDnsKeyTtl(string zoneName, uint dnsKeyTtl)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.UpdateDnsKeyTtl(dnsKeyTtl);

            SaveZoneFile(primaryZone.Name);
        }

        public DnssecPrivateKey GenerateAndAddPrimaryZoneDnssecPrivateKey(string zoneName, DnssecPrivateKeyType keyType, DnssecAlgorithm algorithm, ushort rolloverDays, int keySize = -1)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            DnssecPrivateKey privateKey = primaryZone.GenerateAndAddPrivateKey(keyType, algorithm, rolloverDays, keySize);

            SaveZoneFile(primaryZone.Name);

            return privateKey;
        }

        public void AddPrimaryZoneDnssecPrivateKey(string zoneName, DnssecPrivateKey privateKey)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.AddPrivateKey(privateKey);

            SaveZoneFile(primaryZone.Name);
        }

        public DnssecPrivateKey UpdatePrimaryZoneDnssecPrivateKey(string zoneName, ushort keyTag, ushort rolloverDays)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            DnssecPrivateKey privateKey = primaryZone.UpdatePrivateKey(keyTag, rolloverDays);

            SaveZoneFile(primaryZone.Name);

            return privateKey;
        }

        public void DeletePrimaryZoneDnssecPrivateKey(string zoneName, ushort keyTag)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.DeletePrivateKey(keyTag);

            SaveZoneFile(primaryZone.Name);
        }

        public void PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(string zoneName)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.PublishAllGeneratedKeys();

            SaveZoneFile(primaryZone.Name);
        }

        public void ActivatePrimaryZoneKskDnsKey(string zoneName, ushort keyTag)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.ActivateKskDnsKey(keyTag);

            SaveZoneFile(primaryZone.Name);
        }

        public void RolloverPrimaryZoneDnsKey(string zoneName, ushort keyTag)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.RolloverDnsKey(keyTag);

            SaveZoneFile(primaryZone.Name);
        }

        public async Task RetirePrimaryZoneDnsKeyAsync(string zoneName, ushort keyTag)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone))
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            await primaryZone.RetireDnsKeyAsync(keyTag);

            SaveZoneFile(primaryZone.Name);
        }

        public void LoadTrustAnchorsTo(DnsClient dnsClient, string domain, DnsResourceRecordType type)
        {
            if (type == DnsResourceRecordType.DS)
            {
                domain = GetParentZone(domain);
                if (domain is null)
                    domain = "";
            }

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.FindAuthZoneInfo(domain, false);
            if ((zoneInfo is not null) && (zoneInfo.ApexZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned))
            {
                IReadOnlyList<DnsResourceRecord> dnsKeyRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.DNSKEY);
                List<DnsResourceRecord> dsRecords = new List<DnsResourceRecord>(dnsKeyRecords.Count);

                foreach (DnsResourceRecord dnsKeyRecord in dnsKeyRecords)
                {
                    DnsDNSKEYRecordData dnsKey = dnsKeyRecord.RDATA as DnsDNSKEYRecordData;

                    if (dnsKey.Flags.HasFlag(DnsDnsKeyFlag.SecureEntryPoint) && !dnsKey.Flags.HasFlag(DnsDnsKeyFlag.Revoke))
                        dsRecords.Add(new DnsResourceRecord(dnsKeyRecord.Name, DnsResourceRecordType.DS, DnsClass.IN, 0, dnsKey.CreateDS(dnsKeyRecord.Name, DnssecDigestType.SHA256)));
                }

                //set trust anchor
                dnsClient.TrustAnchors[zoneInfo.Name] = dsRecords;
            }
        }

        #endregion

        #region zone listing

        public IEnumerable<AuthZoneInfo> EnumerateAllZones()
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                foreach (AuthZoneInfo zoneInfo in _zoneIndex)
                    yield return zoneInfo;
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        public IReadOnlyList<AuthZoneInfo> GetAllZones()
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                return _zoneIndex.ToArray();
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        public IReadOnlyList<AuthZoneInfo> GetZones(Func<AuthZoneInfo, bool> predicate)
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                List<AuthZoneInfo> zoneInfoList = new List<AuthZoneInfo>();

                foreach (AuthZoneInfo zoneInfo in _zoneIndex)
                {
                    if (predicate(zoneInfo))
                        zoneInfoList.Add(zoneInfo);
                }

                return zoneInfoList;
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        public IReadOnlyList<AuthZoneInfo> GetAllCatalogZones()
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                return _catalogZoneIndex.ToArray();
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        public IReadOnlyList<AuthZoneInfo> GetCatalogZones(Func<AuthZoneInfo, bool> predicate)
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                List<AuthZoneInfo> catalogZoneInfoList = new List<AuthZoneInfo>();

                foreach (AuthZoneInfo zone in _catalogZoneIndex)
                {
                    if (predicate(zone))
                        catalogZoneInfoList.Add(zone);
                }

                return catalogZoneInfoList;
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        #endregion

        #region zone record management

        public void ListAllZoneRecords(string zoneName, List<DnsResourceRecord> records)
        {
            foreach (AuthZone authZone in _root.GetApexZoneWithSubDomainZones(zoneName))
                authZone.ListAllRecords(records);
        }

        public void ListAllZoneRecords(string zoneName, DnsResourceRecordType[] types, List<DnsResourceRecord> records)
        {
            foreach (AuthZone authZone in _root.GetApexZoneWithSubDomainZones(zoneName))
            {
                foreach (DnsResourceRecordType type in types)
                    records.AddRange(authZone.GetRecords(type));
            }
        }

        public void ListAllRecords(string zoneName, string domain, List<DnsResourceRecord> records)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (TryGetAuthZone(zoneName, domain, out AuthZone authZone))
                authZone.ListAllRecords(records);
        }

        public IEnumerable<DnsResourceRecord> EnumerateAllRecords(string zoneName, string domain, bool includeAllSubDomainNames = false)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (includeAllSubDomainNames)
            {
                foreach (AuthZone authZone in _root.GetSubDomainZoneWithSubDomainZones(domain))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in authZone.Entries)
                    {
                        foreach (DnsResourceRecord record in entry.Value)
                            yield return record;
                    }
                }
            }
            else
            {
                if (TryGetAuthZone(zoneName, domain, out AuthZone authZone))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in authZone.Entries)
                    {
                        foreach (DnsResourceRecord record in entry.Value)
                            yield return record;
                    }
                }
            }
        }

        public IReadOnlyList<DnsResourceRecord> GetRecords(string zoneName, string domain, DnsResourceRecordType type)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (TryGetAuthZone(zoneName, domain, out AuthZone authZone))
                return authZone.GetRecords(type);

            return Array.Empty<DnsResourceRecord>();
        }

        public IReadOnlyDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> GetEntriesFor(string zoneName, string domain)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (TryGetAuthZone(zoneName, domain, out AuthZone authZone))
                return authZone.Entries;

            return new Dictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(1);
        }

        public void SetRecords(string zoneName, IReadOnlyList<DnsResourceRecord> records)
        {
            if (records.Count < 1)
                throw new ArgumentException();

            string domain = records[0].Name;

            for (int i = 1; i < records.Count; i++)
            {
                if (!records[i].Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException();

                if (records[i].Type != records[0].Type)
                    throw new ArgumentException();

                if (records[i].Class != records[0].Class)
                    throw new ArgumentException();
            }

            ValidateIfDomainBelongsToZone(zoneName, domain);

            AuthZone authZone = GetOrAddSubDomainZone(zoneName, domain);

            authZone.SetRecords(records[0].Type, records);

            if (authZone is SubDomainZone subDomainZone)
                subDomainZone.AutoUpdateState();
        }

        public void SetRecord(string zoneName, DnsResourceRecord record)
        {
            ValidateIfDomainBelongsToZone(zoneName, record.Name);

            AuthZone authZone = GetOrAddSubDomainZone(zoneName, record.Name);

            authZone.SetRecords(record.Type, new DnsResourceRecord[] { record });

            if (authZone is SubDomainZone subDomainZone)
                subDomainZone.AutoUpdateState();
        }

        public bool AddRecord(string zoneName, DnsResourceRecord record)
        {
            ValidateIfDomainBelongsToZone(zoneName, record.Name);

            AuthZone authZone = GetOrAddSubDomainZone(zoneName, record.Name);

            if (authZone.AddRecord(record))
            {
                if (authZone is SubDomainZone subDomainZone)
                    subDomainZone.AutoUpdateState();

                return true;
            }

            return false;
        }

        public void UpdateRecord(string zoneName, DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            ValidateIfDomainBelongsToZone(zoneName, oldRecord.Name);
            ValidateIfDomainBelongsToZone(zoneName, newRecord.Name);

            if (oldRecord.Type != newRecord.Type)
                throw new DnsServerException("Cannot update record: new record must be of same type.");

            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new DnsServerException("Cannot update record: use SetRecords() for updating SOA record.");

            if (!TryGetAuthZone(zoneName, oldRecord.Name, out AuthZone authZone))
                throw new DnsServerException("Cannot update record: domain '" + oldRecord.Name + "' does not exists.");

            switch (oldRecord.Type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.DNAME:
                case DnsResourceRecordType.APP:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        authZone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });

                        if (authZone is SubDomainZone subDomainZone)
                            subDomainZone.AutoUpdateState();
                    }
                    else
                    {
                        authZone.DeleteRecords(oldRecord.Type);

                        if (authZone is SubDomainZone subDomainZone)
                        {
                            if (authZone.IsEmpty)
                                _root.TryRemove(oldRecord.Name, out SubDomainZone _); //remove empty sub zone
                            else
                                subDomainZone.AutoUpdateState();
                        }

                        AuthZone newZone = GetOrAddSubDomainZone(zoneName, newRecord.Name);

                        newZone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });

                        if (newZone is SubDomainZone subDomainZone1)
                            subDomainZone1.AutoUpdateState();
                    }
                    break;

                default:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        authZone.UpdateRecord(oldRecord, newRecord);

                        if (authZone is SubDomainZone subDomainZone)
                            subDomainZone.AutoUpdateState();
                    }
                    else
                    {
                        if (!authZone.DeleteRecord(oldRecord.Type, oldRecord.RDATA))
                            throw new DnsWebServiceException("Cannot update record: the old record does not exists.");

                        if (authZone is SubDomainZone subDomainZone)
                        {
                            if (authZone.IsEmpty)
                                _root.TryRemove(oldRecord.Name, out SubDomainZone _); //remove empty sub zone
                            else
                                subDomainZone.AutoUpdateState();
                        }

                        AuthZone newZone = GetOrAddSubDomainZone(zoneName, newRecord.Name);

                        newZone.AddRecord(newRecord);

                        if (newZone is SubDomainZone subDomainZone1)
                            subDomainZone1.AutoUpdateState();
                    }
                    break;
            }
        }

        public bool DeleteRecord(string zoneName, DnsResourceRecord record)
        {
            return DeleteRecord(zoneName, record.Name, record.Type, record.RDATA);
        }

        public bool DeleteRecord(string zoneName, string domain, DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (TryGetAuthZone(zoneName, domain, out AuthZone authZone))
            {
                if (authZone.DeleteRecord(type, rdata))
                {
                    if (authZone is SubDomainZone subDomainZone)
                    {
                        if (authZone.IsEmpty)
                            _root.TryRemove(domain, out SubDomainZone _); //remove empty sub zone
                        else
                            subDomainZone.AutoUpdateState();
                    }

                    return true;
                }
            }

            return false;
        }

        public bool DeleteRecords(string zoneName, string domain, DnsResourceRecordType type)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (TryGetAuthZone(zoneName, domain, out AuthZone authZone))
            {
                if (authZone.DeleteRecords(type))
                {
                    if (authZone is SubDomainZone subDomainZone)
                    {
                        if (authZone.IsEmpty)
                            _root.TryRemove(domain, out SubDomainZone _); //remove empty sub zone
                        else
                            subDomainZone.AutoUpdateState();
                    }

                    return true;
                }
            }

            return false;
        }

        public void DeleteAllRecords(string zoneName)
        {
            foreach (AuthZone authZone in _root.GetApexZoneWithSubDomainZones(zoneName))
            {
                foreach (DnsResourceRecordType recordType in authZone.Entries.Keys)
                {
                    switch (recordType)
                    {
                        case DnsResourceRecordType.SOA:
                            break; //skip SOA record

                        case DnsResourceRecordType.DNSKEY:
                        case DnsResourceRecordType.RRSIG:
                        case DnsResourceRecordType.NSEC:
                        case DnsResourceRecordType.NSEC3PARAM:
                        case DnsResourceRecordType.NSEC3:
                            break; //skip DNSSEC records

                        default:
                            authZone.DeleteRecords(recordType);
                            break;
                    }
                }

                if (authZone is SubDomainZone subDomainZone)
                {
                    if (authZone.IsEmpty)
                        _root.TryRemove(authZone.Name, out SubDomainZone _); //remove empty sub zone
                    else
                        subDomainZone.AutoUpdateState();
                }
            }
        }

        #endregion

        #region zone transfer / import

        public IReadOnlyList<DnsResourceRecord> QueryZoneTransferRecords(string zoneName)
        {
            AuthZoneInfo zoneInfo = GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new InvalidOperationException("Zone was not found: " + zoneName);

            //primary, secondary, and forwarder zones support zone transfer
            IReadOnlyList<DnsResourceRecord> soaRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.SOA);
            if (soaRecords.Count != 1)
                throw new InvalidOperationException("Zone must be a primary, secondary, or forwarder zone.");

            DnsResourceRecord soaRecord = soaRecords[0];

            List<DnsResourceRecord> records = new List<DnsResourceRecord>();
            ListAllZoneRecords(zoneName, records);

            List<DnsResourceRecord> xfrRecords = new List<DnsResourceRecord>(records.Count + 1);

            //start message
            xfrRecords.Add(soaRecord);

            foreach (DnsResourceRecord record in records)
            {
                GenericRecordInfo authRecordInfo = record.GetAuthGenericRecordInfo();
                if (authRecordInfo.Disabled)
                    continue;

                switch (record.Type)
                {
                    case DnsResourceRecordType.SOA:
                        break; //skip record

                    case DnsResourceRecordType.NS:
                        xfrRecords.Add(record);

                        IReadOnlyList<DnsResourceRecord> glueRecords = (authRecordInfo as NSRecordInfo).GlueRecords;
                        if (glueRecords is not null)
                        {
                            foreach (DnsResourceRecord glueRecord in glueRecords)
                                xfrRecords.Add(glueRecord);
                        }
                        break;

                    default:
                        xfrRecords.Add(record);
                        break;
                }
            }

            //end message
            xfrRecords.Add(soaRecord);

            return xfrRecords;
        }

        public IReadOnlyList<DnsResourceRecord> QueryIncrementalZoneTransferRecords(string zoneName, DnsResourceRecord clientSoaRecord)
        {
            AuthZoneInfo authZone = GetAuthZoneInfo(zoneName, true);
            if (authZone is null)
                throw new InvalidOperationException("Zone was not found: " + zoneName);

            //primary, secondary, forwarder, and catalog zones support zone transfer
            IReadOnlyList<DnsResourceRecord> soaRecords = authZone.ApexZone.GetRecords(DnsResourceRecordType.SOA);
            if (soaRecords.Count != 1)
                throw new InvalidOperationException("No SOA record was found for IXFR.");

            DnsResourceRecord currentSoaRecord = soaRecords[0];
            uint clientSerial = (clientSoaRecord.RDATA as DnsSOARecordData).Serial;

            if (clientSerial == (currentSoaRecord.RDATA as DnsSOARecordData).Serial)
            {
                //zone not modified
                return [currentSoaRecord];
            }

            //find history record start from client serial
            IReadOnlyList<DnsResourceRecord> zoneHistory = authZone.ZoneHistory;

            int index = 0;
            while (index < zoneHistory.Count)
            {
                //check difference sequence
                if ((zoneHistory[index].RDATA as DnsSOARecordData).Serial == clientSerial)
                    break; //found history for client's serial

                //skip to next difference sequence
                index++;
                int soaCount = 1;

                while (index < zoneHistory.Count)
                {
                    if (zoneHistory[index].Type == DnsResourceRecordType.SOA)
                    {
                        soaCount++;

                        if (soaCount == 3)
                            break;
                    }

                    index++;
                }
            }

            if (index == zoneHistory.Count)
            {
                //client's serial was not found in zone history
                //do full zone transfer
                return QueryZoneTransferRecords(zoneName);
            }

            List<DnsResourceRecord> xfrRecords = new List<DnsResourceRecord>();

            //start incremental message
            xfrRecords.Add(currentSoaRecord);

            //write history
            for (int i = index; i < zoneHistory.Count; i++)
                xfrRecords.Add(zoneHistory[i]);

            //end incremental message
            xfrRecords.Add(currentSoaRecord);

            //condense
            return CondenseIncrementalZoneTransferRecords(zoneName, clientSoaRecord, xfrRecords);
        }

        public void SyncZoneTransferRecords(string zoneName, IReadOnlyList<DnsResourceRecord> xfrRecords)
        {
            if ((xfrRecords.Count < 2) || (xfrRecords[0].Type != DnsResourceRecordType.SOA) || !xfrRecords[0].Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || !xfrRecords[xfrRecords.Count - 1].Equals(xfrRecords[0]))
                throw new DnsServerException("Invalid AXFR response was received.");

            List<DnsResourceRecord> latestRecords = new List<DnsResourceRecord>(xfrRecords.Count);
            List<DnsResourceRecord> allGlueRecords = new List<DnsResourceRecord>(4);

            if (zoneName.Length == 0)
            {
                //root zone case
                for (int i = 1; i < xfrRecords.Count; i++)
                {
                    DnsResourceRecord record = xfrRecords[i];

                    switch (record.Type)
                    {
                        case DnsResourceRecordType.A:
                        case DnsResourceRecordType.AAAA:
                            if (!allGlueRecords.Contains(record))
                                allGlueRecords.Add(record);

                            break;

                        default:
                            if (!latestRecords.Contains(record))
                                latestRecords.Add(record);

                            break;
                    }
                }
            }
            else
            {
                for (int i = 1; i < xfrRecords.Count; i++)
                {
                    DnsResourceRecord record = xfrRecords[i];

                    if (record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!latestRecords.Contains(record))
                            latestRecords.Add(record);
                    }
                    else if (!allGlueRecords.Contains(record))
                    {
                        allGlueRecords.Add(record);
                    }
                }
            }

            if (allGlueRecords.Count > 0)
            {
                foreach (DnsResourceRecord record in latestRecords)
                {
                    if (record.Type == DnsResourceRecordType.NS)
                        record.SyncGlueRecords(allGlueRecords);
                }
            }

            //sync records
            List<DnsResourceRecord> currentRecords = new List<DnsResourceRecord>();
            ListAllZoneRecords(zoneName, currentRecords);

            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> currentRecordsGroupedByDomain = DnsResourceRecord.GroupRecords(currentRecords);
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> latestRecordsGroupedByDomain = DnsResourceRecord.GroupRecords(latestRecords);

            //remove domains that do not exists in new records
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> currentDomain in currentRecordsGroupedByDomain)
            {
                if (!latestRecordsGroupedByDomain.ContainsKey(currentDomain.Key))
                    _root.TryRemove(currentDomain.Key, out SubDomainZone _);
            }

            //sync new records
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> latestEntries in latestRecordsGroupedByDomain)
            {
                AuthZone zone = GetOrAddSubDomainZone(zoneName, latestEntries.Key);

                if (zone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    zone.SyncRecords(latestEntries.Value);
                else if ((zone is SubDomainZone subDomainZone) && subDomainZone.AuthoritativeZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    zone.SyncRecords(latestEntries.Value);
            }

            if (!_root.TryGet(zoneName, out ApexZone apexZone))
                throw new InvalidOperationException();

            apexZone.UpdateDnssecStatus();

            SaveZoneFile(apexZone.Name);
        }

        public IReadOnlyList<DnsResourceRecord> SyncIncrementalZoneTransferRecords(string zoneName, IReadOnlyList<DnsResourceRecord> xfrRecords)
        {
            if ((xfrRecords.Count < 2) || (xfrRecords[0].Type != DnsResourceRecordType.SOA) || !xfrRecords[0].Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || !xfrRecords[xfrRecords.Count - 1].Equals(xfrRecords[0]))
                throw new DnsServerException("Invalid IXFR/AXFR response was received.");

            if ((xfrRecords.Count < 4) || (xfrRecords[1].Type != DnsResourceRecordType.SOA))
            {
                //received AXFR response
                SyncZoneTransferRecords(zoneName, xfrRecords);
                return Array.Empty<DnsResourceRecord>();
            }

            if (!_root.TryGet(zoneName, out ApexZone apexZone))
                throw new InvalidOperationException("No such zone was found: " + zoneName);

            IReadOnlyList<DnsResourceRecord> soaRecords = apexZone.GetRecords(DnsResourceRecordType.SOA);
            if (soaRecords.Count != 1)
                throw new InvalidOperationException("No authoritative zone was found: " + zoneName);

            //process IXFR response
            DnsResourceRecord currentSoaRecord = soaRecords[0];
            DnsSOARecordData currentSoa = currentSoaRecord.RDATA as DnsSOARecordData;

            List<DnsResourceRecord> condensedXfrRecords = CondenseIncrementalZoneTransferRecords(zoneName, currentSoaRecord, xfrRecords);

            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedGlueRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> addedGlueRecords = new List<DnsResourceRecord>();

            //read and apply difference sequences
            int index = 1;
            int count = condensedXfrRecords.Count - 1;

            while (index < count)
            {
                //read deleted records
                DnsResourceRecord deletedSoaRecord = condensedXfrRecords[index];
                if ((deletedSoaRecord.Type != DnsResourceRecordType.SOA) || !deletedSoaRecord.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = condensedXfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (zoneName.Length == 0)
                    {
                        //root zone case
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                deletedGlueRecords.Add(record);
                                break;

                            default:
                                deletedRecords.Add(record);
                                break;
                        }
                    }
                    else
                    {
                        if (record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            deletedRecords.Add(record);
                        }
                        else
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                case DnsResourceRecordType.AAAA:
                                    deletedGlueRecords.Add(record);
                                    break;
                            }
                        }
                    }

                    index++;
                }

                //read added records
                DnsResourceRecord addedSoaRecord = condensedXfrRecords[index];
                if (!addedSoaRecord.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = condensedXfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (zoneName.Length == 0)
                    {
                        //root zone case
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                addedGlueRecords.Add(record);
                                break;

                            default:
                                addedRecords.Add(record);
                                break;
                        }
                    }
                    else
                    {
                        if (record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            addedRecords.Add(record);
                        }
                        else
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                case DnsResourceRecordType.AAAA:
                                    addedGlueRecords.Add(record);
                                    break;
                            }
                        }
                    }

                    index++;
                }

                //check sequence soa serial
                DnsSOARecordData deletedSoa = deletedSoaRecord.RDATA as DnsSOARecordData;

                if (currentSoa.Serial != deletedSoa.Serial)
                    throw new InvalidOperationException("Current SOA serial does not match with the IXFR difference sequence deleted SOA.");

                //sync difference sequence
                if (deletedRecords.Count > 0)
                {
                    foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> deletedEntry in DnsResourceRecord.GroupRecords(deletedRecords))
                    {
                        AuthZone zone = GetOrAddSubDomainZone(zoneName, deletedEntry.Key);

                        if (zone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            zone.SyncRecords(deletedEntry.Value, null);
                        }
                        else if ((zone is SubDomainZone subDomainZone) && subDomainZone.AuthoritativeZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            zone.SyncRecords(deletedEntry.Value, null);

                            if (zone.IsEmpty)
                                _root.TryRemove(deletedEntry.Key, out SubDomainZone _); //remove empty sub zone
                        }
                    }
                }

                if (addedRecords.Count > 0)
                {
                    foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> addedEntry in DnsResourceRecord.GroupRecords(addedRecords))
                    {
                        AuthZone zone = GetOrAddSubDomainZone(zoneName, addedEntry.Key);

                        if (zone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                            zone.SyncRecords(null, addedEntry.Value);
                        else if ((zone is SubDomainZone subDomainZone) && subDomainZone.AuthoritativeZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                            zone.SyncRecords(null, addedEntry.Value);
                    }
                }

                if ((deletedGlueRecords.Count > 0) || (addedGlueRecords.Count > 0))
                {
                    foreach (AuthZone zone in _root.GetApexZoneWithSubDomainZones(zoneName))
                        zone.SyncGlueRecords(deletedGlueRecords, addedGlueRecords);
                }

                {
                    AuthZone zone = GetOrAddSubDomainZone(zoneName, zoneName);

                    addedSoaRecord.CopyRecordInfoFrom(currentSoaRecord);

                    zone.LoadRecords(DnsResourceRecordType.SOA, new DnsResourceRecord[] { addedSoaRecord });
                }

                //check next difference sequence
                currentSoa = addedSoaRecord.RDATA as DnsSOARecordData;

                deletedRecords.Clear();
                deletedGlueRecords.Clear();
                addedRecords.Clear();
                addedGlueRecords.Clear();
            }

            apexZone.UpdateDnssecStatus();

            SaveZoneFile(apexZone.Name);

            //return history
            List<DnsResourceRecord> historyRecords = new List<DnsResourceRecord>(xfrRecords.Count - 2);

            for (int i = 1; i < xfrRecords.Count - 1; i++)
                historyRecords.Add(xfrRecords[i]);

            return historyRecords;
        }

        private static List<DnsResourceRecord> CondenseIncrementalZoneTransferRecords(string zoneName, DnsResourceRecord currentSoaRecord, IReadOnlyList<DnsResourceRecord> xfrRecords)
        {
            DnsResourceRecord firstSoaRecord = xfrRecords[0];
            DnsResourceRecord lastSoaRecord = xfrRecords[xfrRecords.Count - 1];

            DnsResourceRecord firstDeletedSoaRecord = null;
            DnsResourceRecord lastAddedSoaRecord = null;

            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedGlueRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> addedGlueRecords = new List<DnsResourceRecord>();

            //read and apply difference sequences
            int index = 1;
            int count = xfrRecords.Count - 1;
            DnsSOARecordData currentSoa = (DnsSOARecordData)currentSoaRecord.RDATA;

            while (index < count)
            {
                //read deleted records
                DnsResourceRecord deletedSoaRecord = xfrRecords[index];
                if ((deletedSoaRecord.Type != DnsResourceRecordType.SOA) || !deletedSoaRecord.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                if (firstDeletedSoaRecord is null)
                    firstDeletedSoaRecord = deletedSoaRecord;

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = xfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (zoneName.Length == 0)
                    {
                        //root zone case
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                if (!addedGlueRecords.Remove(record))
                                {
                                    if (!deletedGlueRecords.Contains(record)) //check to prevent duplicate delete entries
                                        deletedGlueRecords.Add(record);
                                }

                                break;

                            default:
                                if (!addedRecords.Remove(record))
                                {
                                    if (!deletedRecords.Contains(record)) //check to prevent duplicate delete entries
                                        deletedRecords.Add(record);
                                }

                                break;
                        }
                    }
                    else
                    {
                        if (record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            if (!addedRecords.Remove(record))
                            {
                                if (!deletedRecords.Contains(record)) //check to prevent duplicate delete entries which Microsoft DNS Server may emit in IXFR response
                                    deletedRecords.Add(record);
                            }
                        }
                        else
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                case DnsResourceRecordType.AAAA:
                                    if (!addedGlueRecords.Remove(record))
                                    {
                                        if (!deletedGlueRecords.Contains(record)) //check to prevent duplicate delete entries
                                            deletedGlueRecords.Add(record);
                                    }

                                    break;
                            }
                        }
                    }

                    index++;
                }

                //read added records
                DnsResourceRecord addedSoaRecord = xfrRecords[index];
                if (!addedSoaRecord.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                lastAddedSoaRecord = addedSoaRecord;

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = xfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (zoneName.Length == 0)
                    {
                        //root zone case
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                if (!deletedGlueRecords.Remove(record))
                                {
                                    if (!addedGlueRecords.Contains(record)) //check to prevent duplicate add entries
                                        addedGlueRecords.Add(record);
                                }

                                break;

                            default:
                                if (!deletedRecords.Remove(record))
                                {
                                    if (!addedRecords.Contains(record)) //check to prevent duplicate add entries
                                        addedRecords.Add(record);
                                }

                                break;
                        }
                    }
                    else
                    {
                        if (record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            if (!deletedRecords.Remove(record))
                            {
                                if (!addedRecords.Contains(record)) //check to prevent duplicate add entries
                                    addedRecords.Add(record);
                            }
                        }
                        else
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                case DnsResourceRecordType.AAAA:
                                    if (!deletedGlueRecords.Remove(record))
                                    {
                                        if (!addedGlueRecords.Contains(record)) //check to prevent duplicate add entries
                                            addedGlueRecords.Add(record);
                                    }

                                    break;
                            }
                        }
                    }

                    index++;
                }

                //check sequence soa serial
                DnsSOARecordData deletedSoa = deletedSoaRecord.RDATA as DnsSOARecordData;

                if (currentSoa.Serial != deletedSoa.Serial)
                    throw new InvalidOperationException("Current SOA serial does not match with the IXFR difference sequence deleted SOA.");

                //check next difference sequence
                currentSoa = addedSoaRecord.RDATA as DnsSOARecordData;
            }

            //create condensed records
            List<DnsResourceRecord> condensedRecords = new List<DnsResourceRecord>(2 + 2 + deletedRecords.Count + deletedGlueRecords.Count + addedRecords.Count + addedGlueRecords.Count);

            condensedRecords.Add(firstSoaRecord);

            condensedRecords.Add(firstDeletedSoaRecord);
            condensedRecords.AddRange(deletedRecords);
            condensedRecords.AddRange(deletedGlueRecords);

            condensedRecords.Add(lastAddedSoaRecord);
            condensedRecords.AddRange(addedRecords);
            condensedRecords.AddRange(addedGlueRecords);

            condensedRecords.Add(lastSoaRecord);

            return condensedRecords;
        }

        internal void ImportRecords(string zoneName, IReadOnlyList<DnsResourceRecord> records, bool overwriteRecords, bool overwriteZone, bool overwriteSoaSerial)
        {
            _ = _root.FindZone(zoneName, out _, out _, out ApexZone apexZone, out _);
            if ((apexZone is null) || !apexZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                throw new DnsServerException("No such zone was found: " + zoneName);

            if ((apexZone is not PrimaryZone) && (apexZone is not ForwarderZone))
                throw new DnsServerException("Zone must be a primary or forwarder type: " + apexZone.ToString());

            if (overwriteZone)
            {
                //remove all existing records from the zone
                DeleteAllRecords(zoneName);

                overwriteRecords = true; //set to true for optimization
            }

            List<DnsResourceRecord> soaRRSet = null;

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> zoneEntry in DnsResourceRecord.GroupRecords(records))
            {
                if (zoneName.Equals(zoneEntry.Key, StringComparison.OrdinalIgnoreCase))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                    {
                        switch (rrsetEntry.Key)
                        {
                            case DnsResourceRecordType.CNAME:
                            case DnsResourceRecordType.DNAME:
                                apexZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                                break;

                            case DnsResourceRecordType.SOA:
                                if (!overwriteSoaSerial)
                                    rrsetEntry.Value[0].GetAuthSOARecordInfo().UseSoaSerialDateScheme = apexZone.GetRecords(DnsResourceRecordType.SOA)[0].GetAuthSOARecordInfo().UseSoaSerialDateScheme;

                                apexZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                                soaRRSet = rrsetEntry.Value;
                                break;

                            default:
                                if (overwriteRecords)
                                {
                                    apexZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                                }
                                else
                                {
                                    foreach (DnsResourceRecord record in rrsetEntry.Value)
                                        apexZone.AddRecord(record);
                                }
                                break;
                        }
                    }
                }
                else
                {
                    ValidateIfDomainBelongsToZone(zoneName, zoneEntry.Key);

                    AuthZone authZone = GetOrAddSubDomainZone(zoneName, zoneEntry.Key);

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                    {
                        switch (rrsetEntry.Key)
                        {
                            case DnsResourceRecordType.CNAME:
                            case DnsResourceRecordType.DNAME:
                            case DnsResourceRecordType.SOA:
                                authZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                                break;

                            default:
                                if (overwriteRecords)
                                {
                                    authZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                                }
                                else
                                {
                                    foreach (DnsResourceRecord record in rrsetEntry.Value)
                                        authZone.AddRecord(record);
                                }
                                break;
                        }
                    }

                    if (authZone is SubDomainZone subDomainZone)
                        subDomainZone.AutoUpdateState();
                }
            }

            if (overwriteSoaSerial && (soaRRSet is not null) && ((apexZone is PrimaryZone) || (apexZone is ForwarderZone)))
                apexZone.SetSoaSerial((soaRRSet[0].RDATA as DnsSOARecordData).Serial);

            SaveZoneFile(apexZone.Name);
        }

        #endregion

        #region query processing

        public DnsDatagram QueryClosestDelegation(DnsDatagram request)
        {
            _ = _root.FindZone(request.Question[0].Name, out _, out SubDomainZone delegation, out ApexZone apexZone, out _);
            if (delegation is not null)
            {
                bool dnssecOk = request.DnssecOk && (apexZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned);

                return GetReferralResponse(request, dnssecOk, delegation, apexZone);
            }

            if (apexZone is StubZone)
                return GetReferralResponse(request, false, apexZone, apexZone);

            //no delegation found
            return null;
        }

        public async Task<DnsDatagram> QueryAsync(DnsDatagram request, IPAddress remoteIP, bool isRecursionAllowed)
        {
            AuthZone zone = _root.FindZone(request.Question[0].Name, out SubDomainZone closest, out SubDomainZone delegation, out ApexZone apexZone, out bool hasSubDomains);

            if ((apexZone is null) || !apexZone.IsActive)
                return null; //no authority for requested zone

            if (!await IsQueryAllowedAsync(apexZone, remoteIP))
                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Question);

            return InternalQuery(request, isRecursionAllowed, zone, closest, delegation, apexZone, hasSubDomains);
        }

        public DnsDatagram Query(DnsDatagram request, bool isRecursionAllowed)
        {
            AuthZone zone = _root.FindZone(request.Question[0].Name, out SubDomainZone closest, out SubDomainZone delegation, out ApexZone apexZone, out bool hasSubDomains);

            if ((apexZone is null) || !apexZone.IsActive)
                return null; //no authority for requested zone

            return InternalQuery(request, isRecursionAllowed, zone, closest, delegation, apexZone, hasSubDomains);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private DnsDatagram InternalQuery(DnsDatagram request, bool isRecursionAllowed, AuthZone zone, SubDomainZone closest, SubDomainZone delegation, ApexZone apexZone, bool hasSubDomains)
        {
            DnsQuestionRecord question = request.Question[0];
            bool dnssecOk = request.DnssecOk && (apexZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned);

            if ((zone is null) || !zone.IsActive)
            {
                //zone not found
                if ((delegation is not null) && delegation.IsActive && (delegation.Name.Length > apexZone.Name.Length))
                    return GetReferralResponse(request, dnssecOk, delegation, apexZone);

                if (apexZone is StubZone)
                    return GetReferralResponse(request, false, apexZone, apexZone);

                DnsResponseCode rCode = DnsResponseCode.NoError;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                if (closest is not null)
                {
                    answer = closest.QueryRecords(DnsResourceRecordType.DNAME, dnssecOk);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, dnssecOk, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                    else
                    {
                        answer = null;
                        authority = closest.QueryRecords(DnsResourceRecordType.APP, false);
                    }
                }

                if (((answer is null) || (answer.Count == 0)) && ((authority is null) || (authority.Count == 0)))
                {
                    answer = apexZone.QueryRecords(DnsResourceRecordType.DNAME, dnssecOk);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, dnssecOk, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                    else
                    {
                        answer = null;
                        authority = apexZone.QueryRecords(DnsResourceRecordType.APP, false);
                        if (authority.Count == 0)
                        {
                            if ((apexZone is ForwarderZone) || (apexZone is SecondaryForwarderZone))
                                return GetForwarderResponse(request, null, closest, apexZone); //no DNAME or APP record available so process FWD response

                            if (!hasSubDomains)
                                rCode = DnsResponseCode.NxDomain;

                            authority = apexZone.QueryRecords(DnsResourceRecordType.SOA, dnssecOk);

                            if (dnssecOk)
                            {
                                //add proof of non existence to prove the qname does not have a RRset of its own.
                                //When hasSubDomains is true, qname is an empty non-terminal (rCode stays NoError
                                //above) rather than a genuinely non-existent name - RFC 4035 2.3 forbids creating
                                //an NSEC record for an ENT, so the covering NSEC from the closest real predecessor
                                //is the only proof available, and the wildcard-disproof step that would normally
                                //follow must be skipped: the wildcard name it computes from qname can itself be a
                                //real, existing record (the ENT's own child), and asserting its non-existence is
                                //simply wrong. NSEC3 is unaffected: an ENT always gets its own NSEC3 record
                                //(RFC 5155 7.1), so a genuine ENT never reaches this "zone not found" branch.
                                IReadOnlyList<DnsResourceRecord> nsecRecords;

                                if (apexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
                                    nsecRecords = _root.FindNSec3ProofOfNonExistenceNxDomain(question.Name, false);
                                else
                                    nsecRecords = _root.FindNSecProofOfNonExistenceNxDomain(question.Name, hasSubDomains);

                                if (nsecRecords.Count > 0)
                                {
                                    List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(authority.Count + nsecRecords.Count);

                                    newAuthority.AddRange(authority);
                                    newAuthority.AddRange(nsecRecords);

                                    authority = newAuthority;
                                }
                            }
                        }
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, rCode, request.Question, answer, authority);
            }
            else
            {
                //zone found
                if (question.Type == DnsResourceRecordType.DS)
                {
                    if (zone is ApexZone)
                    {
                        if ((delegation is null) || !delegation.IsActive || !delegation.AuthoritativeZone.IsActive || (delegation.Name.Length > apexZone.Name.Length))
                            return null; //no authoritative parent side delegation zone available to answer for DS

                        zone = delegation; //switch zone to parent side sub domain delegation zone for DS record

                        if (request.DnssecOk)
                            dnssecOk = delegation.AuthoritativeZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned;
                    }
                }
                else if ((delegation is not null) && delegation.IsActive && (delegation.Name.Length > apexZone.Name.Length))
                {
                    //zone is delegation
                    return GetReferralResponse(request, dnssecOk, delegation, apexZone);
                }

                DnsResponseCode rCode = DnsResponseCode.NoError;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;
                IReadOnlyList<DnsResourceRecord> additional = null;
                IReadOnlyList<EDnsOption> eDnsOptions = null;

                if (closest is not null)
                {
                    answer = closest.QueryRecords(DnsResourceRecordType.DNAME, dnssecOk);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, dnssecOk, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                }

                if (((answer is null) || (answer.Count == 0)) && (question.Name.Length > apexZone.Name.Length))
                {
                    //query for DNAME only for subdomain names
                    answer = apexZone.QueryRecords(DnsResourceRecordType.DNAME, dnssecOk);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, dnssecOk, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                }

                if ((answer is null) || (answer.Count == 0))
                {
                    answer = zone.QueryRecords(question.Type, dnssecOk);
                    if (answer.Count == 0)
                    {
                        //record type not found
                        if (question.Type == DnsResourceRecordType.DS)
                        {
                            //check for correct auth zone
                            if (apexZone.Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase))
                            {
                                //current auth zone is child side; find parent side auth zone for DS
                                string parentZone = GetParentZone(question.Name);
                                if (parentZone is null)
                                    parentZone = string.Empty;

                                _ = _root.FindZone(parentZone, out _, out _, out apexZone, out _);

                                if ((apexZone is null) || !apexZone.IsActive)
                                    return null; //no authority for requested zone
                            }
                        }
                        else
                        {
                            //check for delegation, stub & forwarder
                            if ((delegation is not null) && delegation.IsActive && (delegation.Name.Length > apexZone.Name.Length))
                                return GetReferralResponse(request, dnssecOk, delegation, apexZone);

                            if (apexZone is StubZone)
                                return GetReferralResponse(request, false, apexZone, apexZone);
                        }

                        authority = zone.QueryRecords(DnsResourceRecordType.APP, false);
                        if (authority.Count == 0)
                        {
                            if ((apexZone is ForwarderZone) || (apexZone is SecondaryForwarderZone))
                                return GetForwarderResponse(request, zone, closest, apexZone); //no APP record available so process FWD response

                            authority = apexZone.QueryRecords(DnsResourceRecordType.SOA, dnssecOk);

                            if (dnssecOk)
                            {
                                //add proof of non existence (NODATA) to prove that no such type or record exists
                                IReadOnlyList<DnsResourceRecord> nsecRecords;

                                if (apexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
                                    nsecRecords = _root.FindNSec3ProofOfNonExistenceNoData(question.Name, zone, apexZone);
                                else
                                    nsecRecords = _root.FindNSecProofOfNonExistenceNoData(question.Name, zone);

                                if (nsecRecords.Count > 0)
                                {
                                    List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(authority.Count + nsecRecords.Count);

                                    newAuthority.AddRange(authority);
                                    newAuthority.AddRange(nsecRecords);

                                    authority = newAuthority;
                                }
                            }
                        }

                        additional = null;
                    }
                    else
                    {
                        //record type found
                        if (zone.Name.StartsWith('*') && !zone.Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            //wildcard zone; generate new answer records
                            DnsResourceRecord[] wildcardAnswers = new DnsResourceRecord[answer.Count];

                            for (int i = 0; i < answer.Count; i++)
                                wildcardAnswers[i] = new DnsResourceRecord(question.Name, answer[i].Type, answer[i].Class, answer[i].TTL, answer[i].RDATA) { Tag = answer[i].Tag };

                            answer = wildcardAnswers;

                            //add proof of non existence (WILDCARD) to prove that the wildcard expansion was legit and the qname actually does not exists
                            if (dnssecOk)
                            {
                                IReadOnlyList<DnsResourceRecord> nsecRecords;

                                if (apexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
                                    nsecRecords = _root.FindNSec3ProofOfNonExistenceNxDomain(question.Name, true);
                                else
                                    nsecRecords = _root.FindNSecProofOfNonExistenceNxDomain(question.Name, true);

                                if (nsecRecords.Count > 0)
                                    authority = nsecRecords;
                            }
                        }

                        DnsResourceRecord lastRR = answer[answer.Count - 1];
                        if ((lastRR.Type != question.Type) && (question.Type != DnsResourceRecordType.ANY))
                        {
                            switch (lastRR.Type)
                            {
                                case DnsResourceRecordType.CNAME:
                                    List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answer.Count + 1);
                                    newAnswers.AddRange(answer);

                                    ResolveCNAME(question, dnssecOk, lastRR, newAnswers);

                                    answer = newAnswers;
                                    break;

                                case DnsResourceRecordType.ANAME:
                                case DnsResourceRecordType.ALIAS:
                                    authority = apexZone.GetRecords(DnsResourceRecordType.SOA); //adding SOA for use with NO DATA response
                                    break;
                            }
                        }

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.SOA:
                                if (request.EDNS is not null)
                                {
                                    //RFC 7314 EDNS EXPIRE option support
                                    if ((zone is PrimaryZone) || (zone is SecondaryZone && zone is not SecondaryForwarderZone))
                                    {
                                        foreach (EDnsOption option in request.EDNS.Options)
                                        {
                                            if ((option.Code == EDnsOptionCode.EDNS_EXPIRE) && (option.Data is EDnsExpireOptionData expireOptionData) && (expireOptionData.Expire is null))
                                            {
                                                if (zone is PrimaryZone primaryZone)
                                                {
                                                    DnsResourceRecord soaRecord = primaryZone.GetRecords(DnsResourceRecordType.SOA)[0];
                                                    DnsSOARecordData soa = soaRecord.RDATA as DnsSOARecordData;

                                                    eDnsOptions = [new EDnsOption(EDnsOptionCode.EDNS_EXPIRE, new EDnsExpireOptionData(soa.Expire))];
                                                }
                                                else if (zone is SecondaryZone secondaryZone)
                                                {
                                                    eDnsOptions = [new EDnsOption(EDnsOptionCode.EDNS_EXPIRE, new EDnsExpireOptionData(secondaryZone.CurrentExpireValue))];
                                                }

                                                break;
                                            }
                                        }
                                    }
                                }

                                break;

                            case DnsResourceRecordType.NS:
                            case DnsResourceRecordType.MX:
                            case DnsResourceRecordType.SRV:
                            case DnsResourceRecordType.SVCB:
                            case DnsResourceRecordType.HTTPS:
                                additional = GetAdditionalRecords(answer, dnssecOk);
                                break;

                            default:
                                additional = null;
                                break;
                        }
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, rCode, request.Question, answer, authority, additional, _dnsServer.UdpPayloadSize, dnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, eDnsOptions);
            }
        }

        private static async Task<bool> IsQueryAllowedAsync(ApexZone apexZone, IPAddress remoteIP)
        {
            async Task<bool> IsZoneNameServerAllowedAsync()
            {
                IReadOnlyList<NameServerAddress> zoneNameServers = await apexZone.GetAllResolvedNameServerAddressesAsync();

                foreach (NameServerAddress nameServer in zoneNameServers)
                {
                    if (nameServer.IPEndPoint.Address.Equals(remoteIP))
                        return true;
                }

                return false;
            }

            CatalogZone catalogZone = apexZone.CatalogZone;
            if (catalogZone is not null)
            {
                if (!apexZone.OverrideCatalogQueryAccess)
                    apexZone = catalogZone; //use catalog query access options
            }
            else
            {
                SecondaryCatalogZone secondaryCatalogZone = apexZone.SecondaryCatalogZone;
                if (secondaryCatalogZone is not null)
                {
                    if (!apexZone.OverrideCatalogQueryAccess)
                        apexZone = secondaryCatalogZone; //use secondary query access options
                }
            }

            switch (apexZone.QueryAccess)
            {
                case AuthZoneQueryAccess.Allow:
                    return true;

                case AuthZoneQueryAccess.AllowOnlyPrivateNetworks:
                    if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                        return true;

                    switch (remoteIP.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                        case AddressFamily.InterNetworkV6:
                            return NetUtilities.IsPrivateIP(remoteIP);

                        default:
                            return false;
                    }

                case AuthZoneQueryAccess.AllowOnlyZoneNameServers:
                    if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                        return true;

                    return await IsZoneNameServerAllowedAsync();

                case AuthZoneQueryAccess.UseSpecifiedNetworkACL:
                    if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                        return true;

                    return NetworkAccessControl.IsAddressAllowed(remoteIP, apexZone.QueryAccessNetworkACL);

                case AuthZoneQueryAccess.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                    if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                        return true;

                    return NetworkAccessControl.IsAddressAllowed(remoteIP, apexZone.QueryAccessNetworkACL) || await IsZoneNameServerAllowedAsync();

                default:
                    if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                        return true;

                    return false;
            }
        }

        private void ResolveCNAME(DnsQuestionRecord question, bool dnssecOk, DnsResourceRecord lastCNAME, List<DnsResourceRecord> answerRecords)
        {
            int queryCount = 0;

            do
            {
                string cnameDomain = (lastCNAME.RDATA as DnsCNAMERecordData).Domain;
                if (lastCNAME.Name.Equals(cnameDomain, StringComparison.OrdinalIgnoreCase))
                    break; //loop detected

                if (!_root.TryGet(cnameDomain, out AuthZoneNode zoneNode))
                    break;

                IReadOnlyList<DnsResourceRecord> records = zoneNode.QueryRecords(question.Type, dnssecOk);
                if (records.Count < 1)
                    break;

                DnsResourceRecord lastRR = records[records.Count - 1];
                if (lastRR.Type != DnsResourceRecordType.CNAME)
                {
                    answerRecords.AddRange(records);
                    break;
                }

                foreach (DnsResourceRecord answerRecord in answerRecords)
                {
                    if (answerRecord.Type != DnsResourceRecordType.CNAME)
                        continue;

                    if (answerRecord.RDATA.Equals(lastRR.RDATA))
                        return; //loop detected
                }

                answerRecords.AddRange(records);

                lastCNAME = lastRR;
            }
            while (++queryCount < DnsServer.MAX_CNAME_HOPS);
        }

        private bool DoDNAMESubstitution(DnsQuestionRecord question, bool dnssecOk, IReadOnlyList<DnsResourceRecord> answer, out IReadOnlyList<DnsResourceRecord> newAnswer)
        {
            DnsResourceRecord dnameRR = answer[0];

            string result = (dnameRR.RDATA as DnsDNAMERecordData).Substitute(question.Name, dnameRR.Name);

            if (DnsClient.IsDomainNameValid(result))
            {
                DnsResourceRecord cnameRR = new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, question.Class, dnameRR.TTL, new DnsCNAMERecordData(result));

                List<DnsResourceRecord> list = new List<DnsResourceRecord>(5);

                list.AddRange(answer);
                list.Add(cnameRR);

                ResolveCNAME(question, dnssecOk, cnameRR, list);

                newAnswer = list;
                return true;
            }
            else
            {
                newAnswer = answer;
                return false;
            }
        }

        private List<DnsResourceRecord> GetAdditionalRecords(IReadOnlyList<DnsResourceRecord> refRecords, bool dnssecOk)
        {
            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>(refRecords.Count);

            foreach (DnsResourceRecord refRecord in refRecords)
            {
                switch (refRecord.Type)
                {
                    case DnsResourceRecordType.NS:
                        IReadOnlyList<DnsResourceRecord> glueRecords = refRecord.GetAuthNSRecordInfo().GlueRecords;
                        if (glueRecords is not null)
                        {
                            additionalRecords.AddRange(glueRecords);
                        }
                        else
                        {
                            ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsNSRecordData).NameServer, dnssecOk, additionalRecords);
                        }
                        break;

                    case DnsResourceRecordType.MX:
                        ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsMXRecordData).Exchange, dnssecOk, additionalRecords);
                        break;

                    case DnsResourceRecordType.SRV:
                        ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsSRVRecordData).Target, dnssecOk, additionalRecords);
                        break;

                    case DnsResourceRecordType.SVCB:
                    case DnsResourceRecordType.HTTPS:
                        DnsSVCBRecordData svcb = refRecord.RDATA as DnsSVCBRecordData;
                        string targetName = svcb.TargetName;

                        if (svcb.SvcPriority == 0)
                        {
                            //For AliasMode SVCB RRs, a TargetName of "." indicates that the service is not available or does not exist [draft-ietf-dnsop-svcb-https-12]
                            if ((targetName.Length == 0) || targetName.Equals(refRecord.Name, StringComparison.OrdinalIgnoreCase))
                                break;
                        }
                        else
                        {
                            //For ServiceMode SVCB RRs, if TargetName has the value ".", then the owner name of this record MUST be used as the effective TargetName [draft-ietf-dnsop-svcb-https-12]
                            if (targetName.Length == 0)
                                targetName = refRecord.Name;
                        }

                        ResolveAdditionalRecords(refRecord, targetName, dnssecOk, additionalRecords);
                        break;
                }
            }

            return additionalRecords;
        }

        private void ResolveAdditionalRecords(DnsResourceRecord refRecord, string domain, bool dnssecOk, List<DnsResourceRecord> additionalRecords)
        {
            int count = 0;

            while (count++ < DnsServer.MAX_CNAME_HOPS)
            {
                AuthZone zone = _root.FindZone(domain, out _, out _, out _, out _);
                if ((zone is null) || !zone.IsActive)
                    break;

                if (((refRecord.Type == DnsResourceRecordType.SVCB) || (refRecord.Type == DnsResourceRecordType.HTTPS)) && ((refRecord.RDATA as DnsSVCBRecordData).SvcPriority == 0))
                {
                    //resolve SVCB/HTTPS for Alias mode refRecord
                    IReadOnlyList<DnsResourceRecord> records = zone.QueryRecordsWildcard(refRecord.Type, dnssecOk, domain);
                    if ((records.Count > 0) && (records[0].Type == refRecord.Type) && (records[0].RDATA is DnsSVCBRecordData svcb))
                    {
                        additionalRecords.AddRange(records);

                        string targetName = svcb.TargetName;

                        if (svcb.SvcPriority == 0)
                        {
                            //Alias mode
                            if ((targetName.Length == 0) || targetName.Equals(records[0].Name, StringComparison.OrdinalIgnoreCase))
                                break; //For AliasMode SVCB RRs, a TargetName of "." indicates that the service is not available or does not exist [draft-ietf-dnsop-svcb-https-12]

                            foreach (DnsResourceRecord additionalRecord in additionalRecords)
                            {
                                if (additionalRecord.Name.Equals(targetName, StringComparison.OrdinalIgnoreCase))
                                    return; //loop detected
                            }

                            //continue to resolve SVCB/HTTPS further
                            domain = targetName;
                            refRecord = records[0];
                            continue;
                        }
                        else
                        {
                            //Service mode
                            if (targetName.Length > 0)
                            {
                                //continue to resolve A/AAAA for target name
                                domain = targetName;
                                refRecord = records[0];
                                continue;
                            }

                            //resolve A/AAAA below
                        }
                    }
                }

                bool hasA = false;
                bool hasAAAA = false;

                if ((refRecord.Type == DnsResourceRecordType.SRV) || (refRecord.Type == DnsResourceRecordType.SVCB) || (refRecord.Type == DnsResourceRecordType.HTTPS))
                {
                    foreach (DnsResourceRecord additionalRecord in additionalRecords)
                    {
                        if (additionalRecord.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (additionalRecord.Type)
                            {
                                case DnsResourceRecordType.A:
                                    hasA = true;
                                    break;

                                case DnsResourceRecordType.AAAA:
                                    hasAAAA = true;
                                    break;
                            }
                        }

                        if (hasA && hasAAAA)
                            break;
                    }
                }

                if (!hasA)
                {
                    IReadOnlyList<DnsResourceRecord> records = zone.QueryRecordsWildcard(DnsResourceRecordType.A, dnssecOk, domain);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.A))
                        additionalRecords.AddRange(records);
                }

                if (!hasAAAA)
                {
                    IReadOnlyList<DnsResourceRecord> records = zone.QueryRecordsWildcard(DnsResourceRecordType.AAAA, dnssecOk, domain);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.AAAA))
                        additionalRecords.AddRange(records);
                }

                break;
            }
        }

        private DnsDatagram GetReferralResponse(DnsDatagram request, bool dnssecOk, AuthZone delegationZone, ApexZone apexZone)
        {
            IReadOnlyList<DnsResourceRecord> authority;

            if (delegationZone is StubZone)
            {
                authority = delegationZone.GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant query

                //update last used on
                DateTime utcNow = DateTime.UtcNow;

                foreach (DnsResourceRecord record in authority)
                    record.GetAuthGenericRecordInfo().LastUsedOn = utcNow;
            }
            else
            {
                authority = delegationZone.QueryRecords(DnsResourceRecordType.NS, false);

                if (dnssecOk)
                {
                    IReadOnlyList<DnsResourceRecord> dsRecords = delegationZone.QueryRecords(DnsResourceRecordType.DS, true);
                    if (dsRecords.Count > 0)
                    {
                        List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(authority.Count + dsRecords.Count);

                        newAuthority.AddRange(authority);
                        newAuthority.AddRange(dsRecords);

                        authority = newAuthority;
                    }
                    else
                    {
                        //add proof of non existence (NODATA) to prove DS record does not exists
                        IReadOnlyList<DnsResourceRecord> nsecRecords;

                        if (apexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
                            nsecRecords = _root.FindNSec3ProofOfNonExistenceNoData(request.Question[0].Name, delegationZone, apexZone);
                        else
                            nsecRecords = _root.FindNSecProofOfNonExistenceNoData(request.Question[0].Name, delegationZone);

                        if (nsecRecords.Count > 0)
                        {
                            List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(authority.Count + nsecRecords.Count);

                            newAuthority.AddRange(authority);
                            newAuthority.AddRange(nsecRecords);

                            authority = newAuthority;
                        }
                    }
                }
            }

            IReadOnlyList<DnsResourceRecord> additional = GetAdditionalRecords(authority, dnssecOk);

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, null, authority, additional);
        }

        private DnsDatagram GetForwarderResponse(DnsDatagram request, AuthZone zone, SubDomainZone closestZone, ApexZone forwarderZone)
        {
            IReadOnlyList<DnsResourceRecord> authority = null;

            if (zone is not null)
            {
                if (zone.ContainsNameServerRecords())
                    return GetReferralResponse(request, false, zone, forwarderZone);

                authority = zone.QueryRecords(DnsResourceRecordType.FWD, false);
            }

            if (((authority is null) || (authority.Count == 0)) && (closestZone is not null))
            {
                if (closestZone.ContainsNameServerRecords())
                    return GetReferralResponse(request, false, closestZone, forwarderZone);

                authority = closestZone.QueryRecords(DnsResourceRecordType.FWD, false);
            }

            if ((authority is null) || (authority.Count == 0))
            {
                if (forwarderZone.ContainsNameServerRecords())
                    return GetReferralResponse(request, false, forwarderZone, forwarderZone);

                authority = forwarderZone.QueryRecords(DnsResourceRecordType.FWD, false);
            }

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, null, authority);
        }

        #endregion

        #region properties

        public uint DefaultRecordTtl
        {
            get { return _defaultRecordTtl; }
            set { _defaultRecordTtl = value; }
        }

        public uint DefaultNsRecordTtl
        {
            get { return _defaultNsRecordTtl; }
            set { _defaultNsRecordTtl = value; }
        }

        public uint DefaultSoaRecordTtl
        {
            get { return _defaultSoaRecordTtl; }
            set { _defaultSoaRecordTtl = value; }
        }

        public bool UseSoaSerialDateScheme
        {
            get { return _useSoaSerialDateScheme; }
            set { _useSoaSerialDateScheme = value; }
        }

        public uint MinSoaRefresh
        {
            get { return _minSoaRefresh; }
            set { _minSoaRefresh = value; }
        }

        public uint MinSoaRetry
        {
            get { return _minSoaRetry; }
            set { _minSoaRetry = value; }
        }

        public int TotalZones
        { get { return _zoneIndex.Count; } }

        #endregion
    }
}
