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

using DnsServerCore.Configuration;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class BlockedZoneManager
    {
        #region variables

        readonly DnsServer _dnsServer;

        AuthZoneManager _zoneManager;

        readonly DnsSOARecordDataExtended _soaRecord;
        readonly DnsNSRecordDataExtended _nsRecord;

        readonly Lock _saveLock = new Lock();
        bool _pendingSave;
        internal bool ManifestOwnsList { get; private set; }
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        public BlockedZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _zoneManager = new AuthZoneManager(_dnsServer);

            _soaRecord = new DnsSOARecordDataExtended(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, _dnsServer.BlockingAnswerTtl);
            _nsRecord = new DnsNSRecordDataExtended(_dnsServer.ServerDomain);

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveZoneFileInternal();
                            _pendingSave = false;
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

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave)
                {
                    try
                    {
                        SaveZoneFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            _disposed = true;
        }

        #endregion

        #region zone file

        public void LoadBlockedZoneFile()
        {
            string blockedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "blocked.config");

            try
            {
                string oldCustomBlockedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "custom-blocked.config");
                if (File.Exists(oldCustomBlockedZoneFile))
                {
                    if (File.Exists(blockedZoneFile))
                        File.Delete(blockedZoneFile);

                    File.Move(oldCustomBlockedZoneFile, blockedZoneFile);
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }

            try
            {
                using (FileStream fS = new FileStream(blockedZoneFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS, readOwnership: true);
                }

                _dnsServer.LogManager.Write("DNS Server blocked zone file was loaded: " + blockedZoneFile);
            }
            catch (FileNotFoundException)
            {
                SaveZoneFileInternal();
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server encountered an error while loading blocked zone file: " + blockedZoneFile, ex);
            }
        }

        public void LoadBlockedZone(Stream s)
        {
            lock (_saveLock)
            {
                ReadConfigFrom(s);

                SaveZoneFileInternal();
                _pendingSave = false;
            }
        }

        private void SaveZoneFileInternal(IReadOnlyList<string> names = null, bool? managed = null)
        {
            string tmpBlockedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "blocked.tmp");
            string blockedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "blocked.config");

            using (FileStream fS = new FileStream(tmpBlockedZoneFile, FileMode.Create, FileAccess.Write))
            {
                ConfigurationDomainLists.WriteStore(fS, "BZ", names ?? GetManifestNames(), managed ?? ManifestOwnsList);
                fS.Flush(flushToDisk: true);
            }

            File.Move(tmpBlockedZoneFile, blockedZoneFile, true);

            _dnsServer.LogManager.Write("DNS Server blocked zone file was saved: " + blockedZoneFile);
        }

        public void SaveZoneFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void ReadConfigFrom(Stream s, bool readOwnership = false)
        {
            var (names, managed) = ConfigurationDomainLists.ReadStore(s, "BZ");
            if (!readOwnership && ManifestOwnsList && !GetManifestNames().SequenceEqual(names.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)))
                ConfigurationDomainLists.RejectManagedChange("/blockZones");

            _zoneManager = BuildList(names);
            if (readOwnership)
                ManifestOwnsList = managed;
        }

        internal string[] GetManifestNames() =>
            _zoneManager.GetAllZones().Select(zone => zone.Name).Order(StringComparer.Ordinal).ToArray();

        internal void CheckRestoreManifestList(Stream stream)
        {
            var (names, _) = ConfigurationDomainLists.ReadStore(stream, "BZ");
            if (ManifestOwnsList && !GetManifestNames().SequenceEqual(names.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)))
                ConfigurationDomainLists.RejectManagedChange("/blockZones");
        }

        private AuthZoneManager BuildList(IReadOnlyList<string> names)
        {
            var manager = new AuthZoneManager(_dnsServer);
            manager.LoadSpecialPrimaryZones(names, _soaRecord, _nsRecord);
            return manager;
        }

        internal void ApplyManifestList(string[] names, Action<Action> persist)
        {
            lock (_saveLock)
            {
                string[] current = GetManifestNames();
                bool managed = names is not null;
                bool changed = managed && !current.SequenceEqual(names);
                if (!changed && managed == ManifestOwnsList)
                {
                    persist(null);
                    return;
                }

                AuthZoneManager candidate = changed ? BuildList(names) : null;
                try
                {
                    persist(() => SaveZoneFileInternal(names ?? current, managed));
                }
                catch
                {
                    candidate?.Dispose();
                    throw;
                }
                if (candidate is not null)
                    _zoneManager = candidate;
                ManifestOwnsList = managed;
                _pendingSave = false;
            }
        }

        #endregion

        #region private

        internal void UpdateServerDomain()
        {
            _soaRecord.UpdatePrimaryNameServerAndMinimum(_dnsServer.ServerDomain, _dnsServer.BlockingAnswerTtl);
            _nsRecord.UpdateNameServer(_dnsServer.ServerDomain);
        }

        #endregion

        #region public

        public void ImportZones(string[] domains)
        {
            if (ManifestOwnsList)
            {
                var current = GetManifestNames().ToHashSet(StringComparer.Ordinal);
                if (domains.Any(domain => !current.Contains(ConfigurationDomainLists.Normalize(domain, "/blockZones"))))
                    ConfigurationDomainLists.RejectManagedChange("/blockZones");
                return;
            }
            _zoneManager.LoadSpecialPrimaryZones(domains, _soaRecord, _nsRecord);
        }

        public bool BlockZone(string domain)
        {
            if (ManifestOwnsList)
            {
                if (!GetManifestNames().Contains(ConfigurationDomainLists.Normalize(domain, "/blockZones"), StringComparer.Ordinal))
                    ConfigurationDomainLists.RejectManagedChange("/blockZones");
                return false;
            }
            if (_zoneManager.CreateSpecialPrimaryZone(domain, _soaRecord, _nsRecord) != null)
                return true;

            return false;
        }

        public bool DeleteZone(string domain)
        {
            if (ManifestOwnsList)
            {
                if (GetManifestNames().Contains(ConfigurationDomainLists.Normalize(domain, "/blockZones"), StringComparer.Ordinal))
                    ConfigurationDomainLists.RejectManagedChange("/blockZones");
                return false;
            }
            if (_zoneManager.DeleteZone(domain))
                return true;

            return false;
        }

        public void Flush()
        {
            if (ManifestOwnsList && GetManifestNames().Length != 0)
                ConfigurationDomainLists.RejectManagedChange("/blockZones");
            _zoneManager.Flush();
        }

        public IReadOnlyList<AuthZoneInfo> GetAllZones()
        {
            return _zoneManager.GetAllZones();
        }

        public void ListAllRecords(string domain, List<DnsResourceRecord> records)
        {
            _zoneManager.ListAllRecords(domain, domain, records);
        }

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            _zoneManager.ListSubDomains(domain, subDomains);
        }

        public DnsDatagram Query(DnsDatagram request)
        {
            if (_zoneManager.TotalZones < 1)
                return null;

            return _zoneManager.Query(request, false);
        }

        #endregion

        #region properties

        internal DnsSOARecordData DnsSOARecord
        { get { return _soaRecord; } }

        public int TotalZonesBlocked
        { get { return _zoneManager.TotalZones; } }

        #endregion
    }
}
