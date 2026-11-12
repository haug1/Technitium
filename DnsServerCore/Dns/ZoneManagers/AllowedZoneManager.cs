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
    public sealed class AllowedZoneManager : IDisposable
    {
        #region variables

        readonly DnsServer _dnsServer;

        AuthZoneManager _zoneManager;

        readonly DnsSOARecordDataExtended _soaRecord;
        readonly DnsNSRecordDataExtended _nsRecord;

        readonly Lock _saveLock = new Lock();
        bool _pendingSave;
        private ConfigurationDomainLists.Ownership _ownership;
        internal bool ManifestOwnsList => _ownership != ConfigurationDomainLists.Ownership.None;
        internal bool ManifestOwnershipFromPrimary => _ownership == ConfigurationDomainLists.Ownership.Primary;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        public AllowedZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _zoneManager = new AuthZoneManager(_dnsServer);

            _soaRecord = new DnsSOARecordDataExtended(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 900, 300, 604800, 60);
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

        public void LoadAllowedZoneFile()
        {
            string allowedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "allowed.config");

            try
            {
                using (FileStream fS = new FileStream(allowedZoneFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS);
                }

                _dnsServer.LogManager.Write("DNS Server allowed zone file was loaded: " + allowedZoneFile);
            }
            catch (FileNotFoundException)
            {
                SaveZoneFileInternal();
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server encountered an error while loading allowed zone file: " + allowedZoneFile, ex);
            }
        }

        public void LoadAllowedZone(Stream s) => LoadAllowedZone(s, isConfigTransfer: false);

        internal void LoadAllowedZone(Stream s, bool isConfigTransfer)
        {
            lock (_saveLock)
            {
                var (names, owner) = ConfigurationDomainLists.ReadStore(s, "AZ");
                CheckRestoreManifestList(names, isConfigTransfer);
                var ownership = _ownership;
                if (isConfigTransfer && ownership != ConfigurationDomainLists.Ownership.Local)
                    ownership = owner == ConfigurationDomainLists.Ownership.None ? owner : ConfigurationDomainLists.Ownership.Primary;
                AuthZoneManager candidate = BuildList(names);
                try
                {
                    SaveZoneFileInternal(GetManifestNames(candidate), ownership);
                }
                catch
                {
                    candidate.Dispose();
                    throw;
                }
                _zoneManager = candidate;
                _ownership = ownership;
                _pendingSave = false;
            }
        }

        private void SaveZoneFileInternal(IReadOnlyList<string> names = null, ConfigurationDomainLists.Ownership? ownership = null)
        {
            string tmpAllowedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "allowed.tmp");
            string allowedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "allowed.config");

            using (FileStream fS = new FileStream(tmpAllowedZoneFile, FileMode.Create, FileAccess.Write))
            {
                ConfigurationDomainLists.WriteStore(fS, "AZ", names ?? GetManifestNames(), ownership ?? _ownership);
                fS.Flush(flushToDisk: true);
            }

            File.Move(tmpAllowedZoneFile, allowedZoneFile, true);

            _dnsServer.LogManager.Write("DNS Server allowed zone file was saved: " + allowedZoneFile);
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

        private void ReadConfigFrom(Stream s)
        {
            var (names, ownership) = ConfigurationDomainLists.ReadStore(s, "AZ");
            _zoneManager = BuildList(names);
            _ownership = ownership;
        }

        internal string[] GetManifestNames() => GetManifestNames(_zoneManager);

        private static string[] GetManifestNames(AuthZoneManager manager) =>
            manager.GetAllZones().Select(zone => zone.Name).Order(StringComparer.Ordinal).ToArray();

        internal void CheckRestoreManifestList(Stream stream, bool isConfigTransfer = false)
        {
            var (names, _) = ConfigurationDomainLists.ReadStore(stream, "AZ");
            CheckRestoreManifestList(names, isConfigTransfer);
        }

        private void CheckRestoreManifestList(string[] names, bool isConfigTransfer)
        {
            if (ManifestOwnsList && (!isConfigTransfer || _ownership == ConfigurationDomainLists.Ownership.Local) &&
                !GetManifestNames().SequenceEqual(names.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)))
                ConfigurationDomainLists.RejectManagedChange("/allowZones");
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
                var ownership = names is null ? ConfigurationDomainLists.Ownership.None : ConfigurationDomainLists.Ownership.Local;
                bool changed = names is not null && !current.SequenceEqual(names);
                if (!changed && ownership == _ownership)
                {
                    persist(null);
                    return;
                }

                AuthZoneManager candidate = changed ? BuildList(names) : null;
                try
                {
                    persist(() => SaveZoneFileInternal(names ?? current, ownership));
                }
                catch
                {
                    candidate?.Dispose();
                    throw;
                }
                if (candidate is not null)
                    _zoneManager = candidate;
                _ownership = ownership;
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
                if (domains.Any(domain => !current.Contains(ConfigurationDomainLists.Normalize(domain, "/allowZones"))))
                    ConfigurationDomainLists.RejectManagedChange("/allowZones");
                return;
            }
            _zoneManager.LoadSpecialPrimaryZones(domains, _soaRecord, _nsRecord);
        }

        public bool AllowZone(string domain)
        {
            if (ManifestOwnsList)
            {
                if (!GetManifestNames().Contains(ConfigurationDomainLists.Normalize(domain, "/allowZones"), StringComparer.Ordinal))
                    ConfigurationDomainLists.RejectManagedChange("/allowZones");
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
                if (GetManifestNames().Contains(ConfigurationDomainLists.Normalize(domain, "/allowZones"), StringComparer.Ordinal))
                    ConfigurationDomainLists.RejectManagedChange("/allowZones");
                return false;
            }
            if (_zoneManager.DeleteZone(domain))
                return true;

            return false;
        }

        public void Flush()
        {
            if (ManifestOwnsList && GetManifestNames().Length != 0)
                ConfigurationDomainLists.RejectManagedChange("/allowZones");
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

        public bool IsAllowed(DnsDatagram request)
        {
            if (_zoneManager.TotalZones < 1)
                return false;

            return _zoneManager.Query(request, false) is not null;
        }

        #endregion

        #region properties

        public int TotalZonesAllowed
        { get { return _zoneManager.TotalZones; } }

        #endregion
    }
}
