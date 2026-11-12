/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class CatalogZone : ForwarderZone
    {
        #region variables

        readonly Dictionary<string, string> _membersIndex = new Dictionary<string, string>();
        readonly ReaderWriterLockSlim _membersIndexLock = new ReaderWriterLockSlim();
        Action<string, DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> _manifestPropertyWriter;

        #endregion

        #region constructor

        public CatalogZone(DnsServer dnsServer, AuthZoneInfo zoneInfo, bool initializeTimers = true)
            : base(dnsServer, zoneInfo, initializeTimers)
        { }

        public CatalogZone(DnsServer dnsServer, string name, bool initializeTimers = true)
            : base(dnsServer, name, initializeTimers)
        { }

        #endregion

        #region IDisposable

        protected override void Dispose(bool disposing)
        {
            try
            {
                _membersIndexLock.Dispose();
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        #endregion

        #region internal

        internal override void InitZone()
        {
            //init catalog zone with dummy SOA and NS records
            DnsSOARecordData soa = new DnsSOARecordData("invalid", "invalid", 1, 300, 60, 604800, 900);
            DnsResourceRecord soaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, 0, soa);
            soaRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

            _entries[DnsResourceRecordType.SOA] = [soaRecord];
            _entries[DnsResourceRecordType.NS] = [new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, 0, new DnsNSRecordData("invalid"))];
        }

        internal void InitZoneProperties()
        {
            //set catalog zone version record
            string version = "version." + _name;
            WritePropertyRecords(version, DnsResourceRecordType.TXT, [new DnsResourceRecord(version, DnsResourceRecordType.TXT, DnsClass.IN, 0, new DnsTXTRecordData("2"))]);

            //init catalog global properties
            QueryAccess = AuthZoneQueryAccess.Allow;
            ZoneTransfer = AuthZoneTransfer.Deny;
        }

        internal void ApplyManifestPolicies(ConfigurationZonePolicies.Changes policies, bool initialize,
            Action<string, DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> write)
        {
            // The manifest transaction journals generated RRsets with the zone metadata.
            _manifestPropertyWriter = write;
            try
            {
                if (initialize)
                    InitZoneProperties();
                policies.Apply(new AuthZoneInfo(this));
                if (policies.QueryAcl is not null && !policies.QueryAccess.HasValue)
                    QueryAccess = QueryAccess;
                if (policies.TransferAcl is not null && !policies.Transfer.HasValue)
                    ZoneTransfer = ZoneTransfer;
            }
            finally
            {
                _manifestPropertyWriter = null;
            }
        }

        private void WritePropertyRecords(string name, DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (_manifestPropertyWriter is not null)
                _manifestPropertyWriter(name, type, records);
            else if (records.Count == 0)
                _dnsServer.AuthZoneManager.DeleteRecords(_name, name, type);
            else
                _dnsServer.AuthZoneManager.SetRecords(_name, records);
        }

        internal void BuildMembersIndex()
        {
            foreach (KeyValuePair<string, string> memberEntry in EnumerateCatalogMemberZones(_dnsServer))
                _membersIndex.TryAdd(memberEntry.Key.ToLowerInvariant(), memberEntry.Value);
        }

        #endregion

        #region catalog

        public void AddMemberZone(string memberZoneName, AuthZoneType zoneType)
        {
            memberZoneName = memberZoneName.ToLowerInvariant();

            _membersIndexLock.EnterWriteLock();
            try
            {
                if (_membersIndex.TryGetValue(memberZoneName, out _))
                {
                    if (_membersIndex.Remove(memberZoneName, out string removedMemberZoneDomain))
                    {
                        foreach (DnsResourceRecord record in _dnsServer.AuthZoneManager.EnumerateAllRecords(_name, removedMemberZoneDomain, true))
                            _dnsServer.AuthZoneManager.DeleteRecord(_name, record);
                    }
                }

                var (memberZoneDomain, records) = CreateMemberRecords(memberZoneName, zoneType);
                foreach (var record in records)
                    _dnsServer.AuthZoneManager.AddRecord(_name, record);

                _membersIndex[memberZoneName] = memberZoneDomain;
            }
            finally
            {
                _membersIndexLock.ExitWriteLock();
            }
        }

        internal (string Domain, DnsResourceRecord[] Records) CreateMemberRecords(string member, AuthZoneType type)
        {
            string domain = GetDomainWithLabel("zones." + _name);
            var pointer = new DnsResourceRecord(domain, DnsResourceRecordType.PTR, DnsClass.IN, 0, new DnsPTRRecordData(member));
            var kind = new DnsResourceRecord("zone-type.ext." + domain, DnsResourceRecordType.TXT, DnsClass.IN, 0,
                new DnsTXTRecordData(type.ToString().ToLowerInvariant()));
            pointer.GetAuthGenericRecordInfo().LastModified = kind.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;
            return (domain, [pointer, kind]);
        }

        internal void RebuildManifestMembersIndex()
        {
            _membersIndexLock.EnterWriteLock();
            try
            {
                _membersIndex.Clear();
                BuildMembersIndex();
            }
            finally
            {
                _membersIndexLock.ExitWriteLock();
            }
        }

        public bool RemoveMemberZone(string memberZoneName)
        {
            memberZoneName = memberZoneName.ToLowerInvariant();

            _membersIndexLock.EnterWriteLock();
            try
            {
                if (_membersIndex.Remove(memberZoneName, out string removedMemberZoneDomain))
                {
                    foreach (DnsResourceRecord record in _dnsServer.AuthZoneManager.EnumerateAllRecords(_name, removedMemberZoneDomain, true))
                        _dnsServer.AuthZoneManager.DeleteRecord(_name, record);

                    return true;
                }

                return false;
            }
            finally
            {
                _membersIndexLock.ExitWriteLock();
            }
        }

        public void ChangeMemberZoneOwnership(string memberZoneName, string newCatalogZoneName)
        {
            string memberZoneDomain = GetMemberZoneDomain(memberZoneName);
            DateTime utcNow = DateTime.UtcNow;
            uint soaExpiry = GetZoneSoaExpire();
            _dnsServer.AuthZoneManager.SetRecord(_name, CreateChangeOfOwnershipRecord(memberZoneDomain, newCatalogZoneName, utcNow, soaExpiry));

            //set expiry for other member zone records
            foreach (DnsResourceRecord record in _dnsServer.AuthZoneManager.EnumerateAllRecords(_name, memberZoneDomain, true))
            {
                GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                recordInfo.LastModified = utcNow;
                recordInfo.ExpiryTtl = soaExpiry;
            }
        }

        internal static DnsResourceRecord CreateChangeOfOwnershipRecord(string memberDomain, string catalogName, DateTime timestamp, uint expiry)
        {
            var record = new DnsResourceRecord("coo." + memberDomain, DnsResourceRecordType.PTR, DnsClass.IN, 0, new DnsPTRRecordData(catalogName));
            GenericRecordInfo info = record.GetAuthGenericRecordInfo();
            info.LastModified = timestamp;
            info.ExpiryTtl = expiry;
            return record;
        }

        public IReadOnlyCollection<string> GetAllMemberZoneNames()
        {
            _membersIndexLock.EnterReadLock();
            try
            {
                return _membersIndex.Keys.ToArray();
            }
            finally
            {
                _membersIndexLock.ExitReadLock();
            }
        }

        public AuthZoneType GetZoneTypeProperty(string memberZoneName)
        {
            string domain = "zone-type.ext." + GetMemberZoneDomain(memberZoneName);

            IReadOnlyList<DnsResourceRecord> records = _dnsServer.AuthZoneManager.GetRecords(_name, domain, DnsResourceRecordType.TXT);
            if (records.Count > 0)
                return Enum.Parse<AuthZoneType>((records[0].RDATA as DnsTXTRecordData).GetText(), true);

            return AuthZoneType.Primary;
        }

        public void SetAllowQueryProperty(IReadOnlyCollection<NetworkAccessControl> acl = null, string memberZoneName = null) =>
            WriteAccessProperty("allow-query.ext." + GetMemberZoneDomain(memberZoneName), acl);

        public void SetAllowTransferProperty(IReadOnlyCollection<NetworkAccessControl> acl = null, string memberZoneName = null) =>
            WriteAccessProperty("allow-transfer.ext." + GetMemberZoneDomain(memberZoneName), acl);

        private void WriteAccessProperty(string domain, IReadOnlyCollection<NetworkAccessControl> acl)
        {
            if (acl is null || acl.Count == 0)
            {
                WritePropertyRecords(domain, DnsResourceRecordType.APL, []);
                return;
            }
            var record = new DnsResourceRecord(domain, DnsResourceRecordType.APL, DnsClass.IN, 0, NetworkAccessControl.ConvertToAPLRecordData(acl));
            record.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;
            WritePropertyRecords(domain, DnsResourceRecordType.APL, [record]);
        }

        public void SetZoneTransferTsigKeyNamesProperty(IReadOnlySet<string> tsigKeyNames = null, string memberZoneName = null) =>
            WriteTransferKeysProperty("transfer-tsig-key-names.ext." + GetMemberZoneDomain(memberZoneName), tsigKeyNames);

        private void WriteTransferKeysProperty(string domain, IReadOnlySet<string> keys)
        {
            DnsResourceRecord[] records = keys?.Select(key =>
            {
                var record = new DnsResourceRecord(domain, DnsResourceRecordType.PTR, DnsClass.IN, 0, new DnsPTRRecordData(key));
                record.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;
                return record;
            }).ToArray() ?? [];
            WritePropertyRecords(domain, DnsResourceRecordType.PTR, records);
        }

        internal void StageManifestMemberPolicies(string domain, IReadOnlyCollection<NetworkAccessControl> query,
            IReadOnlyCollection<NetworkAccessControl> transfer, IReadOnlySet<string> keys, ConfigurationZonePrimary.Changes primary,
            Action<string, DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> write)
        {
            _manifestPropertyWriter = write;
            try
            {
                WriteAccessProperty("allow-query.ext." + domain, query);
                WriteAccessProperty("allow-transfer.ext." + domain, transfer);
                WriteTransferKeysProperty("transfer-tsig-key-names.ext." + domain, keys);
                WritePrimaryAddressesProperty("primary-addresses.ext." + domain, primary.Servers);
                WriteTextProperty("primary-transfer-protocol.ext." + domain, primary.Protocol?.ToString());
                WriteRecordProperty("primary-transfer-tsig-key-name.ext." + domain, DnsResourceRecordType.PTR,
                    string.IsNullOrEmpty(primary.TsigKey) ? null : new DnsPTRRecordData(primary.TsigKey));
                WriteTextProperty("zonemd-validation.ext." + domain, primary.Validate?.ToString());
            }
            finally
            {
                _manifestPropertyWriter = null;
            }
        }

        public void SetPrimaryAddressesProperty(IReadOnlyList<NameServerAddress> primaryServerAddresses = null, string memberZoneName = null) =>
            WritePrimaryAddressesProperty("primary-addresses.ext." + GetMemberZoneDomain(memberZoneName), primaryServerAddresses);

        private void WritePrimaryAddressesProperty(string domain, IReadOnlyList<NameServerAddress> addresses) =>
            WriteRecordProperty(domain, DnsResourceRecordType.TXT, addresses is { Count: > 0 }
                ? new DnsTXTRecordData(addresses.Select(server => server.ToString()).ToArray()) : null);

        public void SetPrimaryZoneTransferProtocolProperty(DnsTransportProtocol? zoneTransferProtocol = null, string memberZoneName = null) =>
            WriteTextProperty("primary-transfer-protocol.ext." + GetMemberZoneDomain(memberZoneName), zoneTransferProtocol?.ToString());

        public void SetPrimaryZoneTransferTsigKeyNameProperty(string tsigKeyName = null, string memberZoneName = null) =>
            WriteRecordProperty("primary-transfer-tsig-key-name.ext." + GetMemberZoneDomain(memberZoneName), DnsResourceRecordType.PTR,
                tsigKeyName is null ? null : new DnsPTRRecordData(tsigKeyName));

        public void SetZoneMdValidationProperty(bool? validateZone = null, string memberZoneName = null) =>
            WriteTextProperty("zonemd-validation.ext." + GetMemberZoneDomain(memberZoneName), validateZone?.ToString());

        private void WriteTextProperty(string domain, string value) =>
            WriteRecordProperty(domain, DnsResourceRecordType.TXT, value is null ? null : new DnsTXTRecordData(value));

        private void WriteRecordProperty(string domain, DnsResourceRecordType type, DnsResourceRecordData data)
        {
            if (data is null)
            {
                WritePropertyRecords(domain, type, []);
                return;
            }
            var record = new DnsResourceRecord(domain, type, DnsClass.IN, 0, data);
            record.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;
            WritePropertyRecords(domain, type, [record]);
        }

        private string GetMemberZoneDomain(string memberZoneName = null)
        {
            if (memberZoneName is null)
            {
                return _name;
            }
            else
            {
                memberZoneName = memberZoneName.ToLowerInvariant();

                _membersIndexLock.EnterReadLock();
                try
                {
                    if (!_membersIndex.TryGetValue(memberZoneName, out string memberZoneDomain))
                        throw new DnsServerException("Failed to find '" + memberZoneName + "' member zone entry in '" + ToString() + "' Catalog zone: member zone does not exists.");

                    return memberZoneDomain;
                }
                finally
                {
                    _membersIndexLock.ExitReadLock();
                }
            }
        }

        private string GetDomainWithLabel(string domain)
        {
            Span<byte> buffer = stackalloc byte[8];
            int i = 0;

            do
            {
                RandomNumberGenerator.Fill(buffer);
                string label = Base32.ToBase32HexString(buffer, true).ToLowerInvariant();
                string domainWithLabel = label + "." + domain;

                if (_dnsServer.AuthZoneManager.NameExists(_name, domainWithLabel))
                    continue;

                return domainWithLabel;
            }
            while (++i < 10);

            throw new DnsServerException("Failed to generate unique label for the given domain name '" + domain + "'. Please try again.");
        }

        #endregion

        #region public

        public override string GetZoneTypeName()
        {
            return "Catalog";
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.SOA:
                    if ((records.Count != 1) || !records[0].Name.Equals(_name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Invalid SOA record.");

                    DnsResourceRecord newSoaRecord = records[0];
                    DnsSOARecordData newSoa = newSoaRecord.RDATA as DnsSOARecordData;

                    //reset fixed record values
                    DnsSOARecordData modifiedSoa = new DnsSOARecordData("invalid", "invalid", newSoa.Serial, newSoa.Refresh, newSoa.Retry, newSoa.Expire, newSoa.Minimum);
                    DnsResourceRecord modifiedSoaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, 0, modifiedSoa) { Tag = newSoaRecord.Tag };

                    base.SetRecords(type, [modifiedSoaRecord]);
                    break;

                default:
                    throw new InvalidOperationException("Cannot set records in Catalog zone.");
            }

        }

        public override bool AddRecord(DnsResourceRecord record)
        {
            throw new InvalidOperationException("Cannot add record in Catalog zone.");
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            throw new InvalidOperationException("Cannot delete record in Catalog zone.");
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            throw new InvalidOperationException("Cannot delete records in Catalog zone.");
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            throw new InvalidOperationException("Cannot update record in Catalog zone.");
        }

        public override IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool dnssecOk)
        {
            if (type == DnsResourceRecordType.SOA)
                return base.QueryRecords(type, dnssecOk); //allow SOA for zone transfer to work with bind

            return []; //catalog zone is not queriable
        }

        #endregion

        #region properties

        public override string CatalogZoneName
        {
            get { return base.CatalogZoneName; }
            set { throw new InvalidOperationException(); }
        }

        public override bool OverrideCatalogQueryAccess
        {
            get { return base.OverrideCatalogQueryAccess; }
            set { throw new InvalidOperationException(); }
        }

        public override bool OverrideCatalogZoneTransfer
        {
            get { return base.OverrideCatalogZoneTransfer; }
            set { throw new InvalidOperationException(); }
        }

        public override bool OverrideCatalogNotify
        {
            get { return base.OverrideCatalogNotify; }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneUpdate Update
        {
            get { return base.Update; }
            set { throw new InvalidOperationException(); }
        }

        #endregion
    }
}
