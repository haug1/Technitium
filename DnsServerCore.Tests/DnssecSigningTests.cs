using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.Trees;
using DnsServerCore.Dns.Zones;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class DnssecSigningTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task StagedSigningKeepsDenialRecordsAndKeysOutOfTheLiveZone(bool useNsec3)
        {
            const string name = "example.test";
            const string host = "www.example.test";
            await using var fixture = new LoopbackDnsServer();
            fixture.AddPrimaryZone(name, host, IPAddress.Parse("192.0.2.10"));

            using var staged = new PrimaryZone(fixture.Server, name, useSoaSerialDateScheme: false);
            var tree = new AuthZoneTree();
            Assert.True(tree.TryAdd(staged));
            AuthZone child = tree.GetOrAddSubDomainZone(name, host, () => new PrimarySubDomainZone(staged, host));
            child.LoadRecords(DnsResourceRecordType.A,
                [new DnsResourceRecord(host, DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.20")))]);

            const DnssecAlgorithm algorithm = DnssecAlgorithm.ECDSAP256SHA256;
            DnssecPrivateKey[] keys =
            [
                DnssecPrivateKey.Create(algorithm, DnssecPrivateKeyType.KeySigningKey),
                DnssecPrivateKey.Create(algorithm, DnssecPrivateKeyType.ZoneSigningKey)
            ];
            while (keys[0].KeyTag == keys[1].KeyTag)
                keys[1] = DnssecPrivateKey.Create(algorithm, DnssecPrivateKeyType.ZoneSigningKey);

            staged.SignZone(keys, 3600u, useNsec3, 0, [], tree);

            Assert.Equal(useNsec3 ? AuthZoneDnssecStatus.SignedWithNSEC3 : AuthZoneDnssecStatus.SignedWithNSEC, staged.DnssecStatus);
            Assert.Equal(2, staged.GetRecords(DnsResourceRecordType.DNSKEY).Count);
            Assert.Contains(staged.GetRecords(DnsResourceRecordType.RRSIG),
                record => Assert.IsType<DnsRRSIGRecordData>(record.RDATA).TypeCovered == DnsResourceRecordType.SOA);

            IReadOnlyList<AuthZone> stagedNodes = tree.GetApexZoneWithSubDomainZones(name);
            Assert.Contains(child.GetRecords(DnsResourceRecordType.RRSIG),
                record => Assert.IsType<DnsRRSIGRecordData>(record.RDATA).TypeCovered == DnsResourceRecordType.A);
            DnsResourceRecordType proofType = useNsec3 ? DnsResourceRecordType.NSEC3 : DnsResourceRecordType.NSEC;
            Assert.Contains(stagedNodes, node => node.GetRecords(proofType).Any());

            keys[0].SetState(DnssecPrivateKeyState.Ready);
            staged.UpdateStagedSigning(tree, disable: false, changeProof: false, useNsec3, iterations: 0, salt: [], changeTtl: true, ttl: 1800);
            Assert.All(staged.GetRecords(DnsResourceRecordType.DNSKEY), record => Assert.Equal(1800u, record.OriginalTtlValue));
            Assert.Contains(staged.GetRecords(DnsResourceRecordType.RRSIG),
                record => record.RDATA is DnsRRSIGRecordData signature && signature.TypeCovered == DnsResourceRecordType.DNSKEY &&
                    signature.OriginalTtl == 1800u);

            var liveRecords = new List<DnsResourceRecord>();
            fixture.Server.AuthZoneManager.ListAllZoneRecords(name, liveRecords);
            Assert.Contains(liveRecords, record => record.Name == host && record.Type == DnsResourceRecordType.A);
            Assert.DoesNotContain(liveRecords, record => record.Type is DnsResourceRecordType.DNSKEY or DnsResourceRecordType.RRSIG ||
                record.Type == proofType);
        }
    }
}
