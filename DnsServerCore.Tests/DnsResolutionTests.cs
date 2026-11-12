using System.Net;
using System.Threading.Tasks;
using DnsServerCore.Dns;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class DnsResolutionTests
    {
        private static readonly IPAddress _recordAddress = IPAddress.Parse("192.0.2.10");

        [Fact]
        public async Task PrimaryZoneDistinguishesAnAnswerFromMissingDataAndMissingNames()
        {
            await using var server = new LoopbackDnsServer();
            server.AddPrimaryZone("example.test", "www.example.test", _recordAddress);
            await server.StartAsync();

            DnsDatagram answer = await server.QueryAsync("www.example.test", DnsResourceRecordType.A);
            Assert.True(answer.AuthoritativeAnswer);
            Assert.Equal(DnsResponseCode.NoError, answer.RCODE);
            Assert.Equal(_recordAddress, Assert.IsType<DnsARecordData>(Assert.Single(answer.Answer).RDATA).Address);

            DnsDatagram noData = await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA);
            Assert.True(noData.AuthoritativeAnswer);
            Assert.Equal(DnsResponseCode.NoError, noData.RCODE);
            Assert.Empty(noData.Answer);
            Assert.Contains(noData.Authority, record => record.Type == DnsResourceRecordType.SOA);

            DnsDatagram missingName = await server.QueryAsync("missing.example.test", DnsResourceRecordType.A);
            Assert.True(missingName.AuthoritativeAnswer);
            Assert.Equal(DnsResponseCode.NxDomain, missingName.RCODE);
            Assert.Empty(missingName.Answer);
            Assert.Contains(missingName.Authority, record => record.Type == DnsResourceRecordType.SOA);
        }

        [Fact]
        public async Task ResolverReturnsAnswersFromItsConfiguredForwarder()
        {
            await using var upstream = new LoopbackDnsServer();
            // The resolver serves .test locally, so use a name that reaches the forwarder.
            upstream.AddPrimaryZone("example.net", "www.example.net", _recordAddress);
            await upstream.StartAsync();

            await using var resolver = new LoopbackDnsServer();
            resolver.Server.Recursion = DnsServerRecursion.AllowOnlyForPrivateNetworks;
            resolver.Server.Forwarders = [new NameServerAddress(upstream.EndPoint)];
            await resolver.StartAsync();

            DnsDatagram answer = await resolver.QueryAsync("www.example.net", DnsResourceRecordType.A);
            Assert.False(answer.AuthoritativeAnswer);
            Assert.True(answer.RecursionAvailable);
            Assert.Equal(DnsResponseCode.NoError, answer.RCODE);
            Assert.Equal(_recordAddress, Assert.IsType<DnsARecordData>(Assert.Single(answer.Answer).RDATA).Address);
        }
    }
}
