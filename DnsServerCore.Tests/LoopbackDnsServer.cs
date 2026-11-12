using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using DnsServerCore.Dns;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    internal sealed class LoopbackDnsServer : IAsyncDisposable
    {
        private readonly DirectoryInfo _configuration;
        private readonly LogManager _log;

        public LoopbackDnsServer()
        {
            EndPoint = GetLoopbackEndPoint();
            _configuration = Directory.CreateTempSubdirectory("technitium-dns-test-");
            Directory.CreateDirectory(Path.Combine(_configuration.FullName, "zones"));
            _log = new LogManager(true, _configuration.FullName);
            Server = new DnsServer(_configuration.FullName, _configuration.FullName, EndPoint, _log, "server.test");
            Server.DnssecValidation = false;
            Server.Recursion = DnsServerRecursion.Deny;
        }

        public IPEndPoint EndPoint { get; }
        public DnsServer Server { get; }

        public void AddPrimaryZone(string zone, string host, IPAddress address)
        {
            Assert.NotNull(Server.AuthZoneManager.CreatePrimaryZone(zone));
            Assert.True(Server.AuthZoneManager.AddRecord(zone,
                new DnsResourceRecord(host, DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(address))));
        }

        public Task StartAsync() => Server.StartAsync(throwIfBindFails: true);

        public Task<DnsDatagram> QueryAsync(string name, DnsResourceRecordType type)
        {
            var client = new DnsClient(EndPoint) { Timeout = 2000, Retries = 2 };
            return client.ResolveAsync(name, type);
        }

        public async ValueTask DisposeAsync()
        {
            await Server.DisposeAsync();
            await _log.DisposeAsync();
            _configuration.Delete(recursive: true);
        }

        private static IPEndPoint GetLoopbackEndPoint()
        {
            for (int attempt = 0; attempt < 10; attempt++)
            {
                using var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                tcp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                var endPoint = (IPEndPoint)tcp.LocalEndPoint!;

                using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                try
                {
                    udp.Bind(endPoint);
                    return endPoint;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
                {
                    // TCP and UDP allocate ephemeral ports independently.
                }
            }

            throw new InvalidOperationException("Could not find a free loopback port for DNS.");
        }
    }
}
