using DnsServerCore.Dns;
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace DnsServerCore.Tests
{
    [Collection("Web service")]
    public sealed class LegacyDnsConfigurationTests
    {
        [Fact]
        public async Task VersionSixSettingsLoadAndSurviveSavingInTheCurrentFormat()
        {
            DirectoryInfo directory = Directory.CreateTempSubdirectory("technitium-legacy-dns-test-");
            try
            {
                // Written by v15.5.1 with a zero prefetch trigger, before the separate enable flag existed.
                File.Copy(Path.Combine(AppContext.BaseDirectory, "Fixtures", "dns-v6.config"),
                    Path.Combine(directory.FullName, "dns.config"));

                await using var log = new LogManager(true, directory.FullName);
                await using (var legacy = new DnsServer(directory.FullName, directory.FullName, log))
                {
                    legacy.LoadConfigFile();
                    AssertEffectiveSettings(legacy);
                    legacy.SaveConfigFile(immediately: true);
                }

                await using var current = new DnsServer(directory.FullName, directory.FullName, log);
                current.LoadConfigFile();
                AssertEffectiveSettings(current);
            }
            finally
            {
                directory.Delete(recursive: true);
            }
        }

        private static void AssertEffectiveSettings(DnsServer server)
        {
            Assert.Equal("legacy.example.test", server.ServerDomain);
            Assert.Equal(new IPEndPoint(IPAddress.Loopback, 5353), Assert.Single(server.LocalEndPoints));
            Assert.Equal(1234u, server.AuthZoneManager.DefaultRecordTtl);
            Assert.Equal(DnsServerRecursion.Deny, server.Recursion);
            Assert.False(server.EnableCachePrefetch);
            Assert.Equal(365, server.StatsManager.MaxStatFileDays);
        }
    }
}
