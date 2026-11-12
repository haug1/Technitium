using DnsServerCore.Configuration;
using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Security.OTP;
using Xunit;

namespace DnsServerCore.Tests
{
    [Collection("Web service")]
    public sealed class ConfigurationPlanTests : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("technitium-plan-test-");

        [Fact]
        public async Task PreviewUsesTheCurrentServerSnapshotWithoutChangingSettings()
        {
            await using var server = await LoopbackWebService.StartAsync();
            JsonElement before = await server.GetSettingsAsync();
            int port = before.GetProperty("webServiceHttpPort").GetInt32();
            ConfigurationManifest manifest = Load(JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                web = new { httpPort = port == 5380 ? 5381 : 5380 },
                dns = new { authoritative = new { defaultResponsiblePerson = "Lab <ops@example.test>" } },
                logging = new { logQueries = before.GetProperty("logQueries").GetBoolean() }
            }));

            var changes = ConfigurationPlan.Create(manifest, before);

            Assert.Collection(changes,
                change => Assert.Equal(new ConfigurationChange("/dns/authoritative/defaultResponsiblePerson", ConfigurationChangeKind.Add, false), change),
                change => Assert.Equal(new ConfigurationChange("/web/httpPort", ConfigurationChangeKind.Update, true), change));

            JsonElement after = await server.GetSettingsAsync();
            Assert.Equal(port, after.GetProperty("webServiceHttpPort").GetInt32());
            Assert.Equal(JsonValueKind.Null, after.GetProperty("defaultResponsiblePerson").ValueKind);
        }

        [Fact]
        public async Task DnsListenerPreviewReportsRestartWithoutChangingListeners()
        {
            await using var server = await LoopbackWebService.StartAsync();
            JsonElement before = await server.GetSettingsAsync();
            const string manifest = """{"schemaVersion":1,"dns":{"localEndpoints":[]}}""";

            JsonElement preview = await PreviewAsync(server, manifest);
            JsonElement change = Assert.Single(preview.GetProperty("changes").EnumerateArray());
            Assert.Equal("/dns/localEndpoints", change.GetProperty("path").GetString());
            Assert.True(change.GetProperty("restartDnsService").GetBoolean());
            Assert.False(change.GetProperty("restartWebService").GetBoolean());
            Assert.True(JsonElement.DeepEquals(before.GetProperty("dnsServerLocalEndPoints"),
                (await server.GetSettingsAsync()).GetProperty("dnsServerLocalEndPoints")));
        }

        [Fact]
        public async Task WebAddressPreviewUsesEffectiveBindingsAndReportsRestarts()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string equivalent = """{"schemaVersion":1,"web":{"localAddresses":["0.0.0.0","127.0.0.1","127.0.0.1"]}}""";
            Assert.Empty((await PreviewAsync(server, equivalent)).GetProperty("changes").EnumerateArray());

            const string defaults = """{"schemaVersion":1,"web":{"localAddresses":null}}""";
            JsonElement change = Assert.Single((await PreviewAsync(server, defaults)).GetProperty("changes").EnumerateArray());
            Assert.Equal("/web/localAddresses", change.GetProperty("path").GetString());
            Assert.True(change.GetProperty("restartWebService").GetBoolean());
            Assert.False(change.GetProperty("restartDnsService").GetBoolean());

            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal("127.0.0.1", Assert.Single(settings.GetProperty("webServiceLocalAddresses").EnumerateArray()).GetString());
        }

        [Fact]
        public void DnsListenerValidationUsesSettingsDefaultsAndRejectsInvalidEndpoints()
        {
            using var snapshot = JsonDocument.Parse("""{"dnsServerLocalEndPoints":["0.0.0.0:53","[::]:53"]}""");
            ConfigurationManifest manifest = Load("""{"schemaVersion":1,"dns":{"localEndpoints":["::","0.0.0.0:0"]}}""");
            Assert.Empty(ConfigurationPlan.Create(manifest, snapshot.RootElement));

            Assert.Contains("/dns/localEndpoints/0", Assert.Throws<InvalidDataException>(() =>
                Load("""{"schemaVersion":1,"dns":{"localEndpoints":["example.test"]}}""")).Message);
            Assert.Contains("/dns/localEndpoints/0", Assert.Throws<InvalidDataException>(() =>
                Load("""{"schemaVersion":1,"dns":{"localEndpoints":["[::1]:99999"]}}""")).Message);
            Assert.Contains("/dns/localEndpoints/0", Assert.Throws<InvalidDataException>(() =>
                Load("""{"schemaVersion":1,"dns":{"localEndpoints":["127.0.0.1:bogus"]}}""")).Message);
            Assert.Contains("/dns/localEndpoints/1", Assert.Throws<InvalidDataException>(() =>
                Load("""{"schemaVersion":1,"dns":{"localEndpoints":["127.0.0.1","127.0.0.1:53"]}}""")).Message);
            Assert.Contains("853", Assert.Throws<InvalidDataException>(() =>
                Load("""{"schemaVersion":1,"dns":{"localEndpoints":["127.0.0.1:853"]}}""")).Message);
        }

        [Fact]
        public async Task LiveDnsListenerApplyPersistsOwnershipAndRejectsConflictingEdits()
        {
            await using var server = await LoopbackWebService.StartAsync();
            string previous = (await server.GetSettingsAsync()).GetProperty("dnsServerLocalEndPoints")[0].GetString()!;
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] previousBackup = await backup.Content.ReadAsByteArrayAsync();

            IPEndPoint endpoint = LoopbackDnsServer.GetLoopbackEndPoint();
            string manifest = ListenerManifest(endpoint);
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await AssertListenerAnswersAsync(endpoint);
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            await server.RestartAsync();
            await AssertListenerAnswersAsync(endpoint);
            JsonElement rejected = await server.CallAsync(
                $"settings/set?dnsServerLocalEndPoints={Uri.EscapeDataString(previous)}&noStackTrace=true", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dns/localEndpoints", rejected.GetProperty("errorMessage").GetString());
            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(previousBackup), "file", "backup.zip");
            JsonElement restore = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restore.GetProperty("status").GetString());
            Assert.Contains("/dns/localEndpoints", restore.GetProperty("errorMessage").GetString());

            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(180, current.GetProperty("maxLogFileDays").GetInt32());
            Assert.Equal(endpoint.ToString(), current.GetProperty("dnsServerLocalEndPoints")[0].GetString());
            Assert.False(current.GetProperty("noStackTrace").GetBoolean());
        }

        [Theory]
        [InlineData(false, "/dns/localEndpoints")]
        [InlineData(true, "/dns/authoritative/defaultRecordTtl")]
        [InlineData(true, "/dns/authoritative/minSoaRefresh")]
        [InlineData(true, "/dns/authoritative/defaultResponsiblePerson")]
        [InlineData(true, "/dns/authoritative/notifyAllowedNetworks")]
        public async Task LegacyCombinedBackupChecksManagedDnsSettingsBeforeChangingSettings(bool preserveListener, string conflictPath)
        {
            await using var server = await LoopbackWebService.StartAsync();
            JsonElement settings = await server.GetSettingsAsync();
            IPEndPoint current = IPEndPoint.Parse(settings.GetProperty("dnsServerLocalEndPoints")[0].GetString()!);
            string manifest = JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                dns = new { localEndpoints = new[] { current.ToString() }, authoritative = new { defaultRecordTtl = 600, minSoaRefresh = 900, defaultResponsiblePerson = "ops@example.test", notifyAllowedNetworks = new[] { "192.0.2.1" } } }
            });
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));

            using var backup = new MemoryStream();
            using (var archive = new ZipArchive(backup, ZipArchiveMode.Create, leaveOpen: true))
            {
                using var writer = new BinaryWriter(archive.CreateEntry("dns.config").Open());
                writer.Write("DS"u8);
                writer.Write((byte)42);
                writer.Write(5380); // web HTTP port
                writer.Write(53443); // web TLS port
                writer.Write((byte)0); // web listener addresses
                writer.Write(false); // web TLS
                writer.Write(false); // web HTTP/3
                writer.Write(false); // redirect to TLS
                writer.Write(false); // self-signed certificate
                writer.Write(string.Empty);
                writer.Write(string.Empty);
                writer.Write("X-Real-IP");
                writer.Write("legacy.test");
                writer.Write((byte)1);
                (preserveListener ? current : LoopbackDnsServer.GetLoopbackEndPoint()).WriteTo(writer);
                writer.Write((byte)0); // IPv4 source networks
                writer.Write((byte)0); // IPv6 source networks
                writer.Write(conflictPath.EndsWith("defaultRecordTtl", StringComparison.Ordinal) ? 3600u : 600u);
                writer.Write(conflictPath.EndsWith("defaultResponsiblePerson", StringComparison.Ordinal) ? string.Empty : "ops@example.test");
                writer.Write(false); // SOA date serial format
                writer.Write(conflictPath.EndsWith("minSoaRefresh", StringComparison.Ordinal) ? 300u : 900u);
                writer.Write(300u); // SOA minimum retry
                writer.Write((byte)0); // zone transfer networks
                bool notifyConflict = conflictPath.EndsWith("notifyAllowedNetworks", StringComparison.Ordinal);
                writer.Write((byte)(notifyConflict ? 0 : 1));
                if (!notifyConflict)
                    NetworkAddress.Parse("192.0.2.1").WriteTo(writer);
                // The prefix is sufficient for ownership preflight.
            }

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(backup.ToArray()), "file", "legacy.zip");
            JsonElement rejected = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);

            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains(conflictPath, rejected.GetProperty("errorMessage").GetString());
            JsonElement after = await server.GetSettingsAsync();
            Assert.Equal(settings.GetProperty("dnsServerDomain").GetString(), after.GetProperty("dnsServerDomain").GetString());
            Assert.Equal(settings.GetProperty("webServiceHttpPort").GetInt32(), after.GetProperty("webServiceHttpPort").GetInt32());
            Assert.Equal(600u, after.GetProperty("defaultRecordTtl").GetUInt32());
            await AssertListenerAnswersAsync(current);
        }

        [Fact]
        public async Task AuthoritativeDefaultsPersistAndRejectConflictingWrites()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"authoritative":{"defaultRecordTtl":600,"defaultNsRecordTtl":7200,"defaultSoaRecordTtl":null,"useSoaSerialDateScheme":true,"minSoaRefresh":900,"minSoaRetry":null}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(4, preview.GetProperty("changes").GetArrayLength());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));

            await server.RestartAsync();
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(600u, current.GetProperty("defaultRecordTtl").GetUInt32());
            Assert.Equal(7200u, current.GetProperty("defaultNsRecordTtl").GetUInt32());
            Assert.Equal(900u, current.GetProperty("defaultSoaRecordTtl").GetUInt32());
            Assert.True(current.GetProperty("useSoaSerialDateScheme").GetBoolean());
            Assert.Equal(900u, current.GetProperty("minSoaRefresh").GetUInt32());
            Assert.Equal(300u, current.GetProperty("minSoaRetry").GetUInt32());
            Assert.Equal(6, current.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement rejected = await server.CallAsync("settings/set?defaultRecordTtl=601&maxLogFileDays=180", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dns/authoritative/defaultRecordTtl", rejected.GetProperty("errorMessage").GetString());

            JsonElement timingConflict = await server.CallAsync("settings/set?minSoaRetry=301", server.AdminToken);
            Assert.Equal("error", timingConflict.GetProperty("status").GetString());
            Assert.Contains("/dns/authoritative/minSoaRetry", timingConflict.GetProperty("errorMessage").GetString());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restore = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restore.GetProperty("status").GetString());
            Assert.Contains("/dns/authoritative/defaultRecordTtl", restore.GetProperty("errorMessage").GetString());
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());

            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?defaultRecordTtl=10m&maxLogFileDays=180", server.AdminToken));
            Assert.Equal(180, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
        }

        [Fact]
        public async Task ResponsiblePersonNormalizesPersistsAndCanBeExplicitlyReset()
        {
            await using var server = await LoopbackWebService.StartAsync();
            // Exercise a valid address whose stored short-string length exceeds 127 bytes.
            string label = new('a', 48);
            string address = $"ops@{label}.{label}.{label}.test";
            string manifest = JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                dns = new { authoritative = new { defaultResponsiblePerson = $"Lab <{address}>" } }
            });

            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal("Add", Assert.Single(preview.GetProperty("changes").EnumerateArray()).GetProperty("kind").GetString());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(address, current.GetProperty("defaultResponsiblePerson").GetString());
            Assert.Equal("/dns/authoritative/defaultResponsiblePerson",
                Assert.Single(current.GetProperty("managedSettings").EnumerateArray()).GetString());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement conflict = await server.CallAsync("settings/set?defaultResponsiblePerson=other%40example.test", server.AdminToken);
            Assert.Equal("error", conflict.GetProperty("status").GetString());
            Assert.Contains("/dns/authoritative/defaultResponsiblePerson", conflict.GetProperty("errorMessage").GetString());

            const string reset = """{"schemaVersion":1,"dns":{"authoritative":{"defaultResponsiblePerson":null}}}""";
            JsonElement resetPreview = await PreviewAsync(server, reset);
            Assert.Equal("Remove", Assert.Single(resetPreview.GetProperty("changes").EnumerateArray()).GetProperty("kind").GetString());
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, resetPreview.GetProperty("revision").GetString()!));
            Assert.Equal(JsonValueKind.Null, (await server.GetSettingsAsync()).GetProperty("defaultResponsiblePerson").ValueKind);
        }

        [Fact]
        public async Task AuthoritativeNetworkAllowlistsNormalizeAndKeepOwnershipAfterRestart()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"dns":{"authoritative":{"zoneTransferAllowedNetworks":["192.0.2.129/24","192.0.2.0/24"],"notifyAllowedNetworks":["2001:db8::2"]}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(2, preview.GetProperty("changes").GetArrayLength());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));

            await server.RestartAsync();
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal("192.0.2.0/24", Assert.Single(current.GetProperty("zoneTransferAllowedNetworks").EnumerateArray()).GetString());
            Assert.Equal("2001:db8::2", Assert.Single(current.GetProperty("notifyAllowedNetworks").EnumerateArray()).GetString());
            Assert.Equal(2, current.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement conflict = await server.CallAsync("settings/set?zoneTransferAllowedNetworks=198.51.100.0%2F24&maxLogFileDays=90", server.AdminToken);
            Assert.Equal("error", conflict.GetProperty("status").GetString());
            Assert.Contains("/dns/authoritative/zoneTransferAllowedNetworks", conflict.GetProperty("errorMessage").GetString());
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());

            const string reset = """
                {"schemaVersion":1,"dns":{"authoritative":{"zoneTransferAllowedNetworks":null,"notifyAllowedNetworks":[]}}}
                """;
            string revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            current = await server.GetSettingsAsync();
            Assert.Empty(current.GetProperty("zoneTransferAllowedNetworks").EnumerateArray());
            Assert.Empty(current.GetProperty("notifyAllowedNetworks").EnumerateArray());
            Assert.Equal(2, current.GetProperty("managedSettings").GetArrayLength());
        }

        [Theory]
        [InlineData("sourceNetworks", "ipv4", "2001:db8::1")]
        [InlineData("sourceNetworks", "ipv6", "192.0.2.1")]
        [InlineData("authoritative", "notifyAllowedNetworks", "192.0.2.1/255")]
        public void ManifestRejectsInvalidNetworkPrefixesAndAddressFamilies(string section, string field, string network)
        {
            string manifest = new JsonObject
            {
                ["schemaVersion"] = 1,
                ["dns"] = new JsonObject { [section] = new JsonObject { [field] = new JsonArray(network) } }
            }.ToJsonString();
            InvalidDataException error = Assert.Throws<InvalidDataException>(() => Load(manifest));
            Assert.Contains($"/dns/{section}/{field}/0", error.Message);
            Assert.DoesNotContain(network, error.Message);
        }

        [Fact]
        public async Task SourceNetworkPreviewUsesDefaultAddressesWithoutChangingSettings()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string defaults = """{"schemaVersion":1,"dns":{"sourceNetworks":{"ipv4":null,"ipv6":[]}}}""";
            Assert.Empty((await PreviewAsync(server, defaults)).GetProperty("changes").EnumerateArray());

            const string changed = """{"schemaVersion":1,"dns":{"sourceNetworks":{"ipv4":["192.0.2.129/24"]}}}""";
            JsonElement change = Assert.Single((await PreviewAsync(server, changed)).GetProperty("changes").EnumerateArray());
            Assert.Equal("/dns/sourceNetworks/ipv4", change.GetProperty("path").GetString());
            Assert.False(change.GetProperty("restartDnsService").GetBoolean());
            Assert.Empty((await PreviewAsync(server, defaults)).GetProperty("changes").EnumerateArray());
        }

        [Fact]
        public async Task SourceNetworksApplyPersistAndRejectConflictingRestores()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """{"schemaVersion":1,"dns":{"sourceNetworks":{"ipv4":["127.0.0.1"],"ipv6":null}}}""";
            const string reset = """{"schemaVersion":1,"dns":{"sourceNetworks":{"ipv4":null,"ipv6":[]}}}""";
            try
            {
                string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
                await server.RestartAsync();
                JsonElement current = await server.GetSettingsAsync();
                Assert.Equal("127.0.0.1", Assert.Single(current.GetProperty("dnsServerIPv4SourceAddresses").EnumerateArray()).GetString());
                Assert.Equal(2, current.GetProperty("managedSettings").GetArrayLength());
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                JsonElement edit = await server.CallAsync("settings/set?dnsServerIPv4SourceAddresses=0.0.0.0&maxLogFileDays=180", server.AdminToken);
                Assert.Equal("error", edit.GetProperty("status").GetString());
                Assert.Contains("/dns/sourceNetworks/ipv4", edit.GetProperty("errorMessage").GetString());

                using var form = new MultipartFormDataContent();
                form.Add(new ByteArrayContent(original), "file", "backup.zip");
                JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
                Assert.Equal("error", restored.GetProperty("status").GetString());
                Assert.Contains("/dns/sourceNetworks/ipv4", restored.GetProperty("errorMessage").GetString());
                Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
            }
            finally
            {
                string revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            }

            Assert.Empty((await PreviewAsync(server, reset)).GetProperty("changes").EnumerateArray());
        }

        [Fact]
        public async Task ManagedUpdateChecksResetToDefaultAndRejectConflictingRestore()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """{"schemaVersion":1,"dns":{"checkForUpdates":null}}""";
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();

            JsonElement current = await server.GetSettingsAsync();
            Assert.True(current.GetProperty("dnsServerEnableCheckForUpdate").GetBoolean());
            Assert.Equal("/dns/checkForUpdates", Assert.Single(current.GetProperty("managedSettings").EnumerateArray()).GetString());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement edit = await server.CallAsync("settings/set?dnsServerEnableCheckForUpdate=false&maxLogFileDays=180", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/dns/checkForUpdates", edit.GetProperty("errorMessage").GetString());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restore = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restore.GetProperty("status").GetString());
            Assert.Contains("/dns/checkForUpdates", restore.GetProperty("errorMessage").GetString());
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
        }

        [Fact]
        public async Task OutboundSocketSettingsPersistAndRejectConflictingRestore()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?ipv6Mode=Disabled&enableUdpSocketPool=false", server.AdminToken));
            await server.RestartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """{"schemaVersion":1,"dns":{"ipv6Mode":"Enabled","udpSocketPool":{"enabled":false}}}""";
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal("/dns/ipv6Mode", Assert.Single(preview.GetProperty("changes").EnumerateArray()).GetProperty("path").GetString());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal("Enabled", settings.GetProperty("ipv6Mode").GetString());
            Assert.False(settings.GetProperty("enableUdpSocketPool").GetBoolean());
            Assert.Equal(2, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            JsonNode export = ConfigurationPlan.Export(settings, includePreviewOnly: false);
            Assert.Equal("Enabled", export["dns"]!["ipv6Mode"]!.GetValue<string>());
            Assert.False(export["dns"]!["udpSocketPool"]!["enabled"]!.GetValue<bool>());

            JsonElement aliasEdit = await server.CallAsync("settings/set?preferIPv6=true", server.AdminToken);
            Assert.Equal("error", aliasEdit.GetProperty("status").GetString());
            Assert.Contains("/dns/ipv6Mode", aliasEdit.GetProperty("errorMessage").GetString());
            JsonElement poolEdit = await server.CallAsync("settings/set?enableUdpSocketPool=true", server.AdminToken);
            Assert.Equal("error", poolEdit.GetProperty("status").GetString());
            Assert.Contains("/dns/udpSocketPool/enabled", poolEdit.GetProperty("errorMessage").GetString());
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?ipv6Mode=Enabled&preferIPv6=true", server.AdminToken));

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/dns/ipv6Mode", restored.GetProperty("errorMessage").GetString());
            Assert.Equal("Enabled", (await server.GetSettingsAsync()).GetProperty("ipv6Mode").GetString());
        }

        [Fact]
        public async Task DnsListenerPolicyAppliesLiveAndRejectsConflictingWriters()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"listeners":{"useClientSubnetAsSource":true,
                  "http":{"helpRedirect":false,"realIpHeader":"X-Resolver-Client"},
                  "reverseProxyAcl":["!192.0.2.8","192.0.2.0/24"]}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            JsonElement changes = preview.GetProperty("changes");
            Assert.Equal(4, changes.GetArrayLength());
            Assert.All(changes.EnumerateArray(), change => Assert.False(change.GetProperty("restartDnsService").GetBoolean()));
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();
            JsonElement settings = await server.GetSettingsAsync();
            Assert.True(settings.GetProperty("enableEDnsClientSubnetSourceAddress").GetBoolean());
            Assert.False(settings.GetProperty("enableDnsOverHttpHelpRedirect").GetBoolean());
            Assert.Equal("X-Resolver-Client", settings.GetProperty("dnsOverHttpRealIpHeader").GetString());
            Assert.Collection(settings.GetProperty("dnsReverseProxyNetworkACL").EnumerateArray(),
                rule => Assert.Equal("!192.0.2.8", rule.GetString()),
                rule => Assert.Equal("192.0.2.0/24", rule.GetString()));
            JsonNode? exported = ConfigurationPlan.Export(settings, includePreviewOnly: false)["dns"]?["listeners"];
            Assert.Equal("X-Resolver-Client", exported?["http"]?["realIpHeader"]?.GetValue<string>());
            Assert.Equal(2, exported?["reverseProxyAcl"]?.AsArray().Count);
            Assert.Equal(4, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement rejected = await server.CallAsync(
                "settings/set?reverseProxyNetworkACL=198.51.100.0%2F24&maxLogFileDays=22", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dns/listeners/reverseProxyAcl", rejected.GetProperty("errorMessage").GetString());
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?dnsOverHttpRealIpHeader=x-resolver-client", server.AdminToken));

            using var restore = new MultipartFormDataContent();
            restore.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, restore);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/dns/listeners/", restored.GetProperty("errorMessage").GetString());

            const string reset = """
                {"schemaVersion":1,"dns":{"listeners":{"useClientSubnetAsSource":null,"reverseProxyAcl":null,
                  "http":{"helpRedirect":null,"realIpHeader":null}}}}
                """;
            JsonElement resetPreview = await PreviewAsync(server, reset);
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, resetPreview.GetProperty("revision").GetString()!));
            Assert.Empty((await PreviewAsync(server, reset)).GetProperty("changes").EnumerateArray());
        }

        [Fact]
        public async Task ProxyApplyRejectsRotatedPreviewAndPersistsTheNewPassword()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string variable = "TECHNITIUM_TEST_PROXY_PREVIEW_PASSWORD";
            const string firstSecret = "fixture-current-proxy-password";
            const string nextSecret = "fixture-next-proxy-password";
            LoopbackWebService.AssertOk(await server.CallAsync(
                "settings/set?proxyType=Http&proxyAddress=127.0.0.1&proxyPort=8080&proxyUsername=fixture&proxyPassword=" + firstSecret, server.AdminToken));

            await server.RestartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] originalBackup = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"proxy":{"password":{"environment":"TECHNITIUM_TEST_PROXY_PREVIEW_PASSWORD"}}}}
                """;
            string? original = Environment.GetEnvironmentVariable(variable);
            try
            {
                Environment.SetEnvironmentVariable(variable, firstSecret);
                JsonElement matched = await PreviewAsync(server, manifest);
                Assert.Empty(matched.GetProperty("changes").EnumerateArray());

                Environment.SetEnvironmentVariable(variable, nextSecret);
                JsonElement changed = await PreviewAsync(server, manifest);
                JsonElement change = Assert.Single(changed.GetProperty("changes").EnumerateArray());
                Assert.Equal("/dns/proxy/password", change.GetProperty("path").GetString());
                Assert.NotEqual(matched.GetProperty("revision").GetString(), changed.GetProperty("revision").GetString());
                Assert.DoesNotContain(firstSecret, changed.GetRawText());
                Assert.DoesNotContain(nextSecret, changed.GetRawText());
                Assert.Equal(firstSecret, (await server.GetSettingsAsync()).GetProperty("proxy").GetProperty("password").GetString());

                JsonElement stale = await ApplyAsync(server, manifest, matched.GetProperty("revision").GetString()!);
                Assert.Equal("error", stale.GetProperty("status").GetString());
                Assert.Contains("stale", stale.GetProperty("errorMessage").GetString());
                Assert.Equal(firstSecret, (await server.GetSettingsAsync()).GetProperty("proxy").GetProperty("password").GetString());

                JsonElement applied = await ApplyAsync(server, manifest, changed.GetProperty("revision").GetString()!);
                LoopbackWebService.AssertOk(applied);
                Assert.DoesNotContain(nextSecret, applied.GetRawText());
                await server.RestartAsync();
                JsonElement settings = await server.GetSettingsAsync();
                Assert.Equal(nextSecret, settings.GetProperty("proxy").GetProperty("password").GetString());
                Assert.Equal("/dns/proxy/password", Assert.Single(settings.GetProperty("managedSettings").EnumerateArray()).GetString());
                JsonElement repeated = await PreviewAsync(server, manifest);
                Assert.Empty(repeated.GetProperty("changes").EnumerateArray());
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, repeated.GetProperty("revision").GetString()!));

                JsonElement conflicting = await server.CallAsync(
                    "settings/set?proxyType=None&maxLogFileDays=22", server.AdminToken);
                Assert.Equal("error", conflicting.GetProperty("status").GetString());
                Assert.Contains("/dns/proxy/password", conflicting.GetProperty("errorMessage").GetString());
                Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());

                using var restore = new MultipartFormDataContent();
                restore.Add(new ByteArrayContent(originalBackup), "file", "backup.zip");
                JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, restore);
                Assert.Equal("error", restored.GetProperty("status").GetString());
                Assert.Contains("/dns/proxy/password", restored.GetProperty("errorMessage").GetString());
                Assert.Equal(nextSecret, (await server.GetSettingsAsync()).GetProperty("proxy").GetProperty("password").GetString());

                Environment.SetEnvironmentVariable(variable, null);
                using var content = new StringContent(manifest, Encoding.UTF8, "application/json");
                JsonElement missing = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                Assert.Equal("error", missing.GetProperty("status").GetString());
                Assert.Contains("/dns/proxy/password", missing.GetProperty("errorMessage").GetString());
                Assert.DoesNotContain(variable, missing.GetRawText());
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, original);
            }
        }

        [Fact]
        public async Task StartupAppliesProxyUsingAManifestRelativePasswordFile()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string invalid = """
                {"schemaVersion":1,"dns":{"proxy":{"type":"Http","address":"127.0.0.1","port":8080,"bypass":["bad bypass entry"]}}}
                """;
            using var content = new StringContent(invalid, Encoding.UTF8, "application/json");
            JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dns/proxy/bypass/0", rejected.GetProperty("errorMessage").GetString());
            Assert.DoesNotContain("bad bypass entry", rejected.GetRawText());

            const string manifest = """
                {"schemaVersion":1,"dns":{"proxy":{"type":"Http","address":"127.0.0.1","port":8080,
                  "username":"fixture","password":{"file":"proxy-password"},"bypass":["localhost"]}}}
                """;
            string manifestPath = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);
            await File.WriteAllTextAsync(Path.Combine(server.ConfigurationDirectory, "proxy-password"), "fixture-file-password");
            await File.WriteAllTextAsync(manifestPath, manifest);

            await server.RestartAsync();
            JsonElement proxy = (await server.GetSettingsAsync()).GetProperty("proxy");
            Assert.Equal("fixture-file-password", proxy.GetProperty("password").GetString());
            Assert.Equal("localhost", Assert.Single(proxy.GetProperty("bypass").EnumerateArray()).GetString());

            File.Delete(manifestPath);
            const string disabled = """{"schemaVersion":1,"dns":{"proxy":{"type":null}}}""";
            JsonElement preview = await PreviewAsync(server, disabled);
            Assert.Contains(preview.GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").GetString() == "/dns/proxy/password");
            LoopbackWebService.AssertOk(await ApplyAsync(server, disabled, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();
            Assert.Equal(JsonValueKind.Null, (await server.GetSettingsAsync()).GetProperty("proxy").ValueKind);
        }

        [Fact]
        public async Task TsigApplyRotatesTheSigningKeyAndPersistsOwnership()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string variable = "TECHNITIUM_TEST_TSIG_PASSWORD";
            const string currentSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
            const string nextSecret = "YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODk=";
            string keys = $"current.test|{currentSecret}|hmac-sha256|remove.test|{currentSecret}|hmac-sha256";
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?tsigKeys=" + Uri.EscapeDataString(keys), server.AdminToken));

            await server.RestartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] originalBackup = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"tsigKeys":{
                  "CURRENT.TEST.":{"secret":{"environment":"TECHNITIUM_TEST_TSIG_PASSWORD"}},
                  "new.test":{"algorithm":"hmac-sha512","secret":{"environment":"TECHNITIUM_TEST_TSIG_PASSWORD"}},
                  "remove.test":null}}}
                """;
            string? original = Environment.GetEnvironmentVariable(variable);
            try
            {
                Environment.SetEnvironmentVariable(variable, currentSecret);
                JsonElement first = await PreviewAsync(server, manifest);
                Assert.Equal(2, first.GetProperty("changes").GetArrayLength());

                Environment.SetEnvironmentVariable(variable, nextSecret);
                JsonElement rotated = await PreviewAsync(server, manifest);
                Assert.NotEqual(first.GetProperty("revision").GetString(), rotated.GetProperty("revision").GetString());
                Assert.Collection(rotated.GetProperty("changes").EnumerateArray(),
                    change => AssertChange(change, "/dns/tsigKeys/current.test/secret", "Update"),
                    change => AssertChange(change, "/dns/tsigKeys/new.test", "Add"),
                    change => AssertChange(change, "/dns/tsigKeys/remove.test", "Remove"));
                Assert.DoesNotContain(currentSecret, rotated.GetRawText());
                Assert.DoesNotContain(nextSecret, rotated.GetRawText());
                Assert.Equal(2, (await server.GetSettingsAsync()).GetProperty("tsigKeys").GetArrayLength());

                JsonElement inspection = await server.CallAsync("settings/config/export?includePreviewOnly=true", server.AdminToken);
                LoopbackWebService.AssertOk(inspection);
                JsonElement exported = inspection.GetProperty("response").GetProperty("manifest").GetProperty("dns").GetProperty("tsigKeys");
                Assert.Equal("hmac-sha256", exported.GetProperty("current.test").GetProperty("algorithm").GetString());
                Assert.False(exported.GetProperty("current.test").TryGetProperty("secret", out _));
                Assert.DoesNotContain(currentSecret, inspection.GetRawText());

                JsonElement stale = await ApplyAsync(server, manifest, first.GetProperty("revision").GetString()!);
                Assert.Equal("error", stale.GetProperty("status").GetString());
                Assert.Contains("stale", stale.GetProperty("errorMessage").GetString());
                JsonNode failedCandidate = JsonNode.Parse(manifest)!;
                failedCandidate["logging"] = new JsonObject { ["retentionDays"] = 90 };
                string failedManifest = failedCandidate.ToJsonString();
                JsonElement failurePreview = await PreviewAsync(server, failedManifest);
                string blockedLogFile = Path.Combine(server.ConfigurationDirectory, "log.tmp");
                Directory.CreateDirectory(blockedLogFile);
                JsonElement failed = await ApplyAsync(server, failedManifest, failurePreview.GetProperty("revision").GetString()!);
                Assert.Equal("error", failed.GetProperty("status").GetString());
                Directory.Delete(blockedLogFile);
                await server.QueryAsync("localhost", DnsResourceRecordType.A, new TsigKey("current.test", currentSecret, "hmac-sha256"));

                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, rotated.GetProperty("revision").GetString()!));
                await server.RestartAsync();
                await server.QueryAsync("localhost", DnsResourceRecordType.A, new TsigKey("current.test", nextSecret, "hmac-sha256"));
                await server.QueryAsync("localhost", DnsResourceRecordType.A, new TsigKey("new.test", nextSecret, "hmac-sha512"));
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                JsonElement conflict = await server.CallAsync("settings/set?maxLogFileDays=22&tsigKeys=" + Uri.EscapeDataString(keys), server.AdminToken);
                Assert.Equal("error", conflict.GetProperty("status").GetString());
                Assert.Contains("/dns/tsigKeys/", conflict.GetProperty("errorMessage").GetString());
                Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());

                using var restore = new MultipartFormDataContent();
                restore.Add(new ByteArrayContent(originalBackup), "file", "backup.zip");
                JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, restore);
                Assert.Equal("error", restored.GetProperty("status").GetString());
                Assert.Contains("/dns/tsigKeys/", restored.GetProperty("errorMessage").GetString());

                Environment.SetEnvironmentVariable(variable, "invalid-fixture-secret");
                InvalidDataException invalid = Assert.Throws<InvalidDataException>(() => Load(manifest).ValidateReferences());
                Assert.Contains("/secret", invalid.Message);
                Assert.DoesNotContain("invalid-fixture-secret", invalid.Message);
                using var content = new StringContent(manifest, Encoding.UTF8, "application/json");
                JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/secret", rejected.GetProperty("errorMessage").GetString());
                Assert.DoesNotContain("invalid-fixture-secret", rejected.GetRawText());

                const string clear = """{"schemaVersion":1,"dns":{"tsigKeys":null}}""";
                LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=transfer.test&type=Primary", server.AdminToken));
                LoopbackWebService.AssertOk(await server.CallAsync("zones/options/set?zone=transfer.test&zoneTransferTsigKeyNames=current.test", server.AdminToken));
                using var clearContent = new StringContent(clear, Encoding.UTF8, "application/json");
                JsonElement inUse = await server.CallAsync("settings/config/plan", server.AdminToken, clearContent);
                Assert.Equal("error", inUse.GetProperty("status").GetString());
                Assert.Contains("still referenced by a zone", inUse.GetProperty("errorMessage").GetString());
                const string clearWithReferences = """
                    {"schemaVersion":1,"dns":{"tsigKeys":null},"zones":{"transfer.test":{"transfer":{"tsigKeys":null}}}}
                    """;
                JsonElement cleared = await PreviewAsync(server, clearWithReferences);
                Assert.Contains(cleared.GetProperty("changes").EnumerateArray(),
                    change => change.GetProperty("path").ValueEquals("/zones/transfer.test/transfer/tsigKeys"));
                LoopbackWebService.AssertOk(await ApplyAsync(server, clearWithReferences, cleared.GetProperty("revision").GetString()!));
                await server.RestartAsync();
                JsonElement settings = await server.GetSettingsAsync();
                Assert.Empty(settings.GetProperty("tsigKeys").EnumerateArray());
                Assert.Empty((await PreviewAsync(server, clearWithReferences)).GetProperty("changes").EnumerateArray());
                Assert.Contains(settings.GetProperty("managedSettings").EnumerateArray(), path => path.GetString() == "/dns/tsigKeys");
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, original);
            }

            static void AssertChange(JsonElement change, string path, string kind)
            {
                Assert.Equal(path, change.GetProperty("path").GetString());
                Assert.Equal(kind, change.GetProperty("kind").GetString());
            }
        }

        [Fact]
        public async Task ConfigurationExportEndpointReportsMissingInputsWithoutReturningSecrets()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string proxyPassword = "fixture-proxy-secret";
            const string forwarderToken = "fixture-doh-token";
            const string tsigSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
            LoopbackWebService.AssertOk(await server.CallAsync(
                "settings/set?proxyType=Http&proxyAddress=127.0.0.1&proxyPort=8080&proxyUsername=fixture&proxyPassword=" + proxyPassword +
                "&forwarderProtocol=Https&forwarders=" + Uri.EscapeDataString("https://fixture.net/dns-query?token=" + forwarderToken) +
                "&tsigKeys=" + Uri.EscapeDataString("migration-key.test|" + tsigSecret + "|hmac-sha256"), server.AdminToken));

            JsonElement legacy = await server.GetSettingsAsync();
            Assert.Equal(proxyPassword, legacy.GetProperty("proxy").GetProperty("password").GetString());

            JsonElement first = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(first);
            JsonElement response = first.GetProperty("response");
            Assert.DoesNotContain(proxyPassword, first.GetRawText());
            Assert.DoesNotContain(tsigSecret, first.GetRawText());
            Assert.DoesNotContain(forwarderToken, first.GetRawText());
            Assert.Collection(response.GetProperty("missingInputs").EnumerateArray(),
                entry => Assert.Equal("/auth/users/admin/password", entry.GetString()),
                entry => Assert.Equal("/dns/forwarding/servers", entry.GetString()),
                entry => Assert.Equal("/dns/proxy/password", entry.GetString()),
                entry => Assert.Equal("/dns/tsigKeys/migration-key.test/secret", entry.GetString()));
            JsonElement manifest = response.GetProperty("manifest");
            Assert.Equal(ConfigurationManifest.CurrentSchemaVersion, manifest.GetProperty("schemaVersion").GetInt32());
            JsonObject expectedExport = ConfigurationPlan.Export(legacy, includePreviewOnly: false);
            expectedExport["allowZones"] = new JsonArray();
            expectedExport["blockZones"] = new JsonArray();
            JsonObject actualExport = JsonNode.Parse(manifest.GetRawText())!.AsObject();
            Assert.NotNull(actualExport["dhcp"]?["scopes"]?["Default"]);
            actualExport.Remove("dhcp");
            Assert.NotNull(actualExport["auth"]?["groups"]?["Administrators"]);
            actualExport.Remove("auth");
            Assert.True(JsonNode.DeepEquals(expectedExport, actualExport));
            Assert.Equal("Http", manifest.GetProperty("dns").GetProperty("proxy").GetProperty("type").GetString());

            JsonElement inspection = await server.CallAsync("settings/config/export?includePreviewOnly=true", server.AdminToken);
            LoopbackWebService.AssertOk(inspection);
            JsonElement proxy = inspection.GetProperty("response").GetProperty("manifest").GetProperty("dns").GetProperty("proxy");
            Assert.Equal("Http", proxy.GetProperty("type").GetString());
            Assert.False(proxy.TryGetProperty("password", out _));
            Assert.DoesNotContain(proxyPassword, inspection.GetRawText());

            JsonElement repeat = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(repeat);
            Assert.Equal(response.GetRawText(), repeat.GetProperty("response").GetRawText());

            using var user = new FormUrlEncodedContent([new("user", "export-viewer"), new("pass", "fixture-password")]);
            LoopbackWebService.AssertOk(await server.CallAsync("admin/users/create", server.AdminToken, user));
            string token = await server.LoginAsync("export-viewer", "fixture-password");
            JsonElement rejected = await server.CallAsync("settings/config/export", token);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.False(rejected.TryGetProperty("response", out JsonElement denied) && denied.TryGetProperty("manifest", out _));

            LoopbackWebService.AssertOk(await server.CallAsync(
                "admin/permissions/set?section=Settings&userPermissions=export-viewer%7Ctrue%7Cfalse%7Cfalse", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "admin/permissions/set?section=DhcpServer&groupPermissions=Administrators%7Ctrue%7Ctrue%7Ctrue", server.AdminToken));
            JsonElement restricted = await server.CallAsync("settings/config/export", token);
            LoopbackWebService.AssertOk(restricted);
            Assert.False(restricted.GetProperty("response").GetProperty("manifest").TryGetProperty("dhcp", out _));
            Assert.DoesNotContain(restricted.GetProperty("response").GetProperty("missingInputs").EnumerateArray(),
                entry => entry.GetString()!.StartsWith("/dhcp", StringComparison.Ordinal));
        }

        [Fact]
        public async Task DnsTuningRestartsListenersAndPreservesSettingsAcrossReload()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"dns":{"tuning":{"clientTimeoutMs":2500,"tcpSendTimeoutMs":8000,
                    "udpReceiveBufferKiB":1024,"maxConcurrentResolutionsPerCore":90}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Collection(preview.GetProperty("changes").EnumerateArray(),
                change => Assert.False(change.GetProperty("restartDnsService").GetBoolean()),
                change => Assert.False(change.GetProperty("restartDnsService").GetBoolean()),
                change => Assert.True(change.GetProperty("restartDnsService").GetBoolean()),
                change => Assert.True(change.GetProperty("restartDnsService").GetBoolean()));
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.QueryAsync("example.invalid", DnsResourceRecordType.A);
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal(8000, settings.GetProperty("tcpSendTimeout").GetInt32());
            Assert.Equal(1024, settings.GetProperty("udpReceiveBufferSizeKB").GetInt32());
            Assert.Equal(90, settings.GetProperty("maxConcurrentResolutionsPerCore").GetInt32());
            Assert.Equal(4, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement conflict = await server.CallAsync("settings/set?tcpSendTimeout=10000", server.AdminToken);
            Assert.Equal("error", conflict.GetProperty("status").GetString());
            Assert.Contains("/dns/tuning/tcpSendTimeoutMs", conflict.GetProperty("errorMessage").GetString());

            using var occupied = new TcpListener(IPAddress.Loopback, 0);
            occupied.Start();
            JsonNode candidate = JsonNode.Parse(ListenerManifest((IPEndPoint)occupied.LocalEndpoint))!;
            candidate["dns"]!["tuning"] = new JsonObject { ["tcpSendTimeoutMs"] = 7000 };
            string changed = candidate.ToJsonString();
            string revision = (await PreviewAsync(server, changed)).GetProperty("revision").GetString()!;
            JsonElement rejected = await ApplyAsync(server, changed, revision);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            await server.QueryAsync("example.invalid", DnsResourceRecordType.A);
            Assert.Equal(8000, (await server.GetSettingsAsync()).GetProperty("tcpSendTimeout").GetInt32());
        }

        [Fact]
        public async Task LocalManifestChangesTheServedWebRootAndPersistsIt()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """{"schemaVersion":1,"web":{"rootPath":"console-assets"}}""";
            const string marker = "configured web root fixture";
            string root = Path.Combine(server.ConfigurationDirectory, "console-assets");
            Directory.CreateDirectory(root);
            await File.WriteAllTextAsync(Path.Combine(root, "root-fixture.txt"), marker);

            JsonElement preview = await PreviewAsync(server, manifest);
            JsonElement change = Assert.Single(preview.GetProperty("changes").EnumerateArray());
            Assert.Equal("/web/rootPath", change.GetProperty("path").GetString());
            Assert.True(change.GetProperty("restartWebService").GetBoolean());
            JsonElement denied = await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!);
            Assert.Equal("error", denied.GetProperty("status").GetString());
            Assert.Contains("local startup manifest", denied.GetProperty("errorMessage").GetString());

            string startup = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);
            await File.WriteAllTextAsync(startup, manifest);
            await server.RestartAsync();
            Assert.Equal(marker, await server.Client.GetStringAsync("/root-fixture.txt"));
            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal(root, settings.GetProperty("webServiceRootPath").GetString());
            Assert.Contains(settings.GetProperty("managedSettings").EnumerateArray(), item => item.GetString() == "/web/rootPath");
            JsonElement exported = await server.CallAsync("settings/config/export?includePreviewOnly=true", server.AdminToken);
            LoopbackWebService.AssertOk(exported);
            Assert.Equal(root, exported.GetProperty("response").GetProperty("manifest").GetProperty("web").GetProperty("rootPath").GetString());

            JsonElement migration = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(migration);
            JsonElement migrationResponse = migration.GetProperty("response");
            Assert.False(migrationResponse.GetProperty("manifest").GetProperty("web").TryGetProperty("rootPath", out _));
            Assert.Contains(migrationResponse.GetProperty("missingInputs").EnumerateArray(), item => item.GetString() == "/web/rootPath");

            File.Delete(startup);
            await server.RestartAsync();
            Assert.Equal(marker, await server.Client.GetStringAsync("/root-fixture.txt"));

            await File.WriteAllTextAsync(startup, """{"schemaVersion":1,"web":{"rootPath":"missing-assets"}}""");
            await Assert.ThrowsAsync<InvalidDataException>(() => server.RestartAsync());
            File.Delete(startup);
            await server.RestartAsync();
            Assert.Equal(marker, await server.Client.GetStringAsync("/root-fixture.txt"));

            await File.WriteAllTextAsync(startup, """{"schemaVersion":1,"web":{"rootPath":null}}""");
            await server.RestartAsync();
            Assert.Equal(JsonValueKind.Null, (await server.GetSettingsAsync()).GetProperty("webServiceRootPath").ValueKind);
            using HttpResponseMessage response = await server.Client.GetAsync("/root-fixture.txt");
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }

        [Fact]
        public async Task WebCertificateApplyChecksTheRevisionAndRecoversHttps()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string variable = "TECHNITIUM_TEST_WEB_CERTIFICATE_PASSWORD";
            const string password = "fixture-web-pfx-password";
            string manifest = """
                {"schemaVersion":1,"web":{"tlsEnabled":true,
                  "certificate":{"path":"console.pfx","password":{"environment":"TECHNITIUM_TEST_WEB_CERTIFICATE_PASSWORD"}}}}
                """;
            int tlsPort = LoopbackDnsServer.GetLoopbackEndPoint().Port;
            JsonNode candidate = JsonNode.Parse(manifest)!;
            candidate["web"]!["tlsPort"] = tlsPort;
            manifest = candidate.ToJsonString();
            string? original = Environment.GetEnvironmentVariable(variable);
            try
            {
                Environment.SetEnvironmentVariable(variable, password);
                string path = Path.Combine(server.ConfigurationDirectory, "console.pfx");
                WriteCertificate(path);
                JsonElement first = await PreviewAsync(server, manifest);
                Assert.DoesNotContain(password, first.GetRawText());
                Assert.Contains(first.GetProperty("changes").EnumerateArray(),
                    change => change.GetProperty("path").GetString() == "/web/certificate/path" &&
                        change.GetProperty("restartWebService").GetBoolean());

                string thumbprint = WriteCertificate(path);
                JsonElement rotated = await PreviewAsync(server, manifest);
                Assert.NotEqual(first.GetProperty("revision").GetString(), rotated.GetProperty("revision").GetString());

                JsonElement stale = await ApplyAsync(server, manifest, first.GetProperty("revision").GetString()!);
                Assert.Equal("error", stale.GetProperty("status").GetString());
                Assert.Contains("stale", stale.GetProperty("errorMessage").GetString());

                Environment.SetEnvironmentVariable(variable, "incorrect-fixture-password");
                using var content = new StringContent(manifest, Encoding.UTF8, "application/json");
                JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/web/certificate", rejected.GetProperty("errorMessage").GetString());
                Assert.DoesNotContain("incorrect-fixture-password", rejected.GetRawText());

                JsonElement settings = await server.GetSettingsAsync();
                Assert.False(settings.GetProperty("webServiceEnableTls").GetBoolean());
                Assert.Equal(JsonValueKind.Null, settings.GetProperty("webServiceTlsCertificatePath").ValueKind);

                Environment.SetEnvironmentVariable(variable, password);
                int httpPort = settings.GetProperty("webServiceHttpPort").GetInt32();
                JsonElement applied = await ApplyAsync(server, manifest, rotated.GetProperty("revision").GetString()!);
                LoopbackWebService.AssertOk(applied);
                string operation = applied.GetProperty("response").GetProperty("operationId").GetString()!;
                Assert.Equal("applied", await WaitForWebApplyAsync(httpPort, server.AdminToken, operation));
                Assert.Equal(thumbprint, await ReadThumbprintAsync(tlsPort));

                using var occupied = new TcpListener(IPAddress.Loopback, 0);
                occupied.Start();
                WriteCertificate(Path.Combine(server.ConfigurationDirectory, "replacement.pfx"));
                candidate["web"]!["tlsPort"] = ((IPEndPoint)occupied.LocalEndpoint).Port;
                candidate["web"]!["certificate"]!["path"] = "replacement.pfx";
                string replacement = candidate.ToJsonString();
                JsonElement replacementPreview = await PreviewAsync(server, replacement);
                JsonElement queued = await ApplyAsync(server, replacement, replacementPreview.GetProperty("revision").GetString()!);
                LoopbackWebService.AssertOk(queued);
                operation = queued.GetProperty("response").GetProperty("operationId").GetString()!;
                Assert.Equal("failed", await WaitForWebApplyAsync(httpPort, server.AdminToken, operation));
                Assert.Equal(thumbprint, await ReadThumbprintAsync(tlsPort));
                await server.RestartAsync();
                Assert.Equal(thumbprint, await ReadThumbprintAsync(tlsPort));

                JsonElement conflict = await server.CallAsync("settings/set?webServiceTlsCertificatePath=replacement.pfx", server.AdminToken);
                Assert.Equal("error", conflict.GetProperty("status").GetString());
                Assert.Contains("/web/certificate/path", conflict.GetProperty("errorMessage").GetString());

                string startup = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);
                await File.WriteAllTextAsync(startup, """{"schemaVersion":1,"web":{"useSelfSignedCertificate":true,"certificate":null}}""");
                await server.RestartAsync();
                string generatedThumbprint = await ReadThumbprintAsync(tlsPort);
                Assert.NotEqual(thumbprint, generatedThumbprint);
                File.Delete(startup);
                await server.RestartAsync();
                Assert.Equal(generatedThumbprint, await ReadThumbprintAsync(tlsPort));
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, original);
            }

            static string WriteCertificate(string path)
            {
                using var key = System.Security.Cryptography.RSA.Create(2048);
                var request = new CertificateRequest("CN=console.test", key, System.Security.Cryptography.HashAlgorithmName.SHA256,
                    System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
                File.WriteAllBytes(path, certificate.Export(X509ContentType.Pkcs12, password));
                return certificate.Thumbprint;
            }

            static async Task<string> ReadThumbprintAsync(int port)
            {
                using var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, port);
                using var stream = new System.Net.Security.SslStream(client.GetStream(), false, (_, _, _, _) => true);
                await stream.AuthenticateAsClientAsync("console.test");
                return stream.RemoteCertificate!.GetCertHashString();
            }
        }

        [Fact]
        public async Task DnsCertificateApplyVerifiesThePreviewAndPreservesTheWorkingCertificate()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string variable = "TECHNITIUM_TEST_DNS_CERTIFICATE_PASSWORD";
            const string password = "fixture-certificate-password";
            string? original = Environment.GetEnvironmentVariable(variable);
            try
            {
                Environment.SetEnvironmentVariable(variable, password);
                string certificateFile = Path.Combine(server.ConfigurationDirectory, "resolver.pfx");
                WriteCertificate(certificateFile);
                int port = LoopbackDnsServer.GetLoopbackEndPoint().Port;
                string manifest = Manifest(port);
                JsonElement preview = await PreviewAsync(server, manifest);
                Assert.DoesNotContain(password, preview.GetRawText());
                string activeThumbprint = WriteCertificate(certificateFile);
                JsonElement stale = await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!);
                Assert.Equal("error", stale.GetProperty("status").GetString());
                Assert.Contains("stale", stale.GetProperty("errorMessage").GetString());
                Assert.Equal(JsonValueKind.Null, (await server.GetSettingsAsync()).GetProperty("dnsTlsCertificatePath").ValueKind);

                preview = await PreviewAsync(server, manifest);
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
                Assert.Equal(activeThumbprint, await ReadThumbprintAsync(port));
                await server.RestartAsync();
                Assert.Equal(activeThumbprint, await ReadThumbprintAsync(port));
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                JsonElement exported = await server.CallAsync("settings/config/export", server.AdminToken);
                LoopbackWebService.AssertOk(exported);
                JsonElement response = exported.GetProperty("response");
                Assert.Equal("resolver.pfx", response.GetProperty("manifest").GetProperty("dns").GetProperty("listeners")
                    .GetProperty("certificate").GetProperty("path").GetString());
                Assert.Contains(response.GetProperty("missingInputs").EnumerateArray(),
                    input => input.GetString() == "/dns/listeners/certificate/password");
                Assert.DoesNotContain(password, response.GetRawText());

                JsonElement conflict = await server.CallAsync("settings/set?dnsTlsCertificatePath=replacement.pfx", server.AdminToken);
                Assert.Equal("error", conflict.GetProperty("status").GetString());
                Assert.Contains("/dns/listeners/certificate/path", conflict.GetProperty("errorMessage").GetString());

                using var occupied = new TcpListener(IPAddress.Loopback, 0);
                occupied.Start();
                string rejectedManifest = Manifest(((IPEndPoint)occupied.LocalEndpoint).Port, "replacement.pfx");
                WriteCertificate(Path.Combine(server.ConfigurationDirectory, "replacement.pfx"));
                JsonElement replacement = await PreviewAsync(server, rejectedManifest);
                JsonElement rejected = await ApplyAsync(server, rejectedManifest, replacement.GetProperty("revision").GetString()!);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Equal(activeThumbprint, await ReadThumbprintAsync(port));
                await server.RestartAsync();
                Assert.Equal(activeThumbprint, await ReadThumbprintAsync(port));

                const string reset = """
                    {"schemaVersion":1,"dns":{"listeners":{"tls":{"enabled":false},"certificate":null}}}
                    """;
                JsonElement remove = await PreviewAsync(server, reset);
                LoopbackWebService.AssertOk(await ApplyAsync(server, reset, remove.GetProperty("revision").GetString()!));
                Assert.Equal(JsonValueKind.Null, (await server.GetSettingsAsync()).GetProperty("dnsTlsCertificatePath").ValueKind);

                string startupPath = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);
                await File.WriteAllTextAsync(Path.Combine(server.ConfigurationDirectory, "certificate-password"), password);
                JsonNode startup = JsonNode.Parse(manifest)!;
                startup["dns"]!["listeners"]!["certificate"]!["password"] = new JsonObject { ["file"] = "certificate-password" };
                await File.WriteAllTextAsync(startupPath, startup.ToJsonString());
                await server.RestartAsync();
                Assert.Equal(activeThumbprint, await ReadThumbprintAsync(port));
                File.Delete(startupPath);
                await server.RestartAsync();
                Assert.Equal(activeThumbprint, await ReadThumbprintAsync(port));
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, original);
            }

            static string Manifest(int port, string file = "resolver.pfx") => $$"""
                {"schemaVersion":1,"dns":{"listeners":{"tls":{"enabled":true,"port":{{port}} },
                  "certificate":{"path":"{{file}}","password":{"environment":"TECHNITIUM_TEST_DNS_CERTIFICATE_PASSWORD"} } } } }
                """;

            static string WriteCertificate(string path)
            {
                using var key = System.Security.Cryptography.RSA.Create(2048);
                var request = new CertificateRequest("CN=resolver.test", key, System.Security.Cryptography.HashAlgorithmName.SHA256,
                    System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
                File.WriteAllBytes(path, certificate.Export(X509ContentType.Pkcs12, password));
                return certificate.Thumbprint;
            }

            static async Task<string> ReadThumbprintAsync(int port)
            {
                using var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, port);
                using var stream = new System.Net.Security.SslStream(client.GetStream(), false, (_, _, _, _) => true);
                await stream.AuthenticateAsClientAsync("resolver.test");
                return stream.RemoteCertificate!.GetCertHashString();
            }
        }

        [Fact]
        public async Task OptionalDnsBindingPersistsAndRecoversAfterABindFailure()
        {
            await using var server = await LoopbackWebService.StartAsync();
            int port;
            using (var available = new TcpListener(IPAddress.Loopback, 0))
            {
                available.Start();
                port = ((IPEndPoint)available.LocalEndpoint).Port;
            }

            string manifest = Manifest(port);
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(2, preview.GetProperty("changes").GetArrayLength());
            Assert.All(preview.GetProperty("changes").EnumerateArray(),
                change => Assert.True(change.GetProperty("restartDnsService").GetBoolean()));
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();
            await AssertBoundAsync(port);
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            using var occupied = new TcpListener(IPAddress.Loopback, 0);
            occupied.Start();
            int occupiedPort = ((IPEndPoint)occupied.LocalEndpoint).Port;
            string changed = Manifest(occupiedPort);
            JsonElement candidate = await PreviewAsync(server, changed);
            JsonElement rejected = await ApplyAsync(server, changed, candidate.GetProperty("revision").GetString()!);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            await AssertBoundAsync(port);
            await server.QueryAsync("example.invalid", DnsResourceRecordType.A);
            await server.RestartAsync();
            await AssertBoundAsync(port);

            JsonElement conflict = await server.CallAsync($"settings/set?dnsOverTcpProxyPort={occupiedPort}", server.AdminToken);
            Assert.Equal("error", conflict.GetProperty("status").GetString());
            Assert.Contains("/dns/listeners/tcpProxy/port", conflict.GetProperty("errorMessage").GetString());

            occupied.Stop();
            string path = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);
            await File.WriteAllTextAsync(path, changed);
            await server.RestartAsync();
            await AssertBoundAsync(occupiedPort);
            File.Delete(path);
            await server.RestartAsync();
            await AssertBoundAsync(occupiedPort);

            static string Manifest(int port) => $$"""
                {"schemaVersion":1,"dns":{"listeners":{"tcpProxy":{"enabled":true,"port":{{port}} } } } }
                """;

            static async Task AssertBoundAsync(int port)
            {
                using var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, port);
            }
        }

        [Fact]
        public async Task StartupPersistsNewListenerTuningForAnAlreadyOwnedField()
        {
            const string initial = """{"schemaVersion":1,"dns":{"tuning":{"tcpReceiveTimeoutMs":8000}}}""";
            await using var server = await LoopbackWebService.StartAsync(startupManifest: initial);
            Assert.Equal(8000, (await server.GetSettingsAsync()).GetProperty("tcpReceiveTimeout").GetInt32());

            string path = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);
            await File.WriteAllTextAsync(path, """{"schemaVersion":1,"dns":{"tuning":{"tcpReceiveTimeoutMs":7000}}}""");
            await server.RestartAsync();
            Assert.Equal(7000, (await server.GetSettingsAsync()).GetProperty("tcpReceiveTimeout").GetInt32());

            File.Delete(path);
            await server.RestartAsync();
            Assert.Equal(7000, (await server.GetSettingsAsync()).GetProperty("tcpReceiveTimeout").GetInt32());
            await server.QueryAsync("example.invalid", DnsResourceRecordType.A);
        }

        [Fact]
        public async Task RateLimitsPersistExtendedOwnershipAndRejectConflictingRestore()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"rateLimits":{"ipv4":[{"prefix":32,"udpLimit":40,"tcpLimit":50},{"prefix":24,"udpLimit":400,"tcpLimit":500}],
                    "ipv6":[],"sampleMinutes":3,"udpTruncationPercentage":75,"bypassNetworks":["192.0.2.10/24"]}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(5, preview.GetProperty("changes").GetArrayLength());
            Assert.DoesNotContain("192.0.2.", preview.GetRawText());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal(5, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            Assert.Empty(settings.GetProperty("qpmPrefixLimitsIPv6").EnumerateArray());
            JsonNode exported = ConfigurationPlan.Export(settings, includePreviewOnly: false)["dns"]!["rateLimits"]!;
            Assert.Equal("192.0.2.0/24", exported["bypassNetworks"]![0]!.GetValue<string>());

            LoopbackWebService.AssertOk(await server.CallAsync(
                "settings/set?qpmPrefixLimitsIPv4=24%7C400%7C500%7C32%7C40%7C50", server.AdminToken));

            JsonElement rejected = await server.CallAsync("settings/set?qpmLimitSampleMinutes=4", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dns/rateLimits/sampleMinutes", rejected.GetProperty("errorMessage").GetString());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/dns/rateLimits/", restored.GetProperty("errorMessage").GetString());

            const string reset = """{"schemaVersion":1,"dns":{"rateLimits":{"ipv6":null}}}""";
            string revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            settings = await server.GetSettingsAsync();
            Assert.Equal(3, settings.GetProperty("qpmPrefixLimitsIPv6").GetArrayLength());
            Assert.Equal("/dns/rateLimits/ipv6", Assert.Single(settings.GetProperty("managedSettings").EnumerateArray()).GetString());
        }

        [Fact]
        public async Task DeclarativeForwardingPersistsTransportsAndResolvesThroughTheUpstream()
        {
            await using var upstream = new LoopbackDnsServer();
            upstream.AddPrimaryZone("fixture.net", "www.fixture.net", IPAddress.Parse("192.0.2.42"));
            await upstream.StartAsync();
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "settings/set?recursion=AllowOnlyForPrivateNetworks&dnssecValidation=false", server.AdminToken));

            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            string manifest = $$"""
                {"schemaVersion":1,"dns":{"forwarding":{"servers":[{"address":"{{upstream.EndPoint}}","transport":"Tcp"},
                    {"address":"{{upstream.EndPoint}}","transport":"Udp"}],"concurrent":false,"retries":1,"timeoutMs":1200,"concurrency":1 } } }
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(5, preview.GetProperty("changes").GetArrayLength());
            Assert.DoesNotContain(upstream.EndPoint.ToString(), preview.GetRawText());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal(5, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            JsonArray exported = ConfigurationPlan.Export(settings, includePreviewOnly: false)["dns"]!["forwarding"]!["servers"]!.AsArray();
            Assert.Equal("Tcp", exported[0]!["transport"]!.GetValue<string>());
            Assert.Equal("Udp", exported[1]!["transport"]!.GetValue<string>());
            DnsResourceRecord answer = Assert.Single((await server.QueryAsync("www.fixture.net", DnsResourceRecordType.A)).Answer);
            Assert.Equal(IPAddress.Parse("192.0.2.42"), Assert.IsType<DnsARecordData>(answer.RDATA).Address);

            JsonElement rejected = await server.CallAsync("settings/set?forwarders=192.0.2.53", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dns/forwarding/servers", rejected.GetProperty("errorMessage").GetString());

            JsonElement proxy = await server.CallAsync("settings/set?proxyType=Http&proxyAddress=localhost&proxyPort=8080", server.AdminToken);
            Assert.Equal("error", proxy.GetProperty("status").GetString());
            Assert.Contains("/dns/forwarding/servers", proxy.GetProperty("errorMessage").GetString());
            Assert.Equal(JsonValueKind.Null, (await server.GetSettingsAsync()).GetProperty("proxy").ValueKind);

            const string incompatible = """{"schemaVersion":1,"dns":{"proxy":{"type":"Http","address":"localhost","port":8080}}}""";
            using var proxyContent = new StringContent(incompatible, Encoding.UTF8, "application/json");
            JsonElement proxyPreview = await server.CallAsync("settings/config/plan", server.AdminToken, proxyContent);
            Assert.Equal("error", proxyPreview.GetProperty("status").GetString());
            Assert.Contains("/dns/forwarding/servers", proxyPreview.GetProperty("errorMessage").GetString());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/dns/forwarding/servers", restored.GetProperty("errorMessage").GetString());

        }

        [Fact]
        public async Task ForwardingExportOmitsDohQueryCredentials()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "settings/set?forwarderProtocol=Https&forwarders=" + Uri.EscapeDataString("https://fixture.net/dns-query?token=fixture-secret"),
                server.AdminToken));

            JsonObject exported = ConfigurationPlan.Export(await server.GetSettingsAsync(), includePreviewOnly: false);

            Assert.Null(exported["dns"]!["forwarding"]!["servers"]);
            Assert.DoesNotContain("fixture-secret", exported.ToJsonString());
        }

        [Fact]
        public async Task ManifestDomainListsChangeDnsResponsesAndRecoverTogether()
        {
            await using var upstream = new LoopbackDnsServer();
            upstream.AddPrimaryZone("fixture.net", "allowed.fixture.net", IPAddress.Parse("192.0.2.99"));
            await upstream.StartAsync();
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "settings/set?recursion=AllowOnlyForPrivateNetworks&enableBlocking=true&blockingType=NxDomain&dnssecValidation=false&forwarders=" + Uri.EscapeDataString(upstream.EndPoint.ToString()), server.AdminToken));

            const string manifest = """
                {"schemaVersion":1,"allowZones":["ALLOWED.fixture.net.","allowed.fixture.net"],
                  "blockZones":["fixture.net","192.0.2.1"]}
                """;
            JsonElement initial = await PreviewAsync(server, manifest);
            LoopbackWebService.AssertOk(await server.CallAsync("blocked/add?domain=allowed.fixture.net", server.AdminToken));
            JsonElement stale = await ApplyAsync(server, manifest, initial.GetProperty("revision").GetString()!);
            Assert.Equal("error", stale.GetProperty("status").GetString());
            Assert.Contains("stale", stale.GetProperty("errorMessage").GetString());

            await server.RestartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?allowedZones=true&blockedZones=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(4, preview.GetProperty("changes").GetArrayLength());
            string revision = preview.GetProperty("revision").GetString()!;
            string blockedFile = Path.Combine(server.ConfigurationDirectory, "blocked.tmp");
            Directory.CreateDirectory(blockedFile);
            JsonElement failed = await ApplyAsync(server, manifest, revision);
            Assert.Equal("error", failed.GetProperty("status").GetString());
            Directory.Delete(blockedFile);
            Assert.Equal(DnsResponseCode.NxDomain, (await server.QueryAsync("allowed.fixture.net", DnsResourceRecordType.A)).RCODE);
            await server.RestartAsync();
            Assert.Equal(DnsResponseCode.NxDomain, (await server.QueryAsync("allowed.fixture.net", DnsResourceRecordType.A)).RCODE);

            preview = await PreviewAsync(server, manifest);
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            DnsResourceRecord answer = Assert.Single((await server.QueryAsync("allowed.fixture.net", DnsResourceRecordType.A)).Answer);
            Assert.Equal(IPAddress.Parse("192.0.2.99"), Assert.IsType<DnsARecordData>(answer.RDATA).Address);
            Assert.Equal(DnsResponseCode.NxDomain, (await server.QueryAsync("other.fixture.net", DnsResourceRecordType.A)).RCODE);
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement exported = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(exported);
            JsonElement settings = exported.GetProperty("response").GetProperty("manifest");
            Assert.Equal("allowed.fixture.net", Assert.Single(settings.GetProperty("allowZones").EnumerateArray()).GetString());
            Assert.Contains(settings.GetProperty("blockZones").EnumerateArray(), domain => domain.GetString() == "1.2.0.192.in-addr.arpa");

            JsonElement conflict = await server.CallAsync("allowed/delete?domain=allowed.fixture.net", server.AdminToken);
            Assert.Equal("error", conflict.GetProperty("status").GetString());
            Assert.Contains("/allowZones", conflict.GetProperty("errorMessage").GetString());
            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?allowedZones=true&blockedZones=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/allowZones", restored.GetProperty("errorMessage").GetString());
        }

        [Fact]
        public async Task BlockingPolicyAppliesAndExportsConfiguredStateDuringTemporaryPause()
        {
            await using var upstream = new LoopbackDnsServer();
            upstream.AddPrimaryZone("fixture.net", "blocked.fixture.net", IPAddress.Parse("192.0.2.99"));
            await upstream.StartAsync();

            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "settings/set?recursion=AllowOnlyForPrivateNetworks&dnssecValidation=false&forwarders=" + Uri.EscapeDataString(upstream.EndPoint.ToString()), server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync("blocked/add?domain=blocked.fixture.net", server.AdminToken));
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"blocking":{"enabled":true,"allowTxtReport":false,"bypassNetworks":["192.0.2.0/24"],
                    "responseType":"CustomAddress","answerTtl":90,"customAddresses":["2001:db8::10","192.0.2.10"]}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal(6, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            DnsResourceRecord answer = Assert.Single((await server.QueryAsync("blocked.fixture.net", DnsResourceRecordType.A)).Answer);
            Assert.Equal(IPAddress.Parse("192.0.2.10"), Assert.IsType<DnsARecordData>(answer.RDATA).Address);
            Assert.Equal(90u, answer.OriginalTtlValue);

            JsonElement rejected = await server.CallAsync("settings/set?blockingAnswerTtl=30", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dns/blocking/answerTtl", rejected.GetProperty("errorMessage").GetString());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/dns/blocking/", restored.GetProperty("errorMessage").GetString());

            LoopbackWebService.AssertOk(await server.CallAsync("settings/temporaryDisableBlocking?minutes=2", server.AdminToken));
            settings = await server.GetSettingsAsync();
            Assert.False(settings.GetProperty("enableBlocking").GetBoolean());
            DnsResourceRecord forwarded = Assert.Single((await server.QueryAsync("blocked.fixture.net", DnsResourceRecordType.A)).Answer);
            Assert.Equal(IPAddress.Parse("192.0.2.99"), Assert.IsType<DnsARecordData>(forwarded.RDATA).Address);
            Assert.True(ConfigurationPlan.Export(settings, includePreviewOnly: false)["dns"]!["blocking"]!["enabled"]!.GetValue<bool>());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?defaultRecordTtl=123", server.AdminToken));
            await server.RestartAsync();
            Assert.True((await server.GetSettingsAsync()).GetProperty("enableBlocking").GetBoolean());
        }

        [Fact]
        public async Task CachePrefetchPreviewIncludesImplicitChangesAndProtectsOwnedFields()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?cachePrefetchTrigger=0", server.AdminToken));
            const string manifest = """{"schemaVersion":1,"dns":{"cache":{"prefetch":{"enabled":true,"eligibility":4}}}}""";
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Collection(preview.GetProperty("changes").EnumerateArray(),
                change => Assert.Equal("/dns/cache/prefetch/eligibility", change.GetProperty("path").GetString()),
                change => Assert.Equal("/dns/cache/prefetch/enabled", change.GetProperty("path").GetString()),
                change => Assert.Equal("/dns/cache/prefetch/trigger", change.GetProperty("path").GetString()));
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.True(settings.GetProperty("enableCachePrefetch").GetBoolean());
            Assert.Equal(9, settings.GetProperty("cachePrefetchTrigger").GetInt32());
            Assert.Equal(4, settings.GetProperty("cachePrefetchEligibility").GetInt32());
            Assert.Equal(2, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            JsonNode exported = ConfigurationPlan.Export(settings, includePreviewOnly: false)["dns"]!["cache"]!["prefetch"]!;
            Assert.Equal(9, exported["trigger"]!.GetValue<int>());

            JsonElement conflict = await server.CallAsync("settings/set?cachePrefetchTrigger=0", server.AdminToken);
            Assert.Equal("error", conflict.GetProperty("status").GetString());
            Assert.Contains("/dns/cache/prefetch/enabled", conflict.GetProperty("errorMessage").GetString());

            const string disable = """{"schemaVersion":1,"dns":{"cache":{"prefetch":{"trigger":0}}}}""";
            JsonElement disabled = await PreviewAsync(server, disable);
            Assert.Equal(2, disabled.GetProperty("changes").GetArrayLength());
            LoopbackWebService.AssertOk(await ApplyAsync(server, disable, disabled.GetProperty("revision").GetString()!));
            settings = await server.GetSettingsAsync();
            Assert.False(settings.GetProperty("enableCachePrefetch").GetBoolean());
            Assert.Equal(0, settings.GetProperty("cachePrefetchTrigger").GetInt32());
            Assert.Equal("/dns/cache/prefetch/trigger", Assert.Single(settings.GetProperty("managedSettings").EnumerateArray()).GetString());

            conflict = await server.CallAsync("settings/set?enableCachePrefetch=true", server.AdminToken);
            Assert.Equal("error", conflict.GetProperty("status").GetString());
            Assert.Contains("/dns/cache/prefetch/trigger", conflict.GetProperty("errorMessage").GetString());
        }

        [Fact]
        public async Task CachePolicyAppliesAndProtectsManagedTtls()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"cache":{"saveToDisk":false,"maximumEntries":12345,"minimumRecordTtl":15,
                    "maximumRecordTtl":86400,"negativeRecordTtl":180,"failureRecordTtl":20,
                    "serveStale":{"enabled":false,"ttl":3600,"answerTtl":10,"resetTtl":20,"maxWaitMs":900}}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            string cachePath = Path.Combine(server.ConfigurationDirectory, "cache.bin");
            await File.WriteAllBytesAsync(cachePath, []);
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            Assert.False(File.Exists(cachePath));

            await server.RestartAsync();
            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal(11, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            JsonObject declared = JsonNode.Parse(manifest)!["dns"]!["cache"]!.AsObject();
            JsonObject exported = ConfigurationPlan.Export(settings, includePreviewOnly: false)["dns"]!["cache"]!.AsObject();
            foreach ((string key, JsonNode? value) in declared)
                Assert.True(JsonNode.DeepEquals(value, exported[key]), key);

            int ttl = settings.GetProperty("defaultRecordTtl").GetInt32();
            JsonElement edit = await server.CallAsync("settings/set?cacheNegativeRecordTtl=300&defaultRecordTtl=123", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/dns/cache/negativeRecordTtl", edit.GetProperty("errorMessage").GetString());
            Assert.Equal(ttl, (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/dns/cache/", restored.GetProperty("errorMessage").GetString());

            const string reset = """{"schemaVersion":1,"dns":{"cache":{"negativeRecordTtl":null}}}""";
            revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            settings = await server.GetSettingsAsync();
            Assert.Equal(300, settings.GetProperty("cacheNegativeRecordTtl").GetInt32());
            Assert.Equal("/dns/cache/negativeRecordTtl", Assert.Single(settings.GetProperty("managedSettings").EnumerateArray()).GetString());
        }

        [Fact]
        public async Task ResolverOptionsPersistOwnershipAndRejectConflictingBackup()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"recursion":{"randomizeName":true,"qnameMinimization":false,"locallyServedDnsZones":false,
                    "retries":3,"timeoutMs":2500,"concurrency":4,"maxStackCount":20}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(7, preview.GetProperty("changes").GetArrayLength());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal(7, settings.GetProperty("managedSettings").GetArrayLength());
            JsonNode declared = JsonNode.Parse(manifest)!["dns"]!["recursion"]!;
            JsonNode exported = ConfigurationPlan.Export(settings, includePreviewOnly: false)["dns"]!["recursion"]!;
            foreach ((string field, JsonNode? value) in declared.AsObject())
                Assert.True(JsonNode.DeepEquals(value, exported[field]));
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            int ttl = settings.GetProperty("defaultRecordTtl").GetInt32();
            JsonElement edit = await server.CallAsync("settings/set?resolverMaxStackCount=16&defaultRecordTtl=123", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/dns/recursion/maxStackCount", edit.GetProperty("errorMessage").GetString());
            Assert.Equal(ttl, (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?resolverMaxStackCount=20", server.AdminToken));

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/dns/recursion/", restored.GetProperty("errorMessage").GetString());

            const string reset = """{"schemaVersion":1,"dns":{"recursion":{"maxStackCount":null}}}""";
            string revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            settings = await server.GetSettingsAsync();
            Assert.Equal(16, settings.GetProperty("resolverMaxStackCount").GetInt32());
            Assert.Equal(3, settings.GetProperty("resolverRetries").GetInt32());
            Assert.Equal("/dns/recursion/maxStackCount", Assert.Single(settings.GetProperty("managedSettings").EnumerateArray()).GetString());
        }

        [Fact]
        public async Task RecursionPolicyAppliesAndProtectsAclOrder()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=recursion.test&type=Primary", server.AdminToken));
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"recursion":{"mode":"UseSpecifiedNetworkACL",
                    "networkAcl":["!127.0.0.0/8","127.0.0.1"]}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(2, preview.GetProperty("changes").GetArrayLength());
            Assert.DoesNotContain("127.0.0.0", preview.GetRawText());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal("UseSpecifiedNetworkACL", settings.GetProperty("recursion").GetString());
            Assert.Equal(2, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            JsonNode exported = ConfigurationPlan.Export(settings, includePreviewOnly: false)["dns"]!["recursion"]!;
            Assert.Equal("UseSpecifiedNetworkACL", exported["mode"]!.GetValue<string>());
            Assert.Equal("""["!127.0.0.0/8","127.0.0.1"]""", exported["networkAcl"]!.ToJsonString());

            JsonElement reordered = await server.CallAsync(
                "settings/set?recursionNetworkACL=127.0.0.1%2C%21127.0.0.0%2F8", server.AdminToken);
            Assert.Equal("error", reordered.GetProperty("status").GetString());
            Assert.Contains("/dns/recursion/networkAcl", reordered.GetProperty("errorMessage").GetString());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/dns/recursion/mode", restored.GetProperty("errorMessage").GetString());
            Assert.Equal("UseSpecifiedNetworkACL", (await server.GetSettingsAsync()).GetProperty("recursion").GetString());

            Assert.False((await server.QueryAsync("recursion.test", DnsResourceRecordType.SOA)).RecursionAvailable);
            const string allowFirst = """
                {"schemaVersion":1,"dns":{"recursion":{"mode":"UseSpecifiedNetworkACL","networkAcl":["127.0.0.1","!127.0.0.0/8"]}}}
                """;
            string allowRevision = (await PreviewAsync(server, allowFirst)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, allowFirst, allowRevision));
            Assert.True((await server.QueryAsync("recursion.test", DnsResourceRecordType.SOA)).RecursionAvailable);

            const string clear = """{"schemaVersion":1,"dns":{"recursion":{"networkAcl":null}}}""";
            string revision = (await PreviewAsync(server, clear)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, clear, revision));
            Assert.Empty((await server.GetSettingsAsync()).GetProperty("recursionNetworkACL").EnumerateArray());
        }

        [Fact]
        public async Task DnsRestoreAcceptsMatchingOwnedLoggingAndStatistics()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"logging":{"logQueries":true,"ignoreResolverLogs":true},
                 "statistics":{"inMemory":true,"retentionDays":180}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            JsonElement previous = await server.GetSettingsAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            int originalTtl = previous.GetProperty("defaultRecordTtl").GetInt32();
            int changedTtl = originalTtl == 60 ? 61 : 60;
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?defaultRecordTtl=" + changedTtl, server.AdminToken));
            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            LoopbackWebService.AssertOk(await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form));

            JsonElement restored = await server.GetSettingsAsync();
            Assert.Equal(originalTtl, restored.GetProperty("defaultRecordTtl").GetInt32());
            Assert.True(restored.GetProperty("logQueries").GetBoolean());
            Assert.True(restored.GetProperty("ignoreResolverLogs").GetBoolean());
            Assert.True(restored.GetProperty("enableInMemoryStats").GetBoolean());
            Assert.Equal(180, restored.GetProperty("maxStatFileDays").GetInt32());
            Assert.True(JsonElement.DeepEquals(previous.GetProperty("managedSettings"), restored.GetProperty("managedSettings")));
        }

        [Fact]
        public async Task DnsLoggingFlagsApplyPersistAndRejectMixedEdits()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"logging":{"ignoreResolverLogs":true,"logQueries":true,"retentionDays":180}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();
            JsonElement settings = await server.GetSettingsAsync();
            Assert.True(settings.GetProperty("ignoreResolverLogs").GetBoolean());
            Assert.True(settings.GetProperty("logQueries").GetBoolean());
            Assert.Equal(180, settings.GetProperty("maxLogFileDays").GetInt32());
            Assert.Equal(3, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            JsonNode logging = ConfigurationPlan.Export(settings, includePreviewOnly: false)["logging"]!;
            Assert.True(logging["ignoreResolverLogs"]!.GetValue<bool>());
            Assert.True(logging["logQueries"]!.GetValue<bool>());

            int ttl = settings.GetProperty("defaultRecordTtl").GetInt32();
            JsonElement rejected = await server.CallAsync("settings/set?logQueries=false&defaultRecordTtl=123", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/logging/logQueries", rejected.GetProperty("errorMessage").GetString());
            Assert.Equal(ttl, (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?ignoreResolverLogs=true&logQueries=true", server.AdminToken));

            int unownedTtl = ttl == 90 ? 91 : 90;
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?defaultRecordTtl=" + unownedTtl, server.AdminToken));
            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/logging/", restored.GetProperty("errorMessage").GetString());
            Assert.Equal(unownedTtl, (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());

            const string reset = """{"schemaVersion":1,"logging":{"logQueries":null}}""";
            revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            settings = await server.GetSettingsAsync();
            Assert.False(settings.GetProperty("logQueries").GetBoolean());
            Assert.True(settings.GetProperty("ignoreResolverLogs").GetBoolean());
            Assert.Equal("/logging/logQueries", Assert.Single(settings.GetProperty("managedSettings").EnumerateArray()).GetString());
        }

        [Fact]
        public async Task ClientSubnetApplyNormalizesOverridesAndProtectsOwnedSettings()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"clientSubnet":{"enabled":true,"ipv4PrefixLength":25,
                    "ipv6PrefixLength":60,"ipv4Override":"192.0.2.200","ipv6Override":"2001:db8:1234:5678::abcd"}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(5, preview.GetProperty("changes").GetArrayLength());
            Assert.DoesNotContain("192.0.2.", preview.GetRawText());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.True(settings.GetProperty("eDnsClientSubnet").GetBoolean());
            Assert.Equal("192.0.2.128/25", settings.GetProperty("eDnsClientSubnetIpv4Override").GetString());
            Assert.Equal("2001:db8:1234:5670::/60", settings.GetProperty("eDnsClientSubnetIpv6Override").GetString());
            Assert.Equal(5, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            Assert.Equal("192.0.2.128/25",
                ConfigurationPlan.Export(settings, includePreviewOnly: false)["dns"]!["clientSubnet"]!["ipv4Override"]!.GetValue<string>());

            int ttl = settings.GetProperty("defaultRecordTtl").GetInt32();
            JsonElement edit = await server.CallAsync("settings/set?eDnsClientSubnetIpv4Override=&defaultRecordTtl=123", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/dns/clientSubnet/ipv4Override", edit.GetProperty("errorMessage").GetString());
            Assert.Equal(ttl, (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?eDnsClientSubnetIpv4Override=192.0.2.201", server.AdminToken));

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/dns/clientSubnet/", restored.GetProperty("errorMessage").GetString());

            const string reset = """{"schemaVersion":1,"dns":{"clientSubnet":{"enabled":null,"ipv4Override":null}}}""";
            string revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            settings = await server.GetSettingsAsync();
            Assert.False(settings.GetProperty("eDnsClientSubnet").GetBoolean());
            Assert.Equal(JsonValueKind.Null, settings.GetProperty("eDnsClientSubnetIpv4Override").ValueKind);
            Assert.Equal(25, settings.GetProperty("eDnsClientSubnetIPv4PrefixLength").GetInt32());
        }

        [Fact]
        public async Task UdpPortExclusionsRoundTripAsASetAndResetToWebTlsPort()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "settings/set?enableUdpSocketPool=false&socketPoolExcludedPorts=5300", server.AdminToken));
            await server.RestartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """{"schemaVersion":1,"dns":{"udpSocketPool":{"excludedPorts":[5302,5301,5302]}}}""";
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();
            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal("[5301,5302]", settings.GetProperty("socketPoolExcludedPorts").GetRawText());
            Assert.Equal("/dns/udpSocketPool/excludedPorts", Assert.Single(settings.GetProperty("managedSettings").EnumerateArray()).GetString());
            Assert.Equal("[5301,5302]", ConfigurationPlan.Export(settings, includePreviewOnly: false)["dns"]!["udpSocketPool"]!["excludedPorts"]!.ToJsonString());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?socketPoolExcludedPorts=5302,5301", server.AdminToken));

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/dns/udpSocketPool/excludedPorts", restored.GetProperty("errorMessage").GetString());

            const string clear = """{"schemaVersion":1,"dns":{"udpSocketPool":{"excludedPorts":[]}}}""";
            revision = (await PreviewAsync(server, clear)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, clear, revision));
            Assert.Empty((await server.GetSettingsAsync()).GetProperty("socketPoolExcludedPorts").EnumerateArray());

            const string reset = """{"schemaVersion":1,"dns":{"udpSocketPool":{"excludedPorts":null}}}""";
            revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            settings = await server.GetSettingsAsync();
            Assert.Equal(settings.GetProperty("webServiceTlsPort").GetInt32(),
                Assert.Single(settings.GetProperty("socketPoolExcludedPorts").EnumerateArray()).GetInt32());
            Assert.Empty((await PreviewAsync(server, reset)).GetProperty("changes").EnumerateArray());
        }

        [Fact]
        public async Task AppAutoUpdateAppliesAndRejectsConflictingBackup()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?dnsAppsEnableAutomaticUpdate=true", server.AdminToken));
            await server.RestartAsync();
            Assert.True((await server.GetSettingsAsync()).GetProperty("dnsAppsEnableAutomaticUpdate").GetBoolean());
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """{"schemaVersion":1,"apps":{"autoUpdate":false}}""";
            JsonElement preview = await PreviewAsync(server, manifest);
            JsonElement change = Assert.Single(preview.GetProperty("changes").EnumerateArray());
            Assert.Equal("/apps/autoUpdate", change.GetProperty("path").GetString());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.False(settings.GetProperty("dnsAppsEnableAutomaticUpdate").GetBoolean());
            Assert.Equal("/apps/autoUpdate", Assert.Single(settings.GetProperty("managedSettings").EnumerateArray()).GetString());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            Assert.False(ConfigurationPlan.Export(settings, includePreviewOnly: false)["apps"]!["autoUpdate"]!.GetValue<bool>());

            int ttl = settings.GetProperty("defaultRecordTtl").GetInt32();
            JsonElement edit = await server.CallAsync("settings/set?dnsAppsEnableAutomaticUpdate=true&defaultRecordTtl=123", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/apps/autoUpdate", edit.GetProperty("errorMessage").GetString());
            Assert.Equal(ttl, (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restored = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restored.GetProperty("status").GetString());
            Assert.Contains("/apps/autoUpdate", restored.GetProperty("errorMessage").GetString());

            const string reset = """{"schemaVersion":1,"apps":{"autoUpdate":null}}""";
            string revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            Assert.True((await server.GetSettingsAsync()).GetProperty("dnsAppsEnableAutomaticUpdate").GetBoolean());
        }

        [Fact]
        public async Task StatisticsApplyPersistsAndPreflightsLegacyEdits()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?enableInMemoryStats=false&maxStatFileDays=120", server.AdminToken));
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """{"schemaVersion":1,"statistics":{"inMemory":true,"retentionDays":0}}""";
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(2, preview.GetProperty("changes").GetArrayLength());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));

            await server.RestartAsync();
            JsonElement settings = await server.GetSettingsAsync();
            Assert.True(settings.GetProperty("enableInMemoryStats").GetBoolean());
            Assert.Equal(0, settings.GetProperty("maxStatFileDays").GetInt32());
            Assert.Contains(settings.GetProperty("managedSettings").EnumerateArray(), path => path.ValueEquals("/statistics/inMemory"));
            Assert.Contains(settings.GetProperty("managedSettings").EnumerateArray(), path => path.ValueEquals("/statistics/retentionDays"));
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            int ttl = settings.GetProperty("defaultRecordTtl").GetInt32();
            JsonElement rejected = await server.CallAsync("settings/set?defaultRecordTtl=123&maxStatFileDays=90", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/statistics/retentionDays", rejected.GetProperty("errorMessage").GetString());
            Assert.Equal(ttl, (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?enableInMemoryStats=true&maxStatFileDays=0", server.AdminToken));

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restore = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restore.GetProperty("status").GetString());
            Assert.Contains("/statistics", restore.GetProperty("errorMessage").GetString());
            Assert.Equal(0, (await server.GetSettingsAsync()).GetProperty("maxStatFileDays").GetInt32());

            const string reset = """{"schemaVersion":1,"statistics":{"inMemory":null,"retentionDays":null}}""";
            string revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            settings = await server.GetSettingsAsync();
            Assert.False(settings.GetProperty("enableInMemoryStats").GetBoolean());
            Assert.Equal(365, settings.GetProperty("maxStatFileDays").GetInt32());

            const string release = """{"schemaVersion":1}""";
            revision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, release, revision));
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?maxStatFileDays=90", server.AdminToken));
        }

        [Fact]
        public async Task ResolverProtocolSettingsApplyAndRejectConflictingRestore()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """{"schemaVersion":1,"dns":{"udpPayloadSize":1400,"dnssecValidation":false}}""";
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(2, preview.GetProperty("changes").GetArrayLength());
            string revision = preview.GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();

            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(1400, current.GetProperty("udpPayloadSize").GetInt32());
            Assert.False(current.GetProperty("dnssecValidation").GetBoolean());
            Assert.Equal(2, current.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement edit = await server.CallAsync("settings/set?dnssecValidation=true&maxLogFileDays=180", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/dns/dnssecValidation", edit.GetProperty("errorMessage").GetString());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restore = await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", restore.GetProperty("status").GetString());
            Assert.Contains("/dns/udpPayloadSize", restore.GetProperty("errorMessage").GetString());
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());

            const string reset = """{"schemaVersion":1,"dns":{"udpPayloadSize":null,"dnssecValidation":null}}""";
            revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            current = await server.GetSettingsAsync();
            Assert.Equal(1232, current.GetProperty("udpPayloadSize").GetInt32());
            Assert.True(current.GetProperty("dnssecValidation").GetBoolean());
        }

        [Fact]
        public async Task ServerDomainPreviewUsesCanonicalNamesWithoutChangingIdentity()
        {
            await using var server = await LoopbackWebService.StartAsync(serverDomain: "server.test");
            const string equivalent = """{"schemaVersion":1,"dns":{"serverDomain":"SERVER.TEST."}}""";
            Assert.Empty((await PreviewAsync(server, equivalent)).GetProperty("changes").EnumerateArray());

            const string updated = """{"schemaVersion":1,"dns":{"serverDomain":"bücher.test"}}""";
            JsonElement change = Assert.Single((await PreviewAsync(server, updated)).GetProperty("changes").EnumerateArray());
            Assert.Equal("/dns/serverDomain", change.GetProperty("path").GetString());
            Assert.Equal("server.test", (await server.GetSettingsAsync()).GetProperty("dnsServerDomain").GetString());

            using var snapshot = JsonDocument.Parse("""{"dnsServerDomain":"xn--bcher-kva.test","clusterDomain":"test"}""");
            Assert.Empty(ConfigurationPlan.Create(Load(updated), snapshot.RootElement));
            InvalidDataException conflict = Assert.Throws<InvalidDataException>(() =>
                ConfigurationPlan.Create(Load("""{"schemaVersion":1,"dns":{"serverDomain":"outside.example"}}"""), snapshot.RootElement));
            Assert.Contains("/dns/serverDomain", conflict.Message);
            Assert.Contains("cluster domain", conflict.Message);
        }

        [Theory]
        [InlineData("192.0.2.1")]
        [InlineData("invalid host.test")]
        [InlineData(".")]
        public void InvalidServerDomainsReportTheManifestPath(string domain)
        {
            string manifest = JsonSerializer.Serialize(new { schemaVersion = 1, dns = new { serverDomain = domain } });
            InvalidDataException error = Assert.Throws<InvalidDataException>(() => Load(manifest));
            Assert.StartsWith("/dns/serverDomain:", error.Message);
        }

        [Fact]
        public async Task ServerDomainApplyUpdatesSelfSignedCertificateAndPersistsOwnership()
        {
            await using var server = await LoopbackWebService.StartAsync(enableTls: true);
            const string manifest = """{"schemaVersion":1,"dns":{"serverDomain":"RENAMED.TEST."}}""";
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;

            string blockedPath = Path.Combine(server.ConfigurationDirectory, "dns.tmp");
            Directory.CreateDirectory(blockedPath);
            JsonElement failed = await ApplyAsync(server, manifest, revision);
            Assert.Equal("error", failed.GetProperty("status").GetString());
            Assert.Equal("server.test", (await server.GetSettingsAsync()).GetProperty("dnsServerDomain").GetString());
            Directory.Delete(blockedPath);

            revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            using var certificate = X509CertificateLoader.LoadPkcs12FromFile(
                Path.Combine(server.ConfigurationDirectory, "self-signed-cert.pfx"), null);
            Assert.Equal("renamed.test", certificate.GetNameInfo(X509NameType.SimpleName, false));

            await server.RestartAsync();
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal("renamed.test", current.GetProperty("dnsServerDomain").GetString());
            Assert.Equal("/dns/serverDomain", Assert.Single(current.GetProperty("managedSettings").EnumerateArray()).GetString());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement rejected = await server.CallAsync("settings/set?dnsServerDomain=other.test&maxLogFileDays=180", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dns/serverDomain", rejected.GetProperty("errorMessage").GetString());
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
        }

        [Fact]
        public async Task FreshStartupUsesDeclaredDomainWhenLegacyEnvironmentIsInvalid()
        {
            const string variable = "DNS_SERVER_DOMAIN";
            const string invalidDomain = "invalid legacy domain";
            string? previous = Environment.GetEnvironmentVariable(variable);
            Environment.SetEnvironmentVariable(variable, invalidDomain);
            try
            {
                IPEndPoint endpoint = LoopbackDnsServer.GetLoopbackEndPoint();
                string manifest = JsonSerializer.Serialize(new
                {
                    schemaVersion = 1,
                    dns = new { serverDomain = "declared.test", localEndpoints = new[] { endpoint.ToString() } }
                });
                await using var server = await LoopbackWebService.StartAsync(startupManifest: manifest, seedDnsConfiguration: false);
                JsonElement current = await server.GetSettingsAsync();
                Assert.Equal("declared.test", current.GetProperty("dnsServerDomain").GetString());
                Assert.Contains(current.GetProperty("managedSettings").EnumerateArray(),
                    path => path.GetString() == "/dns/serverDomain");

                JsonElement preview = await PreviewAsync(server, manifest);
                string warning = Assert.Single(preview.GetProperty("warnings").EnumerateArray()).GetString()!;
                Assert.Contains("/dns/serverDomain", warning);
                Assert.Contains(variable, warning);
                Assert.DoesNotContain(invalidDomain, warning);
                Assert.Empty(preview.GetProperty("changes").EnumerateArray());

                Environment.SetEnvironmentVariable(variable, "DECLARED.TEST.");
                Assert.False((await PreviewAsync(server, manifest)).TryGetProperty("warnings", out _));
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }
        }

        [Fact]
        public async Task BlockListSchedulePersistsAndRollsBackWithOtherSettings()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?blockLists=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """{"schemaVersion":1,"blocklists":{"updateIntervalHours":0},"logging":{"retentionDays":180}}""";
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            string blockedPath = Path.Combine(server.ConfigurationDirectory, "blocklist.tmp");
            Directory.CreateDirectory(blockedPath);
            JsonElement failed = await ApplyAsync(server, manifest, revision);
            Assert.Equal("error", failed.GetProperty("status").GetString());
            Directory.Delete(blockedPath);
            await server.RestartAsync();
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(24, current.GetProperty("blockListUpdateIntervalHours").GetInt32());
            Assert.Equal(365, current.GetProperty("maxLogFileDays").GetInt32());

            revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();
            current = await server.GetSettingsAsync();
            Assert.Equal(0, current.GetProperty("blockListUpdateIntervalHours").GetInt32());
            Assert.Equal(180, current.GetProperty("maxLogFileDays").GetInt32());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement edit = await server.CallAsync("settings/set?blockListUpdateIntervalHours=24", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/blocklists/updateIntervalHours", edit.GetProperty("errorMessage").GetString());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restore = await server.CallAsync("settings/restore?blockLists=true", server.AdminToken, form);
            Assert.Equal("error", restore.GetProperty("status").GetString());
            Assert.Contains("/blocklists/updateIntervalHours", restore.GetProperty("errorMessage").GetString());
        }

        [Fact]
        public async Task BlockListSourcesPersistWithoutLeakingUrlsInPreviewOrExport()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string secret = "fixture-sensitive";
            const string source = "https://example.test/list?token=" + secret;
            string manifest = JsonSerializer.Serialize(new { schemaVersion = 1, blocklists = new { sources = new[] { source, source }, updateIntervalHours = 0 } });

            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.DoesNotContain(secret, preview.GetRawText());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));

            await server.RestartAsync();
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(source, Assert.Single(current.GetProperty("blockListUrls").EnumerateArray()).GetString());
            Assert.Contains(current.GetProperty("managedSettings").EnumerateArray(), path => path.GetString() == "/blocklists/sources");
            Assert.DoesNotContain(secret, ConfigurationPlan.Export(current, includePreviewOnly: false).ToJsonString());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement edit = await server.CallAsync("settings/set?blockListUrls=https%3A%2F%2Fexample.test%2Fother", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/blocklists/sources", edit.GetProperty("errorMessage").GetString());

            const string clear = """{"schemaVersion":1,"blocklists":{"sources":null,"updateIntervalHours":0}}""";
            string revision = (await PreviewAsync(server, clear)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, clear, revision));
            Assert.Equal(JsonValueKind.Null, (await server.GetSettingsAsync()).GetProperty("blockListUrls").ValueKind);
            Assert.Empty((await PreviewAsync(server, clear)).GetProperty("changes").EnumerateArray());
        }

        [Fact]
        public async Task ManagedWebHeadersTakeEffectLiveAndRejectConflictingRestore()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?webServiceSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """{"schemaVersion":1,"web":{"realIpHeader":"X-Proxy-IP","frameAncestors":"'self'"}}""";
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(2, preview.GetProperty("changes").GetArrayLength());
            Assert.All(preview.GetProperty("changes").EnumerateArray(), change => Assert.False(change.GetProperty("restartWebService").GetBoolean()));
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));

            using HttpResponseMessage page = await server.Client.GetAsync("/index.html");
            page.EnsureSuccessStatusCode();
            Assert.Contains("frame-ancestors 'self';", Assert.Single(page.Headers.GetValues("Content-Security-Policy")));
            Assert.False(page.Headers.Contains("X-Frame-Options"));

            await server.RestartAsync();
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal("X-Proxy-IP", current.GetProperty("webServiceRealIpHeader").GetString());
            Assert.Equal("'self'", current.GetProperty("webServiceCspFrameAncestorsHeader").GetString());
            Assert.Equal(2, current.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement edit = await server.CallAsync("settings/set?webServiceRealIpHeader=X-Other-IP&maxLogFileDays=180", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/web/realIpHeader", edit.GetProperty("errorMessage").GetString());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(original), "file", "backup.zip");
            JsonElement restore = await server.CallAsync("settings/restore?webServiceSettings=true", server.AdminToken, form);
            Assert.Equal("error", restore.GetProperty("status").GetString());
            Assert.Contains("/web/realIpHeader", restore.GetProperty("errorMessage").GetString());
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
        }

        [Fact]
        public async Task ReverseProxyAclPreservesFirstMatchOrderAndTakesEffectLive()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string denyFirst = """{"schemaVersion":1,"web":{"reverseProxyAcl":["!127.0.0.1","127.0.0.0/8"]}}""";
            string revision = (await PreviewAsync(server, denyFirst)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, denyFirst, revision));
            Assert.Equal("127.0.0.1", await ReportedRemoteAddressAsync());

            const string allowFirst = """{"schemaVersion":1,"web":{"reverseProxyAcl":["127.0.0.0/8","!127.0.0.1"]}}""";
            JsonElement preview = await PreviewAsync(server, allowFirst);
            Assert.Equal("/web/reverseProxyAcl", Assert.Single(preview.GetProperty("changes").EnumerateArray()).GetProperty("path").GetString());
            LoopbackWebService.AssertOk(await ApplyAsync(server, allowFirst, preview.GetProperty("revision").GetString()!));
            Assert.Equal("192.0.2.42", await ReportedRemoteAddressAsync());

            await server.RestartAsync();
            Assert.Equal("192.0.2.42", await ReportedRemoteAddressAsync());
            Assert.Empty((await PreviewAsync(server, allowFirst)).GetProperty("changes").EnumerateArray());
            JsonElement rejected = await server.CallAsync("settings/set?webServiceReverseProxyAddresses=", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/web/reverseProxyAcl", rejected.GetProperty("errorMessage").GetString());

            async Task<string?> ReportedRemoteAddressAsync()
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/sessions/list");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
                request.Headers.Add(LoopbackWebService.LegacyRealIpHeader, "192.0.2.42");
                using HttpResponseMessage response = await server.Client.SendAsync(request);
                response.EnsureSuccessStatusCode();
                using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStreamAsync());
                LoopbackWebService.AssertOk(body.RootElement);
                JsonElement session = Assert.Single(body.RootElement.GetProperty("response").GetProperty("sessions").EnumerateArray(),
                    entry => entry.GetProperty("isCurrentSession").GetBoolean());
                return session.GetProperty("lastSeenRemoteAddress").GetString();
            }
        }

        [Fact]
        public async Task StartupWebListenersCommitOnlyAfterSuccessfulBind()
        {
            await using var server = await LoopbackWebService.StartAsync();
            int originalPort = server.Client.BaseAddress!.Port;
            string manifestFile = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);
            using var occupied = new TcpListener(IPAddress.Loopback, 0);
            occupied.Start();
            int occupiedPort = ((IPEndPoint)occupied.LocalEndpoint).Port;
            await File.WriteAllTextAsync(manifestFile, WebListenerManifest(occupiedPort));
            await Assert.ThrowsAnyAsync<IOException>(server.RestartAsync);

            File.Delete(manifestFile);
            await server.RestartAsync();
            Assert.Equal(originalPort, (await server.GetSettingsAsync()).GetProperty("webServiceHttpPort").GetInt32());

            int candidatePort = LoopbackDnsServer.GetLoopbackEndPoint().Port;
            await File.WriteAllTextAsync(manifestFile, WebListenerManifest(candidatePort));
            await server.RestartAsync(candidatePort);
            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal(candidatePort, settings.GetProperty("webServiceHttpPort").GetInt32());
            Assert.Contains(settings.GetProperty("managedSettings").EnumerateArray(), path => path.GetString() == "/web/httpPort");

            File.Delete(manifestFile);
            await server.RestartAsync();
            JsonElement edit = await server.CallAsync($"settings/set?webServiceHttpPort={originalPort}", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/web/httpPort", edit.GetProperty("errorMessage").GetString());

            static string WebListenerManifest(int port) => JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                web = new { localAddresses = new[] { "127.0.0.1" }, httpPort = port }
            });
        }

        [Fact]
        public async Task StartupWebProtocolSettingsPersistAndRejectConflictingEdits()
        {
            await using var server = await LoopbackWebService.StartAsync(enableTls: true);
            string path = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);
            const string invalid = """{"schemaVersion":1,"web":{"tlsEnabled":false,"http3Enabled":true}}""";
            using (var content = new StringContent(invalid, Encoding.UTF8, "application/json"))
            {
                JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/web/http3Enabled", rejected.GetProperty("errorMessage").GetString());
            }

            await File.WriteAllTextAsync(path, """{"schemaVersion":1,"web":{"tlsEnabled":true}}""");
            await server.RestartAsync();
            JsonElement removeCertificate = await server.CallAsync("settings/set?webServiceUseSelfSignedTlsCertificate=false", server.AdminToken);
            Assert.Equal("error", removeCertificate.GetProperty("status").GetString());
            Assert.Contains("/web/tlsEnabled", removeCertificate.GetProperty("errorMessage").GetString());

            const string manifest = """{"schemaVersion":1,"web":{"tlsEnabled":false,"http3Enabled":false,"redirectHttpToTls":false}}""";
            await File.WriteAllTextAsync(path, manifest);
            await server.RestartAsync();
            JsonElement settings = await server.GetSettingsAsync();
            Assert.False(settings.GetProperty("webServiceEnableTls").GetBoolean());
            Assert.False(settings.GetProperty("webServiceEnableHttp3").GetBoolean());
            Assert.False(settings.GetProperty("webServiceHttpToTlsRedirect").GetBoolean());

            File.Delete(path);
            await server.RestartAsync();
            settings = await server.GetSettingsAsync();
            Assert.Equal(3, settings.GetProperty("managedSettings").GetArrayLength());
            Assert.Contains(settings.GetProperty("managedSettings").EnumerateArray(), path => path.GetString() == "/web/redirectHttpToTls");
            JsonElement edit = await server.CallAsync("settings/set?webServiceEnableTls=true", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains("/web/tlsEnabled", edit.GetProperty("errorMessage").GetString());
        }

        [Fact]
        public async Task LiveWebListenerApplyReportsBindFailureAndMovesTheConsoleOnSuccess()
        {
            await using var server = await LoopbackWebService.StartAsync();
            int originalPort = server.Client.BaseAddress!.Port;
            using var occupied = new TcpListener(IPAddress.Loopback, 0);
            occupied.Start();
            int occupiedPort = ((IPEndPoint)occupied.LocalEndpoint).Port;
            string manifest = ListenerChange(occupiedPort);
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            JsonElement queued = await ApplyAsync(server, manifest, revision);
            LoopbackWebService.AssertOk(queued);
            string id = queued.GetProperty("response").GetProperty("operationId").GetString()!;
            Assert.Equal("failed", await WaitForWebApplyAsync(originalPort, server.AdminToken, id));

            JsonElement previous = await server.GetSettingsAsync();
            Assert.Equal(originalPort, previous.GetProperty("webServiceHttpPort").GetInt32());
            Assert.Equal(365, previous.GetProperty("maxLogFileDays").GetInt32());

            int candidatePort = LoopbackDnsServer.GetLoopbackEndPoint().Port;
            manifest = ListenerChange(candidatePort);
            revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            queued = await ApplyAsync(server, manifest, revision);
            LoopbackWebService.AssertOk(queued);
            id = queued.GetProperty("response").GetProperty("operationId").GetString()!;
            Assert.Equal("applied", await WaitForWebApplyAsync(candidatePort, server.AdminToken, id));

            await server.RestartAsync(candidatePort);
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(candidatePort, current.GetProperty("webServiceHttpPort").GetInt32());
            Assert.Equal(180, current.GetProperty("maxLogFileDays").GetInt32());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            static string ListenerChange(int port) => JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                web = new { httpPort = port },
                logging = new { retentionDays = 180 }
            });
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task WebUnixSocketManifestBindsAndPreservesExistingFiles(bool useTls)
        {
            if (!OperatingSystem.IsLinux())
                return;

            await using var server = await LoopbackWebService.StartAsync(enableTls: useTls);
            int port = server.Client.BaseAddress!.Port;
            string field = useTls ? "tlsUnixSocket" : "httpUnixSocket";
            string apiField = useTls ? "webServiceEnableTlsUnixSocket" : "webServiceEnableHttpUnixSocket";
            string socketPath = Path.Combine(server.ConfigurationDirectory, "web.sock");
            string occupiedPath = Path.Combine(server.ConfigurationDirectory, "existing");
            await File.WriteAllTextAsync(occupiedPath, "keep this file");

            string invalid = SocketManifest(occupiedPath);
            string revision = (await PreviewAsync(server, invalid)).GetProperty("revision").GetString()!;
            JsonElement queued = await ApplyAsync(server, invalid, revision);
            LoopbackWebService.AssertOk(queued);
            string operationId = queued.GetProperty("response").GetProperty("operationId").GetString()!;
            Assert.Equal("failed", await WaitForWebApplyAsync(port, server.AdminToken, operationId));
            Assert.Equal("keep this file", await File.ReadAllTextAsync(occupiedPath));

            string manifest = SocketManifest(socketPath);
            revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            queued = await ApplyAsync(server, manifest, revision);
            LoopbackWebService.AssertOk(queued);
            operationId = queued.GetProperty("response").GetProperty("operationId").GetString()!;
            Assert.Equal("applied", await WaitForWebApplyAsync(port, server.AdminToken, operationId));

            await server.RestartAsync();
            using var expectedCertificate = useTls ? X509CertificateLoader.LoadPkcs12FromFile(
                Path.Combine(server.ConfigurationDirectory, "self-signed-cert.pfx"), null) : null;
            using var client = new HttpClient(new SocketsHttpHandler
            {
                UseProxy = false,
                SslOptions = new System.Net.Security.SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                        expectedCertificate is not null && certificate?.GetCertHashString() == expectedCertificate.Thumbprint
                },
                ConnectCallback = async (_, cancellationToken) =>
                {
                    var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                    try
                    {
                        await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), cancellationToken);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }
            });
            using HttpResponseMessage page = await client.GetAsync(useTls ? "https://localhost/index.html" : "http://localhost/index.html");
            page.EnsureSuccessStatusCode();

            JsonElement edit = await server.CallAsync($"settings/set?{apiField}=false", server.AdminToken);
            Assert.Equal("error", edit.GetProperty("status").GetString());
            Assert.Contains($"/web/{field}/enabled", edit.GetProperty("errorMessage").GetString());

            string reset = new JsonObject { ["schemaVersion"] = 1, ["web"] = new JsonObject { [field] = null } }.ToJsonString();
            revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            queued = await ApplyAsync(server, reset, revision);
            LoopbackWebService.AssertOk(queued);
            operationId = queued.GetProperty("response").GetProperty("operationId").GetString()!;
            Assert.Equal("applied", await WaitForWebApplyAsync(port, server.AdminToken, operationId));
            Assert.False((await server.GetSettingsAsync()).GetProperty(apiField).GetBoolean());
            Assert.Empty((await PreviewAsync(server, reset)).GetProperty("changes").EnumerateArray());

            string SocketManifest(string path) => new JsonObject
            {
                ["schemaVersion"] = 1,
                ["web"] = new JsonObject { [field] = new JsonObject { ["enabled"] = true, ["path"] = path } }
            }.ToJsonString();
        }

        private static async Task<string> WaitForWebApplyAsync(int port, string token, string operationId)
        {
            using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false })
            {
                BaseAddress = new Uri($"http://127.0.0.1:{port}"),
                Timeout = TimeSpan.FromSeconds(2)
            };
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            for (int attempt = 0; attempt < 100; attempt++)
            {
                try
                {
                    using HttpResponseMessage response = await client.GetAsync("/api/settings/config/status?operationId=" + operationId);
                    response.EnsureSuccessStatusCode();
                    using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStreamAsync());
                    LoopbackWebService.AssertOk(body.RootElement);
                    string state = body.RootElement.GetProperty("response").GetProperty("state").GetString()!;
                    if (state != "pending")
                        return state;
                }
                catch (Exception ex) when (ex is HttpRequestException or SocketException)
                {
                    // The old and new listeners can both be unavailable briefly during restart.
                }
                await Task.Delay(100);
            }
            throw new TimeoutException("The web listener apply did not reach a terminal state.");
        }

        [Fact]
        public async Task DhcpPreviewReconcilesScopeDeclarationsAgainstLiveRanges()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/set?name=Lab&startingAddress=192.0.2.10&endingAddress=192.0.2.30&subnetMask=255.255.255.0", server.AdminToken));

            const string manifest = """
                {"schemaVersion":1,"dhcp":{"scopes":{
                    "Lab":{"endingAddress":"192.0.2.40"},
                    "lab":{"enabled":false,"startingAddress":"192.0.2.50","endingAddress":"192.0.2.60","subnetMask":"255.255.255.0"}
                }}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Collection(preview.GetProperty("changes").EnumerateArray(),
                change => Assert.Equal("/dhcp/scopes/Lab/endingAddress", change.GetProperty("path").GetString()),
                change => Assert.Equal("/dhcp/scopes/lab", change.GetProperty("path").GetString()));
            Assert.DoesNotContain("192.0.2.", preview.GetRawText());

            JsonElement scopes = await server.CallAsync("dhcp/scopes/list", server.AdminToken);
            LoopbackWebService.AssertOk(scopes);
            JsonElement scopeList = scopes.GetProperty("response").GetProperty("scopes");
            JsonElement current = Assert.Single(scopeList.EnumerateArray(), scope => scope.GetProperty("name").ValueEquals("Lab"));
            Assert.Equal("192.0.2.30", current.GetProperty("endingAddress").GetString());
            Assert.DoesNotContain(scopeList.EnumerateArray(), scope => scope.GetProperty("name").ValueEquals("lab"));

            const string conflict = """
                {"schemaVersion":1,"dhcp":{"scopes":{
                    "other":{"enabled":false,"startingAddress":"192.0.2.5","endingAddress":"192.0.2.45","subnetMask":"255.255.255.0"}
                }}}
                """;
            using var content = new StringContent(conflict, Encoding.UTF8, "application/json");
            JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dhcp/scopes/other", rejected.GetProperty("errorMessage").GetString());

            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/addReservedLease?name=Lab&hardwareAddress=02-00-00-00-00-01&ipAddress=192.0.2.25", server.AdminToken));
            const string shrink = """{"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"endingAddress":"192.0.2.20"}}}}""";
            using var shrinkContent = new StringContent(shrink, Encoding.UTF8, "application/json");
            JsonElement protectedRange = await server.CallAsync("settings/config/plan", server.AdminToken, shrinkContent);
            Assert.Equal("error", protectedRange.GetProperty("status").GetString());
            Assert.Contains("/dhcp/scopes/Lab", protectedRange.GetProperty("errorMessage").GetString());
            Assert.DoesNotContain("192.0.2.25", protectedRange.GetRawText());

            const string remove = """{"schemaVersion":1,"dhcp":{"scopes":{"Lab":null}}}""";
            JsonElement removal = await PreviewAsync(server, remove);
            Assert.Equal("Remove", Assert.Single(removal.GetProperty("changes").EnumerateArray()).GetProperty("kind").GetString());
            LoopbackWebService.AssertOk(await server.CallAsync("dhcp/scopes/delete?name=Lab", server.AdminToken));
            JsonElement after = await PreviewAsync(server, remove);
            Assert.Empty(after.GetProperty("changes").EnumerateArray());
            Assert.NotEqual(removal.GetProperty("revision").GetString(), after.GetProperty("revision").GetString());
        }

        [Fact]
        public async Task DhcpApplyPersistsScopeChangesAndRejectsStalePreviews()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"dhcp":{"scopes":{"Lab":{
                    "enabled":false,"startingAddress":"192.0.2.10","endingAddress":"192.0.2.30","subnetMask":"255.255.255.0",
                    "exclusions":[{"startingAddress":"192.0.2.12","endingAddress":"192.0.2.14"}],
                    "reservations":{"02-00-00-00-00-01":{"address":"192.0.2.20"}}
                }}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            const string update = """{"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"endingAddress":"192.0.2.40"}}}}""";
            revision = (await PreviewAsync(server, update)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/set?name=Lab&leaseTimeHours=2", server.AdminToken));
            Assert.Equal("error", (await ApplyAsync(server, update, revision)).GetProperty("status").GetString());

            revision = (await PreviewAsync(server, update)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, update, revision));
            Assert.Empty((await PreviewAsync(server, update)).GetProperty("changes").EnumerateArray());

            const string removal = """{"schemaVersion":1,"dhcp":{"scopes":{"Lab":null}}}""";
            revision = (await PreviewAsync(server, removal)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, removal, revision));
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, removal)).GetProperty("changes").EnumerateArray());
            Assert.False(File.Exists(Path.Combine(server.ConfigurationDirectory, "scopes", "Lab.scope")));
        }

        [Fact]
        public async Task DhcpManifestProtectsMembershipAndEnabledStateUntilReleased()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"dhcp":{"scopes":{"Default":{"enabled":false},"Reserved":null}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Empty(preview.GetProperty("changes").EnumerateArray());
            string revision = preview.GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            Assert.NotEqual(revision, (await PreviewAsync(server, manifest)).GetProperty("revision").GetString());
            await server.RestartAsync();

            JsonElement scopes = await server.CallAsync("dhcp/scopes/list", server.AdminToken);
            LoopbackWebService.AssertOk(scopes);
            Assert.Collection(scopes.GetProperty("response").GetProperty("managedSettings").EnumerateArray(),
                path => Assert.Equal("/dhcp/scopes/Default", path.GetString()),
                path => Assert.Equal("/dhcp/scopes/Default/enabled", path.GetString()),
                path => Assert.Equal("/dhcp/scopes/Reserved", path.GetString()));

            await AssertConflictAsync("dhcp/scopes/delete?name=Default", "/dhcp/scopes/Default");
            await AssertConflictAsync("dhcp/scopes/enable?name=Default", "/dhcp/scopes/Default/enabled");
            await AssertConflictAsync("dhcp/scopes/set?name=Default&newName=Other&leaseTimeDays=3", "/dhcp/scopes/Default");
            await AssertConflictAsync(
                "dhcp/scopes/set?name=Reserved&startingAddress=192.0.2.10&endingAddress=192.0.2.30&subnetMask=255.255.255.0",
                "/dhcp/scopes/Reserved");
            LoopbackWebService.AssertOk(await server.CallAsync("dhcp/scopes/disable?name=Default", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync("dhcp/scopes/set?name=Default&leaseTimeDays=2", server.AdminToken));

            const string release = """{"schemaVersion":1}""";
            revision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, release, revision));
            await server.RestartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("dhcp/scopes/delete?name=Default", server.AdminToken));

            async Task AssertConflictAsync(string endpoint, string path)
            {
                JsonElement result = await server.CallAsync(endpoint, server.AdminToken);
                Assert.Equal("error", result.GetProperty("status").GetString());
                Assert.Contains(path, result.GetProperty("errorMessage").GetString());
            }
        }

        [Fact]
        public async Task DhcpManagedOptionsRejectMixedEditsAndAllowEqualValues()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"dhcp":{"scopes":{"Default":{
                    "domainName":"example.test","leaseTime":{"days":4},"dns":{"servers":[],"useThisServer":false},
                    "vendorInfo":{"a/b":"AA:BB"}
                }}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();

            JsonElement rejected = await server.CallAsync(
                "dhcp/scopes/set?name=Default&endingAddress=192.168.1.240&leaseTimeDays=5", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dhcp/scopes/Default/leaseTime/days", rejected.GetProperty("errorMessage").GetString());
            JsonElement current = await server.CallAsync("dhcp/scopes/get?name=Default", server.AdminToken);
            LoopbackWebService.AssertOk(current);
            Assert.Equal("192.168.1.254", current.GetProperty("response").GetProperty("endingAddress").GetString());

            JsonElement vendorConflict = await server.CallAsync(
                "dhcp/scopes/set?name=Default&vendorInfo=a%2Fb%7CAA%3ACC", server.AdminToken);
            Assert.Equal("error", vendorConflict.GetProperty("status").GetString());
            Assert.Contains("/dhcp/scopes/Default/vendorInfo/a~1b", vendorConflict.GetProperty("errorMessage").GetString());

            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/set?name=Default&leaseTimeDays=4&leaseTimeHours=2&domainName=EXAMPLE.TEST&vendorInfo=a%2Fb%7CAA%3ABB%7Cother%7CCC", server.AdminToken));
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            current = await server.CallAsync("dhcp/scopes/get?name=Default", server.AdminToken);
            Assert.Equal(2, current.GetProperty("response").GetProperty("leaseTimeHours").GetInt32());

            const string release = """{"schemaVersion":1}""";
            revision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, release, revision));
            LoopbackWebService.AssertOk(await server.CallAsync("dhcp/scopes/set?name=Default&leaseTimeDays=5", server.AdminToken));
        }

        [Fact]
        public async Task DhcpManagedReservationsRejectLegacyEditsAndLeaseConversions()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"dhcp":{"scopes":{"Default":{"reservations":{
                    "02:00:00:00:00:0a":{"address":"192.168.1.20","hostName":"managed"},
                    "02:00:00:00:00:0b":null
                }}}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));

            string scopesFolder = Path.Combine(server.ConfigurationDirectory, "scopes");
            string scopeFile = Path.Combine(scopesFolder, "Default.scope");
            await server.RestartAsync(httpPort: null, updateConfiguration: () =>
            {
                using (var output = File.Open(scopeFile, FileMode.Open, FileAccess.ReadWrite))
                using (var writer = new BinaryWriter(output))
                {
                    // Scope files end with the active lease count and lease records.
                    output.Position = output.Length - sizeof(int);
                    writer.Write(2);
                    WriteLease(LeaseType.Reserved, "02000000000A", "192.168.1.20");
                    WriteLease(LeaseType.Dynamic, "02000000000B", "192.168.1.21");

                    void WriteLease(LeaseType type, string mac, string address)
                    {
                        byte[] bytes = Convert.FromHexString(mac);
                        DateTimeOffset now = DateTimeOffset.UtcNow;
                        writer.Write((byte)2); // Lease file format version.
                        writer.Write((byte)type);
                        new ClientIdentifierOption(1, bytes).WriteTo(output);
                        writer.Write((byte)0); // Empty hostname.
                        writer.Write((byte)bytes.Length);
                        writer.Write(bytes);
                        IPAddress.Parse(address).WriteTo(writer);
                        writer.Write((byte)0); // Empty comments.
                        writer.Write(now.ToUnixTimeMilliseconds());
                        writer.Write(now.AddHours(1).ToUnixTimeMilliseconds());
                    }
                }
            });

            await RejectAsync("dhcp/scopes/set?name=Default&leaseTimeDays=3&reservedLeases=changed%7C02-00-00-00-00-0A%7C192.168.1.20%7C", "0A/hostName");
            await RejectAsync("dhcp/scopes/removeReservedLease?name=Default&hardwareAddress=02-00-00-00-00-0A", "0A");
            await RejectAsync("dhcp/scopes/addReservedLease?name=Default&hardwareAddress=02-00-00-00-00-0B&ipAddress=192.168.1.21", "0B");
            await RejectAsync("dhcp/leases/convertToDynamic?name=Default&hardwareAddress=02-00-00-00-00-0A", "0A");
            await RejectAsync("dhcp/leases/remove?name=Default&hardwareAddress=02-00-00-00-00-0A", "0A");
            await RejectAsync("dhcp/leases/convertToReserved?name=Default&hardwareAddress=02-00-00-00-00-0B", "0B");

            JsonElement scopeResponse = await server.CallAsync("dhcp/scopes/get?name=Default", server.AdminToken);
            LoopbackWebService.AssertOk(scopeResponse);
            Assert.Equal(1, scopeResponse.GetProperty("response").GetProperty("leaseTimeDays").GetInt32());
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/set?name=Default&reservedLeases=managed%7C02-00-00-00-00-0A%7C192.168.1.20%7Ceditable", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/addReservedLease?name=Default&hardwareAddress=02-00-00-00-00-0C&ipAddress=192.168.1.22", server.AdminToken));
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            async Task RejectAsync(string endpoint, string suffix)
            {
                JsonElement response = await server.CallAsync(endpoint, server.AdminToken);
                Assert.Equal("error", response.GetProperty("status").GetString());
                Assert.Contains("/dhcp/scopes/Default/reservations/02-00-00-00-00-" + suffix, response.GetProperty("errorMessage").GetString());
            }
        }

        [Fact]
        public async Task DhcpRestoreRejectsManagedChangesBeforeRestoringOtherStores()
        {
            await using var server = await LoopbackWebService.StartAsync();
            await using var source = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"dhcp":{"scopes":{"Default":{"leaseTime":{"days":1}}}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));

            LoopbackWebService.AssertOk(await source.CallAsync("settings/set?maxLogFileDays=10", source.AdminToken));
            await source.RestartAsync();
            LoopbackWebService.AssertOk(await source.CallAsync("dhcp/scopes/set?name=Default&leaseTimeDays=2", source.AdminToken));
            JsonElement rejected = await RestoreAsync(await BackupAsync(includeScopes: true), deleteExisting: false);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dhcp/scopes/Default/leaseTime/days", rejected.GetProperty("errorMessage").GetString());
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());

            rejected = await RestoreAsync(await BackupAsync(includeScopes: false), deleteExisting: true);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dhcp/scopes/Default", rejected.GetProperty("errorMessage").GetString());
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());

            LoopbackWebService.AssertOk(await source.CallAsync("dhcp/scopes/set?name=Default&leaseTimeDays=1&leaseTimeHours=3", source.AdminToken));
            LoopbackWebService.AssertOk(await RestoreAsync(await BackupAsync(includeScopes: true), deleteExisting: true));
            Assert.Equal(10, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
            JsonElement scope = await server.CallAsync("dhcp/scopes/get?name=Default", server.AdminToken);
            LoopbackWebService.AssertOk(scope);
            Assert.Equal(3, scope.GetProperty("response").GetProperty("leaseTimeHours").GetInt32());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            async Task<byte[]> BackupAsync(bool includeScopes)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/settings/backup?logSettings=true&scopes={includeScopes}");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", source.AdminToken);
                using HttpResponseMessage response = await source.Client.SendAsync(request);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsByteArrayAsync();
            }

            async Task<JsonElement> RestoreAsync(byte[] backup, bool deleteExisting)
            {
                using var form = new MultipartFormDataContent();
                form.Add(new ByteArrayContent(backup), "file", "backup.zip");
                return await server.CallAsync($"settings/restore?scopes=true&logSettings=true&deleteExistingFiles={deleteExisting}", server.AdminToken, form);
            }
        }

        [Fact]
        public async Task DhcpApplyRestoresLoggingAndExistingScopeWhenScopeWriteFails()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/set?name=Lab&startingAddress=192.0.2.10&endingAddress=192.0.2.30&subnetMask=255.255.255.0", server.AdminToken));

            const string manifest = """
                {"schemaVersion":1,"logging":{"logQueries":true},"dhcp":{"scopes":{"Lab":{"endingAddress":"192.0.2.40"}}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            string stagingPath = Path.Combine(server.ConfigurationDirectory, "scopes", "Lab.tmp");
            Directory.CreateDirectory(stagingPath);
            try
            {
                JsonElement rejected = await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("persist", rejected.GetProperty("errorMessage").GetString());
                Assert.Equal(preview.GetProperty("revision").GetString(),
                    (await PreviewAsync(server, manifest)).GetProperty("revision").GetString());
            }
            finally
            {
                Directory.Delete(stagingPath);
            }

            await server.RestartAsync();
            Assert.False((await server.GetSettingsAsync()).GetProperty("logQueries").GetBoolean());
            Assert.Contains((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/dhcp/scopes/Lab/endingAddress"));
            JsonElement scopes = await server.CallAsync("dhcp/scopes/list", server.AdminToken);
            LoopbackWebService.AssertOk(scopes);
            Assert.Empty(scopes.GetProperty("response").GetProperty("managedSettings").EnumerateArray());
        }

        [Fact]
        public async Task DhcpExportReproducesConfiguredScopeValuesAndExclusions()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/set?name=Lab&startingAddress=192.0.2.10&endingAddress=192.0.2.60&subnetMask=255.255.255.0" +
                "&leaseTimeDays=3&exclusions=192.0.2.45%7C192.0.2.47&genericOptions=224%7CAA%3ABB", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/addReservedLease?name=Lab&hardwareAddress=02-00-00-00-00-0A&ipAddress=192.0.2.30&hostName=reserved", server.AdminToken));

            JsonElement response = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(response);
            JsonElement export = response.GetProperty("response").GetProperty("manifest");
            _ = Load(export.GetRawText());
            JsonElement scope = export.GetProperty("dhcp").GetProperty("scopes").GetProperty("Lab");
            Assert.Equal(3, scope.GetProperty("leaseTime").GetProperty("days").GetInt32());
            Assert.Equal("AABB", Assert.Single(scope.GetProperty("genericOptions").EnumerateArray()).GetProperty("value").GetString());
            Assert.Equal("reserved", scope.GetProperty("reservations").GetProperty("02-00-00-00-00-0A").GetProperty("hostName").GetString());
            Assert.False(scope.TryGetProperty("activeLeases", out _));
            Assert.Equal("192.0.2.45", Assert.Single(scope.GetProperty("exclusions").EnumerateArray()).GetProperty("startingAddress").GetString());

            await using var destination = await LoopbackWebService.StartAsync();
            string dhcpManifest = "{\"schemaVersion\":1,\"dhcp\":" + export.GetProperty("dhcp").GetRawText() + "}";
            string revision = (await PreviewAsync(destination, dhcpManifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(destination, dhcpManifest, revision));
            await destination.RestartAsync();
            Assert.Empty((await PreviewAsync(destination, dhcpManifest)).GetProperty("changes").EnumerateArray());

            JsonElement destinationExport = await destination.CallAsync("settings/config/export", destination.AdminToken);
            LoopbackWebService.AssertOk(destinationExport);
            Assert.Equal(export.GetProperty("dhcp").GetRawText(),
                destinationExport.GetProperty("response").GetProperty("manifest").GetProperty("dhcp").GetRawText());

            const string resize = """{"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"endingAddress":"192.0.2.40"}}}}""";
            using var invalid = new StringContent(resize, Encoding.UTF8, "application/json");
            JsonElement blocked = await server.CallAsync("settings/config/plan", server.AdminToken, invalid);
            Assert.Equal("error", blocked.GetProperty("status").GetString());
            Assert.Contains("/dhcp/scopes/Lab/exclusions/0/", blocked.GetProperty("errorMessage").GetString());

            const string replacement = """
                {"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"endingAddress":"192.0.2.40",
                  "exclusions":[{"startingAddress":"192.0.2.20","endingAddress":"192.0.2.22"}]}}}}
                """;
            JsonElement preview = await PreviewAsync(server, replacement);
            Assert.Collection(preview.GetProperty("changes").EnumerateArray(),
                change => Assert.Equal("/dhcp/scopes/Lab/endingAddress", change.GetProperty("path").GetString()),
                change => Assert.Equal("/dhcp/scopes/Lab/exclusions", change.GetProperty("path").GetString()));

            const string reset = """{"schemaVersion":1,"dhcp":{"scopes":null}}""";
            JsonElement removal = await PreviewAsync(server, reset);
            Assert.Contains(removal.GetProperty("changes").EnumerateArray(), change =>
                change.GetProperty("path").GetString() == "/dhcp/scopes/Lab" && change.GetProperty("kind").GetString() == "Remove");
        }

        [Fact]
        public async Task DhcpPreviewRejectsAnExplicitDnsListThatCannotBeStored()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/set?name=Lab&startingAddress=192.0.2.10&endingAddress=192.0.2.60&subnetMask=255.255.255.0",
                server.AdminToken));

            var servers = new JsonArray();
            for (int index = 0; index < 255; index++)
                servers.Add("192.0.2." + index);
            JsonNode manifest = JsonNode.Parse("""{"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"dns":{}}}}}""")!;
            manifest["dhcp"]!["scopes"]!["Lab"]!["dns"]!["servers"] = servers;
            using var content = new StringContent(manifest.ToJsonString(), Encoding.UTF8, "application/json");
            JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dhcp/scopes/Lab/dns/servers", rejected.GetProperty("errorMessage").GetString());

            manifest["dhcp"]!["scopes"]!["Lab"]!["dns"]!["useThisServer"] = true;
            JsonElement preview = await PreviewAsync(server, manifest.ToJsonString());
            Assert.Equal("/dhcp/scopes/Lab/dns/useThisServer",
                Assert.Single(preview.GetProperty("changes").EnumerateArray()).GetProperty("path").GetString());

            JsonElement live = await server.CallAsync("dhcp/scopes/get?name=Lab", server.AdminToken);
            LoopbackWebService.AssertOk(live);
            Assert.False(live.GetProperty("response").GetProperty("useThisDnsServer").GetBoolean());
        }

        [Fact]
        public async Task DhcpOptionPreviewRoundTripsInspectionExportAndReportsLeafChanges()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/set?name=Options&startingAddress=192.0.2.10&endingAddress=192.0.2.60&subnetMask=255.255.255.0" +
                "&leaseTimeDays=3&genericOptions=224%7CAA%3ABB&vendorInfo=fixture%7CAA%3ABB", server.AdminToken));

            JsonElement inspection = await server.CallAsync("settings/config/export?includePreviewOnly=true", server.AdminToken);
            LoopbackWebService.AssertOk(inspection);
            string dhcp = inspection.GetProperty("response").GetProperty("manifest").GetProperty("dhcp").GetRawText();
            string exported = $$"""{"schemaVersion":1,"dhcp":{{dhcp}} }""";
            Assert.Empty((await PreviewAsync(server, exported)).GetProperty("changes").EnumerateArray());

            const string manifest = """
                {"schemaVersion":1,"dhcp":{"scopes":{"Options":{
                    "leaseTime":{"days":null,"hours":2},
                    "domainSearchList":["EXAMPLE.test."],
                    "dns":{"useThisServer":true,"servers":["192.0.2.53"]},
                    "vendorInfo":{"fixture":"aabb","new":"cc"},
                    "genericOptions":[{"code":224,"value":"aabb"}]
                }}}}
                """;
            JsonElement changes = (await PreviewAsync(server, manifest)).GetProperty("changes");
            Assert.Collection(changes.EnumerateArray(),
                change => Assert.Equal("/dhcp/scopes/Options/dns/useThisServer", change.GetProperty("path").GetString()),
                change => Assert.Equal("/dhcp/scopes/Options/domainSearchList", change.GetProperty("path").GetString()),
                change => Assert.Equal("/dhcp/scopes/Options/leaseTime/days", change.GetProperty("path").GetString()),
                change => Assert.Equal("/dhcp/scopes/Options/leaseTime/hours", change.GetProperty("path").GetString()),
                change => Assert.Equal("/dhcp/scopes/Options/vendorInfo/new", change.GetProperty("path").GetString()));
            Assert.DoesNotContain("192.0.2.53", changes.GetRawText());

            const string invalid = """{"schemaVersion":1,"dhcp":{"scopes":{"Options":{"vendorInfo":{"fixture":"broken"}}}}}""";
            InvalidDataException rejected = Assert.Throws<InvalidDataException>(() => Load(invalid));
            Assert.Contains("/dhcp/scopes/Options/vendorInfo/fixture", rejected.Message);
            Assert.DoesNotContain("broken", rejected.Message);
        }

        [Fact]
        public async Task DhcpReservationPreviewComparesNormalizedEntriesAndEffectiveRange()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/set?name=Lab&startingAddress=192.0.2.10&endingAddress=192.0.2.50&subnetMask=255.255.255.0", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/addReservedLease?name=Lab&hardwareAddress=02-00-00-00-00-0A&ipAddress=192.0.2.45&hostName=existing", server.AdminToken));

            const string manifest = """
                {"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"endingAddress":"192.0.2.30","reservations":{
                    "02:00:00:00:00:0a":{"address":"192.0.2.25","comments":"fixture-private"},
                    "02:00:00:00:00:0b":{"address":"192.0.2.30"}
                }}}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Collection(preview.GetProperty("changes").EnumerateArray(),
                change => Assert.Equal("/dhcp/scopes/Lab/endingAddress", change.GetProperty("path").GetString()),
                change =>
                {
                    Assert.Equal("/dhcp/scopes/Lab/reservations/02:00:00:00:00:0a", change.GetProperty("path").GetString());
                    Assert.Equal("Update", change.GetProperty("kind").GetString());
                },
                change =>
                {
                    Assert.Equal("/dhcp/scopes/Lab/reservations/02:00:00:00:00:0b", change.GetProperty("path").GetString());
                    Assert.Equal("Add", change.GetProperty("kind").GetString());
                });
            Assert.DoesNotContain("192.0.2.", preview.GetRawText());
            Assert.DoesNotContain("fixture-private", preview.GetRawText());

            JsonElement current = await server.CallAsync("dhcp/scopes/get?name=Lab", server.AdminToken);
            LoopbackWebService.AssertOk(current);
            JsonElement reservation = Assert.Single(current.GetProperty("response").GetProperty("reservedLeases").EnumerateArray());
            Assert.Equal("192.0.2.45", reservation.GetProperty("address").GetString());
            Assert.Equal("existing", reservation.GetProperty("hostName").GetString());

            const string unchanged = """
                {"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"reservations":{"02:00:00:00:00:0a":{"hostName":"existing"}}}}}}
                """;
            Assert.Empty((await PreviewAsync(server, unchanged)).GetProperty("changes").EnumerateArray());

            const string reset = """{"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"reservations":null}}}}""";
            JsonElement removal = Assert.Single((await PreviewAsync(server, reset)).GetProperty("changes").EnumerateArray());
            Assert.Equal("/dhcp/scopes/Lab/reservations/02-00-00-00-00-0A", removal.GetProperty("path").GetString());
            Assert.Equal("Remove", removal.GetProperty("kind").GetString());

            const string duplicate = """
                {"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"reservations":{"02:00:00:00:00:0b":{"address":"192.0.2.45"}}}}}}
                """;
            using var content = new StringContent(duplicate, Encoding.UTF8, "application/json");
            JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/reservations/02:00:00:00:00:0b/address", rejected.GetProperty("errorMessage").GetString());
        }

        [Theory]
        [InlineData("02:00:00:00:00:0a", """{"address":"192.0.2.25"}""", "active lease")]
        [InlineData("02:00:00:00:00:0b", """{"address":"192.0.2.20"}""", "another client")]
        [InlineData("02:00:00:00:00:0a", "null", "active lease")]
        [InlineData("02:00:00:00:00:0c", """{"address":"192.0.2.30"}""", "at a different address")]
        public void DhcpReservationPreviewRejectsChangesThatWouldDisplaceAnActiveLease(string key, string entry, string reason)
        {
            ConfigurationManifest manifest = Load($$"""
                {"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"reservations":{"{{key}}":{{entry}} } } } } }
                """);
            using JsonDocument snapshot = JsonDocument.Parse("""
                {"manifestDhcpScopes":{"Lab":{
                    "startingAddress":"192.0.2.10","endingAddress":"192.0.2.50","subnetMask":"255.255.255.0","enabled":true,
                    "reservations":{"02-00-00-00-00-0A":{"address":"192.0.2.20","hostName":null,"comments":null}},
                    "activeLeases":[
                        {"hardwareAddress":"02-00-00-00-00-0A","address":"192.0.2.20"},
                        {"hardwareAddress":"02-00-00-00-00-0C","address":"192.0.2.22"}
                    ],
                    "exclusions":[]
                }}}
                """);

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationPlan.Create(manifest, snapshot.RootElement));

            Assert.Contains("/dhcp/scopes/Lab/reservations/" + key, error.Message);
            Assert.Contains(reason, error.Message);
            Assert.DoesNotContain("192.0.2.", error.Message);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void DhcpPreviewRejectsNewExclusionsOverActiveDynamicLeases(bool dynamicLease)
        {
            ConfigurationManifest manifest = Load("""
                {"schemaVersion":1,"dhcp":{"scopes":{"Lab":{"exclusions":[
                  {"startingAddress":"192.0.2.20","endingAddress":"192.0.2.22"}]}}}}
                """);
            string dynamicFlag = dynamicLease ? "true" : "false";
            using JsonDocument snapshot = JsonDocument.Parse($$"""
                {"manifestDhcpScopes":{"Lab":{
                  "startingAddress":"192.0.2.10","endingAddress":"192.0.2.50","subnetMask":"255.255.255.0","enabled":true,
                  "activeLeases":[{"hardwareAddress":"02-00-00-00-00-0A","address":"192.0.2.20","dynamic":{{dynamicFlag}} }],
                  "exclusions":[]
                } } }
                """);
            if (dynamicLease)
            {
                InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationPlan.Create(manifest, snapshot.RootElement));
                Assert.Contains("/dhcp/scopes/Lab/exclusions", error.Message);
                Assert.DoesNotContain("192.0.2.", error.Message);
            }
            else
            {
                Assert.Equal("/dhcp/scopes/Lab/exclusions", Assert.Single(ConfigurationPlan.Create(manifest, snapshot.RootElement)).Path);
            }
        }

        [Fact]
        public async Task ZonePreviewTracksCreationDeletionAndEnabledStateWithoutMutatingZones()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=update.test&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=remove.test&type=Primary", server.AdminToken));

            const string manifest = """
                {"schemaVersion":1,"zones":{"ADD.TEST.":{"type":"Primary"},"update.test":{"enabled":false},"remove.test":null}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Collection(preview.GetProperty("changes").EnumerateArray(),
                change => AssertChange(change, "/zones/ADD.TEST.", "Add"),
                change => AssertChange(change, "/zones/remove.test", "Remove"),
                change => AssertChange(change, "/zones/update.test/enabled", "Update"));

            JsonElement repeated = await PreviewAsync(server, manifest);
            Assert.Equal(preview.GetProperty("revision").GetString(), repeated.GetProperty("revision").GetString());
            Assert.True(JsonElement.DeepEquals(preview.GetProperty("changes"), repeated.GetProperty("changes")));

            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=add.test&type=Primary", server.AdminToken));
            JsonElement after = await PreviewAsync(server, manifest);
            Assert.NotEqual(preview.GetProperty("revision").GetString(), after.GetProperty("revision").GetString());
            Assert.Collection(after.GetProperty("changes").EnumerateArray(),
                change => AssertChange(change, "/zones/remove.test", "Remove"),
                change => AssertChange(change, "/zones/update.test/enabled", "Update"));

            static void AssertChange(JsonElement change, string path, string kind)
            {
                Assert.Equal(path, change.GetProperty("path").GetString());
                Assert.Equal(kind, change.GetProperty("kind").GetString());
            }
        }

        [Fact]
        public async Task ZoneManifestCreatesAndDeletesPrimaryZonesWithPermissions()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=remove.test&type=Primary", server.AdminToken));
            await server.RestartAsync();
            const string manifest = """
                {"schemaVersion":1,"zones":{"NEW.TEST.":{"type":"Primary"},"remove.test":null}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            string staging = Directory.CreateDirectory(Path.Combine(server.ConfigurationDirectory, "auth.tmp")).FullName;
            try
            {
                JsonElement failure = await ApplyAsync(server, manifest, revision);
                Assert.Equal("error", failure.GetProperty("status").GetString());
                Assert.Equal(revision, (await PreviewAsync(server, manifest)).GetProperty("revision").GetString());
            }
            finally
            {
                Directory.Delete(staging);
            }

            Assert.False(File.Exists(Path.Combine(server.ConfigurationDirectory, "zones", "new.test.zone")));
            Assert.True(File.Exists(Path.Combine(server.ConfigurationDirectory, "zones", "remove.test.zone")));
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();
            Assert.Single((await server.QueryAsync("new.test", DnsResourceRecordType.SOA)).Answer);
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            Assert.False(File.Exists(Path.Combine(server.ConfigurationDirectory, "zones", "remove.test.zone")));
        }

        [Fact]
        public async Task ZoneMembershipAndEnabledOwnershipSurviveRestartUntilReleased()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=managed.test&type=Primary", server.AdminToken));
            const string manifest = """
                {"schemaVersion":1,"zones":{"MANAGED.TEST.":{"enabled":true},"absent.test":null}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Empty(preview.GetProperty("changes").EnumerateArray());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            await AssertConflictAsync("zones/delete?zone=managed.test", "/zones/managed.test");
            await AssertConflictAsync("zones/disable?zone=managed.test", "/zones/managed.test/enabled");
            await AssertConflictAsync("zones/options/set?zone=managed.test&disabled=true&queryAccess=Deny", "/zones/managed.test/enabled");
            await AssertConflictAsync("zones/create?zone=absent.test&type=Primary", "/zones/absent.test");
            await AssertConflictAsync("zones/clone?zone=absent.test&sourceZone=managed.test", "/zones/absent.test");
            LoopbackWebService.AssertOk(await server.CallAsync("zones/enable?zone=managed.test", server.AdminToken));
            const string unchanged = """{"schemaVersion":1,"zones":{"managed.test":{"query":{"mode":"Allow"}}}}""";
            Assert.Empty((await PreviewAsync(server, unchanged)).GetProperty("changes").EnumerateArray());

            const string release = """{"schemaVersion":1}""";
            string revision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, release, revision));
            await server.RestartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/delete?zone=managed.test", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=absent.test&type=Primary", server.AdminToken));

            async Task AssertConflictAsync(string endpoint, string path)
            {
                JsonElement response = await server.CallAsync(endpoint, server.AdminToken);
                Assert.Equal("error", response.GetProperty("status").GetString());
                Assert.Contains(path, response.GetProperty("errorMessage").GetString());
            }
        }

        [Fact]
        public async Task ZoneApplyPersistsEnabledStateAndRollsBackFailedWrites()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=first.test&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=second.test&type=Primary", server.AdminToken));
            const string manifest = """
                {"schemaVersion":1,"zones":{"first.test":{"enabled":false},"second.test":{"enabled":false}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            string staging = Directory.CreateDirectory(Path.Combine(server.ConfigurationDirectory, "zones", "second.test.tmp")).FullName;
            try
            {
                JsonElement failure = await ApplyAsync(server, manifest, revision);
                Assert.Equal("error", failure.GetProperty("status").GetString());
                Assert.Equal(revision, (await PreviewAsync(server, manifest)).GetProperty("revision").GetString());
            }
            finally
            {
                Directory.Delete(staging);
            }

            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();
            JsonElement unchanged = await PreviewAsync(server, manifest);
            Assert.Empty(unchanged.GetProperty("changes").EnumerateArray());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, unchanged.GetProperty("revision").GetString()!));

            const string enable = """{"schemaVersion":1,"zones":{"first.test":{"enabled":true}}}""";
            revision = (await PreviewAsync(server, enable)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, enable, revision));
            Assert.Single((await server.QueryAsync("first.test", DnsResourceRecordType.SOA)).Answer);
        }

        [Fact]
        public async Task ZonePolicyPreviewReportsChangesAndKeepsAclValuesPrivate()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=policy.test&type=Primary", server.AdminToken));
            const string manifest = """
                {"schemaVersion":1,"zones":{"policy.test":{
                    "query":{"mode":"UseSpecifiedNetworkACL","networkAcl":["!192.0.2.0/25","192.0.2.0/24"]},
                    "transfer":{"mode":null,"networkAcl":null},
                    "notify":{"mode":"SpecifiedNameServers","nameServers":["2001:db8::10"]},
                    "updates":{"mode":"Deny","networkAcl":[]}
                }}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Collection(preview.GetProperty("changes").EnumerateArray(),
                change => Assert.Equal("/zones/policy.test/notify/mode", change.GetProperty("path").GetString()),
                change => Assert.Equal("/zones/policy.test/notify/nameServers", change.GetProperty("path").GetString()),
                change => Assert.Equal("/zones/policy.test/query/mode", change.GetProperty("path").GetString()),
                change => Assert.Equal("/zones/policy.test/query/networkAcl", change.GetProperty("path").GetString()));
            Assert.DoesNotContain("192.0.2.", preview.GetRawText());
            Assert.DoesNotContain("2001:db8", preview.GetRawText());
            Assert.Single((await server.QueryAsync("policy.test", DnsResourceRecordType.SOA)).Answer);

            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/options/set?zone=policy.test&queryAccess=UseSpecifiedNetworkACL&queryAccessNetworkACL=%21192.0.2.0%2F25%2C192.0.2.0%2F24",
                server.AdminToken));
            JsonElement updated = await PreviewAsync(server, manifest);
            Assert.Equal(2, updated.GetProperty("changes").GetArrayLength());
            Assert.NotEqual(preview.GetProperty("revision").GetString(), updated.GetProperty("revision").GetString());
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task ManifestSignsPrimaryZonesAndKeepsTheKeysAcrossReapply(bool existing)
        {
            await using var server = await LoopbackWebService.StartAsync();
            if (existing)
                LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=signed.test&type=Primary", server.AdminToken));
            const string manifest = """
                {"schemaVersion":1,"zones":{"signed.test":{"type":"Primary",
                  "dnssec":{"enabled":true,"dnsKeyTtl":600,"proof":{"type":"NSEC3","iterations":1,"saltLength":4},
                    "keys":{
                      "ksk":{"role":"KeySigningKey","algorithm":"ECDSA","curve":"P256"},
                      "zsk":{"role":"ZoneSigningKey","algorithm":"ECDSA","curve":"P256","rolloverDays":0}
                    }},
                  "records":[{"owner":"www.signed.test","type":"A","ttl":60,"data":{"zoneFile":"192.0.2.30"}}]
                }}}
                """;
            JsonElement plan = await PreviewAsync(server, manifest);
            string revision = plan.GetProperty("revision").GetString()!;
            Assert.NotEmpty(plan.GetProperty("changes").EnumerateArray());
            Assert.Empty((await server.QueryAsync("signed.test", DnsResourceRecordType.DNSKEY)).Answer);
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));

            var keys = (await server.QueryAsync("signed.test", DnsResourceRecordType.DNSKEY)).Answer
                .Where(record => record.Type == DnsResourceRecordType.DNSKEY).Select(record => record.RDATA.ToString()).Order().ToArray();
            Assert.Equal(2, keys.Length);
            Assert.Single((await server.QueryAsync("www.signed.test", DnsResourceRecordType.A)).Answer);
            JsonElement blocked = await server.CallAsync("zones/dnssec/unsign?zone=signed.test", server.AdminToken);
            Assert.Equal("error", blocked.GetProperty("status").GetString());
            Assert.Contains("managed by the configuration manifest", blocked.GetProperty("errorMessage").GetString());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            await server.RestartAsync();
            JsonElement repeat = await PreviewAsync(server, manifest);
            Assert.Empty(repeat.GetProperty("changes").EnumerateArray());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, repeat.GetProperty("revision").GetString()!));
            Assert.Equal(keys, (await server.QueryAsync("signed.test", DnsResourceRecordType.DNSKEY)).Answer
                .Where(record => record.Type == DnsResourceRecordType.DNSKEY).Select(record => record.RDATA.ToString()).Order().ToArray());
        }

        [Theory]
        [InlineData("NSEC", DnsResourceRecordType.NSEC)]
        [InlineData("NSEC3", DnsResourceRecordType.NSEC3)]
        public async Task ManifestRecordEditsKeepTheZoneSigned(string proof, DnsResourceRecordType proofType)
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string name = "signed-records.test";
            string initial = $$"""
                {"schemaVersion":1,"zones":{"signed-records.test":{"type":"Primary",
                  "dnssec":{"enabled":true,"proof":{"type":"{{proof}}"},"keys":{
                    "ksk":{"role":"KeySigningKey","algorithm":"ECDSA","curve":"P256"},
                    "zsk":{"role":"ZoneSigningKey","algorithm":"ECDSA","curve":"P256"}
                  } },
                  "records":[
                    {"owner":"old.signed-records.test","type":"A","data":{"zoneFile":"192.0.2.70"} },
                    {"owner":"alias.signed-records.test","type":"A","data":{"zoneFile":"192.0.2.70"} }
                  ]
                } } }
                """;
            const string update = """
                {"schemaVersion":1,"zones":{"signed-records.test":{
                  "dnssec":{"enabled":true},
                  "records":[
                    {"owner":"new.signed-records.test","type":"A","data":{"zoneFile":"192.0.2.71"}},
                    {"owner":"alias.signed-records.test","type":"CNAME","data":{"zoneFile":"new.signed-records.test."}}
                  ]
                }}}
                """;
            string revision = (await PreviewAsync(server, initial)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, initial, revision));

            var dnsKeys = (await server.QueryAsync(name, DnsResourceRecordType.DNSKEY)).Answer.ToArray();
            Assert.Equal(2, dnsKeys.Length);
            revision = (await PreviewAsync(server, update)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, update, revision));
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, update)).GetProperty("changes").EnumerateArray());
            Assert.Equal(dnsKeys.Select(key => key.RDATA.ToString()).Order(),
                (await server.QueryAsync(name, DnsResourceRecordType.DNSKEY)).Answer.Select(key => key.RDATA.ToString()).Order());

            IPEndPoint endpoint = IPEndPoint.Parse((await server.GetSettingsAsync()).GetProperty("dnsServerLocalEndPoints")[0].GetString()!);
            var client = new DnsClient(endpoint) { Timeout = 2000, Retries = 1 };
            DnsDatagram answer = await QuerySignedAsync("new.signed-records.test");
            var data = answer.Answer.Where(record => record.Type == DnsResourceRecordType.A).ToArray();
            Assert.Equal("192.0.2.71", Assert.IsType<DnsARecordData>(Assert.Single(data).RDATA).Address.ToString());
            var signature = Assert.IsType<DnsRRSIGRecordData>(
                Assert.Single(answer.Answer, record => record.Type == DnsResourceRecordType.RRSIG).RDATA);
            Assert.True(signature.IsSignatureValid(data, dnsKeys, out _));

            DnsDatagram alias = await QuerySignedAsync("alias.signed-records.test");
            Assert.Contains(alias.Answer, record => record.RDATA is DnsCNAMERecordData cname &&
                cname.Domain == "new.signed-records.test");

            DnsDatagram removed = await QuerySignedAsync("old.signed-records.test");
            Assert.Equal(DnsResponseCode.NxDomain, removed.RCODE);
            var proofs = removed.Authority.Where(record => record.Type == proofType).ToArray();
            Assert.NotEmpty(proofs);
            Assert.All(proofs, record =>
            {
                var denialSignature = Assert.IsType<DnsRRSIGRecordData>(Assert.Single(removed.Authority, candidate =>
                    candidate.Name == record.Name && candidate.RDATA is DnsRRSIGRecordData sig && sig.TypeCovered == proofType).RDATA);
                Assert.True(denialSignature.IsSignatureValid([record], dnsKeys, out _));
            });

            Task<DnsDatagram> QuerySignedAsync(string owner) => client.RawResolveAsync(new DnsDatagram(
                1, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord(owner, DnsResourceRecordType.A, DnsClass.IN)], udpPayloadSize: 1232, ednsFlags: EDnsHeaderFlags.DNSSEC_OK));
        }

        [Fact]
        public async Task DnssecOwnershipBlocksOnlyDeclaredSigningControls()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string name = "managed-signing.test";
            LoopbackWebService.AssertOk(await server.CallAsync($"zones/create?zone={name}&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                $"zones/dnssec/sign?zone={name}&algorithm=ECDSA&curve=P256", server.AdminToken));
            const string enabled = """{"schemaVersion":1,"zones":{"managed-signing.test":{"dnssec":{"enabled":true}}}}""";
            const string proof = """{"schemaVersion":1,"zones":{"managed-signing.test":{"dnssec":{"enabled":true,"proof":{"type":"NSEC3"}}}}}""";
            const string convertToNsec = "zones/dnssec/properties/convertToNSEC?zone=" + name;

            await ApplyPolicyAsync(enabled);
            await server.RestartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync(
                $"zones/dnssec/properties/convertToNSEC3?zone={name}", server.AdminToken));
            JsonElement unsign = await server.CallAsync($"zones/dnssec/unsign?zone={name}", server.AdminToken);
            Assert.Equal("error", unsign.GetProperty("status").GetString());
            Assert.Contains("/dnssec/enabled", unsign.GetProperty("errorMessage").GetString());

            await ApplyPolicyAsync(proof);
            JsonElement blocked = await server.CallAsync(convertToNsec, server.AdminToken);
            Assert.Equal("error", blocked.GetProperty("status").GetString());
            Assert.Contains("/dnssec/proof", blocked.GetProperty("errorMessage").GetString());
            await ApplyPolicyAsync(enabled);
            LoopbackWebService.AssertOk(await server.CallAsync(convertToNsec, server.AdminToken));

            async Task ApplyPolicyAsync(string manifest)
            {
                string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            }
        }

        [Fact]
        public async Task ManifestStagesAdditionalSigningKeysWithoutPublishingThem()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string name = "pending-key.test";
            LoopbackWebService.AssertOk(await server.CallAsync($"zones/create?zone={name}&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                $"zones/dnssec/sign?zone={name}&algorithm=ECDSA&curve=P256", server.AdminToken));
            const string manifest = """
                {"schemaVersion":1,"zones":{"pending-key.test":{"dnssec":{"keys":{
                  "next":{"role":"ZoneSigningKey","algorithm":"ECDSA","curve":"P384","rolloverDays":60}
                }}}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            JsonElement addition = Assert.Single(preview.GetProperty("changes").EnumerateArray());
            Assert.Equal("/zones/pending-key.test/dnssec/keys/next", addition.GetProperty("path").GetString());
            Assert.Equal("Add", addition.GetProperty("kind").GetString());
            string revision = preview.GetProperty("revision").GetString()!;
            Assert.Equal(2, (await GetKeysAsync()).GetArrayLength());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));

            var pending = await CheckPendingKeyAsync();
            await server.RestartAsync();
            Assert.Equal(pending.GetProperty("keyTag").GetInt32(), (await CheckPendingKeyAsync()).GetProperty("keyTag").GetInt32());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            async Task<JsonElement> GetKeysAsync()
            {
                JsonElement result = await server.CallAsync($"zones/dnssec/properties/get?zone={name}", server.AdminToken);
                LoopbackWebService.AssertOk(result);
                return result.GetProperty("response").GetProperty("dnssecPrivateKeys");
            }

            async Task<JsonElement> CheckPendingKeyAsync()
            {
                var keys = await GetKeysAsync();
                Assert.Equal(3, keys.GetArrayLength());
                JsonElement key = Assert.Single(keys.EnumerateArray(), key => key.GetProperty("state").ValueEquals("Generated"));
                Assert.Equal(60, key.GetProperty("rolloverDays").GetInt32());
                Assert.Equal(2, (await server.QueryAsync(name, DnsResourceRecordType.DNSKEY)).Answer.Count);
                return key;
            }
        }

        [Fact]
        public async Task ManifestUpdatesSigningKeyRolloverWithoutChangingTheKeyOrSoaSerial()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string name = "rollover.test";
            LoopbackWebService.AssertOk(await server.CallAsync($"zones/create?zone={name}&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                $"zones/dnssec/sign?zone={name}&algorithm=ECDSA&curve=P256&zskRolloverDays=30", server.AdminToken));
            const string manifest = """
                {"schemaVersion":1,"zones":{"rollover.test":{"dnssec":{"keys":{
                  "zsk":{"role":"ZoneSigningKey","algorithm":"ECDSA","curve":"P256","rolloverDays":90}
                }}}}}
                """;
            var original = await GetKeyAsync();
            Assert.Equal(30, original.GetProperty("rolloverDays").GetInt32());
            var soa = Assert.IsType<DnsSOARecordData>(
                Assert.Single((await server.QueryAsync(name, DnsResourceRecordType.SOA)).Answer).RDATA);
            JsonElement preview = await PreviewAsync(server, manifest);
            JsonElement change = Assert.Single(preview.GetProperty("changes").EnumerateArray());
            Assert.Equal("/zones/rollover.test/dnssec/keys/zsk/rolloverDays", change.GetProperty("path").GetString());
            Assert.Equal("Update", change.GetProperty("kind").GetString());
            string revision = preview.GetProperty("revision").GetString()!;
            Assert.Equal(30, (await GetKeyAsync()).GetProperty("rolloverDays").GetInt32());
            string blockedPath = Path.Combine(server.ConfigurationDirectory, "zones", name + ".tmp");
            Directory.CreateDirectory(blockedPath);
            try
            {
                Assert.Equal("error", (await ApplyAsync(server, manifest, revision)).GetProperty("status").GetString());
                Assert.Equal(30, (await GetKeyAsync()).GetProperty("rolloverDays").GetInt32());
            }
            finally
            {
                Directory.Delete(blockedPath);
            }
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            var live = await GetKeyAsync();
            Assert.Equal(90, live.GetProperty("rolloverDays").GetInt32());
            Assert.Equal(original.GetProperty("stateChangedOn").GetDateTime(), live.GetProperty("stateChangedOn").GetDateTime());

            await server.RestartAsync();
            var updated = await GetKeyAsync();
            Assert.Equal(90, updated.GetProperty("rolloverDays").GetInt32());
            Assert.Equal(original.GetProperty("keyTag").GetUInt16(), updated.GetProperty("keyTag").GetUInt16());
            Assert.InRange((original.GetProperty("stateChangedOn").GetDateTime() -
                updated.GetProperty("stateChangedOn").GetDateTime()).Duration(), TimeSpan.Zero, TimeSpan.FromSeconds(1));
            Assert.Equal(soa.Serial, Assert.IsType<DnsSOARecordData>(
                Assert.Single((await server.QueryAsync(name, DnsResourceRecordType.SOA)).Answer).RDATA).Serial);
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            async Task<JsonElement> GetKeyAsync()
            {
                JsonElement result = await server.CallAsync($"zones/dnssec/properties/get?zone={name}", server.AdminToken);
                LoopbackWebService.AssertOk(result);
                return Assert.Single(result.GetProperty("response").GetProperty("dnssecPrivateKeys").EnumerateArray(),
                    key => key.GetProperty("keyType").ValueEquals("ZoneSigningKey"));
            }
        }

        [Fact]
        public async Task ManifestChangesDenialProofAndDisablesSigningWithoutLosingOperatorRecords()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string name = "proof.test";
            const string host = "www.proof.test";
            LoopbackWebService.AssertOk(await server.CallAsync($"zones/create?zone={name}&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                $"zones/records/add?zone={name}&domain={host}&type=A&ipAddress=192.0.2.50&ttl=60", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                $"zones/dnssec/sign?zone={name}&algorithm=ECDSA&curve=P256&nxProof=NSEC", server.AdminToken));

            const string nsec3 = """{"schemaVersion":1,"zones":{"proof.test":{"dnssec":{"proof":{"type":"NSEC3","iterations":2,"saltLength":4}}}}}""";
            const string tuneNsec3 = """{"schemaVersion":1,"zones":{"proof.test":{"dnssec":{"proof":{"iterations":3}}}}}""";
            const string nsec = """{"schemaVersion":1,"zones":{"proof.test":{"dnssec":{"proof":{"type":"NSEC"}}}}}""";
            const string disable = """
                {"schemaVersion":1,"zones":{"proof.test":{"dnssec":{"enabled":false},"records":[
                  {"owner":"www.proof.test","type":"A","ttl":60,"data":{"zoneFile":"192.0.2.50"}},
                  {"owner":"new.proof.test","type":"A","ttl":60,"data":{"zoneFile":"192.0.2.51"}}
                ]}}}
                """;

            var originalKeys = await ReadKeysAsync();
            Assert.Equal(2, originalKeys.Length);
            JsonElement plan = await PreviewAsync(server, nsec3);
            Assert.Contains(plan.GetProperty("changes").EnumerateArray(), change =>
                change.GetProperty("path").ValueEquals("/zones/proof.test/dnssec/proof"));
            Assert.Empty((await server.QueryAsync(name, DnsResourceRecordType.NSEC3PARAM)).Answer);
            string revision = plan.GetProperty("revision").GetString()!;

            string blockedPath = Path.Combine(server.ConfigurationDirectory, "zones", name + ".tmp");
            Directory.CreateDirectory(blockedPath);
            try
            {
                Assert.Equal("error", (await ApplyAsync(server, nsec3, revision)).GetProperty("status").GetString());
                Assert.Empty((await server.QueryAsync(name, DnsResourceRecordType.NSEC3PARAM)).Answer);
                Assert.Equal(originalKeys, await ReadKeysAsync());
            }
            finally
            {
                Directory.Delete(blockedPath);
            }

            await ApplyPolicyAsync(nsec3);
            Assert.Equal(2, ReadParameters(await server.QueryAsync(name, DnsResourceRecordType.NSEC3PARAM)).Iterations);
            await ApplyPolicyAsync(tuneNsec3);
            await server.RestartAsync();
            var parameters = ReadParameters(await server.QueryAsync(name, DnsResourceRecordType.NSEC3PARAM));
            Assert.Equal(3, parameters.Iterations);
            Assert.Equal(4, parameters.Salt.Length);
            Assert.Equal(originalKeys, await ReadKeysAsync());

            await ApplyPolicyAsync(nsec);
            Assert.Empty((await server.QueryAsync(name, DnsResourceRecordType.NSEC3PARAM)).Answer);
            Assert.Equal(originalKeys, await ReadKeysAsync());
            await ApplyPolicyAsync(disable);
            await server.RestartAsync();
            Assert.Empty(await ReadKeysAsync());
            Assert.Equal("192.0.2.50", Assert.IsType<DnsARecordData>(
                Assert.Single((await server.QueryAsync(host, DnsResourceRecordType.A)).Answer).RDATA).Address.ToString());
            Assert.Equal("192.0.2.51", Assert.IsType<DnsARecordData>(
                Assert.Single((await server.QueryAsync("new.proof.test", DnsResourceRecordType.A)).Answer).RDATA).Address.ToString());

            async Task ApplyPolicyAsync(string manifest)
            {
                string currentRevision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, currentRevision));
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            }

            async Task<string[]> ReadKeysAsync() => (await server.QueryAsync(name, DnsResourceRecordType.DNSKEY)).Answer
                .Where(record => record.Type == DnsResourceRecordType.DNSKEY).Select(record => record.RDATA.ToString()).Order().ToArray();

            static DnsNSEC3PARAMRecordData ReadParameters(DnsDatagram response) =>
                Assert.IsType<DnsNSEC3PARAMRecordData>(Assert.Single(response.Answer).RDATA);
        }

        [Fact]
        public async Task SignedZoneExportRecreatesTheSameKeysFromReferences()
        {
            await using var source = await LoopbackWebService.StartAsync();
            await using var destination = await LoopbackWebService.StartAsync();
            using var ksk = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var zsk = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            string kskPem = ksk.ExportPkcs8PrivateKeyPem();
            string zskPem = zsk.ExportPkcs8PrivateKeyPem();
            string kskInput = $"TEST_DNSSEC_KSK_{Guid.NewGuid():N}";
            string zskInput = $"TEST_DNSSEC_ZSK_{Guid.NewGuid():N}";
            var environment = new List<string> { kskInput, zskInput };
            try
            {
                Environment.SetEnvironmentVariable(kskInput, kskPem);
                Environment.SetEnvironmentVariable(zskInput, zskPem);
                string manifest = $$"""
                    {"schemaVersion":1,"zones":{"portable.test":{"type":"Primary",
                      "dnssec":{"enabled":true,"keys":{
                        "ksk":{"role":"KeySigningKey","algorithm":"ECDSA","curve":"P256","privateKey":{"environment":"{{kskInput}}"} },
                        "zsk":{"role":"ZoneSigningKey","algorithm":"ECDSA","curve":"P256","privateKey":{"environment":"{{zskInput}}"} }
                      } }
                    } } }
                    """;
                string revision = (await PreviewAsync(source, manifest)).GetProperty("revision").GetString()!;
                using var replacement = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
                Environment.SetEnvironmentVariable(zskInput, replacement.ExportPkcs8PrivateKeyPem());
                JsonElement stale = await ApplyAsync(source, manifest, revision);
                Assert.Equal("error", stale.GetProperty("status").GetString());
                Assert.Empty((await source.QueryAsync("portable.test", DnsResourceRecordType.DNSKEY)).Answer);
                Environment.SetEnvironmentVariable(zskInput, zskPem);
                LoopbackWebService.AssertOk(await ApplyAsync(source, manifest, revision));

                JsonElement export = await source.CallAsync("settings/config/export", source.AdminToken);
                LoopbackWebService.AssertOk(export);
                Assert.DoesNotContain("PRIVATE KEY", export.GetRawText());
                JsonElement response = export.GetProperty("response");
                JsonElement zone = response.GetProperty("manifest").GetProperty("zones").GetProperty("portable.test");
                foreach (JsonProperty key in zone.GetProperty("dnssec").GetProperty("keys").EnumerateObject())
                {
                    Assert.Contains(response.GetProperty("missingInputs").EnumerateArray(),
                        path => path.ValueEquals($"/zones/portable.test/dnssec/keys/{key.Name}/privateKey"));
                    string name = key.Value.GetProperty("privateKey").GetProperty("environment").GetString()!;
                    environment.Add(name);
                    Environment.SetEnvironmentVariable(name, key.Value.GetProperty("role").ValueEquals("KeySigningKey") ? kskPem : zskPem);
                }

                string exported = $$"""{"schemaVersion":1,"zones":{"portable.test":{{zone.GetRawText()}} } }""";
                revision = (await PreviewAsync(destination, exported)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(destination, exported, revision));
                Assert.Empty((await PreviewAsync(destination, exported)).GetProperty("changes").EnumerateArray());

                var expected = (await source.QueryAsync("portable.test", DnsResourceRecordType.DNSKEY)).Answer
                    .Select(record => record.RDATA.ToString()).Order().ToArray();
                Assert.Equal(2, expected.Length);
                Assert.Equal(expected, (await destination.QueryAsync("portable.test", DnsResourceRecordType.DNSKEY)).Answer
                    .Select(record => record.RDATA.ToString()).Order().ToArray());
            }
            finally
            {
                foreach (string name in environment)
                    Environment.SetEnvironmentVariable(name, null);
            }
        }

        [Fact]
        public async Task ZonePoliciesApplyToNewAndExistingZonesAndSurviveRestart()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=existing.test&type=Primary", server.AdminToken));
            const string manifest = """
                {"schemaVersion":1,"zones":{
                  "existing.test":{
                    "query":{"mode":"UseSpecifiedNetworkACL","networkAcl":["!127.0.0.1/32","127.0.0.0/8"]},
                    "transfer":{"mode":"Deny","networkAcl":["192.0.2.0/24"]},
                    "notify":{"mode":"None","nameServers":["2001:db8::10"]},
                    "updates":{"mode":"UseSpecifiedNetworkACL","networkAcl":["192.0.2.32/27"]}
                  },
                  "new.test":{"type":"Primary","query":{"mode":"Deny"}}
                }}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            const string reset = """
                {"schemaVersion":1,"zones":{"existing.test":{
                    "query":{"mode":null,"networkAcl":null},
                    "transfer":{"mode":null,"networkAcl":null},
                    "notify":{"mode":null,"nameServers":null},
                    "updates":{"mode":null,"networkAcl":null}
                }}}
                """;
            revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            Assert.Single((await server.QueryAsync("existing.test", DnsResourceRecordType.SOA)).Answer);
            Assert.Empty((await PreviewAsync(server, reset)).GetProperty("changes").EnumerateArray());
        }

        [Fact]
        public async Task ZoneRestoreRejectsManagedChangesBeforeRestoringLogging()
        {
            await using var destination = await LoopbackWebService.StartAsync();
            await using var source = await LoopbackWebService.StartAsync();
            const string managed = """
                {"schemaVersion":1,"zones":{"restore.test":{"type":"Primary","query":{"mode":"Deny"}}}}
                """;
            string revision = (await PreviewAsync(destination, managed)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(destination, managed, revision));

            LoopbackWebService.AssertOk(await source.CallAsync("zones/create?zone=restore.test&type=Primary", source.AdminToken));
            LoopbackWebService.AssertOk(await source.CallAsync("settings/set?maxLogFileDays=20", source.AdminToken));
            LoopbackWebService.AssertOk(await source.CallAsync(
                "zones/records/add?zone=restore.test&domain=www.restore.test&type=A&ipAddress=192.0.2.42", source.AdminToken));
            await source.RestartAsync();
            JsonElement conflict = await RestoreAsync(includeZones: true, deleteExisting: false);
            Assert.Equal("error", conflict.GetProperty("status").GetString());
            Assert.Contains("/zones/restore.test/query/mode", conflict.GetProperty("errorMessage").GetString());
            conflict = await RestoreAsync(includeZones: false, deleteExisting: true);
            Assert.Equal("error", conflict.GetProperty("status").GetString());
            Assert.Contains("/zones/restore.test", conflict.GetProperty("errorMessage").GetString());
            Assert.Equal(365, (await destination.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());

            revision = (await PreviewAsync(source, managed)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(source, managed, revision));
            LoopbackWebService.AssertOk(await RestoreAsync(includeZones: true, deleteExisting: true));
            Assert.Equal(20, (await destination.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
            Assert.Single((await destination.QueryAsync("www.restore.test", DnsResourceRecordType.A)).Answer);
            Assert.Empty((await PreviewAsync(destination, managed)).GetProperty("changes").EnumerateArray());

            async Task<JsonElement> RestoreAsync(bool includeZones, bool deleteExisting)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/settings/backup?logSettings=true&zones={includeZones}");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", source.AdminToken);
                using HttpResponseMessage response = await source.Client.SendAsync(request);
                response.EnsureSuccessStatusCode();
                using var form = new MultipartFormDataContent();
                form.Add(new ByteArrayContent(await response.Content.ReadAsByteArrayAsync()), "file", "backup.zip");
                return await destination.CallAsync($"settings/restore?zones=true&logSettings=true&deleteExistingFiles={deleteExisting}", destination.AdminToken, form);
            }
        }

        [Fact]
        public async Task ZoneRecordOwnershipProtectsLegacyEditsUntilReleased()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=owned-records.test&type=Primary", server.AdminToken));
            await server.RestartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?zones=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] previousZone = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"zones":{"owned-records.test":{"type":"Primary","records":[
                    {"owner":"www.owned-records.test","type":"A","data":{"zoneFile":"192.0.2.42"}}
                ]}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();

            foreach (string endpoint in new[]
            {
                "zones/records/add?zone=owned-records.test&domain=new.owned-records.test&type=A&ipAddress=192.0.2.43",
                "zones/records/delete?zone=owned-records.test&domain=www.owned-records.test&type=A&ipAddress=192.0.2.42"
            })
            {
                JsonElement rejected = await server.CallAsync(endpoint, server.AdminToken);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/zones/owned-records.test/records", rejected.GetProperty("errorMessage").GetString());
            }
            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(previousZone), "file", "backup.zip");
            JsonElement restore = await server.CallAsync("settings/restore?zones=true", server.AdminToken, form);
            Assert.Equal("error", restore.GetProperty("status").GetString());
            Assert.Contains("/zones/owned-records.test/records", restore.GetProperty("errorMessage").GetString());
            Assert.Single((await server.QueryAsync("www.owned-records.test", DnsResourceRecordType.A)).Answer);

            const string release = """{"schemaVersion":1,"zones":{"owned-records.test":{"type":"Primary"}}}""";
            revision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, release, revision));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/records/add?zone=owned-records.test&domain=new.owned-records.test&type=A&ipAddress=192.0.2.43", server.AdminToken));
        }

        [Fact]
        public async Task LdapManifestPersistsSettingsAndExportsWithoutTheBindPassword()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var backupRequest = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?authConfig=true");
            backupRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(backupRequest);
            backup.EnsureSuccessStatusCode();
            byte[] priorAuth = await backup.Content.ReadAsByteArrayAsync();

            const string variable = "TECHNITIUM_TEST_LDAP_BIND_SECRET";
            const string secret = "test-directory-bind-password";
            string? previous = Environment.GetEnvironmentVariable(variable);
            Environment.SetEnvironmentVariable(variable, secret);
            try
            {
                const string manifest = """
                    {"schemaVersion":1,"auth":{"ldap":{
                        "enabled":true,"server":"directory.test","port":636,"sslOption":"LDAPS",
                        "bindUsername":"cn=reader,dc=example","bindPassword":{"environment":"TECHNITIUM_TEST_LDAP_BIND_SECRET"},
                        "searchBase":"dc=example","groupMap":{"remote-dns":"DNS Administrators"}
                    }}}
                    """;
                JsonElement preview = await PreviewAsync(server, manifest);
                Assert.Contains(preview.GetProperty("changes").EnumerateArray(), change => change.GetProperty("path").ValueEquals("/auth/ldap/bindPassword"));
                Assert.DoesNotContain(secret, preview.GetRawText());
                string revision = preview.GetProperty("revision").GetString()!;

                Environment.SetEnvironmentVariable(variable, "rotated-directory-bind-password");
                Assert.Equal("error", (await ApplyAsync(server, manifest, revision)).GetProperty("status").GetString());
                Environment.SetEnvironmentVariable(variable, secret);
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
                await server.RestartAsync();
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                JsonElement rejected = await server.CallAsync(
                    "admin/ldap/set?ldapServer=other.test&ldapIgnoreSslErrors=true", server.AdminToken);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/auth/ldap/server", rejected.GetProperty("errorMessage").GetString());
                JsonElement ldapConfig = await server.CallAsync("admin/ldap/get", server.AdminToken);
                LoopbackWebService.AssertOk(ldapConfig);
                Assert.False(ldapConfig.GetProperty("response").GetProperty("ldapIgnoreSslErrors").GetBoolean());

                using var form = new MultipartFormDataContent();
                form.Add(new ByteArrayContent(priorAuth), "file", "backup.zip");
                JsonElement restore = await server.CallAsync("settings/restore?authConfig=true", server.AdminToken, form);
                Assert.Equal("error", restore.GetProperty("status").GetString());
                Assert.Contains("/auth/ldap/", restore.GetProperty("errorMessage").GetString());
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
                LoopbackWebService.AssertOk(export);
                JsonElement response = export.GetProperty("response");
                JsonElement ldap = response.GetProperty("manifest").GetProperty("auth").GetProperty("ldap");
                Assert.True(ldap.GetProperty("enabled").GetBoolean());
                Assert.Equal(636, ldap.GetProperty("port").GetInt32());
                Assert.Equal("DNS Administrators", ldap.GetProperty("groupMap").GetProperty("remote-dns").GetString());
                Assert.False(ldap.TryGetProperty("bindPassword", out _));
                Assert.Contains(response.GetProperty("missingInputs").EnumerateArray(), path => path.ValueEquals("/auth/ldap/bindPassword"));
                Assert.DoesNotContain(secret, export.GetRawText());

                const string release = """{"schemaVersion":1}""";
                revision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, release, revision));
                await server.RestartAsync();
                LoopbackWebService.AssertOk(await server.CallAsync("admin/ldap/set?ldapServer=other.test", server.AdminToken));
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }
        }

        [Fact]
        public async Task ManifestCanRemoveAStaticSessionAndItsAccountTogether()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string variable = "TECHNITIUM_TEST_REMOVABLE_STATIC_SESSION";
            string? previous = Environment.GetEnvironmentVariable(variable);
            string token = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            using var user = new FormUrlEncodedContent([new("user", "automation"), new("pass", "fixture-automation-password")]);
            LoopbackWebService.AssertOk(await server.CallAsync("admin/users/create", server.AdminToken, user));
            try
            {
                Environment.SetEnvironmentVariable(variable, token);
                const string add = """
                    {"schemaVersion":1,"auth":{
                        "staticSessions":{"job":{"user":"automation","token":{"environment":"TECHNITIUM_TEST_REMOVABLE_STATIC_SESSION"}}},
                        "permissions":{"Settings":{"users":{"automation":["View"]}}}
                    }}
                    """;
                string revision = (await PreviewAsync(server, add)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, add, revision));
                LoopbackWebService.AssertOk(await server.CallAsync("settings/get", token));

                const string removeAccountOnly = """{"schemaVersion":1,"auth":{"users":{"automation":null}}}""";
                using var content = new StringContent(removeAccountOnly, Encoding.UTF8, "application/json");
                JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/auth/staticSessions/job/user", rejected.GetProperty("errorMessage").GetString());

                const string remove = """
                    {"schemaVersion":1,"auth":{"users":{"automation":null},"staticSessions":{"job":null}}}
                    """;
                revision = (await PreviewAsync(server, remove)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, remove, revision));
                Assert.Equal("invalid-token", (await server.CallAsync("settings/get", token)).GetProperty("status").GetString());
                await server.RestartAsync();
                Assert.Empty((await PreviewAsync(server, remove)).GetProperty("changes").EnumerateArray());
                Assert.Equal("error", (await server.CallAsync("admin/users/get?user=automation", server.AdminToken)).GetProperty("status").GetString());
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }
        }

        [Fact]
        public async Task ManifestStaticSessionPersistsReferencesAndRevokesRotatedTokens()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string variable = "TECHNITIUM_TEST_STATIC_SESSION";
            string? previous = Environment.GetEnvironmentVariable(variable);
            string initial = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            string rotated = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            string local = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            const string declaration = """
                {"schemaVersion":1,"auth":{"staticSessions":{"automation":{"user":"admin",
                    "token":{"environment":"TECHNITIUM_TEST_STATIC_SESSION"}}}}}
                """;
            try
            {
                Environment.SetEnvironmentVariable(variable, initial);
                JsonElement preview = await PreviewAsync(server, declaration);
                Assert.Contains(preview.GetProperty("changes").EnumerateArray(), change =>
                    change.GetProperty("path").ValueEquals("/auth/staticSessions/automation"));
                Assert.DoesNotContain(initial, preview.GetRawText());
                Environment.SetEnvironmentVariable(variable, rotated);
                Assert.Equal("error", (await ApplyAsync(server, declaration, preview.GetProperty("revision").GetString()!))
                    .GetProperty("status").GetString());
                Environment.SetEnvironmentVariable(variable, initial);
                string revision = (await PreviewAsync(server, declaration)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, declaration, revision));
                await server.RestartAsync();
                LoopbackWebService.AssertOk(await server.CallAsync("settings/get", initial));
                Assert.Empty((await PreviewAsync(server, declaration)).GetProperty("changes").EnumerateArray());

                Environment.SetEnvironmentVariable(variable, rotated);
                revision = (await PreviewAsync(server, declaration)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, declaration, revision));
                Assert.Equal("invalid-token", (await server.CallAsync("settings/get", initial)).GetProperty("status").GetString());
                LoopbackWebService.AssertOk(await server.CallAsync("settings/get", rotated));

                string config = server.ConfigurationDirectory;
                string startup = Path.Combine(config, ConfigurationManifest.DefaultFileName);
                await File.WriteAllTextAsync(Path.Combine(config, "automation-token"), local);
                await File.WriteAllTextAsync(startup, """
                    {"schemaVersion":1,"auth":{"staticSessions":{"automation":{"user":"admin","token":{"file":"automation-token"}}}}}
                    """);
                await server.RestartAsync();
                Assert.Equal("invalid-token", (await server.CallAsync("settings/get", rotated)).GetProperty("status").GetString());
                LoopbackWebService.AssertOk(await server.CallAsync("settings/get", local));
                Assert.DoesNotContain(local, await File.ReadAllTextAsync(Path.Combine(config, "static-sessions.config")));
                File.Delete(startup);
                await server.RestartAsync();
                LoopbackWebService.AssertOk(await server.CallAsync("settings/get", local));

                JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
                LoopbackWebService.AssertOk(export);
                Assert.DoesNotContain(local, export.GetRawText());
                Assert.Contains(export.GetProperty("response").GetProperty("missingInputs").EnumerateArray(),
                    path => path.ValueEquals("/auth/staticSessions/automation/token"));
                const string clear = """{"schemaVersion":1,"auth":{"staticSessions":{"automation":null}}}""";
                revision = (await PreviewAsync(server, clear)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, clear, revision));
                await server.RestartAsync();
                Assert.Equal("invalid-token", (await server.CallAsync("settings/get", local)).GetProperty("status").GetString());
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }
        }

        [Fact]
        public async Task ManifestCanRemoveAZoneAndItsPermissionGroupTogether()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string create = """
                {"schemaVersion":1,"auth":{"groups":{"Retired Zone Readers":{}}},
                    "zones":{"obsolete.test":{"type":"Primary","permissions":{"groups":{"Retired Zone Readers":["View"]}}}}}
                """;
            string revision = (await PreviewAsync(server, create)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, create, revision));
            await server.RestartAsync();

            const string removeGroupOnly = """{"schemaVersion":1,"auth":{"groups":{"Retired Zone Readers":null}}}""";
            using var content = new StringContent(removeGroupOnly, Encoding.UTF8, "application/json");
            JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/auth/groups/retired zone readers", rejected.GetProperty("errorMessage").GetString());

            const string remove = """
                {"schemaVersion":1,"auth":{"groups":{"Retired Zone Readers":null}},"zones":{"OBSOLETE.TEST.":null}}
                """;
            JsonElement preview = await PreviewAsync(server, remove);
            Assert.Equal(2, preview.GetProperty("changes").GetArrayLength());
            LoopbackWebService.AssertOk(await ApplyAsync(server, remove, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, remove)).GetProperty("changes").EnumerateArray());
            Assert.Equal("error", (await server.CallAsync("admin/groups/get?group=Retired%20Zone%20Readers", server.AdminToken)).GetProperty("status").GetString());
            Assert.Equal("error", (await server.CallAsync("zones/permissions/get?zone=obsolete.test", server.AdminToken)).GetProperty("status").GetString());
        }

        [Fact]
        public async Task ManifestZoneGrantsApplyWithZoneCreationAndCanBeReset()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string password = "fixture-zone-viewer-password";
            using var user = new FormUrlEncodedContent([new("user", "zone-reader"), new("pass", password)]);
            LoopbackWebService.AssertOk(await server.CallAsync("admin/users/create", server.AdminToken, user));
            const string manifest = """
                {"schemaVersion":1,"zones":{"permission.test":{"type":"Primary",
                    "permissions":{"users":{"zone-reader":["View"]}}}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Contains(preview.GetProperty("changes").EnumerateArray(), change =>
                change.GetProperty("path").ValueEquals("/zones/permission.test/permissions/users/zone-reader") &&
                change.GetProperty("kind").ValueEquals("Add"));
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();

            string token = await server.LoginAsync("zone-reader", password);
            LoopbackWebService.AssertOk(await server.CallAsync("zones/records/get?zone=permission.test&domain=permission.test", token));
            Assert.Equal("error", (await server.CallAsync(
                "zones/records/add?zone=permission.test&domain=unauthorized.permission.test&type=A&ipAddress=192.0.2.42", token))
                .GetProperty("status").GetString());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement denied = await server.CallAsync("zones/permissions/set?zone=permission.test&userPermissions=", server.AdminToken);
            Assert.Equal("error", denied.GetProperty("status").GetString());
            Assert.Contains("/zones/permission.test/permissions/users/zone-reader", denied.GetProperty("errorMessage").GetString());

            JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement grants = export.GetProperty("response").GetProperty("manifest").GetProperty("zones")
                .GetProperty("permission.test").GetProperty("permissions").GetProperty("users");
            Assert.Collection(grants.GetProperty("zone-reader").EnumerateArray(), flag => Assert.Equal("View", flag.GetString()));

            using var backupRequest = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?authConfig=true");
            backupRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(backupRequest);
            backup.EnsureSuccessStatusCode();
            byte[] priorAuth = await backup.Content.ReadAsByteArrayAsync();

            const string reset = """{"schemaVersion":1,"zones":{"permission.test":{"permissions":null}}}""";
            string revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, reset)).GetProperty("changes").EnumerateArray());
            using var restoreForm = new MultipartFormDataContent();
            restoreForm.Add(new ByteArrayContent(priorAuth), "file", "backup.zip");
            JsonElement restore = await server.CallAsync("settings/restore?authConfig=true", server.AdminToken, restoreForm);
            Assert.Equal("error", restore.GetProperty("status").GetString());
            Assert.Contains("/zones/permission.test/permissions/users/", restore.GetProperty("errorMessage").GetString());
            token = await server.LoginAsync("zone-reader", password);
            Assert.Equal("error", (await server.CallAsync("zones/records/get?zone=permission.test&domain=permission.test", token)).GetProperty("status").GetString());
            LoopbackWebService.AssertOk(await server.CallAsync("zones/records/get?zone=permission.test&domain=permission.test", server.AdminToken));
        }

        [Fact]
        public async Task ManagedSectionGrantsRejectConflictingEditsAndRestoreUntilReleased()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string password = "fixture-grant-password";
            using var user = new FormUrlEncodedContent([new("user", "viewer"), new("pass", password)]);
            LoopbackWebService.AssertOk(await server.CallAsync("admin/users/create", server.AdminToken, user));
            LoopbackWebService.AssertOk(await server.CallAsync("admin/groups/create?group=Observers", server.AdminToken));
            await server.RestartAsync();

            using var backupRequest = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?authConfig=true");
            backupRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(backupRequest);
            backup.EnsureSuccessStatusCode();
            byte[] priorAuth = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"auth":{"permissions":{"Settings":{"users":{"viewer":["View"]},"groups":{"Observers":["View"]}}}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();

            JsonElement settings = await server.CallAsync("admin/permissions/get?section=Settings", server.AdminToken);
            LoopbackWebService.AssertOk(settings);
            Assert.Contains(settings.GetProperty("response").GetProperty("managedSettings").EnumerateArray(),
                path => path.ValueEquals("/auth/permissions/Settings/users/viewer"));

            JsonElement denied = await server.CallAsync("admin/permissions/set?section=Settings&userPermissions=", server.AdminToken);
            Assert.Equal("error", denied.GetProperty("status").GetString());
            Assert.Contains("/auth/permissions/Settings/users/viewer", denied.GetProperty("errorMessage").GetString());
            JsonElement rename = await server.CallAsync("admin/users/set?user=viewer&newUser=renamed", server.AdminToken);
            Assert.Equal("error", rename.GetProperty("status").GetString());
            Assert.Contains("/auth/permissions/Settings/users/viewer", rename.GetProperty("errorMessage").GetString());

            JsonElement groupRename = await server.CallAsync("admin/groups/set?group=Observers&newGroup=observers", server.AdminToken);
            Assert.Equal("error", groupRename.GetProperty("status").GetString());
            Assert.Contains("/auth/permissions/Settings/groups/observers", groupRename.GetProperty("errorMessage").GetString());
            JsonElement mixed = await server.CallAsync(
                "admin/permissions/set?section=Settings&userPermissions=viewer%7Ctrue%7Cfalse%7Cfalse%7Cadmin%7Ctrue%7Cfalse%7Cfalse&groupPermissions=",
                server.AdminToken);
            Assert.Equal("error", mixed.GetProperty("status").GetString());
            Assert.Contains("/auth/permissions/Settings/groups/observers", mixed.GetProperty("errorMessage").GetString());
            settings = await server.CallAsync("admin/permissions/get?section=Settings", server.AdminToken);
            Assert.DoesNotContain(settings.GetProperty("response").GetProperty("userPermissions").EnumerateArray(),
                grant => grant.GetProperty("username").ValueEquals("admin"));

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(priorAuth), "file", "backup.zip");
            JsonElement restore = await server.CallAsync("settings/restore?authConfig=true", server.AdminToken, form);
            Assert.Equal("error", restore.GetProperty("status").GetString());
            Assert.Contains("/auth/permissions/Settings/users/viewer", restore.GetProperty("errorMessage").GetString());

            string token = await server.LoginAsync("viewer", password);
            LoopbackWebService.AssertOk(await server.CallAsync("settings/get", token));
            const string release = """{"schemaVersion":1}""";
            revision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, release, revision));
            LoopbackWebService.AssertOk(await server.CallAsync("settings/get", token));
            LoopbackWebService.AssertOk(await server.CallAsync("admin/permissions/set?section=Settings&userPermissions=", server.AdminToken));
            Assert.Equal("error", (await server.CallAsync("settings/get", token)).GetProperty("status").GetString());
        }

        [Fact]
        public async Task ManifestPermissionGrantsResolveNewPrincipalsAndControlAccessAfterRestart()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string variable = "TECHNITIUM_TEST_PERMISSION_USER_PASSWORD";
            const string password = "fixture-permission-user-password";
            string? previous = Environment.GetEnvironmentVariable(variable);
            Environment.SetEnvironmentVariable(variable, password);
            try
            {
                const string manifest = """
                    {"schemaVersion":1,"auth":{
                      "groups":{"Configuration Readers":{}},
                      "users":{"reader":{"groups":["Configuration Readers"],"password":{"environment":"TECHNITIUM_TEST_PERMISSION_USER_PASSWORD"}}},
                      "permissions":{"Settings":{"groups":{"Configuration Readers":["View"]}},
                                     "Administration":{"users":{"reader":["View"]}}}
                    }}
                    """;
                JsonElement preview = await PreviewAsync(server, manifest);
                Assert.Contains(preview.GetProperty("changes").EnumerateArray(), change =>
                    change.GetProperty("path").ValueEquals("/auth/permissions/Settings/groups/configuration readers") &&
                    change.GetProperty("kind").ValueEquals("Add"));
                string revision = preview.GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
                await server.RestartAsync();
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                string reader = await server.LoginAsync("reader", password);
                LoopbackWebService.AssertOk(await server.CallAsync("settings/get", reader));
                LoopbackWebService.AssertOk(await server.CallAsync("admin/users/list", reader));
                Assert.Equal("error", (await server.CallAsync("settings/set?dnsServerDomain=forbidden.test", reader))
                    .GetProperty("status").GetString());

                JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
                LoopbackWebService.AssertOk(export);
                JsonElement permissions = export.GetProperty("response").GetProperty("manifest").GetProperty("auth").GetProperty("permissions");
                Assert.Collection(permissions.GetProperty("Settings").GetProperty("groups").GetProperty("Configuration Readers").EnumerateArray(),
                    flag => Assert.Equal("View", flag.GetString()));

                const string lockout = """
                    {"schemaVersion":1,"auth":{"permissions":{"Administration":{"groups":{"Administrators":null}}}}}
                    """;
                using (var content = new StringContent(lockout, Encoding.UTF8, "application/json"))
                {
                    JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                    Assert.Equal("error", rejected.GetProperty("status").GetString());
                    Assert.Contains("/auth/permissions/Administration/groups/administrators", rejected.GetProperty("errorMessage").GetString());
                }

                const string reset = """
                    {"schemaVersion":1,"auth":{
                      "groups":{"Configuration Readers":null},
                      "users":{"reader":{"groups":[]}},
                      "permissions":{"Settings":null,"Administration":{"users":{"reader":null}}}
                    }}
                    """;
                revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
                await server.RestartAsync();
                Assert.Empty((await PreviewAsync(server, reset)).GetProperty("changes").EnumerateArray());
                reader = await server.LoginAsync("reader", password);
                Assert.Equal("error", (await server.CallAsync("settings/get", reader)).GetProperty("status").GetString());
                Assert.Equal("error", (await server.CallAsync("admin/users/list", reader)).GetProperty("status").GetString());
                LoopbackWebService.AssertOk(await server.CallAsync("settings/get", server.AdminToken));
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }
        }

        [Fact]
        public async Task ManifestTotpEnrollmentSurvivesRestartAndRequiresTheConfiguredCode()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string password = "fixture-totp-account-password";
            using var createUser = new FormUrlEncodedContent([new("user", "enrolled"), new("pass", password)]);
            LoopbackWebService.AssertOk(await server.CallAsync("admin/users/create", server.AdminToken, createUser));
            await server.RestartAsync();

            using var backupRequest = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?authConfig=true");
            backupRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(backupRequest);
            backup.EnsureSuccessStatusCode();
            byte[] priorAuth = await backup.Content.ReadAsByteArrayAsync();

            const string variable = "TECHNITIUM_TEST_TOTP_ENROLLMENT";
            const string malformed = "malformed-fixture-enrollment";
            string? previous = Environment.GetEnvironmentVariable(variable);
            AuthenticatorKeyUri enrollment = AuthenticatorKeyUri.Generate("fixture", "enrolled");
            const string manifest = """
                {"schemaVersion":1,"auth":{"users":{"enrolled":{"totp":{"enabled":true,
                    "enrollment":{"environment":"TECHNITIUM_TEST_TOTP_ENROLLMENT"}}}}}}
                """;
            try
            {
                Environment.SetEnvironmentVariable(variable, malformed);
                using (var content = new StringContent(manifest, Encoding.UTF8, "application/json"))
                {
                    JsonElement invalid = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                    Assert.Equal("error", invalid.GetProperty("status").GetString());
                    Assert.Contains("/auth/users/enrolled/totp/enrollment", invalid.GetProperty("errorMessage").GetString());
                    Assert.DoesNotContain(malformed, invalid.GetRawText());
                }
                await server.LoginAsync("enrolled", password);

                Environment.SetEnvironmentVariable(variable, enrollment.ToString());
                JsonElement preview = await PreviewAsync(server, manifest);
                Assert.Contains(preview.GetProperty("changes").EnumerateArray(), change =>
                    change.GetProperty("path").ValueEquals("/auth/users/enrolled/totp/enrollment"));
                Assert.DoesNotContain(enrollment.Secret, preview.GetRawText());
                string revision = preview.GetProperty("revision").GetString()!;

                Environment.SetEnvironmentVariable(variable, AuthenticatorKeyUri.Generate("fixture", "enrolled").ToString());
                Assert.Equal("error", (await ApplyAsync(server, manifest, revision)).GetProperty("status").GetString());
                Environment.SetEnvironmentVariable(variable, enrollment.ToString());
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
                await server.RestartAsync();
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                using var noCode = new FormUrlEncodedContent([new("user", "enrolled"), new("pass", password)]);
                Assert.Equal("2fa-required", (await server.CallAsync("user/login", content: noCode)).GetProperty("status").GetString());
                using var withCode = new FormUrlEncodedContent([
                    new("user", "enrolled"), new("pass", password), new("totp", new Authenticator(enrollment).GetTOTP())
                ]);
                JsonElement signedIn = await server.CallAsync("user/login", content: withCode);
                LoopbackWebService.AssertOk(signedIn);
                string token = signedIn.GetProperty("token").GetString()!;
                JsonElement deniedDisable = await server.CallAsync("user/2fa/disable", token);
                Assert.Equal("error", deniedDisable.GetProperty("status").GetString());
                Assert.Contains("/auth/users/enrolled/totp/enabled", deniedDisable.GetProperty("errorMessage").GetString());

                using var restoreForm = new MultipartFormDataContent();
                restoreForm.Add(new ByteArrayContent(priorAuth), "file", "backup.zip");
                JsonElement deniedRestore = await server.CallAsync("settings/restore?authConfig=true", server.AdminToken, restoreForm);
                Assert.Equal("error", deniedRestore.GetProperty("status").GetString());
                Assert.Contains("/auth/users/enrolled/totp/", deniedRestore.GetProperty("errorMessage").GetString());

                JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
                LoopbackWebService.AssertOk(export);
                JsonElement response = export.GetProperty("response");
                JsonElement totp = response.GetProperty("manifest").GetProperty("auth").GetProperty("users")
                    .GetProperty("enrolled").GetProperty("totp");
                Assert.True(totp.GetProperty("enabled").GetBoolean());
                Assert.False(totp.TryGetProperty("enrollment", out _));
                Assert.DoesNotContain(enrollment.Secret, export.GetRawText());
                Assert.Contains(response.GetProperty("missingInputs").EnumerateArray(), path => path.ValueEquals("/auth/users/enrolled/totp/enrollment"));

                const string clear = """{"schemaVersion":1,"auth":{"users":{"enrolled":{"totp":{"enabled":false,"enrollment":null}}}}}""";
                revision = (await PreviewAsync(server, clear)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, clear, revision));
                await server.RestartAsync();
                token = await server.LoginAsync("enrolled", password);
                JsonElement deniedInit = await server.CallAsync("user/2fa/init", token);
                Assert.Equal("error", deniedInit.GetProperty("status").GetString());
                Assert.Contains("/auth/users/enrolled/totp/enrollment", deniedInit.GetProperty("errorMessage").GetString());
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }
        }

        [Fact]
        public async Task LocalUserRemovalRevokesSessionsAndPermissionGrants()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string createUser = "admin/users/create?user=retired&pass=fixture-account-password";
            LoopbackWebService.AssertOk(await server.CallAsync(createUser, server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync("admin/groups/create?group=RetiredUsers", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync("admin/groups/set?group=RetiredUsers&members=retired", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=retired.test&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "admin/permissions/set?section=Settings&userPermissions=retired%7Ctrue%7Cfalse%7Cfalse", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/permissions/set?zone=retired.test&userPermissions=retired%7Ctrue%7Cfalse%7Cfalse", server.AdminToken));

            string session = await server.LoginAsync("retired", "fixture-account-password");
            JsonElement issued = await server.CallAsync("admin/sessions/createToken?user=retired&tokenName=fixture", server.AdminToken);
            LoopbackWebService.AssertOk(issued);
            string apiToken = issued.GetProperty("response").GetProperty("token").GetString()!;
            LoopbackWebService.AssertOk(await server.CallAsync("settings/get", apiToken));
            LoopbackWebService.AssertOk(await server.CallAsync("user/profile/get", session));

            const string remove = """{"schemaVersion":1,"auth":{"users":{"Retired":null},"groups":{"RetiredUsers":null}}}""";
            JsonElement preview = await PreviewAsync(server, remove);
            Assert.Contains(preview.GetProperty("changes").EnumerateArray(), change =>
                change.GetProperty("path").ValueEquals("/auth/users/retired") && change.GetProperty("kind").ValueEquals("Remove"));
            Assert.Contains(preview.GetProperty("changes").EnumerateArray(), change =>
                change.GetProperty("path").ValueEquals("/auth/groups/RetiredUsers") && change.GetProperty("kind").ValueEquals("Remove"));
            LoopbackWebService.AssertOk(await ApplyAsync(server, remove, preview.GetProperty("revision").GetString()!));
            Assert.Equal("invalid-token", (await server.CallAsync("settings/get", apiToken)).GetProperty("status").GetString());
            Assert.Equal("invalid-token", (await server.CallAsync("user/profile/get", session)).GetProperty("status").GetString());

            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, remove)).GetProperty("changes").EnumerateArray());
            Assert.Equal("error", (await server.CallAsync("admin/users/get?user=retired", server.AdminToken)).GetProperty("status").GetString());
            Assert.Equal("error", (await server.CallAsync("admin/groups/get?group=RetiredUsers", server.AdminToken)).GetProperty("status").GetString());
            foreach (string endpoint in new[] { "admin/permissions/get?section=Settings", "zones/permissions/get?zone=retired.test" })
            {
                JsonElement permissions = await server.CallAsync(endpoint, server.AdminToken);
                LoopbackWebService.AssertOk(permissions);
                Assert.DoesNotContain(permissions.GetProperty("response").GetProperty("userPermissions").EnumerateArray(),
                    grant => grant.GetProperty("username").ValueEquals("retired"));
            }

            JsonElement recreation = await server.CallAsync(createUser, server.AdminToken);
            Assert.Equal("error", recreation.GetProperty("status").GetString());
            Assert.Contains("/auth/users/retired", recreation.GetProperty("errorMessage").GetString());
            const string release = """{"schemaVersion":1}""";
            string releaseRevision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, release, releaseRevision));
            LoopbackWebService.AssertOk(await server.CallAsync(createUser, server.AdminToken));
            const string reset = """{"schemaVersion":1,"auth":{"users":null}}""";
            string revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            await server.RestartAsync();
            Assert.Equal("error", (await server.CallAsync("admin/users/get?user=retired", server.AdminToken)).GetProperty("status").GetString());
            LoopbackWebService.AssertOk(await server.CallAsync("admin/users/get?user=admin", server.AdminToken));
        }

        [Fact]
        public async Task SsoManifestRestartsTheWebServiceAndKeepsThePreviousConfigOnBindFailure()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var backupRequest = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?authConfig=true");
            backupRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(backupRequest);
            backup.EnsureSuccessStatusCode();
            byte[] priorAuth = await backup.Content.ReadAsByteArrayAsync();

            const string variable = "TECHNITIUM_TEST_SSO_CLIENT_SECRET";
            const string secret = "fixture-provider-secret";
            string? previous = Environment.GetEnvironmentVariable(variable);
            Environment.SetEnvironmentVariable(variable, secret);
            const string manifest = """
                {"schemaVersion":1,"auth":{"groups":{"SSO Readers":{}},"sso":{
                    "enabled":true,"authority":"https://identity.test","clientId":"fixture-client",
                    "clientSecret":{"environment":"TECHNITIUM_TEST_SSO_CLIENT_SECRET"},
                    "scopes":["email"],"groupMap":{"remote-readers":"SSO Readers"}
                }}}
                """;
            try
            {
                int port = server.Client.BaseAddress!.Port;
                using var occupied = new TcpListener(IPAddress.Loopback, 0);
                occupied.Start();
                JsonNode blocked = JsonNode.Parse(manifest)!;
                blocked["web"] = new JsonObject { ["httpPort"] = ((IPEndPoint)occupied.LocalEndpoint).Port };
                string failed = blocked.ToJsonString();
                string revision = (await PreviewAsync(server, failed)).GetProperty("revision").GetString()!;
                JsonElement queued = await ApplyAsync(server, failed, revision);
                LoopbackWebService.AssertOk(queued);
                Assert.Equal("failed", await WaitForWebApplyAsync(port, server.AdminToken,
                    queued.GetProperty("response").GetProperty("operationId").GetString()!));
                JsonElement config = await server.CallAsync("admin/sso/get", server.AdminToken);
                LoopbackWebService.AssertOk(config);
                Assert.False(config.GetProperty("response").GetProperty("ssoEnabled").GetBoolean());

                JsonElement preview = await PreviewAsync(server, manifest);
                Assert.Contains(preview.GetProperty("changes").EnumerateArray(), change =>
                    change.GetProperty("path").ValueEquals("/auth/sso/enabled") && change.GetProperty("restartWebService").GetBoolean());
                Assert.DoesNotContain(secret, preview.GetRawText());
                revision = preview.GetProperty("revision").GetString()!;
                Environment.SetEnvironmentVariable(variable, "different-fixture-secret");
                Assert.Equal("error", (await ApplyAsync(server, manifest, revision)).GetProperty("status").GetString());
                Environment.SetEnvironmentVariable(variable, secret);
                queued = await ApplyAsync(server, manifest, revision);
                LoopbackWebService.AssertOk(queued);
                Assert.Equal("applied", await WaitForWebApplyAsync(port, server.AdminToken,
                    queued.GetProperty("response").GetProperty("operationId").GetString()!));

                await server.RestartAsync();
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
                config = await server.CallAsync("admin/sso/get", server.AdminToken);
                LoopbackWebService.AssertOk(config);
                JsonElement settings = config.GetProperty("response");
                Assert.True(settings.GetProperty("ssoEnabled").GetBoolean());
                Assert.Contains(settings.GetProperty("ssoScopes").EnumerateArray(), scope => scope.ValueEquals("openid"));
                Assert.Contains(settings.GetProperty("ssoScopes").EnumerateArray(), scope => scope.ValueEquals("profile"));

                Assert.Contains(settings.GetProperty("managedSettings").EnumerateArray(),
                    path => path.ValueEquals("/auth/sso/groupMap/remote-readers"));
                JsonElement rejected = await server.CallAsync(
                    "admin/sso/set?ssoAuthority=https%3A%2F%2Fother.test&ssoAllowSignup=true", server.AdminToken);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/auth/sso/authority", rejected.GetProperty("errorMessage").GetString());
                config = await server.CallAsync("admin/sso/get", server.AdminToken);
                Assert.False(config.GetProperty("response").GetProperty("ssoAllowSignup").GetBoolean());

                using var form = new MultipartFormDataContent();
                form.Add(new ByteArrayContent(priorAuth), "file", "backup.zip");
                JsonElement restore = await server.CallAsync("settings/restore?authConfig=true", server.AdminToken, form);
                Assert.Equal("error", restore.GetProperty("status").GetString());
                Assert.Contains("/auth/sso/", restore.GetProperty("errorMessage").GetString());

                JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
                LoopbackWebService.AssertOk(export);
                Assert.DoesNotContain(secret, export.GetRawText());
                JsonElement response = export.GetProperty("response");
                JsonElement sso = response.GetProperty("manifest").GetProperty("auth").GetProperty("sso");
                Assert.Equal("SSO Readers", sso.GetProperty("groupMap").GetProperty("remote-readers").GetString());
                Assert.False(sso.TryGetProperty("clientSecret", out _));
                Assert.Contains(response.GetProperty("missingInputs").EnumerateArray(), path => path.ValueEquals("/auth/sso/clientSecret"));

                JsonNode releaseGroup = JsonNode.Parse(manifest)!;
                releaseGroup["auth"]!.AsObject().Remove("groups");
                string managedSso = releaseGroup.ToJsonString();
                revision = (await PreviewAsync(server, managedSso)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, managedSso, revision));
                JsonElement rename = await server.CallAsync("admin/groups/set?group=SSO%20Readers&newGroup=other", server.AdminToken);
                Assert.Equal("error", rename.GetProperty("status").GetString());
                Assert.Contains("/auth/sso/groupMap/remote-readers", rename.GetProperty("errorMessage").GetString());

                const string release = """{"schemaVersion":1}""";
                revision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, release, revision));
                await server.RestartAsync();
                LoopbackWebService.AssertOk(await server.CallAsync("admin/sso/set?ssoAllowSignup=true", server.AdminToken));
                config = await server.CallAsync("admin/sso/get", server.AdminToken);
                Assert.True(config.GetProperty("response").GetProperty("ssoAllowSignup").GetBoolean());
                Assert.True(config.GetProperty("response").GetProperty("ssoEnabled").GetBoolean());
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }
        }

        [Fact]
        public async Task DirectoryAccountsCanBeProvisionedAndExportedWithoutLocalPasswords()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"auth":{"groups":{"Directory Readers":{}},"users":{
                    "ldap-reader":{"type":"RemoteLDAP","displayName":"LDAP Reader","groups":["Directory Readers"]},
                    "sso-reader":{"type":"RemoteSSO","externalIdentifier":"fixture-identity","sessionTimeoutSeconds":90}
                }}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement ldap = await server.CallAsync("admin/users/get?user=ldap-reader", server.AdminToken);
            LoopbackWebService.AssertOk(ldap);
            Assert.Equal("RemoteLDAP", ldap.GetProperty("response").GetProperty("type").GetString());
            Assert.Contains(ldap.GetProperty("response").GetProperty("memberOfGroups").EnumerateArray(),
                group => group.ValueEquals("Directory Readers"));

            const string duplicate = """
                {"schemaVersion":1,"auth":{"users":{"duplicate":{"type":"RemoteSSO","externalIdentifier":"fixture-identity"}}}}
                """;
            using var content = new StringContent(duplicate, Encoding.UTF8, "application/json");
            JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/auth/users/duplicate/externalIdentifier", rejected.GetProperty("errorMessage").GetString());

            JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement response = export.GetProperty("response");
            JsonElement auth = response.GetProperty("manifest").GetProperty("auth");
            JsonElement users = auth.GetProperty("users");
            Assert.Equal("fixture-identity", users.GetProperty("sso-reader").GetProperty("externalIdentifier").GetString());
            Assert.DoesNotContain(response.GetProperty("missingInputs").EnumerateArray(),
                path => path.GetString()!.StartsWith("/auth/users/ldap-reader", StringComparison.Ordinal) ||
                    path.GetString()!.StartsWith("/auth/users/sso-reader", StringComparison.Ordinal));

            await using var target = await LoopbackWebService.StartAsync();
            JsonObject targetUsers = new()
            {
                ["ldap-reader"] = JsonNode.Parse(users.GetProperty("ldap-reader").GetRawText()),
                ["sso-reader"] = JsonNode.Parse(users.GetProperty("sso-reader").GetRawText())
            };
            string migration = new JsonObject
            {
                ["schemaVersion"] = 1,
                ["auth"] = new JsonObject
                {
                    ["groups"] = JsonNode.Parse(auth.GetProperty("groups").GetRawText()),
                    ["users"] = targetUsers
                }
            }.ToJsonString();
            revision = (await PreviewAsync(target, migration)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(target, migration, revision));
            await target.RestartAsync();
            Assert.Empty((await PreviewAsync(target, migration)).GetProperty("changes").EnumerateArray());

            const string remove = """{"schemaVersion":1,"auth":{"users":{"sso-reader":null}}}""";
            revision = (await PreviewAsync(server, remove)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, remove, revision));
            Assert.Equal("error", (await server.CallAsync("admin/users/get?user=sso-reader", server.AdminToken)).GetProperty("status").GetString());
        }

        [Fact]
        public async Task LocalUserManifestRequiresSecretsAndPreservesAdministrativeAccess()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string variable = "TECHNITIUM_TEST_LOCAL_OPERATOR_PASSWORD";
            const string initial = "fixture-local-password";
            const string rotated = "fixture-rotated-password";
            string? previous = Environment.GetEnvironmentVariable(variable);
            Environment.SetEnvironmentVariable(variable, null);
            try
            {
                const string manifest = """
                    {"schemaVersion":1,"auth":{
                        "groups":{"Operators":{}},
                        "users":{"operator":{"displayName":"Local Operator","groups":["Operators"],"sessionTimeoutSeconds":90,
                            "password":{"environment":"TECHNITIUM_TEST_LOCAL_OPERATOR_PASSWORD"}}}
                    }}
                    """;
                using (var content = new StringContent(manifest, Encoding.UTF8, "application/json"))
                {
                    JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                    Assert.Equal("error", rejected.GetProperty("status").GetString());
                    Assert.Contains("/auth/users/operator/password", rejected.GetProperty("errorMessage").GetString());
                }
                Assert.Equal("error", (await server.CallAsync("admin/groups/get?group=Operators", server.AdminToken)).GetProperty("status").GetString());

                Environment.SetEnvironmentVariable(variable, initial);
                JsonElement preview = await PreviewAsync(server, manifest);
                Assert.Contains(preview.GetProperty("changes").EnumerateArray(), change => change.GetProperty("path").ValueEquals("/auth/users/operator"));
                Assert.DoesNotContain(initial, preview.GetRawText());
                string revision = preview.GetProperty("revision").GetString()!;
                Environment.SetEnvironmentVariable(variable, rotated);
                Assert.Equal("error", (await ApplyAsync(server, manifest, revision)).GetProperty("status").GetString());
                revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
                await server.RestartAsync();
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
                string token = await server.LoginAsync("operator", rotated);
                LoopbackWebService.AssertOk(await server.CallAsync("user/profile/get", token));

                JsonElement group = await server.CallAsync("admin/groups/get?group=Operators", server.AdminToken);
                Assert.Contains(group.GetProperty("response").GetProperty("members").EnumerateArray(), member => member.ValueEquals("operator"));

                using var backupRequest = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?authConfig=true");
                backupRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
                using HttpResponseMessage backup = await server.Client.SendAsync(backupRequest);
                backup.EnsureSuccessStatusCode();
                byte[] priorAuth = await backup.Content.ReadAsByteArrayAsync();

                Environment.SetEnvironmentVariable(variable, initial);
                preview = await PreviewAsync(server, manifest);
                Assert.Contains(preview.GetProperty("changes").EnumerateArray(), change => change.GetProperty("path").ValueEquals("/auth/users/operator/password"));
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
                await server.RestartAsync();
                await server.LoginAsync("operator", initial);
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                JsonElement deniedEdit = await server.CallAsync(
                    "admin/users/set?user=operator&displayName=Legacy&disabled=true", server.AdminToken);
                Assert.Equal("error", deniedEdit.GetProperty("status").GetString());
                Assert.Contains("/auth/users/operator/displayName", deniedEdit.GetProperty("errorMessage").GetString());

                JsonElement deniedMembership = await server.CallAsync(
                    "admin/groups/set?group=Operators&description=Legacy&members=", server.AdminToken);
                Assert.Equal("error", deniedMembership.GetProperty("status").GetString());
                Assert.Contains("/auth/users/operator/groups", deniedMembership.GetProperty("errorMessage").GetString());
                group = await server.CallAsync("admin/groups/get?group=Operators", server.AdminToken);
                Assert.Contains(group.GetProperty("response").GetProperty("members").EnumerateArray(), member => member.ValueEquals("operator"));

                token = await server.LoginAsync("operator", initial);
                JsonElement deniedProfile = await server.CallAsync("user/profile/set?sessionTimeoutSeconds=120", token);
                Assert.Equal("error", deniedProfile.GetProperty("status").GetString());
                Assert.Contains("/auth/users/operator/sessionTimeoutSeconds", deniedProfile.GetProperty("errorMessage").GetString());
                using var password = new FormUrlEncodedContent([new("pass", initial), new("newPass", rotated)]);
                JsonElement deniedPassword = await server.CallAsync("user/changePassword", token, password);
                Assert.Equal("error", deniedPassword.GetProperty("status").GetString());
                Assert.Contains("/auth/users/operator/password", deniedPassword.GetProperty("errorMessage").GetString());

                using var restoreForm = new MultipartFormDataContent();
                restoreForm.Add(new ByteArrayContent(priorAuth), "file", "backup.zip");
                JsonElement deniedRestore = await server.CallAsync("settings/restore?authConfig=true", server.AdminToken, restoreForm);
                Assert.Equal("error", deniedRestore.GetProperty("status").GetString());
                Assert.Contains("/auth/users/operator/password", deniedRestore.GetProperty("errorMessage").GetString());

                const string lockout = """{"schemaVersion":1,"auth":{"users":{"admin":{"groups":[],"disabled":true}}}}""";
                using var lockoutContent = new StringContent(lockout, Encoding.UTF8, "application/json");
                JsonElement lockoutResponse = await server.CallAsync("settings/config/plan", server.AdminToken, lockoutContent);
                Assert.Equal("error", lockoutResponse.GetProperty("status").GetString());
                Assert.Contains("/auth/users/admin", lockoutResponse.GetProperty("errorMessage").GetString());

                JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
                LoopbackWebService.AssertOk(export);
                JsonElement response = export.GetProperty("response");
                JsonElement user = response.GetProperty("manifest").GetProperty("auth").GetProperty("users").GetProperty("operator");
                Assert.Equal("Local Operator", user.GetProperty("displayName").GetString());
                Assert.Contains(user.GetProperty("groups").EnumerateArray(), name => name.ValueEquals("Operators"));
                Assert.Equal(90, user.GetProperty("sessionTimeoutSeconds").GetInt32());
                Assert.False(user.TryGetProperty("password", out _));
                Assert.Contains(response.GetProperty("missingInputs").EnumerateArray(), path => path.ValueEquals("/auth/users/operator/password"));
                Assert.DoesNotContain(initial, export.GetRawText());
                Assert.DoesNotContain(rotated, export.GetRawText());
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }
        }

        [Fact]
        public async Task GroupManifestResolvesLdapMappingsAndPreservesExistingMembership()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var backupRequest = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?authConfig=true");
            backupRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(backupRequest);
            backup.EnsureSuccessStatusCode();
            byte[] priorAuth = await backup.Content.ReadAsByteArrayAsync();

            const string create = """
                {"schemaVersion":1,"auth":{
                    "groups":{"Operations":{"description":"Operations group"}},
                    "ldap":{"groupMap":{"remote-ops":"Operations"}}
                }}
                """;
            JsonElement preview = await PreviewAsync(server, create);
            Assert.Contains(preview.GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/auth/groups/Operations"));
            LoopbackWebService.AssertOk(await ApplyAsync(server, create, preview.GetProperty("revision").GetString()!));
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, create)).GetProperty("changes").EnumerateArray());

            const string remove = """{"schemaVersion":1,"auth":{"groups":{"operations":null}}}""";
            using (var content = new StringContent(remove, Encoding.UTF8, "application/json"))
            {
                JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/auth/groups/operations", rejected.GetProperty("errorMessage").GetString());
            }

            using var user = new FormUrlEncodedContent([new("user", "operator"), new("pass", "fixture-password")]);
            LoopbackWebService.AssertOk(await server.CallAsync("admin/users/create", server.AdminToken, user));
            LoopbackWebService.AssertOk(await server.CallAsync("admin/groups/set?group=operations&members=operator", server.AdminToken));
            const string update = """
                {"schemaVersion":1,"auth":{"groups":{"operations":{"description":"Updated operations"}}}}
                """;
            string revision = (await PreviewAsync(server, update)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, update, revision));
            await server.RestartAsync();
            JsonElement group = await server.CallAsync("admin/groups/get?group=operations", server.AdminToken);
            LoopbackWebService.AssertOk(group);
            Assert.Contains(group.GetProperty("response").GetProperty("members").EnumerateArray(), member => member.ValueEquals("operator"));
            Assert.Contains(group.GetProperty("response").GetProperty("managedSettings").EnumerateArray(),
                path => path.ValueEquals("/auth/groups/operations/description"));

            JsonElement rejectedEdit = await server.CallAsync(
                "admin/groups/set?group=Operations&description=changed&members=", server.AdminToken);
            Assert.Equal("error", rejectedEdit.GetProperty("status").GetString());
            Assert.Contains("/auth/groups/operations/description", rejectedEdit.GetProperty("errorMessage").GetString());
            group = await server.CallAsync("admin/groups/get?group=Operations", server.AdminToken);
            Assert.Contains(group.GetProperty("response").GetProperty("members").EnumerateArray(), member => member.ValueEquals("operator"));

            JsonElement rejectedRename = await server.CallAsync(
                "admin/groups/set?group=Operations&newGroup=renamed", server.AdminToken);
            Assert.Equal("error", rejectedRename.GetProperty("status").GetString());
            Assert.Contains("/auth/groups/operations", rejectedRename.GetProperty("errorMessage").GetString());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(priorAuth), "file", "backup.zip");
            JsonElement rejectedRestore = await server.CallAsync("settings/restore?authConfig=true", server.AdminToken, form);
            Assert.Equal("error", rejectedRestore.GetProperty("status").GetString());
            Assert.Contains("/auth/groups/operations", rejectedRestore.GetProperty("errorMessage").GetString());

            JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement groups = export.GetProperty("response").GetProperty("manifest").GetProperty("auth").GetProperty("groups");
            Assert.Equal("Updated operations", groups.GetProperty("Operations").GetProperty("description").GetString());

            const string removeWithMapping = """
                {"schemaVersion":1,"auth":{"groups":{"operations":null},"ldap":{"groupMap":null}}}
                """;
            using (var content = new StringContent(removeWithMapping, Encoding.UTF8, "application/json"))
            {
                JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/auth/groups/operations", rejected.GetProperty("errorMessage").GetString());
            }
            LoopbackWebService.AssertOk(await server.CallAsync("admin/groups/set?group=operations&members=", server.AdminToken));
            revision = (await PreviewAsync(server, removeWithMapping)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, removeWithMapping, revision));
            await server.RestartAsync();
            Assert.Equal("error", (await server.CallAsync("admin/groups/get?group=operations", server.AdminToken)).GetProperty("status").GetString());
            Assert.Empty((await PreviewAsync(server, removeWithMapping)).GetProperty("changes").EnumerateArray());
            JsonElement rejectedCreate = await server.CallAsync("admin/groups/create?group=Operations", server.AdminToken);
            Assert.Equal("error", rejectedCreate.GetProperty("status").GetString());
            Assert.Contains("/auth/groups/operations", rejectedCreate.GetProperty("errorMessage").GetString());

            const string release = """{"schemaVersion":1}""";
            revision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, release, revision));
            await server.RestartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("admin/groups/create?group=Operations", server.AdminToken));
        }

        [Fact]
        public async Task ZoneTransferKeysResolveAgainstCandidateAndRemainManaged()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string missing = """
                {"schemaVersion":1,"zones":{"transfer.test":{"type":"Primary","transfer":{"tsigKeys":["transfer-key.test"]}}}}
                """;
            using (var content = new StringContent(missing, Encoding.UTF8, "application/json"))
            {
                JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/zones/transfer.test/transfer/tsigKeys", rejected.GetProperty("errorMessage").GetString());
            }

            const string variable = "TECHNITIUM_TEST_ZONE_TRANSFER_SECRET";
            string? previous = Environment.GetEnvironmentVariable(variable);
            Environment.SetEnvironmentVariable(variable, Convert.ToBase64String(new byte[32]));
            try
            {
                const string manifest = """
                    {"schemaVersion":1,
                     "dns":{"tsigKeys":{"transfer-key.test":{"algorithm":"hmac-sha256","secret":{"environment":"TECHNITIUM_TEST_ZONE_TRANSFER_SECRET"}}}},
                     "zones":{"transfer.test":{"type":"Primary","transfer":{"tsigKeys":["TRANSFER-KEY.TEST."]}}}}
                    """;
                string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
                await server.RestartAsync();
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                JsonElement rejected = await server.CallAsync(
                    "zones/options/set?zone=transfer.test&zoneTransferTsigKeyNames=false", server.AdminToken);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/zones/transfer.test/transfer/tsigKeys", rejected.GetProperty("errorMessage").GetString());

                JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
                LoopbackWebService.AssertOk(export);
                JsonElement keys = export.GetProperty("response").GetProperty("manifest").GetProperty("zones")
                    .GetProperty("transfer.test").GetProperty("transfer").GetProperty("tsigKeys");
                Assert.Equal("transfer-key.test", Assert.Single(keys.EnumerateArray()).GetString());
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }
        }

        [Fact]
        public async Task ZoneUpdateSecurityPolicyRequiresItsConfiguredKeyAndOwner()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string variable = "TECHNITIUM_TEST_UPDATE_POLICY_SECRET";
            string? previous = Environment.GetEnvironmentVariable(variable);
            string secret = Convert.ToBase64String(new byte[32]);
            Environment.SetEnvironmentVariable(variable, secret);
            try
            {
                const string manifest = """
                    {"schemaVersion":1,
                     "dns":{"tsigKeys":{"update-key.test":{"algorithm":"hmac-sha256","secret":{"environment":"TECHNITIUM_TEST_UPDATE_POLICY_SECRET"}}}},
                     "zones":{"updates.test":{"type":"Primary","updates":{"mode":"Allow","securityPolicies":{
                         "UPDATE-KEY.TEST.":{"WWW.UPDATES.TEST.":["A",1]}
                     }}}}}
                    """;
                string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
                await server.RestartAsync();
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                IPEndPoint endpoint = IPEndPoint.Parse((await server.GetSettingsAsync()).GetProperty("dnsServerLocalEndPoints")[0].GetString()!);
                var client = new DnsClient(endpoint) { Timeout = 2000, Retries = 1 };
                var key = new TsigKey("update-key.test", secret, "hmac-sha256");
                Assert.Equal(DnsResponseCode.Refused, (await client.RawResolveAsync(CreateUpdate("www.updates.test"))).RCODE);
                Assert.Equal(DnsResponseCode.NoError, (await client.TsigResolveAsync(CreateUpdate("www.updates.test"), key)).RCODE);
                Assert.Single((await server.QueryAsync("www.updates.test", DnsResourceRecordType.A)).Answer);

                JsonElement rejected = await server.CallAsync(
                    "zones/options/set?zone=updates.test&updateSecurityPolicies=false", server.AdminToken);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/zones/updates.test/updates/securityPolicies/update-key.test", rejected.GetProperty("errorMessage").GetString());

                JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
                LoopbackWebService.AssertOk(export);
                JsonElement types = export.GetProperty("response").GetProperty("manifest").GetProperty("zones")
                    .GetProperty("updates.test").GetProperty("updates").GetProperty("securityPolicies")
                    .GetProperty("update-key.test").GetProperty("www.updates.test");
                Assert.Equal(1, Assert.Single(types.EnumerateArray()).GetInt32());

                const string clear = """
                    {"schemaVersion":1,"dns":{"tsigKeys":null},"zones":{"updates.test":{
                        "updates":{"mode":"Deny","securityPolicies":{"update-key.test":null}}
                    }}}
                    """;
                revision = (await PreviewAsync(server, clear)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, clear, revision));
                Assert.Empty((await PreviewAsync(server, clear)).GetProperty("changes").EnumerateArray());
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }

            static DnsDatagram CreateUpdate(string owner) => new(1, false, DnsOpcode.Update, false, false, false, false, false, false,
                DnsResponseCode.NoError, [new DnsQuestionRecord("updates.test", DnsResourceRecordType.SOA, DnsClass.IN)],
                authority: [new DnsResourceRecord(owner, DnsResourceRecordType.A, DnsClass.IN, 60,
                    new DnsARecordData(IPAddress.Parse("192.0.2.42")))]);
        }

        [Fact]
        public async Task ZonePolicyOwnershipRejectsMixedEditsAndAllowsUnmanagedFields()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"zones":{"managed-policy.test":{"type":"Primary","query":{
                  "mode":"UseSpecifiedNetworkACL","networkAcl":["192.0.2.0/24"]
                }}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();

            JsonElement rejected = await server.CallAsync(
                "zones/options/set?zone=managed-policy.test&disabled=true&queryAccessNetworkACL=198.51.100.0%2F24",
                server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/zones/managed-policy.test/query/networkAcl", rejected.GetProperty("errorMessage").GetString());
            Assert.Single((await server.QueryAsync("managed-policy.test", DnsResourceRecordType.SOA)).Answer);

            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/options/set?zone=managed-policy.test&queryAccess=UseSpecifiedNetworkACL&queryAccessNetworkACL=192.0.2.0%2F24&zoneTransfer=Deny",
                server.AdminToken));
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            const string transfer = """
                {"schemaVersion":1,"zones":{"managed-policy.test":{"transfer":{"mode":"Deny"}}}}
                """;
            Assert.Empty((await PreviewAsync(server, transfer)).GetProperty("changes").EnumerateArray());

            revision = (await PreviewAsync(server, transfer)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, transfer, revision));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/options/set?zone=managed-policy.test&queryAccess=Allow", server.AdminToken));
        }

        [Fact]
        public async Task ZoneRecordPreviewLeavesDnsUnchangedUntilApply()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=records.test&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/records/add?zone=records.test&domain=www.records.test&type=A&ipAddress=192.0.2.10&ttl=300", server.AdminToken));

            const string manifest = """
                {"schemaVersion":1,"zones":{"records.test":{"records":[
                  {"owner":"WWW.RECORDS.TEST.","type":"A","ttl":600,"data":{"zoneFile":"192.0.2.10"}},
                  {"owner":"new.records.test","type":1,"data":{"rawHex":"c000020b"}}
                ]}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Collection(preview.GetProperty("changes").EnumerateArray(),
                change =>
                {
                    Assert.Equal("/zones/records.test/records/0", change.GetProperty("path").GetString());
                    Assert.Equal("Update", change.GetProperty("kind").GetString());
                },
                change =>
                {
                    Assert.Equal("/zones/records.test/records/1", change.GetProperty("path").GetString());
                    Assert.Equal("Add", change.GetProperty("kind").GetString());
                });
            Assert.DoesNotContain("192.0.2.", preview.GetRawText());
            Assert.Equal(300u, Assert.Single((await server.QueryAsync("www.records.test", DnsResourceRecordType.A)).Answer).OriginalTtlValue);
            Assert.Empty((await server.QueryAsync("new.records.test", DnsResourceRecordType.A)).Answer);
            Assert.Equal(preview.GetProperty("revision").GetString(),
                (await PreviewAsync(server, manifest)).GetProperty("revision").GetString());

            string revision = preview.GetProperty("revision").GetString()!;
            string staging = Directory.CreateDirectory(Path.Combine(server.ConfigurationDirectory, "zones", "records.test.tmp")).FullName;
            try
            {
                Assert.Equal("error", (await ApplyAsync(server, manifest, revision)).GetProperty("status").GetString());
                Assert.Equal(300u, Assert.Single((await server.QueryAsync("www.records.test", DnsResourceRecordType.A)).Answer).OriginalTtlValue);
            }
            finally
            {
                Directory.Delete(staging);
            }
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            Assert.Equal(600u, Assert.Single((await server.QueryAsync("www.records.test", DnsResourceRecordType.A)).Answer).OriginalTtlValue);
            DnsResourceRecord added = Assert.Single((await server.QueryAsync("new.records.test", DnsResourceRecordType.A)).Answer);
            Assert.Equal(IPAddress.Parse("192.0.2.11"), Assert.IsType<DnsARecordData>(added.RDATA).Address);
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            Assert.Equal(600u, Assert.Single((await server.QueryAsync("www.records.test", DnsResourceRecordType.A)).Answer).OriginalTtlValue);

            const string release = """{"schemaVersion":1,"zones":{"records.test":{"type":"Primary"}}}""";
            revision = (await PreviewAsync(server, release)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, release, revision));
            const string emptyRecords = """{"schemaVersion":1,"zones":{"records.test":{"records":[]}}}""";
            using var content = new StringContent(emptyRecords, Encoding.UTF8, "application/json");
            JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/zones/records.test/records", rejected.GetProperty("errorMessage").GetString());
            Assert.DoesNotContain("192.0.2.", rejected.GetRawText());
        }

        [Fact]
        public async Task CatalogManifestsAdvertiseSecondaryMemberUpstreams()
        {
            await using var upstream = new LoopbackDnsServer();
            upstream.AddPrimaryZone("relay-member.test", "www.relay-member.test", IPAddress.Parse("192.0.2.42"));
            upstream.Server.AuthZoneManager.GetAuthZoneInfo("relay-member.test").ZoneTransfer = AuthZoneTransfer.Allow;
            await upstream.StartAsync();
            await using var source = await LoopbackWebService.StartAsync();
            string manifest = $$$$$"""
                {"schemaVersion":1,"zones":{
                  "relay-catalog.test":{"type":"Catalog","transfer":{"mode":"Allow"}},
                  "relay-member.test":{"type":"Secondary","catalog":{"name":"relay-catalog.test"},
                    "primary":{"servers":[{"address":"{{{{{upstream.EndPoint}}}}}"}]}},
                  "stub-member.test":{"type":"Stub","enabled":false,"catalog":{"name":"relay-catalog.test","overrideQueryAccess":true},
                    "primary":{"servers":[{"address":"127.0.0.1"}]}}
                }}
                """;
            string revision = (await PreviewAsync(source, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(source, manifest, revision));
            await source.RestartAsync();
            Assert.Empty((await PreviewAsync(source, manifest)).GetProperty("changes").EnumerateArray());
            JsonElement export = await source.CallAsync("settings/config/export", source.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement zones = export.GetProperty("response").GetProperty("manifest").GetProperty("zones");
            Assert.Equal("relay-catalog.test", zones.GetProperty("relay-member.test").GetProperty("catalog").GetProperty("name").GetString());
            Assert.True(zones.GetProperty("stub-member.test").GetProperty("catalog").GetProperty("overrideQueryAccess").GetBoolean());

            await using var replica = await LoopbackWebService.StartAsync();
            string replicaManifest = $$$$$"""
                {"schemaVersion":1,"zones":{"relay-catalog.test":{"type":"SecondaryCatalog",
                  "primary":{"servers":[{"address":"127.0.0.1:{{{{{source.DnsPort}}}}}"}]}}}}
                """;
            revision = (await PreviewAsync(replica, replicaManifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(replica, replicaManifest, revision));
            DateTime deadline = DateTime.UtcNow.AddSeconds(20);
            JsonElement member;
            do
            {
                member = await replica.CallAsync("zones/options/get?zone=relay-member.test", replica.AdminToken);
                if (member.GetProperty("status").ValueEquals("ok"))
                    break;
                await Task.Delay(250);
            }
            while (DateTime.UtcNow < deadline);
            LoopbackWebService.AssertOk(member);
            Assert.Equal(upstream.EndPoint.ToString(), Assert.Single(member.GetProperty("response")
                .GetProperty("primaryNameServerAddresses").EnumerateArray()).GetString());
        }

        [Fact]
        public async Task CatalogManifestsPersistTheSourceAndProvisionSecondaryMembers()
        {
            await using var primary = await LoopbackWebService.StartAsync();
            const string source = """
                {"schemaVersion":1,"zones":{"catalog.test":{"type":"Catalog","transfer":{"mode":"Allow"},
                  "notify":{"mode":"None","secondaryCatalogNameServers":["127.0.0.1"]}
                },"destination-catalog.test":{"type":"Catalog","transfer":{"mode":"UseSpecifiedNetworkACL","networkAcl":["127.0.0.1/32"]}},
                "member.test":{"type":"Primary","catalog":{"name":"catalog.test","overrideNotify":false,
                  "overrideQueryAccess":false,"overrideZoneTransfer":false},
                  "query":{"mode":"UseSpecifiedNetworkACL","networkAcl":["127.0.0.1/32"]},
                  "transfer":{"mode":"UseSpecifiedNetworkACL","networkAcl":["127.0.0.1/32"]},
                  "records":[{"owner":"www.member.test","type":"A","data":{"zoneFile":"192.0.2.42"}}]
                }}}
                """;
            string revision = (await PreviewAsync(primary, source)).GetProperty("revision").GetString()!;
            string blockedWrite = Path.Combine(primary.ConfigurationDirectory, "zones", "member.test.tmp");
            Directory.CreateDirectory(blockedWrite);
            JsonElement failed = await ApplyAsync(primary, source, revision);
            Assert.Equal("error", failed.GetProperty("status").GetString());
            Assert.False(File.Exists(Path.Combine(primary.ConfigurationDirectory, "zones", "catalog.test.zone")));
            Directory.Delete(blockedWrite);
            revision = (await PreviewAsync(primary, source)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(primary, source, revision));
            string updatedSource = source.Replace("\"mode\":\"Allow\"", "\"mode\":\"UseSpecifiedNetworkACL\",\"networkAcl\":[\"127.0.0.1/32\"]", StringComparison.Ordinal)
                .Replace("\"overrideNotify\":false", "\"overrideNotify\":true", StringComparison.Ordinal)
                .Replace("\"overrideQueryAccess\":false", "\"overrideQueryAccess\":true", StringComparison.Ordinal)
                .Replace("\"overrideZoneTransfer\":false", "\"overrideZoneTransfer\":true", StringComparison.Ordinal);
            JsonElement sourcePlan = await PreviewAsync(primary, updatedSource);
            Assert.Contains(sourcePlan.GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/zones/catalog.test/transfer/mode"));
            Assert.Contains(sourcePlan.GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/zones/member.test/catalog/overrideNotify"));
            Assert.Contains(sourcePlan.GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/zones/member.test/catalog/overrideQueryAccess"));
            Assert.Contains(sourcePlan.GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/zones/member.test/catalog/overrideZoneTransfer"));
            LoopbackWebService.AssertOk(await ApplyAsync(primary, updatedSource, sourcePlan.GetProperty("revision").GetString()!));
            await primary.RestartAsync();
            Assert.Empty((await PreviewAsync(primary, updatedSource)).GetProperty("changes").EnumerateArray());
            JsonElement denied = await primary.CallAsync("zones/options/set?zone=catalog.test&zoneTransfer=Deny", primary.AdminToken);
            Assert.Equal("error", denied.GetProperty("status").GetString());
            Assert.Contains("/zones/catalog.test/transfer/mode", denied.GetProperty("errorMessage").GetString());
            JsonElement sourceExport = await primary.CallAsync("settings/config/export", primary.AdminToken);
            LoopbackWebService.AssertOk(sourceExport);
            JsonElement sourceZone = sourceExport.GetProperty("response").GetProperty("manifest").GetProperty("zones").GetProperty("catalog.test");
            Assert.Equal("Catalog", sourceZone.GetProperty("type").GetString());
            Assert.False(sourceZone.TryGetProperty("records", out _));
            Assert.Equal("127.0.0.1", Assert.Single(sourceZone.GetProperty("notify").GetProperty("secondaryCatalogNameServers").EnumerateArray()).GetString());
            JsonElement memberExport = sourceExport.GetProperty("response").GetProperty("manifest").GetProperty("zones").GetProperty("member.test");
            Assert.Equal("catalog.test", memberExport.GetProperty("catalog").GetProperty("name").GetString());
            Assert.True(memberExport.GetProperty("catalog").GetProperty("overrideNotify").GetBoolean());
            Assert.True(memberExport.GetProperty("catalog").GetProperty("overrideQueryAccess").GetBoolean());
            Assert.True(memberExport.GetProperty("catalog").GetProperty("overrideZoneTransfer").GetBoolean());
            JsonElement overrideDenied = await primary.CallAsync("zones/options/set?zone=member.test&overrideCatalogNotify=false", primary.AdminToken);
            Assert.Equal("error", overrideDenied.GetProperty("status").GetString());
            Assert.Contains("/zones/member.test/catalog/overrideNotify", overrideDenied.GetProperty("errorMessage").GetString());
            using var detach = new FormUrlEncodedContent([new("zone", "member.test"), new("catalog", "")]);
            JsonElement blocked = await primary.CallAsync("zones/options/set", primary.AdminToken, detach);
            Assert.Equal("error", blocked.GetProperty("status").GetString());
            Assert.Contains("/zones/member.test/catalog/name", blocked.GetProperty("errorMessage").GetString());

            await using var replica = await LoopbackWebService.StartAsync();
            string address = $"127.0.0.1:{primary.DnsPort}";
            string manifest = $$$$$"""
                {"schemaVersion":1,"zones":{"catalog.test":{"type":"SecondaryCatalog",
                  "primary":{"servers":[{"address":"{{{{{address}}}}}"}],"transferProtocol":"Tcp"}
                },"destination-catalog.test":{"type":"SecondaryCatalog","enabled":false,
                  "primary":{"servers":[{"address":"{{{{{address}}}}}"}],"transferProtocol":"Tcp"}
                }}}
                """;
            revision = (await PreviewAsync(replica, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(replica, manifest, revision));

            DateTime deadline = DateTime.UtcNow.AddSeconds(20);
            JsonElement member;
            do
            {
                member = await replica.CallAsync("zones/options/get?zone=member.test", replica.AdminToken);
                if (member.GetProperty("status").ValueEquals("ok") &&
                    member.GetProperty("response").GetProperty("overrideCatalogQueryAccess").GetBoolean() &&
                    member.GetProperty("response").GetProperty("overrideCatalogZoneTransfer").GetBoolean())
                    break;
                await Task.Delay(250);
            }
            while (DateTime.UtcNow < deadline);
            LoopbackWebService.AssertOk(member);
            Assert.True(member.GetProperty("response").GetProperty("overrideCatalogQueryAccess").GetBoolean());
            Assert.True(member.GetProperty("response").GetProperty("overrideCatalogZoneTransfer").GetBoolean());
            deadline = DateTime.UtcNow.AddSeconds(20);
            DnsDatagram answer;
            do
            {
                answer = await replica.QueryAsync("www.member.test", DnsResourceRecordType.A);
                if (answer.Answer.Count != 0)
                    break;
                await Task.Delay(300);
            }
            while (DateTime.UtcNow < deadline);
            Assert.Equal(IPAddress.Parse("192.0.2.42"), Assert.IsType<DnsARecordData>(Assert.Single(answer.Answer).RDATA).Address);
            Assert.Empty((await PreviewAsync(replica, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement export = await replica.CallAsync("settings/config/export", replica.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement zones = export.GetProperty("response").GetProperty("manifest").GetProperty("zones");
            JsonElement catalog = zones.GetProperty("catalog.test");
            Assert.Equal("SecondaryCatalog", catalog.GetProperty("type").GetString());
            Assert.Equal(address, Assert.Single(catalog.GetProperty("primary").GetProperty("servers").EnumerateArray()).GetProperty("address").GetString());
            Assert.False(catalog.TryGetProperty("records", out _));
            Assert.False(zones.TryGetProperty("member.test", out _));

            using var remove = new StringContent("""{"schemaVersion":1,"zones":{"catalog.test":null}}""", Encoding.UTF8, "application/json");
            JsonElement rejected = await replica.CallAsync("settings/config/plan", replica.AdminToken, remove);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("have no members", rejected.GetProperty("errorMessage").GetString());

            string moved = updatedSource.Replace("\"name\":\"catalog.test\"", "\"name\":\"destination-catalog.test\"", StringComparison.Ordinal);
            JsonElement movePlan = await PreviewAsync(primary, moved);
            Assert.Contains(movePlan.GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/zones/member.test/catalog/name"));
            LoopbackWebService.AssertOk(await ApplyAsync(primary, moved, movePlan.GetProperty("revision").GetString()!));
            LoopbackWebService.AssertOk(await replica.CallAsync("zones/disable?zone=catalog.test", replica.AdminToken));
            LoopbackWebService.AssertOk(await replica.CallAsync("zones/enable?zone=catalog.test", replica.AdminToken));
            deadline = DateTime.UtcNow.AddSeconds(20);
            do
            {
                await Task.Delay(300);
                member = await replica.CallAsync("zones/options/get?zone=member.test", replica.AdminToken);
                LoopbackWebService.AssertOk(member);
                if (member.GetProperty("response").GetProperty("catalog").ValueEquals("destination-catalog.test"))
                    break;
            }
            while (DateTime.UtcNow < deadline);
            Assert.Equal("destination-catalog.test", member.GetProperty("response").GetProperty("catalog").GetString());
            answer = await replica.QueryAsync("www.member.test", DnsResourceRecordType.A);
            Assert.Equal(IPAddress.Parse("192.0.2.42"), Assert.IsType<DnsARecordData>(Assert.Single(answer.Answer).RDATA).Address);
            await primary.RestartAsync();
            Assert.Empty((await PreviewAsync(primary, moved)).GetProperty("changes").EnumerateArray());

            string updated = manifest.Replace(address, LoopbackDnsServer.GetLoopbackEndPoint().ToString(), StringComparison.Ordinal);
            JsonElement plan = await PreviewAsync(replica, updated);
            Assert.Contains(plan.GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/zones/catalog.test/primary/servers"));
            LoopbackWebService.AssertOk(await ApplyAsync(replica, updated, plan.GetProperty("revision").GetString()!));
            await replica.RestartAsync();
            LoopbackWebService.AssertOk(await replica.CallAsync("zones/options/get?zone=member.test", replica.AdminToken));
            Assert.Empty((await PreviewAsync(replica, updated)).GetProperty("changes").EnumerateArray());

            string detached = updatedSource.Replace("\"name\":\"catalog.test\"", "\"name\":null", StringComparison.Ordinal);
            plan = await PreviewAsync(primary, detached);
            Assert.Contains(plan.GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/zones/member.test/catalog/name"));
            LoopbackWebService.AssertOk(await ApplyAsync(primary, detached, plan.GetProperty("revision").GetString()!));
            await primary.RestartAsync();
            Assert.Empty((await PreviewAsync(primary, detached)).GetProperty("changes").EnumerateArray());
        }

        [Fact]
        public async Task StubAndSecondaryForwarderExportsPreserveTheirUpstreamSettings()
        {
            await using var upstream = new LoopbackDnsServer();
            upstream.AddPrimaryZone("relay.test", "www.relay.test", IPAddress.Parse("192.0.2.42"));
            await upstream.StartAsync();
            await using var primary = await LoopbackWebService.StartAsync();
            string source = $$$$$"""
                {"schemaVersion":1,"zones":{"relay.test":{"type":"Forwarder","transfer":{"mode":"Allow"},"records":[
                  {"owner":"@","type":"FWD","data":{"forwarder":{"address":"{{{{{upstream.EndPoint}}}}}","proxy":{"type":"NoProxy"}}}}
                ]}}}
                """;
            await ReconcileAsync(primary, source);

            await using var secondary = await LoopbackWebService.StartAsync();
            string manifest = $$$$$"""
                {"schemaVersion":1,"zones":{
                  "relay.test":{"type":"SecondaryForwarder","enabled":false,"primary":{"servers":[{"address":"127.0.0.1:{{{{{primary.DnsPort}}}}}"}]}},
                  "stub.test":{"type":"Stub","enabled":false,"primary":{"servers":[{"address":"192.0.2.53"}]},"query":{"mode":"Deny"}}
                }}
                """;
            await ReconcileAsync(secondary, manifest);
            await secondary.RestartAsync();
            Assert.Empty((await PreviewAsync(secondary, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement export = await secondary.CallAsync("settings/config/export", secondary.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement zones = export.GetProperty("response").GetProperty("manifest").GetProperty("zones");
            JsonElement stub = zones.GetProperty("stub.test");
            Assert.Equal("192.0.2.53", Assert.Single(stub.GetProperty("primary").GetProperty("servers").EnumerateArray()).GetProperty("address").GetString());
            Assert.False(stub.GetProperty("primary").TryGetProperty("transferProtocol", out _));
            JsonElement relay = zones.GetProperty("relay.test");
            Assert.False(relay.TryGetProperty("records", out _));
            Assert.Equal($"127.0.0.1:{primary.DnsPort}",
                Assert.Single(relay.GetProperty("primary").GetProperty("servers").EnumerateArray()).GetProperty("address").GetString());
            Assert.Equal("Tcp", relay.GetProperty("primary").GetProperty("transferProtocol").GetString());
            Assert.False(relay.GetProperty("enabled").GetBoolean());

            await using var destination = await LoopbackWebService.StartAsync();
            string exported = $$"""{"schemaVersion":1,"zones":{{zones.GetRawText()}} }""";
            await ReconcileAsync(destination, exported);
            Assert.Empty((await PreviewAsync(destination, exported)).GetProperty("changes").EnumerateArray());
            var enabled = JsonNode.Parse(exported)!;
            enabled["zones"]!["relay.test"]!["enabled"] = true;
            await ReconcileAsync(destination, enabled.ToJsonString());
            await WaitForAnswerAsync(destination);
            Assert.Empty((await PreviewAsync(destination, enabled.ToJsonString())).GetProperty("changes").EnumerateArray());

            static async Task ReconcileAsync(LoopbackWebService server, string manifest)
            {
                string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            }

            static async Task WaitForAnswerAsync(LoopbackWebService server)
            {
                DateTime deadline = DateTime.UtcNow.AddSeconds(15);
                DnsDatagram result;
                do
                {
                    result = await server.QueryAsync("www.relay.test", DnsResourceRecordType.A);
                    if (result.Answer.Count != 0)
                        break;
                    await Task.Delay(250);
                }
                while (DateTime.UtcNow < deadline);
                Assert.True(result.Answer.Count > 0, string.Join("\n",
                    Directory.GetFiles(Path.Combine(server.ConfigurationDirectory, "logs"), "*.log")
                        .SelectMany(File.ReadAllLines).Where(line => line.Contains("relay.test", StringComparison.Ordinal))));
                Assert.Equal(IPAddress.Parse("192.0.2.42"), Assert.IsType<DnsARecordData>(Assert.Single(result.Answer).RDATA).Address);
            }
        }

        [Fact]
        public async Task SecondaryZoneKeepsTransferredRecordsWhenThePrimarySettingsChange()
        {
            await using var upstream = new LoopbackDnsServer();
            upstream.AddPrimaryZone("replica.test", "www.replica.test", IPAddress.Parse("192.0.2.42"));
            upstream.Server.AuthZoneManager.GetAuthZoneInfo("replica.test").ZoneTransfer = AuthZoneTransfer.Allow;
            await upstream.StartAsync();
            await using var server = await LoopbackWebService.StartAsync();
            string manifest = $$$$$"""
                {"schemaVersion":1,"zones":{"replica.test":{"type":"Secondary","primary":{
                  "servers":[{"address":"{{{{{upstream.EndPoint}}}}}"}],"transferProtocol":"Tcp","validateZone":false
                }}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await WaitForTransferAsync(server);
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement zone = export.GetProperty("response").GetProperty("manifest").GetProperty("zones").GetProperty("replica.test");
            Assert.False(zone.TryGetProperty("records", out _));
            Assert.Equal(JsonValueKind.Null, zone.GetProperty("primary").GetProperty("tsigKey").ValueKind);
            string exported = $$"""{"schemaVersion":1,"zones":{"replica.test":{{zone.GetRawText()}} } }""";
            await using var destination = await LoopbackWebService.StartAsync();
            revision = (await PreviewAsync(destination, exported)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(destination, exported, revision));
            await WaitForTransferAsync(destination);

            string unavailable = LoopbackDnsServer.GetLoopbackEndPoint().ToString();
            string changed = manifest.Replace(upstream.EndPoint.ToString(), unavailable, StringComparison.Ordinal);
            JsonElement plan = await PreviewAsync(server, changed);
            Assert.Contains(plan.GetProperty("changes").EnumerateArray(), change => change.GetProperty("path").ValueEquals("/zones/replica.test/primary/servers"));
            LoopbackWebService.AssertOk(await ApplyAsync(server, changed, plan.GetProperty("revision").GetString()!));
            await server.RestartAsync();
            await AssertAnswerAsync(server);
            Assert.Empty((await PreviewAsync(server, changed)).GetProperty("changes").EnumerateArray());
            JsonElement rejected = await server.CallAsync($"zones/options/set?zone=replica.test&primaryNameServerAddresses={upstream.EndPoint}", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/zones/replica.test/primary/servers", rejected.GetProperty("errorMessage").GetString());

            static async Task WaitForTransferAsync(LoopbackWebService server)
            {
                DateTime deadline = DateTime.UtcNow.AddSeconds(15);
                do
                {
                    if ((await server.QueryAsync("www.replica.test", DnsResourceRecordType.A)).Answer.Count > 0)
                        break;
                    await Task.Delay(250);
                }
                while (DateTime.UtcNow < deadline);
                await AssertAnswerAsync(server);
            }

            static async Task AssertAnswerAsync(LoopbackWebService server)
            {
                var answer = Assert.Single((await server.QueryAsync("www.replica.test", DnsResourceRecordType.A)).Answer);
                Assert.Equal(IPAddress.Parse("192.0.2.42"), Assert.IsType<DnsARecordData>(answer.RDATA).Address);
            }
        }

        [Fact]
        public async Task ForwarderZoneReproducesRoutingAndProtectsProxySecrets()
        {
            const string variable = "TECHNITIUM_TEST_FORWARDER_PASSWORD";
            const string secret = "fixture-forwarder-password";
            string? previous = Environment.GetEnvironmentVariable(variable);
            Environment.SetEnvironmentVariable(variable, secret);
            try
            {
                await using var upstream = new LoopbackDnsServer();
                upstream.AddPrimaryZone("route.test", "www.route.test", IPAddress.Parse("192.0.2.42"));
                await upstream.StartAsync();
                await using var source = await LoopbackWebService.StartAsync();
                string manifest = $$$$$"""
                    {"schemaVersion":1,"zones":{"route.test":{"type":"Forwarder","records":[
                      {"owner":"@","type":"FWD","data":{"forwarder":{"address":"{{{{{upstream.EndPoint}}}}}"}}},
                      {"owner":"unused.route.test","type":"FWD","disabled":true,"data":{"forwarder":{
                        "address":"{{{{{upstream.EndPoint}}}}}","transport":"Tcp","priority":3,
                        "proxy":{"type":"Http","address":"127.0.0.1","port":8080,"username":"fixture",
                                 "password":{"environment":"TECHNITIUM_TEST_FORWARDER_PASSWORD"}}
                      }}}
                    ]}}}
                    """;
                JsonElement plan = await PreviewAsync(source, manifest);
                Assert.DoesNotContain(secret, plan.GetRawText());
                LoopbackWebService.AssertOk(await ApplyAsync(source, manifest, plan.GetProperty("revision").GetString()!));
                Assert.Empty((await PreviewAsync(source, manifest)).GetProperty("changes").EnumerateArray());
                await AssertForwardedAsync(source);
                await source.RestartAsync();
                await AssertForwardedAsync(source);

                JsonElement export = await source.CallAsync("settings/config/export", source.AdminToken);
                LoopbackWebService.AssertOk(export);
                Assert.DoesNotContain(secret, export.GetRawText());
                JsonElement result = export.GetProperty("response");
                var zones = JsonNode.Parse(result.GetProperty("manifest").GetProperty("zones").GetRawText())!;
                var records = zones["route.test"]!["records"]!.AsArray();
                int index = records.IndexOf(Assert.Single(records, record => record!["owner"]!.GetValue<string>() == "unused.route.test"));
                Assert.Contains(result.GetProperty("missingInputs").EnumerateArray(),
                    input => input.ValueEquals($"/zones/route.test/records/{index}/data/forwarder/proxy/password"));
                records[index]!["data"]!["forwarder"]!["proxy"]!["password"] = new JsonObject { ["environment"] = variable };
                string migrated = new JsonObject { ["schemaVersion"] = 1, ["zones"] = zones }.ToJsonString();
                await using var destination = await LoopbackWebService.StartAsync();
                plan = await PreviewAsync(destination, migrated);
                LoopbackWebService.AssertOk(await ApplyAsync(destination, migrated, plan.GetProperty("revision").GetString()!));
                await AssertForwardedAsync(destination);
                Assert.Empty((await PreviewAsync(destination, migrated)).GetProperty("changes").EnumerateArray());
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }

            static async Task AssertForwardedAsync(LoopbackWebService server)
            {
                var answer = Assert.Single((await server.QueryAsync("www.route.test", DnsResourceRecordType.A)).Answer);
                Assert.Equal(IPAddress.Parse("192.0.2.42"), Assert.IsType<DnsARecordData>(answer.RDATA).Address);
            }
        }

        [Fact]
        public async Task ApplicationRecordsReproduceWithReferencedData()
        {
            const string variable = "TECHNITIUM_TEST_APP_RECORD_DATA";
            const string original = "{\"fixture\":\"private-original\"}";
            const string updated = "{\"fixture\":\"private-updated\"}";
            const string manifest = """
                {"schemaVersion":1,"zones":{"app-record.test":{"type":"Primary","records":[
                  {"owner":"app.app-record.test","type":"APP","data":{"app":{"name":"Fixture","classPath":"Fixture.Handler",
                    "configuration":{"secret":{"environment":"TECHNITIUM_TEST_APP_RECORD_DATA"}}}}}
                ]}}}
                """;
            string? previous = Environment.GetEnvironmentVariable(variable);
            try
            {
                await using var server = await LoopbackWebService.StartAsync();
                Environment.SetEnvironmentVariable(variable, original);
                JsonElement plan = await PreviewAsync(server, manifest);
                Assert.DoesNotContain("private-original", plan.GetRawText());
                Environment.SetEnvironmentVariable(variable, updated);
                JsonElement stale = await ApplyAsync(server, manifest, plan.GetProperty("revision").GetString()!);
                Assert.Equal("error", stale.GetProperty("status").GetString());
                Assert.Contains("stale", stale.GetProperty("errorMessage").GetString());
                Assert.DoesNotContain("private-updated", stale.GetRawText());

                plan = await PreviewAsync(server, manifest);
                LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, plan.GetProperty("revision").GetString()!));
                await server.RestartAsync();
                Assert.Equal(updated, await ReadAppDataAsync(server));
                Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

                JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
                LoopbackWebService.AssertOk(export);
                Assert.DoesNotContain("private-updated", export.GetRawText());
                var response = export.GetProperty("response");
                Assert.Contains(response.GetProperty("missingInputs").EnumerateArray(),
                    path => path.ValueEquals("/zones/app-record.test/records/1/data/app/configuration"));
                var zones = JsonNode.Parse(response.GetProperty("manifest").GetProperty("zones").GetRawText())!;
                var app = zones["app-record.test"]!["records"]![1]!["data"]!["app"]!.AsObject();
                Assert.Equal("Fixture.Handler", app["classPath"]!.GetValue<string>());
                app["configuration"] = new JsonObject { ["secret"] = new JsonObject { ["environment"] = variable } };
                string migrated = new JsonObject { ["schemaVersion"] = 1, ["zones"] = zones }.ToJsonString();
                await using var destination = await LoopbackWebService.StartAsync();
                plan = await PreviewAsync(destination, migrated);
                LoopbackWebService.AssertOk(await ApplyAsync(destination, migrated, plan.GetProperty("revision").GetString()!));
                Assert.Equal(updated, await ReadAppDataAsync(destination));
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }

            static async Task<string?> ReadAppDataAsync(LoopbackWebService server)
            {
                JsonElement result = await server.CallAsync("zones/records/get?zone=app-record.test&domain=app.app-record.test", server.AdminToken);
                LoopbackWebService.AssertOk(result);
                JsonElement record = Assert.Single(result.GetProperty("response").GetProperty("records").EnumerateArray());
                return record.GetProperty("rData").GetProperty("data").GetString();
            }
        }

        [Fact]
        public async Task ServiceRecordHintsFollowTheDeclaredAddressRecords()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"zones":{"hints.test":{"type":"Primary","records":[
                    {"owner":"www.hints.test","type":"HTTPS","autoIpv4Hint":true,"autoIpv6Hint":true,
                     "data":{"zoneFile":"1 . alpn=h2"}},
                    {"owner":"www.hints.test","type":"A","data":{"zoneFile":"192.0.2.42"}},
                    {"owner":"www.hints.test","type":"AAAA","data":{"zoneFile":"2001:db8::42"}}
                ]}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await AssertHintsAsync(server, "192.0.2.42", "2001:db8::42");
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            string changed = manifest.Replace("192.0.2.42", "192.0.2.43", StringComparison.Ordinal)
                .Replace("\"type\":\"AAAA\",", "\"type\":\"AAAA\",\"disabled\":true,", StringComparison.Ordinal);
            JsonElement plan = await PreviewAsync(server, changed);
            Assert.Contains(plan.GetProperty("changes").EnumerateArray(), change =>
                change.GetProperty("path").ValueEquals("/zones/hints.test/records/0"));
            LoopbackWebService.AssertOk(await ApplyAsync(server, changed, plan.GetProperty("revision").GetString()!));
            await server.RestartAsync();
            await AssertHintsAsync(server, "192.0.2.43", null);

            JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement zone = export.GetProperty("response").GetProperty("manifest").GetProperty("zones").GetProperty("hints.test");
            JsonElement service = Assert.Single(zone.GetProperty("records").EnumerateArray(),
                record => record.GetProperty("type").GetInt32() == (int)DnsResourceRecordType.HTTPS);
            Assert.True(service.GetProperty("autoIpv4Hint").GetBoolean());
            Assert.True(service.GetProperty("autoIpv6Hint").GetBoolean());

            await using var restored = await LoopbackWebService.StartAsync();
            string exported = $$"""{"schemaVersion":1,"zones":{"hints.test":{{zone.GetRawText()}} } }""";
            revision = (await PreviewAsync(restored, exported)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(restored, exported, revision));
            await AssertHintsAsync(restored, "192.0.2.43", null);
            Assert.Empty((await PreviewAsync(restored, exported)).GetProperty("changes").EnumerateArray());

            static async Task AssertHintsAsync(LoopbackWebService service, string ipv4, string? ipv6)
            {
                var answer = Assert.Single((await service.QueryAsync("www.hints.test", DnsResourceRecordType.HTTPS)).Answer);
                var data = Assert.IsType<DnsSVCBRecordData>(answer.RDATA);
                Assert.True(data.SvcParams.ContainsKey(DnsSvcParamKey.ALPN));
                Assert.Equal(IPAddress.Parse(ipv4), Assert.Single(Assert.IsType<DnsSvcIPv4HintParamValue>(data.SvcParams[DnsSvcParamKey.IPv4Hint]).Addresses));
                if (ipv6 is null)
                    Assert.False(data.SvcParams.ContainsKey(DnsSvcParamKey.IPv6Hint));
                else
                    Assert.Equal(IPAddress.Parse(ipv6), Assert.Single(Assert.IsType<DnsSvcIPv6HintParamValue>(data.SvcParams[DnsSvcParamKey.IPv6Hint]).Addresses));
            }
        }

        [Fact]
        public async Task ZoneGlueAppliesExportsAndClears()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"zones":{"glue.test":{"type":"Primary","records":[
                    {"owner":"child.glue.test","type":"NS","ttl":300,"data":{"zoneFile":"ns.child.glue.test."},
                     "glue":["192.0.2.42","2001:db8::42"]}
                ]}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            await server.RestartAsync();
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement zone = export.GetProperty("response").GetProperty("manifest").GetProperty("zones").GetProperty("glue.test");
            JsonElement record = Assert.Single(zone.GetProperty("records").EnumerateArray(),
                entry => entry.GetProperty("type").GetInt32() == (int)DnsResourceRecordType.NS);
            Assert.Collection(record.GetProperty("glue").EnumerateArray(),
                address => Assert.Equal("192.0.2.42", address.GetString()),
                address => Assert.Equal("2001:db8::42", address.GetString()));

            string clear = manifest.Replace("[\"192.0.2.42\",\"2001:db8::42\"]", "[]", StringComparison.Ordinal);
            JsonElement preview = await PreviewAsync(server, clear);
            Assert.Equal("Update", Assert.Single(preview.GetProperty("changes").EnumerateArray()).GetProperty("kind").GetString());
            LoopbackWebService.AssertOk(await ApplyAsync(server, clear, preview.GetProperty("revision").GetString()!));
            Assert.Empty((await PreviewAsync(server, clear)).GetProperty("changes").EnumerateArray());
        }

        [Fact]
        public async Task ZoneRecordApplyStartsExpiryWithoutRestart()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"zones":{"expiry.test":{"type":"Primary","records":[
                    {"owner":"www.expiry.test","type":"A","ttl":60,"expiryTtl":2,"data":{"zoneFile":"192.0.2.42"}}
                ]}}}
                """;
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            Assert.Single((await server.QueryAsync("www.expiry.test", DnsResourceRecordType.A)).Answer);
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            DateTime deadline = DateTime.UtcNow.AddSeconds(8);
            DnsDatagram answer;
            do
            {
                await Task.Delay(100);
                answer = await server.QueryAsync("www.expiry.test", DnsResourceRecordType.A);
            }
            while (answer.Answer.Count > 0 && DateTime.UtcNow < deadline);

            Assert.Empty(answer.Answer);
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal("Add", Assert.Single(preview.GetProperty("changes").EnumerateArray()).GetProperty("kind").GetString());
        }

        [Fact]
        public async Task ZoneRecordApplyRemovesOwnedRecordsAndRetainsApexRecords()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string initial = """
                {"schemaVersion":1,"zones":{"prune.test":{"type":"Primary","updates":{"mode":"Allow"},"records":[
                    {"owner":"www.prune.test","type":"A","data":{"zoneFile":"192.0.2.42"}}
                ]}}}
                """;
            string revision = (await PreviewAsync(server, initial)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, initial, revision));

            IPEndPoint endpoint = IPEndPoint.Parse((await server.GetSettingsAsync()).GetProperty("dnsServerLocalEndPoints")[0].GetString()!);
            var client = new DnsClient(endpoint) { Timeout = 2000, Retries = 1 };
            var update = new DnsDatagram(1, false, DnsOpcode.Update, false, false, false, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("prune.test", DnsResourceRecordType.SOA, DnsClass.IN)],
                authority: [new DnsResourceRecord("other.prune.test", DnsResourceRecordType.A, DnsClass.IN, 60,
                    new DnsARecordData(IPAddress.Parse("192.0.2.43")))]);
            Assert.Equal(DnsResponseCode.Refused, (await client.RawResolveAsync(update)).RCODE);

            const string reset = """{"schemaVersion":1,"zones":{"prune.test":{"records":null}}}""";
            JsonElement preview = await PreviewAsync(server, reset);
            JsonElement change = Assert.Single(preview.GetProperty("changes").EnumerateArray());
            Assert.Equal("Remove", change.GetProperty("kind").GetString());
            Assert.Equal("/zones/prune.test/records", change.GetProperty("path").GetString());
            Assert.Single((await server.QueryAsync("www.prune.test", DnsResourceRecordType.A)).Answer);
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, preview.GetProperty("revision").GetString()!));
            Assert.Empty((await server.QueryAsync("www.prune.test", DnsResourceRecordType.A)).Answer);
            Assert.Single((await server.QueryAsync("prune.test", DnsResourceRecordType.SOA)).Answer);
            await server.RestartAsync();
            Assert.Empty((await server.QueryAsync("www.prune.test", DnsResourceRecordType.A)).Answer);
            Assert.Empty((await PreviewAsync(server, reset)).GetProperty("changes").EnumerateArray());
        }

        [Fact]
        public async Task ZoneRecordPreviewPreservesGeneratedRecordsAndRecognizesWireData()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """{"schemaVersion":1,"zones":{"records.test":{"type":"Primary","records":[]}}}""";
            JsonElement before = await PreviewAsync(server, manifest);
            Assert.Equal("Add", Assert.Single(before.GetProperty("changes").EnumerateArray()).GetProperty("kind").GetString());

            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=records.test&type=Primary", server.AdminToken));
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());
            Assert.Single((await server.QueryAsync("records.test", DnsResourceRecordType.SOA)).Answer);

            const string create = """
                {"schemaVersion":1,"zones":{"fresh.test":{"type":"Primary","records":[
                    {"owner":"www.fresh.test","type":"A","data":{"rawHex":"c000020b"}}
                ]}}}
                """;
            string revision = (await PreviewAsync(server, create)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, create, revision));
            Assert.Single((await server.QueryAsync("www.fresh.test", DnsResourceRecordType.A)).Answer);
            Assert.Single((await server.QueryAsync("fresh.test", DnsResourceRecordType.SOA)).Answer);
            Assert.Empty((await PreviewAsync(server, create)).GetProperty("changes").EnumerateArray());
            Assert.Single((await server.QueryAsync("records.test", DnsResourceRecordType.NS)).Answer);

            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/records/add?zone=records.test&domain=records.test&type=TXT&text=hello", server.AdminToken));
            const string txtManifest = """
                {"schemaVersion":1,"zones":{"records.test":{"records":[{"owner":"@","type":"TXT","data":{"txtBase64":["aGVsbG8="]}}]}}}
                """;
            Assert.Empty((await PreviewAsync(server, txtManifest)).GetProperty("changes").EnumerateArray());
        }

        [Fact]
        public async Task FailedDnsBindRestoresPreviousServiceAndLeavesLoggingUnchanged()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var occupied = new TcpListener(IPAddress.Loopback, 0);
            occupied.Start();
            string manifest = ListenerManifest((IPEndPoint)occupied.LocalEndpoint);
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;

            JsonElement rejected = await ApplyAsync(server, manifest, revision);

            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dns/localEndpoints", rejected.GetProperty("errorMessage").GetString());
            await server.QueryAsync("example.invalid", DnsResourceRecordType.A);
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
            Assert.Empty((await server.GetSettingsAsync()).GetProperty("managedSettings").EnumerateArray());
        }

        [Fact]
        public async Task StartupBindsAndPersistsDeclaredDnsListeners()
        {
            IPEndPoint endpoint = LoopbackDnsServer.GetLoopbackEndPoint();
            await using var server = await LoopbackWebService.StartAsync(startupManifest: ListenerManifest(endpoint));
            await AssertListenerAnswersAsync(endpoint);
            File.Delete(Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName));
            await server.RestartAsync();
            await AssertListenerAnswersAsync(endpoint);
            Assert.Equal("/dns/localEndpoints", (await server.GetSettingsAsync()).GetProperty("managedSettings")[0].GetString());
        }

        private static string ListenerManifest(IPEndPoint endpoint)
        {
            return JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                dns = new { localEndpoints = new[] { endpoint.ToString() } },
                logging = new { retentionDays = 180 }
            });
        }

        private static async Task AssertListenerAnswersAsync(IPEndPoint endpoint)
        {
            var client = new DnsClient(endpoint) { Timeout = 1000, Retries = 1 };
            Assert.Equal(DnsResponseCode.Refused, (await client.ResolveAsync("example.invalid", DnsResourceRecordType.A)).RCODE);
        }

        [Fact]
        public async Task ServerRevisionBindsTheManifestAndCurrentSettings()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """{"schemaVersion":1,"logging":{"retentionDays":180}}""";

            JsonElement first = await PreviewAsync(server, manifest);
            string revision = first.GetProperty("revision").GetString()!;
            Assert.Equal(64, revision.Length);
            Assert.Equal(revision, (await PreviewAsync(server, manifest)).GetProperty("revision").GetString());
            Assert.NotEqual(revision, (await PreviewAsync(server, manifest.Replace("180", "181", StringComparison.Ordinal))).GetProperty("revision").GetString());
            JsonElement change = Assert.Single(first.GetProperty("changes").EnumerateArray());
            Assert.Equal("/logging/retentionDays", change.GetProperty("path").GetString());

            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?maxLogFileDays=180", server.AdminToken));
            JsonElement updated = await PreviewAsync(server, manifest);
            Assert.NotEqual(revision, updated.GetProperty("revision").GetString());
            Assert.Equal(0, updated.GetProperty("changes").GetArrayLength());
        }

        private static async Task<JsonElement> PreviewAsync(LoopbackWebService server, string json)
        {
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            JsonElement result = await server.CallAsync("settings/config/plan", server.AdminToken, content);
            LoopbackWebService.AssertOk(result);
            return result.GetProperty("response");
        }

        [Fact]
        public async Task ApplyRejectsAStaleRevisionAndPersistsAnUpdatedPreview()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """{"schemaVersion":1,"logging":{"retentionDays":180,"noStackTrace":true}}""";
            string staleRevision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;

            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?maxLogFileDays=240", server.AdminToken));
            JsonElement rejected = await ApplyAsync(server, manifest, staleRevision);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("stale", rejected.GetProperty("errorMessage").GetString());
            JsonElement unchanged = await server.GetSettingsAsync();
            Assert.Equal(240, unchanged.GetProperty("maxLogFileDays").GetInt32());
            Assert.False(unchanged.GetProperty("noStackTrace").GetBoolean());

            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            JsonElement applied = await PreviewAsync(server, manifest);
            Assert.Equal(0, applied.GetProperty("changes").GetArrayLength());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, applied.GetProperty("revision").GetString()!));

            await server.RestartAsync();
            JsonElement restored = await server.GetSettingsAsync();
            Assert.Equal(180, restored.GetProperty("maxLogFileDays").GetInt32());
            Assert.True(restored.GetProperty("noStackTrace").GetBoolean());
        }

        private static async Task<JsonElement> ApplyAsync(LoopbackWebService server, string json, string revision)
        {
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            return await server.CallAsync("settings/config/apply", server.AdminToken, content, revision);
        }

        [Fact]
        public async Task LogFolderPreviewAndOwnershipUseTheNormalizedServerPath()
        {
            await using var server = await LoopbackWebService.StartAsync();
            string destination = Path.Combine(server.ConfigurationDirectory, "manifest-logs");
            string manifest = JsonSerializer.Serialize(new { schemaVersion = 1, logging = new { folder = destination } });
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal("/logging/folder", Assert.Single(preview.GetProperty("changes").EnumerateArray()).GetProperty("path").GetString());

            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));
            Assert.True(Directory.Exists(destination));
            Assert.Equal("manifest-logs", (await server.GetSettingsAsync()).GetProperty("logFolder").GetString());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement rejected = await server.CallAsync("settings/set?logFolder=other-logs", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/logging/folder", rejected.GetProperty("errorMessage").GetString());

            const string reset = """{"schemaVersion":1,"logging":{"folder":null}}""";
            string revision = (await PreviewAsync(server, reset)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, reset, revision));
            await server.RestartAsync();
            JsonElement restored = await server.GetSettingsAsync();
            Assert.Equal("logs", restored.GetProperty("logFolder").GetString());
            Assert.Equal("/logging/folder", Assert.Single(restored.GetProperty("managedSettings").EnumerateArray()).GetString());
        }

        [Fact]
        public async Task StartupReconcilesTheLoggingManifestAndReleasesOmittedFields()
        {
            await using var server = await LoopbackWebService.StartAsync(
                startupManifest: """{"schemaVersion":1,"logging":{"retentionDays":180,"noStackTrace":true}}""");
            string manifest = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);

            JsonElement first = await server.GetSettingsAsync();
            Assert.Equal(180, first.GetProperty("maxLogFileDays").GetInt32());
            Assert.True(first.GetProperty("noStackTrace").GetBoolean());
            Assert.Equal(2, first.GetProperty("managedSettings").GetArrayLength());

            await File.WriteAllTextAsync(manifest, """{"schemaVersion":1,"logging":{"retentionDays":null}}""");
            await server.RestartAsync();
            JsonElement updated = await server.GetSettingsAsync();
            Assert.Equal(365, updated.GetProperty("maxLogFileDays").GetInt32());
            Assert.True(updated.GetProperty("noStackTrace").GetBoolean());
            Assert.Equal("/logging/retentionDays", Assert.Single(updated.GetProperty("managedSettings").EnumerateArray()).GetString());
        }

        [Fact]
        public async Task StartupRecoversLoggingValuesAndOwnershipFromInterruptedApply()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string previous = """{"schemaVersion":1,"logging":{"retentionDays":180}}""";
            string revision = (await PreviewAsync(server, previous)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, previous, revision));

            const string candidate = """{"schemaVersion":1,"logging":{"retentionDays":90,"noStackTrace":true}}""";
            revision = (await PreviewAsync(server, candidate)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, candidate, revision));
            Assert.True((await server.GetSettingsAsync()).GetProperty("noStackTrace").GetBoolean());

            // Simulate interruption after replacing the config and before retiring the journal.
            string journal = Path.Combine(server.ConfigurationDirectory, ".manifest-pending");
            Directory.Move(Path.Combine(server.ConfigurationDirectory, ".manifest-staging"), journal);

            await server.RestartAsync();
            JsonElement restored = await server.GetSettingsAsync();
            Assert.Equal(180, restored.GetProperty("maxLogFileDays").GetInt32());
            Assert.False(restored.GetProperty("noStackTrace").GetBoolean());
            Assert.Equal("/logging/retentionDays", Assert.Single(restored.GetProperty("managedSettings").EnumerateArray()).GetString());
            Assert.False(Directory.Exists(journal));
        }

        [Fact]
        public async Task StartupRecoversCreatedUpdatedAndDeletedDhcpScopeFiles()
        {
            await using var server = await LoopbackWebService.StartAsync();
            await SetScopeAsync("Updated", 10, 30);
            await SetScopeAsync("Deleted", 40, 60);

            string scopes = Path.Combine(server.ConfigurationDirectory, "scopes");
            byte[] updated = await File.ReadAllBytesAsync(Path.Combine(scopes, "Updated.scope"));
            byte[] deleted = await File.ReadAllBytesAsync(Path.Combine(scopes, "Deleted.scope"));

            await SetScopeAsync("Updated", 10, 35);
            LoopbackWebService.AssertOk(await server.CallAsync("dhcp/scopes/delete?name=Deleted", server.AdminToken));
            await SetScopeAsync("Created", 70, 90);

            string journal = Path.Combine(server.ConfigurationDirectory, ".manifest-pending");
            string updatedEntry = Directory.CreateDirectory(Path.Combine(journal, "scopes", "Updated.scope")).FullName;
            string deletedEntry = Directory.CreateDirectory(Path.Combine(journal, "scopes", "Deleted.scope")).FullName;
            Directory.CreateDirectory(Path.Combine(journal, "scopes", "Created.scope"));
            await File.WriteAllBytesAsync(Path.Combine(updatedEntry, "previous"), updated);
            await File.WriteAllBytesAsync(Path.Combine(deletedEntry, "previous"), deleted);

            await server.RestartAsync();

            JsonElement result = await server.CallAsync("dhcp/scopes/list", server.AdminToken);
            LoopbackWebService.AssertOk(result);
            JsonElement configured = result.GetProperty("response").GetProperty("scopes");
            JsonElement restored = Assert.Single(configured.EnumerateArray(), scope => scope.GetProperty("name").ValueEquals("Updated"));
            Assert.Equal("192.0.2.30", restored.GetProperty("endingAddress").GetString());
            Assert.Contains(configured.EnumerateArray(), scope => scope.GetProperty("name").ValueEquals("Deleted"));
            Assert.DoesNotContain(configured.EnumerateArray(), scope => scope.GetProperty("name").ValueEquals("Created"));
            Assert.False(File.Exists(Path.Combine(scopes, "Created.scope")));
            Assert.False(Directory.Exists(journal));

            async Task SetScopeAsync(string name, int start, int end)
            {
                LoopbackWebService.AssertOk(await server.CallAsync(
                    $"dhcp/scopes/set?name={name}&startingAddress=192.0.2.{start}&endingAddress=192.0.2.{end}&subnetMask=255.255.255.0",
                    server.AdminToken));
                LoopbackWebService.AssertOk(await server.CallAsync("dhcp/scopes/disable?name=" + name, server.AdminToken));
            }
        }

        [Fact]
        public async Task StartupRecoversZoneFilesAndPermissionsFromInterruptedApply()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=previous.test&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/records/add?zone=previous.test&domain=www.previous.test&type=A&ipAddress=192.0.2.31", server.AdminToken));
            await server.RestartAsync();

            string zoneDirectory = Path.Combine(server.ConfigurationDirectory, "zones");
            byte[] previousZone = await File.ReadAllBytesAsync(Path.Combine(zoneDirectory, "previous.test.zone"));
            byte[] previousPermissions = await File.ReadAllBytesAsync(Path.Combine(server.ConfigurationDirectory, "auth.config"));

            LoopbackWebService.AssertOk(await server.CallAsync("zones/delete?zone=previous.test", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=candidate.test&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/records/add?zone=candidate.test&domain=www.candidate.test&type=A&ipAddress=192.0.2.32", server.AdminToken));
            await server.RestartAsync();
            Assert.Single((await server.QueryAsync("www.candidate.test", DnsResourceRecordType.A)).Answer);

            // A pending journal has an empty entry for a target that did not previously exist.
            string journal = Path.Combine(server.ConfigurationDirectory, ".manifest-pending");
            string previousEntry = Directory.CreateDirectory(Path.Combine(journal, "zones", "previous.test.zone")).FullName;
            Directory.CreateDirectory(Path.Combine(journal, "zones", "candidate.test.zone"));
            await File.WriteAllBytesAsync(Path.Combine(previousEntry, "previous"), previousZone);
            string permissionsEntry = Directory.CreateDirectory(Path.Combine(journal, "auth.config")).FullName;
            await File.WriteAllBytesAsync(Path.Combine(permissionsEntry, "previous"), previousPermissions);

            await server.RestartAsync();
            DnsResourceRecord restored = Assert.Single((await server.QueryAsync("www.previous.test", DnsResourceRecordType.A)).Answer);
            Assert.Equal(IPAddress.Parse("192.0.2.31"), Assert.IsType<DnsARecordData>(restored.RDATA).Address);
            Assert.Empty((await server.QueryAsync("www.candidate.test", DnsResourceRecordType.A)).Answer);
            Assert.False(File.Exists(Path.Combine(zoneDirectory, "candidate.test.zone")));
            Assert.False(Directory.Exists(journal));

            JsonElement permissions = await server.CallAsync("zones/permissions/get?zone=previous.test", server.AdminToken);
            LoopbackWebService.AssertOk(permissions);
            JsonElement creator = Assert.Single(permissions.GetProperty("response").GetProperty("userPermissions").EnumerateArray());
            Assert.Equal("admin", creator.GetProperty("username").GetString());
            Assert.True(creator.GetProperty("canDelete").GetBoolean());

            await server.RestartAsync();
            Assert.Single((await server.QueryAsync("www.previous.test", DnsResourceRecordType.A)).Answer);
        }

        [Fact]
        public async Task InvalidStartupTlsManifestLeavesPreviousLoggingConfigurationIntact()
        {
            await using var server = await LoopbackWebService.StartAsync();
            string manifest = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);
            await File.WriteAllTextAsync(manifest, """{"schemaVersion":1,"logging":{"retentionDays":180},"web":{"tlsEnabled":true}}""");

            InvalidDataException error = await Assert.ThrowsAsync<InvalidDataException>(server.RestartAsync);
            Assert.Contains("/web", error.Message);

            File.Delete(manifest);
            await server.RestartAsync();
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(365, current.GetProperty("maxLogFileDays").GetInt32());
            Assert.Empty(current.GetProperty("managedSettings").EnumerateArray());
        }

        [Fact]
        public async Task OwnershipSurvivesRestartAndRejectsMixedEditsUntilReleased()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """{"schemaVersion":1,"logging":{"retentionDays":365}}""";
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            Assert.NotEqual(revision, (await PreviewAsync(server, manifest)).GetProperty("revision").GetString());
            await server.RestartAsync();

            JsonElement settings = await server.GetSettingsAsync();
            Assert.Equal("/logging/retentionDays", Assert.Single(settings.GetProperty("managedSettings").EnumerateArray()).GetString());
            int originalTtl = settings.GetProperty("defaultRecordTtl").GetInt32();
            JsonElement rejected = await server.CallAsync("settings/set?defaultRecordTtl=123&maxLogFileDays=180", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/logging/retentionDays", rejected.GetProperty("errorMessage").GetString());
            Assert.Equal(originalTtl, (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?defaultRecordTtl=123&maxLogFileDays=365", server.AdminToken));

            const string unmanaged = """{"schemaVersion":1}""";
            string releaseRevision = (await PreviewAsync(server, unmanaged)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, unmanaged, releaseRevision));
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?maxLogFileDays=180", server.AdminToken));
            Assert.Empty((await server.GetSettingsAsync()).GetProperty("managedSettings").EnumerateArray());
        }

        [Fact]
        public async Task BackupRestoreCannotReplaceAManagedLoggingValue()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?logSettings=true&dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] bytes = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """{"schemaVersion":1,"logging":{"retentionDays":180}}""";
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, revision));
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?defaultRecordTtl=123", server.AdminToken));

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(bytes), "file", "backup.zip");
            JsonElement rejected = await server.CallAsync("settings/restore?logSettings=true&dnsSettings=true", server.AdminToken, form);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/logging/retentionDays", rejected.GetProperty("errorMessage").GetString());
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(180, current.GetProperty("maxLogFileDays").GetInt32());
            Assert.Equal(123, current.GetProperty("defaultRecordTtl").GetInt32());
        }

        [Fact]
        public async Task ApplyRestoresDnsAndLoggingWhenSecondStoreFails()
        {
            await using var server = await LoopbackWebService.StartAsync();
            JsonNode candidate = JsonNode.Parse(ListenerManifest(LoopbackDnsServer.GetLoopbackEndPoint()))!;
            candidate["logging"]!["logQueries"] = true;
            candidate["dns"]!["proxy"] = JsonNode.Parse("""{"type":"Http","address":"127.0.0.1","port":8080}""");
            string manifest = candidate.ToJsonString();
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            string stagingPath = Path.Combine(server.ConfigurationDirectory, "log.tmp");
            Directory.CreateDirectory(stagingPath);

            JsonElement rejected = await ApplyAsync(server, manifest, revision);

            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("persist", rejected.GetProperty("errorMessage").GetString());
            await server.QueryAsync("example.invalid", DnsResourceRecordType.A);
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(365, current.GetProperty("maxLogFileDays").GetInt32());
            Assert.False(current.GetProperty("noStackTrace").GetBoolean());
            Assert.False(current.GetProperty("logQueries").GetBoolean());
            Assert.Equal(JsonValueKind.Null, current.GetProperty("proxy").ValueKind);

            Directory.Delete(stagingPath);
            await server.RestartAsync();
            await server.QueryAsync("example.invalid", DnsResourceRecordType.A);
            JsonElement restored = await server.GetSettingsAsync();
            Assert.Equal(365, restored.GetProperty("maxLogFileDays").GetInt32());
            Assert.False(restored.GetProperty("logQueries").GetBoolean());
            Assert.Equal(JsonValueKind.Null, restored.GetProperty("proxy").ValueKind);
            Assert.Empty(restored.GetProperty("managedSettings").EnumerateArray());
        }

        [Fact]
        public async Task ExportIsStableAndRoundTripsThroughThePreview()
        {
            await using var server = await LoopbackWebService.StartAsync();
            JsonElement current = await server.GetSettingsAsync();
            JsonObject snapshot = JsonNode.Parse(current.GetRawText())!.AsObject();
            snapshot["blockListUrls"] = new JsonArray("https://example.test/list?token=fixture-secret");
            snapshot["proxy"] = new JsonObject { ["type"] = "None", ["password"] = "fixture-secret" };

            string exported = ConfigurationPlan.Export(JsonSerializer.SerializeToElement(snapshot)).ToJsonString();
            Assert.Equal(ConfigurationPlan.Export(current).ToJsonString(), exported);
            Assert.DoesNotContain("fixture-secret", exported);
            Assert.False(JsonNode.Parse(exported)!["blocklists"]!.AsObject().ContainsKey("sources"));
            Assert.Empty(ConfigurationPlan.Create(Load(exported), current));

            snapshot["webServiceLocalAddresses"] = new JsonArray("[::1]");
            string ipv6Export = ConfigurationPlan.Export(JsonSerializer.SerializeToElement(snapshot)).ToJsonString();
            ConfigurationManifest ipv6Manifest = Load(ipv6Export);
            Assert.Equal("::1", ipv6Manifest.Settings.GetProperty("web").GetProperty("localAddresses")[0].GetString());
        }

        [Fact]
        public async Task ZoneExportReproducesPoliciesAndRecordsOnAnotherInstance()
        {
            await using var source = await LoopbackWebService.StartAsync();
            const string manifest = """
                {"schemaVersion":1,"zones":{"migration.test":{"type":"Primary",
                    "transfer":{"mode":"Deny"},
                    "records":[
                      {"owner":"www.migration.test","type":"A","ttl":600,"comments":"fixture","data":{"zoneFile":"192.0.2.42"}},
                      {"owner":"@","type":"SOA","ttl":120,"useSerialDateScheme":true,
                        "data":{"zoneFile":"ns.migration.test. hostmaster.migration.test. 0 3600 600 86400 120"}}
                    ]
                }}}
                """;
            string revision = (await PreviewAsync(source, manifest)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(source, manifest, revision));
            LoopbackWebService.AssertOk(await source.CallAsync("zones/create?zone=expiring.test&type=Primary", source.AdminToken));
            LoopbackWebService.AssertOk(await source.CallAsync(
                "zones/records/add?zone=expiring.test&domain=www.expiring.test&type=A&ipAddress=192.0.2.43&ttl=60&expiryTtl=3600",
                source.AdminToken));

            JsonElement export = await source.CallAsync("settings/config/export", source.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement response = export.GetProperty("response");
            JsonElement zones = response.GetProperty("manifest").GetProperty("zones");
            Assert.DoesNotContain(response.GetProperty("missingInputs").EnumerateArray(), entry => entry.ValueEquals("/zones/expiring.test/records"));
            JsonElement expiring = Assert.Single(zones.GetProperty("expiring.test").GetProperty("records").EnumerateArray(),
                entry => entry.GetProperty("type").GetInt32() == (int)DnsResourceRecordType.A);
            Assert.Equal(3600u, expiring.GetProperty("expiryTtl").GetUInt32());
            JsonElement zone = zones.GetProperty("migration.test");
            Assert.Equal("Deny", zone.GetProperty("transfer").GetProperty("mode").GetString());
            JsonElement record = Assert.Single(zone.GetProperty("records").EnumerateArray(),
                entry => entry.GetProperty("type").GetInt32() == (int)DnsResourceRecordType.A);
            Assert.Equal("C000022A", record.GetProperty("data").GetProperty("rawHex").GetString());
            Assert.Equal("fixture", record.GetProperty("comments").GetString());

            using var user = new FormUrlEncodedContent([new("user", "zone-viewer"), new("pass", "fixture-password")]);
            LoopbackWebService.AssertOk(await source.CallAsync("admin/users/create", source.AdminToken, user));
            LoopbackWebService.AssertOk(await source.CallAsync(
                "admin/permissions/set?section=Settings&userPermissions=zone-viewer%7Ctrue%7Cfalse%7Cfalse", source.AdminToken));
            LoopbackWebService.AssertOk(await source.CallAsync(
                "zones/permissions/set?zone=migration.test&userPermissions=zone-viewer%7Ctrue%7Cfalse%7Cfalse", source.AdminToken));
            string viewerToken = await source.LoginAsync("zone-viewer", "fixture-password");
            JsonElement restricted = await source.CallAsync("settings/config/export", viewerToken);
            LoopbackWebService.AssertOk(restricted);
            Assert.Contains("migration.test", restricted.GetRawText());
            Assert.DoesNotContain("expiring.test", restricted.GetRawText());

            await using var destination = await LoopbackWebService.StartAsync();
            string exported = $$"""{"schemaVersion":1,"zones":{"migration.test":{{zone.GetRawText()}} } }""";
            revision = (await PreviewAsync(destination, exported)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(destination, exported, revision));
            await destination.RestartAsync();
            DnsResourceRecord answer = Assert.Single((await destination.QueryAsync("www.migration.test", DnsResourceRecordType.A)).Answer);
            Assert.Equal(IPAddress.Parse("192.0.2.42"), Assert.IsType<DnsARecordData>(answer.RDATA).Address);
            Assert.Equal(600u, answer.OriginalTtlValue);
            DnsResourceRecord soaRecord = Assert.Single((await destination.QueryAsync("migration.test", DnsResourceRecordType.SOA)).Answer);
            var soa = Assert.IsType<DnsSOARecordData>(soaRecord.RDATA);
            Assert.Equal("ns.migration.test", soa.PrimaryNameServer);
            Assert.Equal("hostmaster@migration.test", soa.ResponsiblePerson);
            Assert.Equal(3600u, soa.Refresh);
            Assert.Equal(600u, soa.Retry);
            Assert.Equal(86400u, soa.Expire);
            Assert.Equal(120u, soa.Minimum);
            Assert.Equal(120u, soaRecord.OriginalTtlValue);
            Assert.True(Assert.Single(zone.GetProperty("records").EnumerateArray(),
                entry => entry.GetProperty("type").GetInt32() == (int)DnsResourceRecordType.SOA).GetProperty("useSerialDateScheme").GetBoolean());
            Assert.Empty((await PreviewAsync(destination, exported)).GetProperty("changes").EnumerateArray());
            JsonElement repeat = await destination.CallAsync("settings/config/export", destination.AdminToken);
            LoopbackWebService.AssertOk(repeat);
            Assert.Equal(zone.GetRawText(), repeat.GetProperty("response").GetProperty("manifest").GetProperty("zones")
                .GetProperty("migration.test").GetRawText());
        }

        [Fact]
        public async Task ApplicableExportReproducesSettingsOnACleanInstance()
        {
            IPEndPoint endpoint;
            string exported;
            int httpPort;
            await using (var source = await LoopbackWebService.StartAsync())
            {
                LoopbackWebService.AssertOk(await source.CallAsync(
                    "settings/set?maxLogFileDays=180&noStackTrace=true&useLocalTime=true&logFolder=archive&enableInMemoryStats=true&maxStatFileDays=120", source.AdminToken));
                JsonElement settings = await source.GetSettingsAsync();
                httpPort = settings.GetProperty("webServiceHttpPort").GetInt32();
                endpoint = IPEndPoint.Parse(settings.GetProperty("dnsServerLocalEndPoints")[0].GetString()!);
                exported = ConfigurationPlan.Export(settings, includePreviewOnly: false).ToJsonString();
            }

            await using var destination = await LoopbackWebService.StartAsync();
            string revision = (await PreviewAsync(destination, exported)).GetProperty("revision").GetString()!;
            JsonElement queued = await ApplyAsync(destination, exported, revision);
            LoopbackWebService.AssertOk(queued);
            if (queued.GetProperty("response").TryGetProperty("operationId", out JsonElement operation))
                Assert.Equal("applied", await WaitForWebApplyAsync(httpPort, destination.AdminToken, operation.GetString()!));

            await destination.RestartAsync(httpPort);
            await AssertListenerAnswersAsync(endpoint);
            JsonElement applied = await destination.GetSettingsAsync();
            Assert.Equal(exported, ConfigurationPlan.Export(applied, includePreviewOnly: false).ToJsonString());

            JsonElement preview = await PreviewAsync(destination, exported);
            Assert.Empty(preview.GetProperty("changes").EnumerateArray());
            string unchangedRevision = preview.GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(destination, exported, unchangedRevision));
            Assert.Equal(unchangedRevision, (await PreviewAsync(destination, exported)).GetProperty("revision").GetString());
        }

        [Fact]
        public void PreviewNormalizesSourcesAndResetsOptionalValues()
        {
            ConfigurationManifest manifest = Load("""
                {"schemaVersion":1,"blocklists":{"sources":["https://example.test/list","https://example.test/list"]},
                 "dns":{"authoritative":{"defaultResponsiblePerson":null}}}
                """);
            using var snapshot = JsonDocument.Parse("""
                {"blockListUrls":["https://example.test/list"],"defaultResponsiblePerson":"ops@example.test"}
                """);

            Assert.Equal(new ConfigurationChange("/dns/authoritative/defaultResponsiblePerson", ConfigurationChangeKind.Remove, false),
                Assert.Single(ConfigurationPlan.Create(manifest, snapshot.RootElement)));
        }

        [Theory]
        [InlineData("""{"schemaVersion":1,"zones":{"example.test":{}}}""", "/zones")]
        [InlineData("""{"schemaVersion":1,"blocklists":{"sources":["bad address"]}}""", "/blocklists/sources")]
        public void PreviewRejectsUnsupportedOrInvalidSettings(string json, string path)
        {
            using var snapshot = JsonDocument.Parse("""{"blockListUrls":[]}""");

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationPlan.Create(Load(json), snapshot.RootElement));

            Assert.Contains(path, error.Message);
            Assert.DoesNotContain("bad address", error.Message);
        }

        private ConfigurationManifest Load(string json)
        {
            string path = Path.Combine(_directory.FullName, ConfigurationManifest.DefaultFileName);
            File.WriteAllText(path, json);
            return ConfigurationManifest.Load(path);
        }

        public void Dispose()
        {
            _directory.Delete(recursive: true);
        }
    }
}
