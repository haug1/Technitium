using DnsServerCore.Configuration;
using System;
using System.IO;
using System.IO.Compression;
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
                entry => Assert.Equal("/dns/forwarding/servers", entry.GetString()),
                entry => Assert.Equal("/dns/proxy/password", entry.GetString()),
                entry => Assert.Equal("/dns/tsigKeys/migration-key.test/secret", entry.GetString()));
            JsonElement manifest = response.GetProperty("manifest");
            Assert.Equal(ConfigurationManifest.CurrentSchemaVersion, manifest.GetProperty("schemaVersion").GetInt32());
            Assert.Equal(ConfigurationPlan.Export(legacy, includePreviewOnly: false).ToJsonString(), manifest.GetRawText());
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
                    "exclusionAddresses":[]
                }}}
                """);

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationPlan.Create(manifest, snapshot.RootElement));

            Assert.Contains("/dhcp/scopes/Lab/reservations/" + key, error.Message);
            Assert.Contains(reason, error.Message);
            Assert.DoesNotContain("192.0.2.", error.Message);
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

        [Fact]
        public async Task ZoneRecordPreviewTracksRecordChangesWithoutMutatingDns()
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

            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/records/add?zone=records.test&domain=new.records.test&type=A&ipAddress=192.0.2.11", server.AdminToken));
            JsonElement after = await PreviewAsync(server, manifest);
            Assert.NotEqual(preview.GetProperty("revision").GetString(), after.GetProperty("revision").GetString());
            Assert.Equal("Update", Assert.Single(after.GetProperty("changes").EnumerateArray()).GetProperty("kind").GetString());

            const string emptyRecords = """{"schemaVersion":1,"zones":{"records.test":{"records":[]}}}""";
            using var content = new StringContent(emptyRecords, Encoding.UTF8, "application/json");
            JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, content);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/zones/records.test/records", rejected.GetProperty("errorMessage").GetString());
            Assert.DoesNotContain("192.0.2.", rejected.GetRawText());
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
