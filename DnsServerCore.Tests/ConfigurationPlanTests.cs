using DnsServerCore.Configuration;
using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.Http.Headers;
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
        public async Task LegacyCombinedBackupChecksManagedDnsSettingsBeforeChangingSettings(bool preserveListener, string conflictPath)
        {
            await using var server = await LoopbackWebService.StartAsync();
            JsonElement settings = await server.GetSettingsAsync();
            IPEndPoint current = IPEndPoint.Parse(settings.GetProperty("dnsServerLocalEndPoints")[0].GetString()!);
            string manifest = JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                dns = new { localEndpoints = new[] { current.ToString() }, authoritative = new { defaultRecordTtl = 600 } }
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
                writer.Write(3600u); // default record TTL
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
        public async Task AuthoritativeTtlDefaultsPersistAndRejectConflictingWrites()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            byte[] original = await backup.Content.ReadAsByteArrayAsync();

            const string manifest = """
                {"schemaVersion":1,"dns":{"authoritative":{"defaultRecordTtl":600,"defaultNsRecordTtl":7200,"defaultSoaRecordTtl":null}}}
                """;
            JsonElement preview = await PreviewAsync(server, manifest);
            Assert.Equal(2, preview.GetProperty("changes").GetArrayLength());
            LoopbackWebService.AssertOk(await ApplyAsync(server, manifest, preview.GetProperty("revision").GetString()!));

            await server.RestartAsync();
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(600u, current.GetProperty("defaultRecordTtl").GetUInt32());
            Assert.Equal(7200u, current.GetProperty("defaultNsRecordTtl").GetUInt32());
            Assert.Equal(900u, current.GetProperty("defaultSoaRecordTtl").GetUInt32());
            Assert.Equal(3, current.GetProperty("managedSettings").GetArrayLength());
            Assert.Empty((await PreviewAsync(server, manifest)).GetProperty("changes").EnumerateArray());

            JsonElement rejected = await server.CallAsync("settings/set?defaultRecordTtl=601&maxLogFileDays=180", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/dns/authoritative/defaultRecordTtl", rejected.GetProperty("errorMessage").GetString());

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
        public async Task UnsupportedStartupManifestLeavesThePreviousLoggingConfigurationIntact()
        {
            await using var server = await LoopbackWebService.StartAsync();
            string manifest = Path.Combine(server.ConfigurationDirectory, ConfigurationManifest.DefaultFileName);
            await File.WriteAllTextAsync(manifest, """{"schemaVersion":1,"logging":{"retentionDays":180},"web":{"httpPort":1}}""");

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
            string manifest = ListenerManifest(LoopbackDnsServer.GetLoopbackEndPoint());
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

            Directory.Delete(stagingPath);
            await server.RestartAsync();
            await server.QueryAsync("example.invalid", DnsResourceRecordType.A);
            JsonElement restored = await server.GetSettingsAsync();
            Assert.Equal(365, restored.GetProperty("maxLogFileDays").GetInt32());
            Assert.Empty(restored.GetProperty("managedSettings").EnumerateArray());
        }

        [Fact]
        public async Task ExportIsStableAndRoundTripsThroughThePreview()
        {
            await using var server = await LoopbackWebService.StartAsync();
            JsonElement current = await server.GetSettingsAsync();
            JsonObject snapshot = JsonNode.Parse(current.GetRawText())!.AsObject();
            snapshot["blockListUrls"] = new JsonArray("https://example.test/list?token=fixture-secret");
            snapshot["proxy"] = new JsonObject { ["password"] = "fixture-secret" };

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
            await using (var source = await LoopbackWebService.StartAsync())
            {
                LoopbackWebService.AssertOk(await source.CallAsync(
                    "settings/set?maxLogFileDays=180&noStackTrace=true&useLocalTime=true&logFolder=archive", source.AdminToken));
                JsonElement settings = await source.GetSettingsAsync();
                endpoint = IPEndPoint.Parse(settings.GetProperty("dnsServerLocalEndPoints")[0].GetString()!);
                exported = ConfigurationPlan.Export(settings, includePreviewOnly: false).ToJsonString();
            }

            await using var destination = await LoopbackWebService.StartAsync();
            string revision = (await PreviewAsync(destination, exported)).GetProperty("revision").GetString()!;
            LoopbackWebService.AssertOk(await ApplyAsync(destination, exported, revision));

            await destination.RestartAsync();
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
            ConfigurationManifest manifest = Load(json);
            using var snapshot = JsonDocument.Parse("""{"blockListUrls":[]}""");

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationPlan.Create(manifest, snapshot.RootElement));

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
