using DnsServerCore.Configuration;
using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
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
        public async Task ApplyRestoresLiveLoggingSettingsWhenPersistenceFails()
        {
            await using var server = await LoopbackWebService.StartAsync();
            const string manifest = """{"schemaVersion":1,"logging":{"retentionDays":180,"noStackTrace":true}}""";
            string revision = (await PreviewAsync(server, manifest)).GetProperty("revision").GetString()!;
            string stagingPath = Path.Combine(server.ConfigurationDirectory, "log.tmp");
            Directory.CreateDirectory(stagingPath);

            JsonElement rejected = await ApplyAsync(server, manifest, revision);

            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("persist", rejected.GetProperty("errorMessage").GetString());
            JsonElement current = await server.GetSettingsAsync();
            Assert.Equal(365, current.GetProperty("maxLogFileDays").GetInt32());
            Assert.False(current.GetProperty("noStackTrace").GetBoolean());

            Directory.Delete(stagingPath);
            await server.RestartAsync();
            JsonElement restored = await server.GetSettingsAsync();
            Assert.Equal(365, restored.GetProperty("maxLogFileDays").GetInt32());
            Assert.False(restored.GetProperty("noStackTrace").GetBoolean());
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
