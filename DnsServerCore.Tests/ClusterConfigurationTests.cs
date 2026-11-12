using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using DnsServerCore.HttpApi;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    [Collection("Web service")]
    public sealed class ClusterConfigurationTests
    {
        [Fact]
        public async Task LivePrimaryBootstrapRequiresFreshPreviewAndRollsBackFailedWrites()
        {
            const string manifest = """
                {"schemaVersion":1,"cluster":{"domain":"cluster.test","bootstrap":{"role":"Primary"},
                  "node":{"addresses":["127.0.0.1","192.0.2.10"]},"configRefreshSeconds":120}}
                """;
            await using var server = await LoopbackWebService.StartAsync("primary.test", enableTls: true);
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=2.0.192.in-addr.arpa&type=Primary", server.AdminToken));
            string revision = await PreviewAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?defaultRecordTtl=180", server.AdminToken));
            JsonElement stale = await ApplyAsync(revision);
            Assert.Equal("error", stale.GetProperty("status").GetString());
            Assert.Contains("stale", stale.GetProperty("errorMessage").GetString());

            string blocked = Path.Combine(server.ConfigurationDirectory, "cluster-ownership.config.tmp");
            Directory.CreateDirectory(blocked);
            JsonElement rejected = await ApplyAsync(await PreviewAsync());
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            JsonElement state = await server.CallAsync("admin/cluster/state", server.AdminToken);
            LoopbackWebService.AssertOk(state);
            Assert.False(state.GetProperty("response").GetProperty("clusterInitialized").GetBoolean());
            Assert.Equal("primary.test", state.GetProperty("response").GetProperty("dnsServerDomain").GetString());
            Assert.False(File.Exists(Path.Combine(server.ConfigurationDirectory, "cluster.config")));

            Assert.DoesNotContain((await server.QueryAsync("10.2.0.192.in-addr.arpa", DnsResourceRecordType.PTR)).Answer,
                record => record.Type == DnsResourceRecordType.PTR);
            Directory.Delete(blocked);
            LoopbackWebService.AssertOk(await ApplyAsync(await PreviewAsync()));
            state = await server.CallAsync("admin/cluster/state", server.AdminToken);
            LoopbackWebService.AssertOk(state);
            Assert.Equal("cluster.test", state.GetProperty("response").GetProperty("clusterDomain").GetString());
            Assert.Equal(120, state.GetProperty("response").GetProperty("configRefreshIntervalSeconds").GetInt32());

            Assert.Contains((await server.QueryAsync("10.2.0.192.in-addr.arpa", DnsResourceRecordType.PTR)).Answer,
                record => record.Type == DnsResourceRecordType.PTR);
            using var repeatBody = new StringContent(manifest, Encoding.UTF8, "application/json");
            JsonElement repeat = await server.CallAsync("settings/config/plan", server.AdminToken, repeatBody);
            LoopbackWebService.AssertOk(repeat);
            Assert.Empty(repeat.GetProperty("response").GetProperty("changes").EnumerateArray());

            async Task<string> PreviewAsync()
            {
                using var body = new StringContent(manifest, Encoding.UTF8, "application/json");
                JsonElement preview = await server.CallAsync("settings/config/plan", server.AdminToken, body);
                LoopbackWebService.AssertOk(preview);
                JsonElement plan = preview.GetProperty("response");
                Assert.Contains(plan.GetProperty("changes").EnumerateArray(), change =>
                    change.GetProperty("path").ValueEquals("/cluster/bootstrap") && change.GetProperty("kind").ValueEquals("Add"));
                return plan.GetProperty("revision").GetString()!;
            }

            async Task<JsonElement> ApplyAsync(string revision)
            {
                using var body = new StringContent(manifest, Encoding.UTF8, "application/json");
                return await server.CallAsync("settings/config/apply", server.AdminToken, body, revision);
            }
        }

        [Fact]
        public async Task StartupManifestInitializesPrimaryOnceAndPersistsOwnedOptions()
        {
            const string manifest = """
                {"schemaVersion":1,"cluster":{"domain":"cluster.test","bootstrap":{"role":"Primary"},
                  "node":{"addresses":["127.0.0.1"]},"configRefreshSeconds":120}}
                """;
            await using var server = await LoopbackWebService.StartAsync("primary.cluster.test", enableTls: true, startupManifest: manifest);
            JsonElement first = await ReadStateAsync();
            Assert.Equal("cluster.test", first.GetProperty("clusterDomain").GetString());
            Assert.Equal(120, first.GetProperty("configRefreshIntervalSeconds").GetInt32());
            Assert.Contains(first.GetProperty("managedOptionPaths").EnumerateArray(), path => path.ValueEquals("/cluster/configRefreshSeconds"));
            Assert.Contains(first.GetProperty("managedOptionPaths").EnumerateArray(), path => path.ValueEquals("/cluster/node/addresses"));
            JsonElement originalNode = Assert.Single(first.GetProperty("clusterNodes").EnumerateArray());
            Assert.Equal("Primary", originalNode.GetProperty("type").GetString());
            Assert.True(File.Exists(Path.Combine(server.ConfigurationDirectory, "zones", "cluster.test.zone")));
            Assert.True(File.Exists(Path.Combine(server.ConfigurationDirectory, "zones", "cluster-catalog.cluster.test.zone")));

            await server.RestartAsync();
            JsonElement second = await ReadStateAsync();
            Assert.Equal(originalNode.GetProperty("id").GetInt32(), Assert.Single(second.GetProperty("clusterNodes").EnumerateArray()).GetProperty("id").GetInt32());
            Assert.Equal(120, second.GetProperty("configRefreshIntervalSeconds").GetInt32());

            JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement cluster = export.GetProperty("response").GetProperty("manifest").GetProperty("cluster");
            Assert.Equal("Primary", cluster.GetProperty("bootstrap").GetProperty("role").GetString());
            string bootstrapManifest = JsonSerializer.Serialize(new { schemaVersion = 1, cluster });
            await using var restored = await LoopbackWebService.StartAsync("restored.cluster.test", enableTls: true, startupManifest: bootstrapManifest);
            JsonElement restoredExport = await restored.CallAsync("settings/config/export", restored.AdminToken);
            LoopbackWebService.AssertOk(restoredExport);
            Assert.True(JsonElement.DeepEquals(cluster, restoredExport.GetProperty("response").GetProperty("manifest").GetProperty("cluster")));

            async Task<JsonElement> ReadStateAsync()
            {
                JsonElement state = await server.CallAsync("admin/cluster/state", server.AdminToken);
                LoopbackWebService.AssertOk(state);
                return state.GetProperty("response");
            }
        }

        [Fact]
        public async Task PrimaryAddressApplyUpdatesDnsRecordsAndRollsBackOnWriteFailure()
        {
            await using var server = await LoopbackWebService.StartAsync("primary.cluster.test", enableTls: true);
            LoopbackWebService.AssertOk(await server.CallAsync(
                "admin/cluster/init?clusterDomain=cluster.test&primaryNodeIpAddresses=127.0.0.1", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=2.0.192.in-addr.arpa&type=Primary", server.AdminToken));

            const string manifest = """{"schemaVersion":1,"cluster":{"node":{"addresses":["127.0.0.1","192.0.2.10"]}}}""";
            string blockedFile = Path.Combine(server.ConfigurationDirectory, "cluster.tmp");
            Directory.CreateDirectory(blockedFile);
            JsonElement rejected = await ApplyAddressesAsync();
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            var originalAnswer = (await server.QueryAsync("primary.cluster.test", DnsResourceRecordType.A)).Answer;
            Assert.Contains(originalAnswer, record => record.RDATA.ToString() == "127.0.0.1");
            Assert.DoesNotContain(originalAnswer, record => record.RDATA.ToString() == "192.0.2.10");
            Assert.DoesNotContain((await server.QueryAsync("10.2.0.192.in-addr.arpa", DnsResourceRecordType.PTR)).Answer,
                record => record.Type == DnsResourceRecordType.PTR);

            Directory.Delete(blockedFile);
            LoopbackWebService.AssertOk(await ApplyAddressesAsync());
            Assert.Contains((await server.QueryAsync("primary.cluster.test", DnsResourceRecordType.A)).Answer,
                record => record.RDATA.ToString() == "192.0.2.10");
            Assert.Contains((await server.QueryAsync("10.2.0.192.in-addr.arpa", DnsResourceRecordType.PTR)).Answer,
                record => record.Type == DnsResourceRecordType.PTR);

            using var repeatBody = new StringContent(manifest, Encoding.UTF8, "application/json");
            JsonElement repeat = await server.CallAsync("settings/config/plan", server.AdminToken, repeatBody);
            LoopbackWebService.AssertOk(repeat);
            Assert.Empty(repeat.GetProperty("response").GetProperty("changes").EnumerateArray());

            JsonElement blocked = await server.CallAsync("admin/cluster/updateIpAddress?ipAddresses=127.0.0.1", server.AdminToken);
            Assert.Equal("error", blocked.GetProperty("status").GetString());
            Assert.Contains("/cluster/node/addresses", blocked.GetProperty("errorMessage").GetString());

            async Task<JsonElement> ApplyAddressesAsync()
            {
                using var previewBody = new StringContent(manifest, Encoding.UTF8, "application/json");
                JsonElement preview = await server.CallAsync("settings/config/plan", server.AdminToken, previewBody);
                LoopbackWebService.AssertOk(preview);
                Assert.Contains(preview.GetProperty("response").GetProperty("changes").EnumerateArray(),
                    change => change.GetProperty("path").ValueEquals("/cluster/node/addresses"));
                using var applyBody = new StringContent(manifest, Encoding.UTF8, "application/json");
                return await server.CallAsync("settings/config/apply", server.AdminToken, applyBody,
                    preview.GetProperty("response").GetProperty("revision").GetString());
            }
        }

        [Fact]
        public async Task FailedStartupBootstrapRestoresFilesAndCanBeRetried()
        {
            const string manifest = """
                {"schemaVersion":1,"cluster":{"domain":"cluster.test","bootstrap":{"role":"Primary"},
                  "node":{"addresses":["127.0.0.1"]},"configRefreshSeconds":120}}
                """;
            await using var server = await LoopbackWebService.StartAsync("primary.cluster.test", enableTls: true);
            string folder = server.ConfigurationDirectory;
            string blockedFile = Path.Combine(folder, "cluster-ownership.config.tmp");

            Exception failure = await Assert.ThrowsAnyAsync<Exception>(() => server.RestartAsync(null, () =>
            {
                File.WriteAllText(Path.Combine(folder, "technitium.json"), manifest);
                Directory.CreateDirectory(blockedFile);
            }));
            Assert.True(failure is IOException or UnauthorizedAccessException, failure.ToString());
            Assert.False(File.Exists(Path.Combine(folder, "cluster.config")));
            Assert.False(File.Exists(Path.Combine(folder, "zones", "cluster.test.zone")));
            Assert.False(File.Exists(Path.Combine(folder, "zones", "cluster-catalog.cluster.test.zone")));

            await server.RestartAsync(null, () => Directory.Delete(blockedFile));
            JsonElement state = await server.CallAsync("admin/cluster/state", server.AdminToken);
            LoopbackWebService.AssertOk(state);
            Assert.True(state.GetProperty("response").GetProperty("clusterInitialized").GetBoolean());
        }

        [Fact]
        public async Task PrimaryInitializationChecksBothClusterZonesBeforeEnablingTlsOrCreatingZones()
        {
            await using var server = await LoopbackWebService.StartAsync("primary.cluster.test");
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=cluster-catalog.cluster.test&type=Primary", server.AdminToken));

            JsonElement rejected = await server.CallAsync(
                "admin/cluster/init?clusterDomain=cluster.test&primaryNodeIpAddresses=127.0.0.1", server.AdminToken);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("cluster-catalog.cluster.test", rejected.GetProperty("errorMessage").GetString());
            JsonElement wildcard = await server.CallAsync(
                "admin/cluster/init?clusterDomain=*.test&primaryNodeIpAddresses=127.0.0.1", server.AdminToken);
            Assert.Equal("error", wildcard.GetProperty("status").GetString());
            Assert.Contains("wildcard", wildcard.GetProperty("errorMessage").GetString());
            Assert.False((await server.GetSettingsAsync()).GetProperty("webServiceEnableTls").GetBoolean());

            JsonElement state = await server.CallAsync("admin/cluster/state", server.AdminToken);
            LoopbackWebService.AssertOk(state);
            Assert.False(state.GetProperty("response").GetProperty("clusterInitialized").GetBoolean());
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=cluster.test&type=Primary", server.AdminToken));
        }

        [Fact]
        public async Task LiveSecondaryJoinRejectsChangedSecretsAndVerifiesPrimaryDomain()
        {
            await using var primary = await LoopbackWebService.StartAsync("primary.cluster.test", enableTls: true);
            await using var secondary = await LoopbackWebService.StartAsync("secondary.cluster.test", enableTls: true);
            JsonElement initialized = await primary.CallAsync(
                "admin/cluster/init?clusterDomain=cluster.test&primaryNodeIpAddresses=127.0.0.1", primary.AdminToken);
            LoopbackWebService.AssertOk(initialized);
            string primaryUrl = Assert.Single(initialized.GetProperty("response").GetProperty("clusterNodes").EnumerateArray())
                .GetProperty("url").GetString()!;
            const string secretName = "TECHNITIUM_TEST_LIVE_CLUSTER_JOIN";
            string? previousSecret = Environment.GetEnvironmentVariable(secretName);
            try
            {
                Environment.SetEnvironmentVariable(secretName, primary.AdminPassword);
                string manifest = Manifest("cluster.test");
                string revision = await PreviewAsync(manifest);
                Environment.SetEnvironmentVariable(secretName, "changed");
                JsonElement stale = await ApplyAsync(manifest, revision);
                Assert.Equal("error", stale.GetProperty("status").GetString());
                Assert.Contains("stale", stale.GetProperty("errorMessage").GetString());

                Environment.SetEnvironmentVariable(secretName, primary.AdminPassword);
                string wrongDomain = Manifest("wrong.test");
                JsonElement rejected = await ApplyAsync(wrongDomain, await PreviewAsync(wrongDomain));
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/cluster/domain", rejected.GetProperty("errorMessage").GetString());
                JsonElement state = await primary.CallAsync("admin/cluster/state", primary.AdminToken);
                LoopbackWebService.AssertOk(state);
                Assert.Single(state.GetProperty("response").GetProperty("clusterNodes").EnumerateArray());

                LoopbackWebService.AssertOk(await ApplyAsync(manifest, await PreviewAsync(manifest)));
                string token = await secondary.LoginAsync("admin", primary.AdminPassword);
                state = await secondary.CallAsync("admin/cluster/state", token);
                LoopbackWebService.AssertOk(state);
                Assert.Contains(state.GetProperty("response").GetProperty("clusterNodes").EnumerateArray(), node =>
                    node.GetProperty("state").ValueEquals("Self") && node.GetProperty("type").ValueEquals("Secondary"));
                Assert.Contains(state.GetProperty("response").GetProperty("managedOptionPaths").EnumerateArray(),
                    path => path.ValueEquals("/cluster/node/addresses"));
                Environment.SetEnvironmentVariable(secretName, null);
                using var repeatBody = new StringContent(manifest, Encoding.UTF8, "application/json");
                JsonElement repeat = await secondary.CallAsync("settings/config/plan", token, repeatBody);
                LoopbackWebService.AssertOk(repeat);
                Assert.Empty(repeat.GetProperty("response").GetProperty("changes").EnumerateArray());
            }
            finally
            {
                Environment.SetEnvironmentVariable(secretName, previousSecret);
            }

            string Manifest(string domain) => JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                cluster = new
                {
                    domain,
                    bootstrap = new
                    {
                        role = "Secondary", primaryUrl, primaryAddress = "127.0.0.1", username = "admin",
                        password = new { environment = secretName }, ignoreCertificateErrors = true
                    },
                    node = new { addresses = new[] { "127.0.0.1" } }
                }
            });

            async Task<string> PreviewAsync(string manifest)
            {
                using var body = new StringContent(manifest, Encoding.UTF8, "application/json");
                JsonElement preview = await secondary.CallAsync("settings/config/plan", secondary.AdminToken, body);
                LoopbackWebService.AssertOk(preview);
                JsonElement plan = preview.GetProperty("response");
                Assert.Contains(plan.GetProperty("changes").EnumerateArray(), change =>
                    change.GetProperty("path").ValueEquals("/cluster/bootstrap") && change.GetProperty("kind").ValueEquals("Add"));
                return plan.GetProperty("revision").GetString()!;
            }

            async Task<JsonElement> ApplyAsync(string manifest, string revision)
            {
                using var body = new StringContent(manifest, Encoding.UTF8, "application/json");
                return await secondary.CallAsync("settings/config/apply", secondary.AdminToken, body, revision);
            }
        }

        [Fact]
        public async Task StartupJoinChecksPrimaryDomainAndKeepsMembershipWithoutTheJoinSecret()
        {
            await using var primary = await LoopbackWebService.StartAsync("primary.cluster.test", enableTls: true);
            await using var secondary = await LoopbackWebService.StartAsync("secondary.cluster.test", enableTls: true, adminPassword: primary.AdminPassword);
            LoopbackWebService.AssertOk(await primary.CallAsync("settings/set?defaultRecordTtl=180", primary.AdminToken));
            JsonElement initialized = await primary.CallAsync(
                "admin/cluster/init?clusterDomain=cluster.test&primaryNodeIpAddresses=127.0.0.1", primary.AdminToken);
            LoopbackWebService.AssertOk(initialized);
            string primaryUrl = Assert.Single(initialized.GetProperty("response").GetProperty("clusterNodes").EnumerateArray())
                .GetProperty("url").GetString()!;
            string manifestFile = Path.Combine(secondary.ConfigurationDirectory, "technitium.json");
            string passwordFile = Path.Combine(secondary.ConfigurationDirectory, "join-password");

            InvalidDataException rejected = await Assert.ThrowsAsync<InvalidDataException>(() => secondary.RestartAsync(null, () =>
            {
                File.WriteAllText(passwordFile, primary.AdminPassword);
                WriteManifest("wrong.test");
            }));
            Assert.Contains("/cluster/domain", rejected.Message);
            Assert.False(File.Exists(Path.Combine(secondary.ConfigurationDirectory, "cluster.config")));
            JsonElement primaryState = await primary.CallAsync("admin/cluster/state", primary.AdminToken);
            LoopbackWebService.AssertOk(primaryState);
            Assert.Single(primaryState.GetProperty("response").GetProperty("clusterNodes").EnumerateArray());

            string blockedFile = Path.Combine(secondary.ConfigurationDirectory, "cluster-ownership.config.tmp");
            Exception failure = await Assert.ThrowsAnyAsync<Exception>(() => secondary.RestartAsync(null, () =>
            {
                WriteManifest("cluster.test");
                Directory.CreateDirectory(blockedFile);
            }));
            Assert.True(failure is IOException or UnauthorizedAccessException, failure.ToString());
            Assert.False(File.Exists(Path.Combine(secondary.ConfigurationDirectory, "cluster.config")));
            Assert.False(File.Exists(Path.Combine(secondary.ConfigurationDirectory, "zones", "cluster-catalog.cluster.test.zone")));
            primaryState = await primary.CallAsync("admin/cluster/state", primary.AdminToken);
            LoopbackWebService.AssertOk(primaryState);
            Assert.Single(primaryState.GetProperty("response").GetProperty("clusterNodes").EnumerateArray());

            await secondary.RestartAsync(null, () => Directory.Delete(blockedFile));
            JsonElement joined = await secondary.CallAsync("admin/cluster/state", secondary.AdminToken);
            LoopbackWebService.AssertOk(joined);
            Assert.Contains(joined.GetProperty("response").GetProperty("managedOptionPaths").EnumerateArray(),
                path => path.ValueEquals("/cluster/node/addresses"));
            int joinedId = await GetSecondaryIdAsync();
            Assert.Equal(180, (await secondary.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());

            await secondary.RestartAsync(null, () => File.Delete(passwordFile));
            Assert.Equal(joinedId, await GetSecondaryIdAsync());

            JsonElement exported = await secondary.CallAsync("settings/config/export", secondary.AdminToken);
            LoopbackWebService.AssertOk(exported);
            JsonElement response = exported.GetProperty("response");
            JsonElement cluster = response.GetProperty("manifest").GetProperty("cluster");
            Assert.Equal("cluster.test", cluster.GetProperty("domain").GetString());
            JsonElement bootstrap = cluster.GetProperty("bootstrap");
            Assert.Equal("Secondary", bootstrap.GetProperty("role").GetString());
            Assert.Equal(primaryUrl, bootstrap.GetProperty("primaryUrl").GetString());
            Assert.False(bootstrap.TryGetProperty("password", out _));
            Assert.Contains(response.GetProperty("missingInputs").EnumerateArray(), path => path.ValueEquals("/cluster/bootstrap/password"));

            await using var restored = await LoopbackWebService.StartAsync("restored.cluster.test", enableTls: true, adminPassword: primary.AdminPassword);
            await restored.RestartAsync(null, () =>
            {
                var topology = JsonNode.Parse(cluster.GetRawText())!.AsObject();
                JsonNode join = topology["bootstrap"]!;
                join["username"] = "admin";
                join["password"] = new JsonObject { ["file"] = "join-password" };
                join["ignoreCertificateErrors"] = true;
                var manifest = new JsonObject { ["schemaVersion"] = 1, ["cluster"] = topology };
                File.WriteAllText(Path.Combine(restored.ConfigurationDirectory, "join-password"), primary.AdminPassword);
                File.WriteAllText(Path.Combine(restored.ConfigurationDirectory, "technitium.json"), manifest.ToJsonString());
            });
            JsonElement restoredExport = await restored.CallAsync("settings/config/export", restored.AdminToken);
            LoopbackWebService.AssertOk(restoredExport);
            Assert.True(JsonElement.DeepEquals(cluster, restoredExport.GetProperty("response").GetProperty("manifest").GetProperty("cluster")));

            void WriteManifest(string domain)
            {
                string declaration = JsonSerializer.Serialize(new
                {
                    schemaVersion = 1,
                    cluster = new
                    {
                        domain,
                        bootstrap = new
                        {
                            role = "Secondary", primaryUrl, primaryAddress = "127.0.0.1", username = "admin",
                            password = new { file = "join-password" }, ignoreCertificateErrors = true
                        },
                        node = new { addresses = new[] { "127.0.0.1" } }
                    }
                });
                File.WriteAllText(manifestFile, declaration);
            }

            async Task<int> GetSecondaryIdAsync()
            {
                JsonElement state = await secondary.CallAsync("admin/cluster/state", secondary.AdminToken);
                LoopbackWebService.AssertOk(state);
                foreach (JsonElement node in state.GetProperty("response").GetProperty("clusterNodes").EnumerateArray())
                {
                    if (node.GetProperty("state").ValueEquals("Self") && node.GetProperty("type").ValueEquals("Secondary"))
                        return node.GetProperty("id").GetInt32();
                }
                throw new InvalidDataException("The local Secondary was not present in cluster state.");
            }
        }

        [Fact]
        public async Task PrimaryRejectsIntervalChangesUntilMembersAdvertiseSupport()
        {
            await using var primary = await LoopbackWebService.StartAsync("primary.cluster.test", enableTls: true);
            await using var secondary = await LoopbackWebService.StartAsync("secondary.cluster.test", enableTls: true);
            JsonElement initialized = await primary.CallAsync(
                "admin/cluster/init?clusterDomain=cluster.test&primaryNodeIpAddresses=127.0.0.1", primary.AdminToken);
            LoopbackWebService.AssertOk(initialized);
            Uri primaryUrl = new(Assert.Single(initialized.GetProperty("response").GetProperty("clusterNodes").EnumerateArray())
                .GetProperty("url").GetString()!);

            const string manifest = """{"schemaVersion":1,"cluster":{"configRefreshSeconds":120}}""";
            JsonElement beforeJoin = await PreviewAsync();
            LoopbackWebService.AssertOk(beforeJoin);

            using var certificate = X509CertificateLoader.LoadPkcs12FromFile(
                Path.Combine(primary.ConfigurationDirectory, "self-signed-cert.pfx"), null);
            using var legacyClient = new HttpApiClient(new Uri($"https://127.0.0.1:{primaryUrl.Port}/"), ipv6Mode: default, ignoreCertificateErrors: true);
            legacyClient.UseApiToken(primary.AdminToken);
            const int legacyId = 1234;
            await legacyClient.JoinClusterAsync(legacyId, new Uri("https://legacy.cluster.test:53443/"), [IPAddress.Loopback], certificate);

            JsonElement blockedPreview = await PreviewAsync();
            Assert.Equal("error", blockedPreview.GetProperty("status").GetString());
            Assert.Contains("legacy.cluster.test", blockedPreview.GetProperty("errorMessage").GetString());
            using var rejectedBody = new StringContent(manifest, Encoding.UTF8, "application/json");
            JsonElement blockedApply = await primary.CallAsync("settings/config/apply", primary.AdminToken, rejectedBody,
                beforeJoin.GetProperty("response").GetProperty("revision").GetString());
            Assert.Equal("error", blockedApply.GetProperty("status").GetString());
            Assert.Contains("has not advertised support", blockedApply.GetProperty("errorMessage").GetString());
            const string apps = """{"schemaVersion":1,"apps":{"packages":{"RemovedFixture":null}}}""";
            using (var appsBody = new StringContent(apps, Encoding.UTF8, "application/json"))
            {
                JsonElement rejectedApps = await primary.CallAsync("settings/config/plan", primary.AdminToken, appsBody);
                Assert.Equal("error", rejectedApps.GetProperty("status").GetString());
                Assert.Contains("has not advertised support for declarative apps", rejectedApps.GetProperty("errorMessage").GetString());
            }
            JsonElement state = await primary.CallAsync("admin/cluster/state", primary.AdminToken);
            LoopbackWebService.AssertOk(state);
            Assert.Equal(900, state.GetProperty("response").GetProperty("configRefreshIntervalSeconds").GetInt32());
            await legacyClient.DeleteSecondaryNodeAsync(legacyId);

            using var form = new FormUrlEncodedContent([
                new("secondaryNodeIpAddresses", "127.0.0.1"),
                new("primaryNodeUrl", primaryUrl.AbsoluteUri),
                new("primaryNodeIpAddress", "127.0.0.1"),
                new("primaryNodeUsername", "admin"),
                new("primaryNodePassword", primary.AdminPassword),
                new("ignoreCertificateErrors", "true")
            ]);
            LoopbackWebService.AssertOk(await secondary.CallAsync("admin/cluster/initJoin", secondary.AdminToken, form));

            JsonElement supported = await PreviewAsync();
            LoopbackWebService.AssertOk(supported);
            using var applyBody = new StringContent(manifest, Encoding.UTF8, "application/json");
            LoopbackWebService.AssertOk(await primary.CallAsync("settings/config/apply", primary.AdminToken, applyBody,
                supported.GetProperty("response").GetProperty("revision").GetString()));

            async Task<JsonElement> PreviewAsync()
            {
                using var body = new StringContent(manifest, Encoding.UTF8, "application/json");
                return await primary.CallAsync("settings/config/plan", primary.AdminToken, body);
            }
        }

        [Fact]
        public async Task PrimaryManifestClearsAppConfigurationAndReplicatesOwnership()
        {
            await using var primary = await LoopbackWebService.StartAsync("primary.cluster.test", enableTls: true);
            await using var secondary = await LoopbackWebService.StartAsync("secondary.cluster.test", enableTls: true,
                adminPassword: primary.AdminPassword);
            using var package = new MemoryStream();
            using (var zip = new ZipArchive(package, ZipArchiveMode.Create, leaveOpen: true))
            {
                using var config = new StreamWriter(zip.CreateEntry("dnsApp.config").Open());
                config.Write("fixture configuration");
            }
            package.Position = 0;
            using var upload = new MultipartFormDataContent();
            upload.Add(new StreamContent(package), "file", "fixture.zip");
            LoopbackWebService.AssertOk(await primary.CallAsync("apps/install?name=Fixture", primary.AdminToken, upload));

            JsonElement initialized = await primary.CallAsync(
                "admin/cluster/init?clusterDomain=cluster.test&primaryNodeIpAddresses=127.0.0.1", primary.AdminToken);
            LoopbackWebService.AssertOk(initialized);
            JsonElement primaryNode = Assert.Single(initialized.GetProperty("response").GetProperty("clusterNodes").EnumerateArray());
            using var join = new FormUrlEncodedContent([
                new("secondaryNodeIpAddresses", "127.0.0.1"),
                new("primaryNodeUrl", primaryNode.GetProperty("url").GetString()!),
                new("primaryNodeIpAddress", "127.0.0.1"),
                new("primaryNodeUsername", "admin"),
                new("primaryNodePassword", primary.AdminPassword),
                new("ignoreCertificateErrors", "true")
            ]);
            LoopbackWebService.AssertOk(await secondary.CallAsync("admin/cluster/initJoin", secondary.AdminToken, join));
            string token = await secondary.LoginAsync("admin", primary.AdminPassword);
            Assert.Equal("fixture configuration", (await ReadSecondaryAppAsync()).GetProperty("config").GetString());

            using var catalog = new FormUrlEncodedContent([
                new("zone", "cluster-catalog.cluster.test"),
                new("primaryZoneTransferProtocol", "Tcp"),
                new("primaryNameServerAddresses", $"127.0.0.1:{primary.DnsPort}")
            ]);
            LoopbackWebService.AssertOk(await secondary.CallAsync("zones/options/set", token, catalog));
            Assert.True(await WaitForAsync(async () =>
            {
                if ((await secondary.CallAsync("zones/options/get?zone=cluster.test", token)).GetProperty("status").ValueEquals("ok"))
                    return true;
                LoopbackWebService.AssertOk(await secondary.CallAsync("zones/resync?zone=cluster-catalog.cluster.test", token));
                return false;
            }),
                "The Secondary did not transfer the cluster zone.");

            const string clear = """{"schemaVersion":1,"apps":{"packages":{"Fixture":{"configuration":null}}}}""";
            using (var secondaryBody = new StringContent(clear, Encoding.UTF8, "application/json"))
            {
                JsonElement denied = await secondary.CallAsync("settings/config/plan", token, secondaryBody);
                Assert.Equal("error", denied.GetProperty("status").GetString());
                Assert.Contains("Only the Primary", denied.GetProperty("errorMessage").GetString());
            }
            await ApplyPrimaryAsync(clear);
            Assert.True(await WaitForAsync(async () => (await ReadSecondaryAppAsync()).GetProperty("config").ValueKind == JsonValueKind.Null),
                "The Secondary did not clear the installed app's configuration.");
            Assert.Contains((await ReadSecondaryAppAsync()).GetProperty("managedSettings").EnumerateArray(),
                path => path.ValueEquals("/apps/packages/Fixture/configuration"));
            using (var edit = new FormUrlEncodedContent([new("config", "local replacement")]))
            {
                JsonElement denied = await secondary.CallAsync("apps/config/set?name=Fixture", token, edit);
                Assert.Equal("error", denied.GetProperty("status").GetString());
                Assert.Contains("/apps/packages/Fixture/configuration", denied.GetProperty("errorMessage").GetString());
            }

            await ApplyPrimaryAsync("""{"schemaVersion":1}""");
            Assert.True(await WaitForAsync(async () => (await ReadSecondaryAppAsync()).GetProperty("managedSettings").GetArrayLength() == 0),
                "The Secondary did not release app ownership.");

            async Task ApplyPrimaryAsync(string manifest)
            {
                using var planBody = new StringContent(manifest, Encoding.UTF8, "application/json");
                JsonElement plan = await primary.CallAsync("settings/config/plan", primary.AdminToken, planBody);
                LoopbackWebService.AssertOk(plan);
                using var body = new StringContent(manifest, Encoding.UTF8, "application/json");
                LoopbackWebService.AssertOk(await primary.CallAsync("settings/config/apply", primary.AdminToken, body,
                    plan.GetProperty("response").GetProperty("revision").GetString()));
            }

            async Task<JsonElement> ReadSecondaryAppAsync()
            {
                JsonElement result = await secondary.CallAsync("apps/config/get?name=Fixture", token);
                LoopbackWebService.AssertOk(result);
                return result.GetProperty("response");
            }

            static async Task<bool> WaitForAsync(Func<Task<bool>> condition)
            {
                DateTime deadline = DateTime.UtcNow.AddSeconds(25);
                do
                {
                    if (await condition())
                        return true;
                    await Task.Delay(1000);
                }
                while (DateTime.UtcNow < deadline);
                return false;
            }
        }

        [Fact]
        public async Task JoiningSecondaryReceivesDnsSettingsAndKeepsItsLocalWebConfiguration()
        {
            await using var primary = await LoopbackWebService.StartAsync("primary.cluster.test", enableTls: true);
            await using var secondary = await LoopbackWebService.StartAsync("secondary.cluster.test", enableTls: true, adminPassword: primary.AdminPassword);
            LoopbackWebService.AssertOk(await primary.CallAsync("settings/set?defaultRecordTtl=180", primary.AdminToken));
            LoopbackWebService.AssertOk(await secondary.CallAsync("settings/set?defaultRecordTtl=240", secondary.AdminToken));

            JsonElement initialized = await primary.CallAsync(
                "admin/cluster/init?clusterDomain=cluster.test&primaryNodeIpAddresses=127.0.0.1", primary.AdminToken);
            LoopbackWebService.AssertOk(initialized);
            JsonElement primaryNode = Assert.Single(initialized.GetProperty("response").GetProperty("clusterNodes").EnumerateArray());

            const string manifest = """{"schemaVersion":1,"cluster":{"heartbeatRefreshSeconds":45,"configRefreshSeconds":120}}""";
            const string invalid = """{"schemaVersion":1,"cluster":{"heartbeatRefreshSeconds":90,"configRefreshSeconds":60}}""";
            JsonElement rejected = await PlanAsync(primary, primary.AdminToken, invalid);
            Assert.Equal("error", rejected.GetProperty("status").GetString());
            Assert.Contains("/cluster/configRefreshSeconds", rejected.GetProperty("errorMessage").GetString());

            JsonElement preview = await PlanAsync(primary, primary.AdminToken, manifest);
            LoopbackWebService.AssertOk(preview);
            JsonElement plan = preview.GetProperty("response");
            Assert.Contains(plan.GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/cluster/heartbeatRefreshSeconds"));
            using var applyBody = new StringContent(manifest, Encoding.UTF8, "application/json");
            LoopbackWebService.AssertOk(await primary.CallAsync("settings/config/apply", primary.AdminToken, applyBody,
                plan.GetProperty("revision").GetString()));

            const string secondaryTopology = """
                {"schemaVersion":1,"cluster":{"domain":"CLUSTER.test.","bootstrap":{"role":"Secondary"}}}
                """;
            JsonElement uninitialized = await PlanAsync(secondary, secondary.AdminToken, secondaryTopology);
            Assert.Equal("error", uninitialized.GetProperty("status").GetString());
            Assert.Contains("/cluster/node/addresses", uninitialized.GetProperty("errorMessage").GetString());

            using var form = new FormUrlEncodedContent([
                new("secondaryNodeIpAddresses", "127.0.0.1"),
                new("primaryNodeUrl", primaryNode.GetProperty("url").GetString()!),
                new("primaryNodeIpAddress", "127.0.0.1"),
                new("primaryNodeUsername", "admin"),
                new("primaryNodePassword", primary.AdminPassword),
                new("ignoreCertificateErrors", "true")
            ]);
            JsonElement joined = await secondary.CallAsync("admin/cluster/initJoin", secondary.AdminToken, form);
            LoopbackWebService.AssertOk(joined);
            JsonElement cluster = joined.GetProperty("response");
            Assert.Equal("cluster.test", cluster.GetProperty("clusterDomain").GetString());
            Assert.Contains(cluster.GetProperty("clusterNodes").EnumerateArray(), node =>
                node.GetProperty("type").GetString() == "Secondary" && node.GetProperty("state").GetString() == "Self");

            string syncedAdmin = await secondary.LoginAsync("admin", primary.AdminPassword);
            JsonElement result = await secondary.CallAsync("settings/get", syncedAdmin);
            LoopbackWebService.AssertOk(result);
            JsonElement settings = result.GetProperty("response");
            Assert.Equal(180, settings.GetProperty("defaultRecordTtl").GetInt32());
            Assert.Equal(secondary.Client.BaseAddress!.Port, settings.GetProperty("webServiceHttpPort").GetInt32());

            JsonElement topologyPreview = await PlanAsync(secondary, syncedAdmin, secondaryTopology);
            LoopbackWebService.AssertOk(topologyPreview);
            JsonElement topologyPlan = topologyPreview.GetProperty("response");
            Assert.Empty(topologyPlan.GetProperty("changes").EnumerateArray());
            using var topologyBody = new StringContent(secondaryTopology, Encoding.UTF8, "application/json");
            LoopbackWebService.AssertOk(await secondary.CallAsync("settings/config/apply", syncedAdmin, topologyBody,
                topologyPlan.GetProperty("revision").GetString()));

            const string wrongTopology = """
                {"schemaVersion":1,"cluster":{"domain":"other.test","bootstrap":{"role":"Primary"},"configRefreshSeconds":300}}
                """;
            JsonElement wrongDomain = await PlanAsync(primary, primary.AdminToken, wrongTopology);
            Assert.Equal("error", wrongDomain.GetProperty("status").GetString());
            Assert.Contains("/cluster/domain", wrongDomain.GetProperty("errorMessage").GetString());

            using var wrongBody = new StringContent(wrongTopology, Encoding.UTF8, "application/json");
            JsonElement wrongApply = await primary.CallAsync("settings/config/apply", primary.AdminToken, wrongBody,
                plan.GetProperty("revision").GetString());
            Assert.Equal("error", wrongApply.GetProperty("status").GetString());
            Assert.Contains("/cluster/domain", wrongApply.GetProperty("errorMessage").GetString());

            JsonElement wrongRole = await PlanAsync(primary, primary.AdminToken, secondaryTopology);
            Assert.Equal("error", wrongRole.GetProperty("status").GetString());
            Assert.Contains("/cluster/bootstrap/role", wrongRole.GetProperty("errorMessage").GetString());

            JsonElement secondaryPreview = await PlanAsync(secondary, syncedAdmin, manifest);
            Assert.Equal("error", secondaryPreview.GetProperty("status").GetString());
            Assert.Contains("Primary", secondaryPreview.GetProperty("errorMessage").GetString());

            using var deniedBody = new StringContent(manifest, Encoding.UTF8, "application/json");
            JsonElement deniedApply = await secondary.CallAsync("settings/config/apply", syncedAdmin, deniedBody,
                plan.GetProperty("revision").GetString());
            Assert.Equal("error", deniedApply.GetProperty("status").GetString());
            Assert.Contains("Primary", deniedApply.GetProperty("errorMessage").GetString());
            Assert.Equal(120, cluster.GetProperty("configRefreshIntervalSeconds").GetInt32());

            JsonElement export = await primary.CallAsync("settings/config/export", primary.AdminToken);
            LoopbackWebService.AssertOk(export);
            Assert.Equal(120, export.GetProperty("response").GetProperty("manifest").GetProperty("cluster")
                .GetProperty("configRefreshSeconds").GetInt32());
            await primary.RestartAsync();
            JsonElement repeated = await PlanAsync(primary, primary.AdminToken, manifest);
            LoopbackWebService.AssertOk(repeated);
            Assert.Empty(repeated.GetProperty("response").GetProperty("changes").EnumerateArray());

            JsonElement state = await primary.CallAsync("admin/cluster/state", primary.AdminToken);
            LoopbackWebService.AssertOk(state);
            Assert.Contains(state.GetProperty("response").GetProperty("managedOptionPaths").EnumerateArray(),
                path => path.ValueEquals("/cluster/configRefreshSeconds"));

            const string changeOptions = "admin/cluster/primary/setOptions?configRefreshIntervalSeconds=180&configRetryIntervalSeconds=80";
            JsonElement blocked = await primary.CallAsync(changeOptions, primary.AdminToken);
            Assert.Equal("error", blocked.GetProperty("status").GetString());
            Assert.Contains("/cluster/configRefreshSeconds", blocked.GetProperty("errorMessage").GetString());
            state = await primary.CallAsync("admin/cluster/state", primary.AdminToken);
            Assert.Equal(60, state.GetProperty("response").GetProperty("configRetryIntervalSeconds").GetInt32());

            JsonElement blockedDelete = await primary.CallAsync("admin/cluster/primary/delete?forceDelete=true", primary.AdminToken);
            Assert.Equal("error", blockedDelete.GetProperty("status").GetString());
            Assert.Contains("Release manifest ownership", blockedDelete.GetProperty("errorMessage").GetString());

            using var backup = new MemoryStream();
            using (var archive = new ZipArchive(backup, ZipArchiveMode.Create, leaveOpen: true))
                archive.CreateEntryFromFile(Path.Combine(primary.ConfigurationDirectory, "cluster.config"), "cluster.config");
            using var restore = new MultipartFormDataContent();
            restore.Add(new ByteArrayContent(backup.ToArray()), "file", "backup.zip");
            JsonElement blockedRestore = await primary.CallAsync("settings/restore?clusterConfig=true", primary.AdminToken, restore);
            Assert.Equal("error", blockedRestore.GetProperty("status").GetString());
            Assert.Contains("Release manifest ownership", blockedRestore.GetProperty("errorMessage").GetString());

            const string release = """{"schemaVersion":1}""";
            JsonElement releasePlan = await PlanAsync(primary, primary.AdminToken, release);
            LoopbackWebService.AssertOk(releasePlan);
            using var releaseBody = new StringContent(release, Encoding.UTF8, "application/json");
            LoopbackWebService.AssertOk(await primary.CallAsync("settings/config/apply", primary.AdminToken, releaseBody,
                releasePlan.GetProperty("response").GetProperty("revision").GetString()));

            state = await primary.CallAsync("admin/cluster/state", primary.AdminToken);
            Assert.Empty(state.GetProperty("response").GetProperty("managedOptionPaths").EnumerateArray());
            Assert.Equal(120, state.GetProperty("response").GetProperty("configRefreshIntervalSeconds").GetInt32());
            LoopbackWebService.AssertOk(await primary.CallAsync(changeOptions, primary.AdminToken));

            JsonElement secondarySettings = await secondary.CallAsync("settings/get", syncedAdmin);
            LoopbackWebService.AssertOk(secondarySettings);
            Assert.Equal(secondary.Client.BaseAddress!.Port, secondarySettings.GetProperty("response").GetProperty("webServiceHttpPort").GetInt32());

            const string addresses = """{"schemaVersion":1,"cluster":{"node":{"addresses":["127.0.0.1","127.0.0.2"]}}}""";
            JsonElement addressPreview = await PlanAsync(secondary, syncedAdmin, addresses);
            LoopbackWebService.AssertOk(addressPreview);
            Assert.Contains(addressPreview.GetProperty("response").GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/cluster/node/addresses"));
            using var addressBody = new StringContent(addresses, Encoding.UTF8, "application/json");
            LoopbackWebService.AssertOk(await secondary.CallAsync("settings/config/apply", syncedAdmin, addressBody,
                addressPreview.GetProperty("response").GetProperty("revision").GetString()));

            JsonElement addressRepeat = await PlanAsync(secondary, syncedAdmin, addresses);
            LoopbackWebService.AssertOk(addressRepeat);
            Assert.Empty(addressRepeat.GetProperty("response").GetProperty("changes").EnumerateArray());
            JsonElement secondaryExport = await secondary.CallAsync("settings/config/export", syncedAdmin);
            LoopbackWebService.AssertOk(secondaryExport);
            Assert.Contains(secondaryExport.GetProperty("response").GetProperty("manifest").GetProperty("cluster")
                .GetProperty("node").GetProperty("addresses").EnumerateArray(), value => value.ValueEquals("127.0.0.2"));

            await secondary.RestartAsync();
            syncedAdmin = secondary.AdminToken;
            JsonElement persisted = await secondary.CallAsync("admin/cluster/state", syncedAdmin);
            LoopbackWebService.AssertOk(persisted);
            Assert.Contains(persisted.GetProperty("response").GetProperty("managedOptionPaths").EnumerateArray(),
                value => value.ValueEquals("/cluster/node/addresses"));

            JsonElement blockedAddress = await secondary.CallAsync("admin/cluster/updateIpAddress?ipAddresses=127.0.0.1", syncedAdmin);
            Assert.Equal("error", blockedAddress.GetProperty("status").GetString());
            Assert.Contains("/cluster/node/addresses", blockedAddress.GetProperty("errorMessage").GetString());

            JsonElement addressRelease = await PlanAsync(secondary, syncedAdmin, release);
            LoopbackWebService.AssertOk(addressRelease);
            using var addressReleaseBody = new StringContent(release, Encoding.UTF8, "application/json");
            LoopbackWebService.AssertOk(await secondary.CallAsync("settings/config/apply", syncedAdmin, addressReleaseBody,
                addressRelease.GetProperty("response").GetProperty("revision").GetString()));
            LoopbackWebService.AssertOk(await secondary.CallAsync("admin/cluster/updateIpAddress?ipAddresses=127.0.0.1", syncedAdmin));

            static async Task<JsonElement> PlanAsync(LoopbackWebService server, string token, string declaration)
            {
                using var body = new StringContent(declaration, Encoding.UTF8, "application/json");
                return await server.CallAsync("settings/config/plan", token, body);
            }
        }
    }
}
