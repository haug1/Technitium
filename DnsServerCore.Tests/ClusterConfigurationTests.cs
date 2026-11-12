using System;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Xunit;

namespace DnsServerCore.Tests
{
    [Collection("Web service")]
    public sealed class ClusterConfigurationTests
    {
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
            Assert.Equal("/cluster/configRefreshSeconds", Assert.Single(first.GetProperty("managedOptionPaths").EnumerateArray()).GetString());
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
            Assert.Contains("Initialize or join", uninitialized.GetProperty("errorMessage").GetString());

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
