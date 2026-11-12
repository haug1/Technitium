using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace DnsServerCore.Tests
{
    [Collection("Web service")]
    public sealed class ClusterConfigurationTests
    {
        [Fact]
        public async Task JoiningSecondaryReceivesDnsSettingsAndKeepsItsLocalWebConfiguration()
        {
            await using var primary = await LoopbackWebService.StartAsync("primary.cluster.test", enableTls: true);
            await using var secondary = await LoopbackWebService.StartAsync("secondary.cluster.test", enableTls: true);
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

            static async Task<JsonElement> PlanAsync(LoopbackWebService server, string token, string declaration)
            {
                using var body = new StringContent(declaration, Encoding.UTF8, "application/json");
                return await server.CallAsync("settings/config/plan", token, body);
            }
        }
    }
}
