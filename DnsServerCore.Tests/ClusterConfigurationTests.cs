using System.Net.Http;
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
        }
    }
}
