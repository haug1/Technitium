using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace DnsServerCore.Tests
{
    [Collection("Web service")]
    public sealed class DhcpConfigurationTests
    {
        [Fact]
        public async Task ScopeAndReservationPersistWithoutReplacingAnExistingReservation()
        {
            await using var server = await LoopbackWebService.StartAsync();

            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/set?name=Lab&startingAddress=192.0.2.10&endingAddress=192.0.2.99&subnetMask=255.255.255.0&allowOnlyReservedLeases=true",
                server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "dhcp/scopes/addReservedLease?name=Lab&hardwareAddress=02-00-00-00-00-01&ipAddress=192.0.2.20&hostName=fixture",
                server.AdminToken));

            JsonElement duplicate = await server.CallAsync(
                "dhcp/scopes/addReservedLease?name=Lab&hardwareAddress=02-00-00-00-00-01&ipAddress=192.0.2.21",
                server.AdminToken);
            Assert.Equal("error", duplicate.GetProperty("status").GetString());

            await server.RestartAsync();
            JsonElement response = await server.CallAsync("dhcp/scopes/get?name=Lab", server.AdminToken);
            LoopbackWebService.AssertOk(response);
            JsonElement scope = response.GetProperty("response");
            Assert.Equal("192.0.2.10", scope.GetProperty("startingAddress").GetString());
            Assert.Equal("192.0.2.99", scope.GetProperty("endingAddress").GetString());
            Assert.True(scope.GetProperty("allowOnlyReservedLeases").GetBoolean());
            JsonElement reservation = Assert.Single(scope.GetProperty("reservedLeases").EnumerateArray());
            Assert.Equal("192.0.2.20", reservation.GetProperty("address").GetString());
            Assert.Equal("fixture", reservation.GetProperty("hostName").GetString());
        }
    }
}
