using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace DnsServerCore.Tests
{
    [CollectionDefinition("Web service", DisableParallelization = true)]
    public sealed class WebServiceCollection
    {
    }

    [Collection("Web service")]
    public sealed class SettingsWorkflowTests
    {
        [Fact]
        public async Task LoadsLegacyWebConfigurationAndKeepsApiChangesAfterRestart()
        {
            await using var server = await LoopbackWebService.StartAsync();
            JsonElement before = await server.GetSettingsAsync();
            Assert.Equal(LoopbackWebService.LegacyRealIpHeader, before.GetProperty("webServiceRealIpHeader").GetString());
            Assert.False(before.GetProperty("webServiceEnableHttpUnixSocket").GetBoolean());

            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?defaultRecordTtl=180", server.AdminToken));
            await server.RestartAsync();

            JsonElement after = await server.GetSettingsAsync();
            Assert.Equal(180, after.GetProperty("defaultRecordTtl").GetInt32());
            Assert.Equal(LoopbackWebService.LegacyRealIpHeader, after.GetProperty("webServiceRealIpHeader").GetString());
        }

        [Fact]
        public async Task RejectedSettingsUpdatesPreserveTheWorkingConfiguration()
        {
            await using var server = await LoopbackWebService.StartAsync();
            int originalTtl = (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32();

            using var form = new FormUrlEncodedContent([
                new("user", "viewer"),
                new("pass", "fixture-password")
            ]);
            LoopbackWebService.AssertOk(await server.CallAsync("admin/users/create", server.AdminToken, form));
            string viewer = await server.LoginAsync("viewer", "fixture-password");
            JsonElement unauthorized = await server.CallAsync("settings/set?defaultRecordTtl=240", viewer);
            Assert.Equal("error", unauthorized.GetProperty("status").GetString());

            JsonElement invalid = await server.CallAsync("settings/set?defaultRecordTtl=invalid", server.AdminToken);
            Assert.Equal("error", invalid.GetProperty("status").GetString());
            Assert.Equal(originalTtl, (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());

            await server.RestartAsync();
            Assert.Equal(originalTtl, (await server.GetSettingsAsync()).GetProperty("defaultRecordTtl").GetInt32());
        }

        [Fact]
        public async Task RestoringSelectedSettingsLeavesUnselectedSettingsInPlace()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?defaultRecordTtl=180&enableLogging=true", server.AdminToken));
            await server.RestartAsync();

            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/settings/backup?dnsSettings=true&logSettings=true");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", server.AdminToken);
            using HttpResponseMessage backup = await server.Client.SendAsync(request);
            backup.EnsureSuccessStatusCode();
            Assert.Equal("application/zip", backup.Content.Headers.ContentType?.MediaType);

            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?defaultRecordTtl=240&enableLogging=false", server.AdminToken));
            await server.RestartAsync();
            JsonElement modified = await server.GetSettingsAsync();
            Assert.Equal(240, modified.GetProperty("defaultRecordTtl").GetInt32());
            Assert.False(modified.GetProperty("enableLogging").GetBoolean());

            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(await backup.Content.ReadAsByteArrayAsync()), "file", "backup.zip");
            LoopbackWebService.AssertOk(await server.CallAsync("settings/restore?dnsSettings=true", server.AdminToken, form));

            JsonElement restored = await server.GetSettingsAsync();
            Assert.Equal(180, restored.GetProperty("defaultRecordTtl").GetInt32());
            Assert.False(restored.GetProperty("enableLogging").GetBoolean());
        }

        [Fact]
        public async Task WebListenerRecoversItsPreviousPortAfterAFailedBind()
        {
            await using var server = await LoopbackWebService.StartAsync();
            using var occupiedListener = new TcpListener(IPAddress.Loopback, 0);
            occupiedListener.Start();

            int workingPort = server.Client.BaseAddress!.Port;
            int occupiedPort = ((IPEndPoint)occupiedListener.LocalEndpoint).Port;
            JsonElement update = await server.CallAsync($"settings/set?webServiceHttpPort={occupiedPort}", server.AdminToken);
            LoopbackWebService.AssertOk(update);
            Assert.Equal(occupiedPort, update.GetProperty("response").GetProperty("webServiceHttpPort").GetInt32());

            int currentPort = occupiedPort;
            var timer = Stopwatch.StartNew();
            while ((currentPort != workingPort) && (timer.Elapsed < TimeSpan.FromSeconds(10)))
            {
                try
                {
                    currentPort = (await server.GetSettingsAsync()).GetProperty("webServiceHttpPort").GetInt32();
                }
                catch (HttpRequestException)
                {
                    // The old listener is temporarily unavailable during restart.
                }

                if (currentPort != workingPort)
                    await Task.Delay(100);
            }

            Assert.Equal(workingPort, currentPort);
            await server.RestartAsync();
            Assert.Equal(workingPort, (await server.GetSettingsAsync()).GetProperty("webServiceHttpPort").GetInt32());
        }
    }
}
