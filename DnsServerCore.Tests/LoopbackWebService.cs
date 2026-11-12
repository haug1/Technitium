using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;
using DnsServerCore.Dns;
using TechnitiumLibrary.Net;
using Xunit;

namespace DnsServerCore.Tests
{
    internal sealed class LoopbackWebService : IAsyncDisposable
    {
        public const string LegacyRealIpHeader = "X-Fixture-Real-IP";

        private readonly DirectoryInfo _configuration = Directory.CreateTempSubdirectory("technitium-web-test-");
        private readonly string _adminPassword = Guid.NewGuid().ToString("N");
        private DnsWebService? _service;

        public HttpClient Client { get; private set; } = null!;
        public string AdminToken { get; private set; } = null!;

        public static async Task<LoopbackWebService> StartAsync()
        {
            var server = new LoopbackWebService();
            try
            {
                IPEndPoint dnsEndPoint = LoopbackDnsServer.GetLoopbackEndPoint();
                int httpPort;
                do
                {
                    httpPort = LoopbackDnsServer.GetLoopbackEndPoint().Port;
                }
                while (httpPort == dnsEndPoint.Port);

                await server.SeedDnsConfigurationAsync(dnsEndPoint);
                server.WriteLegacyWebConfiguration(httpPort);
                server.Client = new HttpClient(new SocketsHttpHandler { UseProxy = false })
                {
                    BaseAddress = new Uri($"http://127.0.0.1:{httpPort}"),
                    Timeout = TimeSpan.FromSeconds(10)
                };
                await server.StartServiceAsync();
                return server;
            }
            catch
            {
                await server.DisposeAsync();
                throw;
            }
        }

        public async Task RestartAsync()
        {
            await _service!.DisposeAsync();
            await StartServiceAsync();
        }

        public async Task<string> LoginAsync(string username, string password)
        {
            using var form = new FormUrlEncodedContent([
                new("user", username),
                new("pass", password)
            ]);
            JsonElement result = await CallAsync("user/login", content: form);
            AssertOk(result);
            return result.GetProperty("token").GetString()!;
        }

        public async Task<JsonElement> CallAsync(string path, string? token = null, HttpContent? content = null)
        {
            using var request = new HttpRequestMessage(content is null ? HttpMethod.Get : HttpMethod.Post, "/api/" + path);
            if (token is not null)
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Content = content;

            using HttpResponseMessage response = await Client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            using var json = JsonDocument.Parse(await response.Content.ReadAsStreamAsync());
            return json.RootElement.Clone();
        }

        public async Task<JsonElement> GetSettingsAsync()
        {
            JsonElement result = await CallAsync("settings/get", AdminToken);
            AssertOk(result);
            return result.GetProperty("response");
        }

        public static void AssertOk(JsonElement result)
        {
            Assert.True(result.GetProperty("status").GetString() == "ok", result.GetRawText());
        }

        public async ValueTask DisposeAsync()
        {
            Client?.Dispose();
            if (_service is not null)
                await _service.DisposeAsync();
            _configuration.Delete(recursive: true);
        }

        private async Task SeedDnsConfigurationAsync(IPEndPoint endPoint)
        {
            await using var log = new LogManager(true, _configuration.FullName);
            await using var dns = new DnsServer(_configuration.FullName, _configuration.FullName, endPoint, log, "server.test");
            dns.EnableCheckForUpdate = false;
            dns.DnsApplicationManager.EnableAutomaticUpdate = false;
            dns.Recursion = DnsServerRecursion.Deny;
            dns.SaveConfigFile(immediately: true);
        }

        private void WriteLegacyWebConfiguration(int httpPort)
        {
            // Version 1 predates the reverse proxy ACL and Unix socket settings.
            using var writer = new BinaryWriter(File.Create(Path.Combine(_configuration.FullName, "webservice.config")));
            writer.Write("WC"u8);
            writer.Write((byte)1);
            writer.Write(httpPort);
            writer.Write(53443);
            writer.Write((byte)1); // address count
            IPAddress.Loopback.WriteTo(writer);
            writer.Write(false); // TLS
            writer.Write(false); // HTTP/3
            writer.Write(false); // HTTP-to-TLS redirect
            writer.Write(false); // self-signed certificate
            writer.Write(string.Empty); // certificate path
            writer.Write(string.Empty); // certificate password
            writer.Write(LegacyRealIpHeader);
        }

        private async Task StartServiceAsync()
        {
            // Only the constructor reads the bootstrap password.
            const string variable = "DNS_SERVER_ADMIN_PASSWORD";
            string? previous = Environment.GetEnvironmentVariable(variable);
            Environment.SetEnvironmentVariable(variable, _adminPassword);
            try
            {
                _service = new DnsWebService(true, _configuration.FullName);
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, previous);
            }

            await _service.StartAsync(throwIfBindFails: true).WaitAsync(TimeSpan.FromSeconds(15));
            AdminToken = await LoginAsync("admin", _adminPassword);
        }
    }
}
