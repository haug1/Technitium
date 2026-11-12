using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    [Collection("Web service")]
    public sealed class ConfigurationCommandTests
    {
        [Fact]
        public async Task ConsoleCommandsMigrateSettingsAndReferencedSecretsToAnotherServer()
        {
            await using var source = await LoopbackWebService.StartAsync();
            await using var destination = await LoopbackWebService.StartAsync();
            string manifest = Path.Combine(source.ConfigurationDirectory, "cli-migration.json");
            await File.WriteAllTextAsync(manifest, """
                {"schemaVersion":1,"logging":{"retentionDays":42},
                 "zones":{"cli-migration.test":{"type":"Primary","records":[
                   {"owner":"www.cli-migration.test","type":"A","ttl":60,"data":{"zoneFile":"192.0.2.82"}}
                 ]}}}
                """);

            Assert.Contains("references are valid", (await RunAsync(source, "validate", manifest)).Output);
            await ApplyAsync(source, manifest);
            const string keyName = "cli-key.test";
            string secret = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
            LoopbackWebService.AssertOk(await source.CallAsync(
                "settings/set?tsigKeys=" + Uri.EscapeDataString($"{keyName}|{secret}|hmac-sha256"), source.AdminToken));
            string sourceUrl = source.Client.BaseAddress!.AbsoluteUri;
            var firstExport = await RunAsync(source, "export", sourceUrl);
            Assert.Equal(firstExport.Output, (await RunAsync(source, "export", sourceUrl)).Output);
            Assert.Contains("Supply separately /dns/tsigKeys/cli-key.test/secret", firstExport.Error);
            Assert.DoesNotContain(secret, firstExport.Output);
            Assert.DoesNotContain(secret, firstExport.Error);

            JsonNode exported = JsonNode.Parse(firstExport.Output)!;
            var migration = new JsonObject
            {
                ["schemaVersion"] = exported["schemaVersion"]!.DeepClone(),
                ["logging"] = exported["logging"]!.DeepClone(),
                ["zones"] = new JsonObject { ["cli-migration.test"] = exported["zones"]!["cli-migration.test"]!.DeepClone() }
            };
            JsonNode keys = exported["dns"]!["tsigKeys"]!.DeepClone();
            string variable = "TECHNITIUM_TEST_CLI_TSIG_" + Guid.NewGuid().ToString("N");
            keys[keyName]!["secret"] = new JsonObject { ["environment"] = variable };
            migration["dns"] = new JsonObject { ["tsigKeys"] = keys };
            string migrationPath = Path.Combine(destination.ConfigurationDirectory, "cli-migration.json");
            await File.WriteAllTextAsync(migrationPath, migration.ToJsonString());
            try
            {
                Environment.SetEnvironmentVariable(variable, secret);
                await RunAsync(destination, "validate", migrationPath);
                await ApplyAsync(destination, migrationPath);
                Assert.Equal(42, (await destination.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
                var answer = await destination.QueryAsync("www.cli-migration.test", DnsResourceRecordType.A,
                    new TsigKey(keyName, secret, TsigAlgorithm.HMAC_SHA256));
                Assert.Equal("192.0.2.82", Assert.IsType<DnsARecordData>(Assert.Single(answer.Answer).RDATA).Address.ToString());
                Assert.Contains("No setting changes.", (await RunAsync(destination, "plan", migrationPath,
                    destination.Client.BaseAddress!.AbsoluteUri)).Output);
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, null);
            }

            static async Task ApplyAsync(LoopbackWebService server, string file)
            {
                string origin = server.Client.BaseAddress!.AbsoluteUri;
                var plan = await RunAsync(server, "plan", file, origin);
                string revision = ReadOutputValue(plan.Output, "Revision ");
                Assert.Contains("Configuration applied.", (await RunAsync(server, "apply", file, origin, revision)).Output);
            }
        }

        [Fact]
        public async Task ConsoleRejectsStalePreviewAndWaitsAcrossWebRestart()
        {
            await using var server = await LoopbackWebService.StartAsync();
            string origin = server.Client.BaseAddress!.AbsoluteUri;
            int port = LoopbackDnsServer.GetLoopbackEndPoint().Port;
            string destination = $"http://127.0.0.1:{port}";
            string path = Path.Combine(server.ConfigurationDirectory, "cli-restart.json");
            var manifest = new JsonObject
            {
                ["schemaVersion"] = 1,
                ["web"] = new JsonObject { ["httpPort"] = port },
                ["logging"] = new JsonObject { ["retentionDays"] = 42 }
            };
            await File.WriteAllTextAsync(path, manifest.ToJsonString());

            var plan = await RunAsync(server, "plan", path, origin);
            Assert.Contains("Update /web/httpPort (web service restart)", plan.Output);
            Assert.Equal(365, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
            LoopbackWebService.AssertOk(await server.CallAsync("settings/set?maxLogFileDays=7", server.AdminToken));
            string stale = ReadOutputValue(plan.Output, "Revision ");
            var rejected = await RunAsync(server, 1, "apply", path, origin, stale);
            Assert.Contains("preview is stale", rejected.Error);
            using (var body = new StringContent(manifest.ToJsonString(), Encoding.UTF8, "application/json"))
            {
                var response = await server.CallAsync("settings/config/apply", server.AdminToken, body, stale);
                Assert.Equal("error", response.GetProperty("status").GetString());
                Assert.Equal("stale-preview", response.GetProperty("errorCode").GetString());
            }
            Assert.Equal(7, (await server.GetSettingsAsync()).GetProperty("maxLogFileDays").GetInt32());
            Assert.Equal(server.Client.BaseAddress.Port, (await server.GetSettingsAsync()).GetProperty("webServiceHttpPort").GetInt32());

            plan = await RunAsync(server, "plan", path, origin);
            string revision = ReadOutputValue(plan.Output, "Revision ");
            var applied = await RunAsync(server, "apply", path, origin, revision, "--wait", destination);
            Assert.Contains("Configuration applied.", applied.Output);
            string operation = ReadOutputValue(applied.Output, "Configuration apply is pending. Operation ");
            Assert.Contains("Configuration applied.", (await RunAsync(server, "status", destination, operation)).Output);
            Assert.Contains("No setting changes.", (await RunAsync(server, "plan", path, destination)).Output);
        }

        [Fact]
        public async Task ConsoleReportsFailedWebRestartAndCanRetryAfterRollback()
        {
            await using var server = await LoopbackWebService.StartAsync();
            string origin = server.Client.BaseAddress!.AbsoluteUri;
            using var occupied = new TcpListener(IPAddress.Loopback, 0);
            occupied.Start();
            int port = ((IPEndPoint)occupied.LocalEndpoint).Port;
            string destination = $"http://127.0.0.1:{port}";
            string path = Path.Combine(server.ConfigurationDirectory, "cli-rollback.json");
            await File.WriteAllTextAsync(path, $$"""
                {"schemaVersion":1,"web":{"httpPort":{{port}} },"logging":{"retentionDays":42} }
                """);

            var plan = await RunAsync(server, "plan", path, origin);
            string revision = ReadOutputValue(plan.Output, "Revision ");
            var failed = await RunAsync(server, 1, "apply", path, origin, revision, "--wait", origin);
            Assert.Contains("Could not bind the web listeners", failed.Error);
            string operation = ReadOutputValue(failed.Output, "Configuration apply is pending. Operation ");
            Assert.Equal(failed.Error, (await RunAsync(server, 1, "status", origin, operation)).Error);
            var settings = await server.GetSettingsAsync();
            Assert.Equal(server.Client.BaseAddress.Port, settings.GetProperty("webServiceHttpPort").GetInt32());
            Assert.Equal(365, settings.GetProperty("maxLogFileDays").GetInt32());

            occupied.Stop();
            plan = await RunAsync(server, "plan", path, origin);
            revision = ReadOutputValue(plan.Output, "Revision ");
            Assert.Contains("Configuration applied.",
                (await RunAsync(server, "apply", path, origin, revision, "--wait", destination)).Output);
            var exported = JsonNode.Parse((await RunAsync(server, "export", destination)).Output)!;
            Assert.Equal(42, exported["logging"]!["retentionDays"]!.GetValue<int>());
            Assert.Equal(port, exported["web"]!["httpPort"]!.GetValue<int>());
            Assert.Contains("No setting changes.", (await RunAsync(server, "plan", path, destination)).Output);
        }

        private static string ReadOutputValue(string output, string prefix) =>
            Assert.Single(output.Split('\n'), line => line.StartsWith(prefix, StringComparison.Ordinal))[prefix.Length..].Trim();

        private static Task<(string Output, string Error)> RunAsync(LoopbackWebService server, params string[] args) =>
            RunAsync(server, 0, args);

        private static async Task<(string Output, string Error)> RunAsync(LoopbackWebService server, int expectedExitCode, params string[] args)
        {
            string dotnet = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
            var start = new ProcessStartInfo(dotnet)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            start.Environment["TECHNITIUM_CONFIG_API_TOKEN"] = server.AdminToken;
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "DnsServerApp.dll"));
            start.ArgumentList.Add("config");
            foreach (string argument in args)
                start.ArgumentList.Add(argument);

            using Process process = Process.Start(start)!;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            Task<string> outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            Task<string> errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
                throw;
            }

            string output = await outputTask;
            string error = await errorTask;
            Assert.DoesNotContain(server.AdminToken, output);
            Assert.DoesNotContain(server.AdminToken, error);
            Assert.True(process.ExitCode == expectedExitCode, error);
            return (output, error);
        }
    }
}
