using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
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
    public sealed class DnsAppConfigurationTests
    {
        [Fact]
        public async Task AppConfigurationChangesDnsResponsesAndSurvivesRestart()
        {
            await using var server = await LoopbackWebService.StartAsync();
            LoopbackWebService.AssertOk(await server.CallAsync("zones/create?zone=example.test&type=Primary", server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/records/add?zone=example.test&domain=www.example.test&type=A&ipAddress=192.0.2.10",
                server.AdminToken));
            LoopbackWebService.AssertOk(await server.CallAsync(
                "zones/records/add?zone=example.test&domain=www.example.test&type=AAAA&ipAddress=2001:db8::10",
                server.AdminToken));

            using var package = new MemoryStream();
            using (var zip = new ZipArchive(package, ZipArchiveMode.Create, leaveOpen: true))
            {
                string assembly = typeof(FilterAaaa.App).Assembly.Location;
                zip.CreateEntryFromFile(assembly, Path.GetFileName(assembly));
                string dependencies = Path.ChangeExtension(assembly, ".deps.json");
                zip.CreateEntryFromFile(dependencies, Path.GetFileName(dependencies));
                string symbols = Path.ChangeExtension(assembly, ".pdb");
                if (File.Exists(symbols))
                    zip.CreateEntryFromFile(symbols, Path.GetFileName(symbols));
                using var config = new StreamWriter(zip.CreateEntry("dnsApp.config").Open());
                config.Write("""{"enableFilterAaaa":false,"defaultTtl":30,"filterDomains":[]}""");
            }

            package.Position = 0;
            using var upload = new MultipartFormDataContent();
            upload.Add(new StreamContent(package), "file", "filter-aaaa.zip");
            JsonElement installed = await server.CallAsync("apps/install?name=FilterAaaa", server.AdminToken, upload);
            LoopbackWebService.AssertOk(installed);
            Assert.Contains(installed.GetProperty("response").GetProperty("installedApp").GetProperty("dnsApps").EnumerateArray(),
                app => app.GetProperty("isPostProcessor").GetBoolean());

            DnsDatagram unfiltered = await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA);
            var address = Assert.IsType<DnsAAAARecordData>(Assert.Single(unfiltered.Answer).RDATA).Address;
            Assert.Equal(IPAddress.Parse("2001:db8::10"), address);

            using var settings = new FormUrlEncodedContent([
                new("config", """{"enableFilterAaaa":true,"defaultTtl":30,"filterDomains":[]}""")
            ]);
            LoopbackWebService.AssertOk(await server.CallAsync("apps/config/set?name=FilterAaaa", server.AdminToken, settings));

            DnsDatagram filtered = await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA);
            Assert.Equal(DnsResponseCode.NoError, filtered.RCODE);
            Assert.Empty(filtered.Answer);

            string version = typeof(FilterAaaa.App).Assembly.GetName().Version!.ToString();
            string manifest = BuildManifest(version, """{"enableFilterAaaa":false,"defaultTtl":30,"filterDomains":[]}""");
            string revision = await PreviewAsync(manifest);
            using (var body = new StringContent(manifest, Encoding.UTF8, "application/json"))
                LoopbackWebService.AssertOk(await server.CallAsync("settings/config/apply", server.AdminToken, body, revision));

            DnsDatagram restored = await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA);
            Assert.Single(restored.Answer);

            string invalid = BuildManifest(version, "fixture-invalid-app-config");
            revision = await PreviewAsync(invalid);
            using (var body = new StringContent(invalid, Encoding.UTF8, "application/json"))
            {
                JsonElement rejected = await server.CallAsync("settings/config/apply", server.AdminToken, body, revision);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/apps/packages/FilterAaaa/configuration", rejected.GetProperty("errorMessage").GetString());
                Assert.DoesNotContain("fixture-invalid-app-config", rejected.GetRawText());
            }
            Assert.Single((await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA)).Answer);

            JsonElement export = await server.CallAsync("settings/config/export", server.AdminToken);
            LoopbackWebService.AssertOk(export);
            JsonElement response = export.GetProperty("response");
            JsonElement appConfig = response.GetProperty("manifest").GetProperty("apps").GetProperty("packages").GetProperty("FilterAaaa");
            Assert.Equal(version, appConfig.GetProperty("version").GetString());
            Assert.False(appConfig.TryGetProperty("configuration", out _));
            Assert.Contains(response.GetProperty("missingInputs").EnumerateArray(),
                input => input.ValueEquals("/apps/packages/FilterAaaa/configuration"));

            string appFile = Path.Combine(server.ConfigurationDirectory, "apps", "FilterAaaa", "dnsApp.config");
            string interrupted = Path.Combine(server.ConfigurationDirectory, ".manifest-app-activation-pending",
                "apps", "FilterAaaa", "dnsApp.config");
            Directory.CreateDirectory(interrupted);
            File.Copy(appFile, Path.Combine(interrupted, "previous"));
            await File.WriteAllTextAsync(appFile, """{"enableFilterAaaa":true,"defaultTtl":30,"filterDomains":[]}""");

            await server.RestartAsync();
            DnsDatagram reloaded = await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA);
            Assert.Equal(DnsResponseCode.NoError, reloaded.RCODE);
            Assert.Single(reloaded.Answer);
            await PreviewAsync(manifest, expectChanges: false);

            JsonElement managed = await server.CallAsync("apps/config/get?name=FilterAaaa", server.AdminToken);
            LoopbackWebService.AssertOk(managed);
            Assert.Contains(managed.GetProperty("response").GetProperty("managedSettings").EnumerateArray(),
                path => path.ValueEquals("/apps/packages/FilterAaaa/configuration"));
            using (var deniedConfig = new FormUrlEncodedContent([
                new("config", """{"enableFilterAaaa":true,"defaultTtl":30,"filterDomains":[]}""")
            ]))
            {
                JsonElement denied = await server.CallAsync("apps/config/set?name=FilterAaaa", server.AdminToken, deniedConfig);
                Assert.Equal("error", denied.GetProperty("status").GetString());
                Assert.Contains("/apps/packages/FilterAaaa/configuration", denied.GetProperty("errorMessage").GetString());
            }
            JsonElement deniedRemoval = await server.CallAsync("apps/uninstall?name=FilterAaaa", server.AdminToken);
            Assert.Equal("error", deniedRemoval.GetProperty("status").GetString());
            Assert.Contains("/apps/packages/FilterAaaa", deniedRemoval.GetProperty("errorMessage").GetString());

            using var backup = new MemoryStream();
            using (var archive = new ZipArchive(backup, ZipArchiveMode.Create, leaveOpen: true))
            {
                using var writer = new StreamWriter(archive.CreateEntry("apps/FilterAaaa/dnsApp.config").Open());
                writer.Write("""{"enableFilterAaaa":true,"defaultTtl":30,"filterDomains":[]}""");
            }
            backup.Position = 0;
            using var restore = new MultipartFormDataContent();
            restore.Add(new StreamContent(backup), "file", "apps-backup.zip");
            JsonElement deniedRestore = await server.CallAsync("settings/restore?apps=true", server.AdminToken, restore);
            Assert.Equal("error", deniedRestore.GetProperty("status").GetString());
            Assert.Contains("/apps/packages/FilterAaaa/configuration", deniedRestore.GetProperty("errorMessage").GetString());
            Assert.Single((await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA)).Answer);

            const string release = """{"schemaVersion":1}""";
            revision = await PreviewAsync(release, expectChanges: false);
            using (var body = new StringContent(release, Encoding.UTF8, "application/json"))
                LoopbackWebService.AssertOk(await server.CallAsync("settings/config/apply", server.AdminToken, body, revision));
            await server.RestartAsync();
            using var enabled = new FormUrlEncodedContent([
                new("config", """{"enableFilterAaaa":true,"defaultTtl":30,"filterDomains":[]}""")
            ]);
            LoopbackWebService.AssertOk(await server.CallAsync("apps/config/set?name=FilterAaaa", server.AdminToken, enabled));
            Assert.Empty((await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA)).Answer);

            async Task<string> PreviewAsync(string input, bool expectChanges = true)
            {
                using var body = new StringContent(input, Encoding.UTF8, "application/json");
                JsonElement plan = await server.CallAsync("settings/config/plan", server.AdminToken, body);
                LoopbackWebService.AssertOk(plan);
                JsonElement response = plan.GetProperty("response");
                if (expectChanges)
                    Assert.Contains(response.GetProperty("changes").EnumerateArray(),
                        change => change.GetProperty("path").ValueEquals("/apps/packages/FilterAaaa/configuration"));
                else
                    Assert.Empty(response.GetProperty("changes").EnumerateArray());
                return response.GetProperty("revision").GetString()!;
            }
        }

        private static string BuildManifest(string version, string text) => new JsonObject
        {
            ["schemaVersion"] = 1,
            ["apps"] = new JsonObject
            {
                ["packages"] = new JsonObject
                {
                    ["FilterAaaa"] = new JsonObject
                    {
                        ["version"] = version,
                        ["configuration"] = new JsonObject { ["text"] = text }
                    }
                }
            }
        }.ToJsonString();
    }
}
