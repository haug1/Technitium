using DnsServerCore.Dns.Applications;
using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
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
        public async Task RemotePackagePreviewDoesNotDownloadAndFailedApplyLeavesTheAppAbsent()
        {
            await using var server = await LoopbackWebService.StartAsync();
            int port = LoopbackDnsServer.GetLoopbackEndPoint().Port;
            string manifest = $$$$$"""
                {"schemaVersion":1,"apps":{"packages":{"RemoteFixture":{
                    "source":{"url":"https://127.0.0.1:{{{{{port}}}}}/fixture.zip"},"version":"1.0"
                }}}}
                """;
            using var previewBody = new StringContent(manifest, Encoding.UTF8, "application/json");
            JsonElement plan = await server.CallAsync("settings/config/plan", server.AdminToken, previewBody);
            LoopbackWebService.AssertOk(plan);
            Assert.Contains(plan.GetProperty("response").GetProperty("changes").EnumerateArray(),
                change => change.GetProperty("path").ValueEquals("/apps/packages/RemoteFixture") &&
                    change.GetProperty("kind").ValueEquals("Add"));
            using var applyBody = new StringContent(manifest, Encoding.UTF8, "application/json");
            JsonElement applied = await server.CallAsync("settings/config/apply", server.AdminToken, applyBody,
                plan.GetProperty("response").GetProperty("revision").GetString());
            Assert.Equal("error", applied.GetProperty("status").GetString());
            Assert.Contains("/apps/packages/RemoteFixture/source", applied.GetProperty("errorMessage").GetString());
            Assert.False(Directory.Exists(Path.Combine(server.ConfigurationDirectory, "apps", "RemoteFixture")));

            using var retryBody = new StringContent(manifest, Encoding.UTF8, "application/json");
            JsonElement retried = await server.CallAsync("settings/config/apply", server.AdminToken, retryBody,
                plan.GetProperty("response").GetProperty("revision").GetString());
            Assert.Equal("error", retried.GetProperty("status").GetString());
            Assert.Equal(applied.GetProperty("errorMessage").GetString(), retried.GetProperty("errorMessage").GetString());
            Assert.False(Directory.Exists(Path.Combine(server.ConfigurationDirectory, "apps", "RemoteFixture")));
        }

        [Fact]
        public async Task ManagedAppTransferRejectsAnUnreadableArchiveAndCanRetry()
        {
            const string appPath = "/apps/packages/Fixture";
            await using var server = await LoopbackWebService.StartAsync();
            string appFolder = Path.Combine(server.ConfigurationDirectory, "apps", "Fixture");

            var error = await Assert.ThrowsAsync<InvalidDataException>(() => TransferAsync("not a ZIP"u8.ToArray()));
            Assert.Contains(appPath + "/source", error.Message);
            Assert.False(Directory.Exists(appFolder));
            Assert.Empty(server.Applications.ManagedPaths);

            using var package = new MemoryStream();
            using (var archive = new ZipArchive(package, ZipArchiveMode.Create, leaveOpen: true))
            {
                using var config = new StreamWriter(archive.CreateEntry("dnsApp.config").Open());
                config.Write("{}");
            }

            await TransferAsync(package.ToArray());
            Assert.True(File.Exists(Path.Combine(appFolder, "Fixture.zip")));
            Assert.Contains("Fixture", server.Applications.Applications.Keys);
            Assert.Contains(appPath, server.Applications.ManagedPaths);

            async Task TransferAsync(byte[] bytes)
            {
                using var transfer = new MemoryStream();
                using (var archive = new ZipArchive(transfer, ZipArchiveMode.Create, leaveOpen: true))
                {
                    using Stream entry = archive.CreateEntry("apps/Fixture/Fixture.zip").Open();
                    entry.Write(bytes);
                }

                transfer.Position = 0;
                using var incoming = new ZipArchive(transfer, ZipArchiveMode.Read);
                await server.Applications.ApplyClusterTransferAsync(DnsApplicationManager.ReadClusterTransfer(incoming), [appPath]);
            }
        }

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
            string packageDigest = Convert.ToHexString(SHA256.HashData(package.ToArray()));
            Assert.Equal(packageDigest, appConfig.GetProperty("packageSha256").GetString());
            var wrongInstalledPackage = JsonNode.Parse(BuildManifest(version, """{"enableFilterAaaa":false}"""))!;
            wrongInstalledPackage["apps"]!["packages"]!["FilterAaaa"]!["packageSha256"] = new string('0', 64);
            using (var body = new StringContent(wrongInstalledPackage.ToJsonString(), Encoding.UTF8, "application/json"))
            {
                JsonElement rejected = await server.CallAsync("settings/config/plan", server.AdminToken, body);
                Assert.Equal("error", rejected.GetProperty("status").GetString());
                Assert.Contains("/apps/packages/FilterAaaa/packageSha256", rejected.GetProperty("errorMessage").GetString());
            }
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

            string appFolder = Path.GetDirectoryName(appFile)!;
            string removalJournal = Path.Combine(server.ConfigurationDirectory, ".manifest-pending", "app-removals", "FilterAaaa");
            Directory.CreateDirectory(removalJournal);
            Directory.Move(appFolder, Path.Combine(removalJournal, "previous"));
            await server.RestartAsync();
            Assert.Empty((await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA)).Answer);

            const string remove = """{"schemaVersion":1,"apps":{"packages":{"FilterAaaa":null}}}""";
            revision = await PreviewAsync(remove, changePath: "/apps/packages/FilterAaaa");
            using (var body = new StringContent(remove, Encoding.UTF8, "application/json"))
                LoopbackWebService.AssertOk(await server.CallAsync("settings/config/apply", server.AdminToken, body, revision));
            Assert.False(Directory.Exists(appFolder));
            Assert.Single((await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA)).Answer);
            await server.RestartAsync();
            await PreviewAsync(remove, expectChanges: false);
            using var reinstall = new MultipartFormDataContent();
            reinstall.Add(new ByteArrayContent(package.ToArray()), "file", "filter-aaaa.zip");
            JsonElement blockedInstall = await server.CallAsync("apps/install?name=FilterAaaa", server.AdminToken, reinstall);
            Assert.Equal("error", blockedInstall.GetProperty("status").GetString());
            Assert.Contains("/apps/packages/FilterAaaa", blockedInstall.GetProperty("errorMessage").GetString());

            string startupPath = Path.Combine(server.ConfigurationDirectory, "technitium.json");
            await File.WriteAllBytesAsync(Path.Combine(server.ConfigurationDirectory, "filter-package.zip"), package.ToArray());
            JsonNode install = JsonNode.Parse(BuildManifest(version,
                """{"enableFilterAaaa":true,"defaultTtl":30,"filterDomains":[]}"""))!;
            install["apps"]!["packages"]!["FilterAaaa"]!["source"] = new JsonObject
            {
                ["file"] = "filter-package.zip",
                ["sha256"] = Convert.ToHexString(SHA256.HashData(package.ToArray())).ToLowerInvariant()
            };
            JsonNode wrongHash = install.DeepClone();
            wrongHash["apps"]!["packages"]!["FilterAaaa"]!["source"]!["sha256"] = new string('0', 64);
            await File.WriteAllTextAsync(startupPath, wrongHash.ToJsonString());
            InvalidDataException digestMismatch = await Assert.ThrowsAsync<InvalidDataException>(() => server.RestartAsync());
            Assert.Contains("/apps/packages/FilterAaaa/source/sha256", digestMismatch.Message);
            Assert.False(Directory.Exists(appFolder));
            JsonNode wrongVersion = install.DeepClone();
            wrongVersion["apps"]!["packages"]!["FilterAaaa"]!["version"] = "999.0";
            await File.WriteAllTextAsync(startupPath, wrongVersion.ToJsonString());
            InvalidDataException mismatch = await Assert.ThrowsAsync<InvalidDataException>(() => server.RestartAsync());
            Assert.Contains("/apps/packages/FilterAaaa/version", mismatch.Message);
            Assert.False(Directory.Exists(appFolder));

            string oldPackage = Path.Combine(server.ConfigurationDirectory, "old-package.zip");
            using (ZipArchive archive = ZipFile.Open(oldPackage, ZipArchiveMode.Create))
            {
                using var writer = new StreamWriter(archive.CreateEntry("dnsApp.config").Open());
                writer.Write("""{"enableFilterAaaa":true,"defaultTtl":30,"filterDomains":[]}""");
            }
            JsonNode old = install.DeepClone();
            JsonNode oldEntry = old["apps"]!["packages"]!["FilterAaaa"]!;
            oldEntry["version"] = "0.0";
            oldEntry["source"] = new JsonObject { ["file"] = "old-package.zip" };
            await File.WriteAllTextAsync(startupPath, old.ToJsonString());
            await server.RestartAsync();
            Assert.Single((await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA)).Answer);

            await File.WriteAllTextAsync(startupPath, wrongVersion.ToJsonString());
            mismatch = await Assert.ThrowsAsync<InvalidDataException>(() => server.RestartAsync());
            Assert.Contains("/apps/packages/FilterAaaa/version", mismatch.Message);
            Assert.True(Directory.Exists(appFolder));
            Assert.Equal(File.ReadAllBytes(oldPackage), File.ReadAllBytes(Path.Combine(appFolder, "FilterAaaa.zip")));

            var migrated = install["apps"]!["packages"]!["FilterAaaa"]!.AsObject();
            migrated.Remove("configuration");
            migrated["packageSha256"] = packageDigest;
            migrated["source"]!.AsObject().Remove("sha256");
            await File.WriteAllTextAsync(startupPath, install.ToJsonString());
            await server.RestartAsync();
            Assert.True(File.Exists(Path.Combine(appFolder, "FilterAaaa.zip")));
            Assert.Empty((await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA)).Answer);
            await server.RestartAsync();
            Assert.Empty((await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA)).Answer);

            using var differentPackageBackup = new MemoryStream();
            using (var archive = new ZipArchive(differentPackageBackup, ZipArchiveMode.Create, leaveOpen: true))
            {
                archive.CreateEntryFromFile(oldPackage, "apps/FilterAaaa/FilterAaaa.zip");
            }
            using var pinnedRestore = new MultipartFormDataContent();
            pinnedRestore.Add(new ByteArrayContent(differentPackageBackup.ToArray()), "file", "apps-backup.zip");
            JsonElement pinnedConflict = await server.CallAsync("settings/restore?apps=true", server.AdminToken, pinnedRestore);
            Assert.Equal("error", pinnedConflict.GetProperty("status").GetString());
            Assert.Contains("/apps/packages/FilterAaaa/packageSha256", pinnedConflict.GetProperty("errorMessage").GetString());
            Assert.Equal(packageDigest, Convert.ToHexString(SHA256.HashData(
                await File.ReadAllBytesAsync(Path.Combine(appFolder, "FilterAaaa.zip")))));

            var appManager = server.Applications;
            var pinnedApp = appManager.Applications["FilterAaaa"];
            using var equalTransfer = new MemoryStream();
            using (var archive = new ZipArchive(equalTransfer, ZipArchiveMode.Create, leaveOpen: true))
                archive.CreateEntryFromFile(Path.Combine(appFolder, "FilterAaaa.zip"), "apps/FilterAaaa/FilterAaaa.zip");
            equalTransfer.Position = 0;
            using (var archive = new ZipArchive(equalTransfer, ZipArchiveMode.Read, leaveOpen: true))
            {
                var transfers = DnsApplicationManager.ReadClusterTransfer(archive);
                appManager.CheckClusterTransfer(transfers);
                await appManager.ApplyClusterTransferAsync(transfers, []);
            }
            Assert.Same(pinnedApp, appManager.Applications["FilterAaaa"]);

            differentPackageBackup.Position = 0;
            using (var archive = new ZipArchive(differentPackageBackup, ZipArchiveMode.Read, leaveOpen: true))
            {
                var transfers = DnsApplicationManager.ReadClusterTransfer(archive);
                var conflict = Assert.Throws<InvalidDataException>(() => appManager.CheckClusterTransfer(transfers));
                Assert.Contains("/apps/packages/FilterAaaa/packageSha256", conflict.Message);
            }
            Assert.Empty((await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA)).Answer);

            async Task<string> PreviewAsync(string input, bool expectChanges = true, string changePath = "/apps/packages/FilterAaaa/configuration")
            {
                using var body = new StringContent(input, Encoding.UTF8, "application/json");
                JsonElement plan = await server.CallAsync("settings/config/plan", server.AdminToken, body);
                LoopbackWebService.AssertOk(plan);
                JsonElement response = plan.GetProperty("response");
                if (expectChanges)
                    Assert.Contains(response.GetProperty("changes").EnumerateArray(),
                        change => change.GetProperty("path").ValueEquals(changePath));
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
