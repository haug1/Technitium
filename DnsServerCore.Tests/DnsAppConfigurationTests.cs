using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text.Json;
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

            await server.RestartAsync();
            DnsDatagram reloaded = await server.QueryAsync("www.example.test", DnsResourceRecordType.AAAA);
            Assert.Equal(DnsResponseCode.NoError, reloaded.RCODE);
            Assert.Empty(reloaded.Answer);
        }
    }
}
