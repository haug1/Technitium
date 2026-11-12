using DnsServerCore.Configuration;
using System;
using System.IO;
using System.Text.Json;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class ConfigurationManifestTests : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("technitium-manifest-test-");

        [Fact]
        public void ExplicitResetIsDistinctFromAnOmittedSetting()
        {
            string path = WriteManifest("""{"schemaVersion":1,"logging":{"retentionDays":null}}""");

            ConfigurationManifest manifest = ConfigurationManifest.Load(path);

            JsonElement logging = manifest.Settings.GetProperty("logging");
            Assert.Equal(JsonValueKind.Null, logging.GetProperty("retentionDays").ValueKind);
            Assert.False(logging.TryGetProperty("logQueries", out _));
        }

        [Theory]
        [InlineData("""{"schemaVersion":2}""", "/schemaVersion", "Unsupported schema version")]
        [InlineData("""{"schemaVersion":1,"dns":{"retryCount":2}}""", "/dns/retryCount", "Unknown setting")]
        [InlineData("""{"schemaVersion":1,"logging":{"logQueries":true,"logQueries":false}}""", "/logging/logQueries", "Duplicate setting")]
        [InlineData("""{"schemaVersion":1,"zones":{"EXAMPLE.test":{},"example.test.":{}}}""", "/zones/example.test.", "Duplicate canonical DNS name")]
        [InlineData("""{"schemaVersion":1,"dns":{"tuning":{"clientTimeoutMs":999}}}""", "/dns/tuning/clientTimeoutMs", "outside the supported range")]
        public void RejectsInvalidManifestsWithFieldDiagnostics(string json, string field, string diagnostic)
        {
            string path = WriteManifest(json);

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));

            Assert.Contains(field, error.Message);
            Assert.Contains(diagnostic, error.Message);
        }

        [Fact]
        public void RejectsPlaintextSecretWithoutPrintingIt()
        {
            string path = WriteManifest("""{"schemaVersion":1,"web":{"certificate":{"password":"private-value"}}}""");

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));

            Assert.Contains("/web/certificate/password", error.Message);
            Assert.DoesNotContain("private-value", error.Message);
        }

        [Fact]
        public void ResolvesRelativeFileReferencesBesideTheManifest()
        {
            string path = WriteManifest("""{"schemaVersion":1,"web":{"certificate":{"password":{"file":"private-name"}}}}""");
            ConfigurationManifest manifest = ConfigurationManifest.Load(path);

            InvalidDataException error = Assert.Throws<InvalidDataException>(manifest.ValidateReferences);
            Assert.Contains("/web/certificate/password", error.Message);
            Assert.DoesNotContain("private-name", error.Message);

            File.WriteAllText(Path.Combine(_directory.FullName, "private-name"), "fixture-value");
            manifest.ValidateReferences();
        }

        [Fact]
        public void FileReferenceValidationRejectsEmptyAndInvalidTextWithoutLeakingThePath()
        {
            string path = WriteManifest("""{"schemaVersion":1,"web":{"certificate":{"password":{"file":"private-file"}}}}""");
            ConfigurationManifest manifest = ConfigurationManifest.Load(path);
            string secretPath = Path.Combine(_directory.FullName, "private-file");

            File.WriteAllText(secretPath, "");
            InvalidDataException empty = Assert.Throws<InvalidDataException>(manifest.ValidateReferences);
            Assert.Contains("/web/certificate/password", empty.Message);
            Assert.Contains("empty", empty.Message);
            Assert.DoesNotContain("private-file", empty.ToString());

            File.WriteAllBytes(secretPath, [0xff, 0xc0, 0x80]);
            InvalidDataException invalid = Assert.Throws<InvalidDataException>(manifest.ValidateReferences);
            Assert.Contains("/web/certificate/password", invalid.Message);
            Assert.DoesNotContain("private-file", invalid.ToString());
        }

        [Fact]
        public void NamedSettingsCanUseNamesThatLookLikeReferenceFields()
        {
            string path = WriteManifest("""{"schemaVersion":1,"auth":{"sso":{"groupMap":{"file":"Local group"}}}}""");

            ConfigurationManifest.Load(path).ValidateReferences();
        }

        [Fact]
        public void MissingEnvironmentReferenceReportsItsField()
        {
            string variable = "TECHNITIUM_TEST_" + Guid.NewGuid().ToString("N");
            string path = WriteManifest(JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                auth = new { ldap = new { bindPassword = new { environment = variable } } }
            }));
            ConfigurationManifest manifest = ConfigurationManifest.Load(path);

            InvalidDataException error = Assert.Throws<InvalidDataException>(manifest.ValidateReferences);

            Assert.Contains("/auth/ldap/bindPassword", error.Message);
            Assert.DoesNotContain(variable, error.Message);
        }

        [Theory]
        [InlineData("@", "A", """{"zoneFile":"bad-address"}""", "/data/zoneFile")]
        [InlineData("@", "A", """{"zoneFile":"192.0.2.1\nother.lab.example.test. 300 IN A 192.0.2.2"}""", "/data/zoneFile")]
        [InlineData("outside.test", "A", "{\"zoneFile\":\"192.0.2.1\"}", "/owner")]
        [InlineData("@", "UNKNOWN", "{\"rawHex\":\"00\"}", "/type")]
        [InlineData("@", "A", "{\"forwarder\":{\"address\":\"192.0.2.1\"}}", "/data/forwarder")]
        [InlineData("@", "TXT", "{\"txtBase64\":[\"invalid***\"]}", "/data/txtBase64/0")]
        public void ZoneRecordValidationReportsInvalidField(string owner, string type, string data, string suffix)
        {
            string path = WriteManifest($$"""
                {"schemaVersion":1,"zones":{"lab.example.test":{"records":[{"owner":"{{owner}}","type":"{{type}}","data":{{data}} }] } } }
                """);

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));
            Assert.Contains("/zones/lab.example.test/records/0" + suffix, error.Message);
            Assert.DoesNotContain("invalid***", error.Message);
            Assert.DoesNotContain("bad-address", error.Message);
        }

        [Fact]
        public void ZoneRecordValidationAcceptsApexAndCanonicalInternationalizedNames()
        {
            string path = WriteManifest("""
                {"schemaVersion":1,"zones":{"bücher.test.":{"records":[
                    {"owner":"@","type":"TXT","data":{"txtBase64":["SGVsbG8="]}},
                    {"owner":"@","type":"MX","data":{"zoneFile":"10 mail"}},
                    {"owner":"@","type":"TXT","data":{"zoneFile":"( \"one\"\n \"two\" )"}},
                    {"owner":"www.XN--BCHER-KVA.TEST.","type":65280,"data":{"rawHex":"00"}}
                ]}}}
                """);

            ConfigurationManifest.Load(path);
        }

        [Theory]
        [InlineData("""{"startingAddress":"192.0.2.50","endingAddress":"192.0.2.40"}""", "/endingAddress")]
        [InlineData("""{"startingAddress":"192.0.2.0","endingAddress":"192.0.2.80","subnetMask":"255.255.255.0"}""", "/startingAddress")]
        [InlineData("""{"exclusions":[{"startingAddress":"192.0.2.30","endingAddress":"192.0.2.20"}]}""", "/exclusions/0/endingAddress")]
        [InlineData("""{"startingAddress":"192.0.2.10","endingAddress":"192.0.2.30","reservations":{"02:00:00:00:00:01":{"address":"192.0.2.40"}}}""", "/reservations/02:00:00:00:00:01/address")]
        [InlineData("""{"reservations":{"02:00:00:00:00:01":null,"02-00-00-00-00-01":{"address":"192.0.2.20"}}}""", "/reservations/02-00-00-00-00-01")]
        [InlineData("""{"reservations":{"garbage":null}}""", "/reservations/garbage")]
        public void DhcpManifestRejectsInvalidScopeDeclarations(string declaration, string suffix)
        {
            string path = WriteManifest($$"""{"schemaVersion":1,"dhcp":{"scopes":{"Lab":{{declaration}} } } }""");

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));

            Assert.Contains("/dhcp/scopes/Lab" + suffix, error.Message);
        }

        [Fact]
        public void DhcpManifestAcceptsPartialScopeUpdates()
        {
            string path = WriteManifest("""
                {"schemaVersion":1,"dhcp":{"scopes":{
                    "Lab":{"enabled":false,"reservations":{"02:00:00:00:00:01":{"comments":"fixture"}}},
                    "lab":null
                }}}
                """);

            ConfigurationManifest.Load(path);
        }

        private string WriteManifest(string json)
        {
            string path = Path.Combine(_directory.FullName, ConfigurationManifest.DefaultFileName);
            File.WriteAllText(path, json);
            return path;
        }

        public void Dispose()
        {
            _directory.Delete(recursive: true);
        }
    }
}
