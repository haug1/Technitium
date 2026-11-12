using DnsServerCore.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class ConfigurationManifestTests : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("technitium-manifest-test-");

        public static IEnumerable<object[]> ShippedExamples()
        {
            string directory = Path.Combine(AppContext.BaseDirectory, "ManifestExamples");
            foreach (string file in Directory.GetFiles(directory, "*.json"))
                yield return [Path.GetFileName(file)];
        }

        [Theory]
        [MemberData(nameof(ShippedExamples))]
        public void ShippedExamplePassesThePublishedSchemaAndManifestValidation(string fileName)
        {
            string path = Path.Combine(AppContext.BaseDirectory, "ManifestExamples", fileName);

            ConfigurationManifest manifest = ConfigurationManifest.Load(path);
            ConfigurationPlan.CheckApplySupport(manifest);
        }

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

        [Theory]
        [InlineData("""{"heartbeatRefreshSeconds":90,"configRefreshSeconds":60}""", "/cluster/configRefreshSeconds")]
        [InlineData("""{"bootstrap":{"role":"Secondary","primaryUrl":"http://primary.example.test/"}}""", "/cluster/bootstrap/primaryUrl")]
        [InlineData("""{"bootstrap":{"role":"Secondary","primaryUrl":"https://primary.example.test/join"}}""", "/cluster/bootstrap/primaryUrl")]
        [InlineData("""{"bootstrap":{"role":"Secondary"},"configRefreshSeconds":120}""", "Only the Primary")]
        [InlineData("""{"bootstrap":{"role":"Primary","username":"operator"}}""", "/cluster/bootstrap/username")]
        [InlineData("""{"bootstrap":{"role":"Secondary","primaryAddress":"192.0.2.1","primaryAddresses":["192.0.2.2"]}}""", "/cluster/bootstrap/primaryAddresses")]
        public void RejectsInvalidClusterDeclarationsWithoutAServer(string cluster, string diagnostic)
        {
            string path = WriteManifest($$"""{"schemaVersion":1,"cluster":{{cluster}} }""");
            var error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));
            Assert.Contains(diagnostic, error.Message);
        }

        [Theory]
        [InlineData("""{"configRefreshSeconds":30}""")]
        [InlineData("""{"bootstrap":{"role":"Secondary"}}""")]
        public void AcceptsClusterDeclarationsThatDependOnCurrentState(string cluster)
        {
            string path = WriteManifest($$"""{"schemaVersion":1,"cluster":{{cluster}} }""");
            ConfigurationManifest.Load(path).ValidateReferences();
        }

        [Theory]
        [InlineData("""{"proof":{"type":"NSEC","iterations":1}}""", "/proof/iterations")]
        [InlineData("""{"enabled":false,"dnsKeyTtl":3600}""", "Enable DNSSEC")]
        [InlineData("""{"keys":{"next":{"role":"ZoneSigningKey","algorithm":"ECDSA","curve":"unknown"}}}""", "/keys/next/algorithm")]
        [InlineData("""{"keys":{"next":{"role":"ZoneSigningKey","algorithm":"RSA","hashAlgorithm":"SHA256","keySize":512}}}""", "/keys/next/keySize")]
        public void RejectsInvalidDnssecSettingsWithoutAServer(string signing, string diagnostic)
        {
            string path = WriteManifest($$"""{"schemaVersion":1,"zones":{"example.test":{"dnssec":{{signing}} } } }""");

            var error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));

            Assert.Contains("/zones/example.test/dnssec", error.Message);
            Assert.Contains(diagnostic, error.Message);
        }

        [Fact]
        public void ValidatesDnssecPrivateKeyFilesWithoutPrintingTheirContents()
        {
            const string keyFile = "local-signing-key.pem";
            string path = WriteManifest("""
                {"schemaVersion":1,"zones":{"example.test":{"dnssec":{"keys":{
                  "next":{"role":"ZoneSigningKey","algorithm":"ECDSA","curve":"P256","privateKey":{"file":"local-signing-key.pem"}}
                }}}}}
                """);
            var manifest = ConfigurationManifest.Load(path);
            string keyPath = Path.Combine(_directory.FullName, keyFile);
            const string invalidKey = "malformed-operator-secret";
            File.WriteAllText(keyPath, invalidKey);

            var error = Assert.Throws<InvalidDataException>(manifest.ValidateReferences);
            Assert.Contains("/zones/example.test/dnssec/keys/next/privateKey", error.Message);
            Assert.DoesNotContain(invalidKey, error.Message);
            Assert.DoesNotContain(keyFile, error.Message);

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
            manifest.ValidateReferences();
        }

        [Fact]
        public void ValidatesExportedAppPackageDigestAgainstLocalArchive()
        {
            string archivePath = Path.Combine(_directory.FullName, "app.zip");
            using (ZipArchive archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
                archive.CreateEntry("dnsApp.config");

            string digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(archivePath)));
            string manifest = WriteManifest(Manifest(digest));
            ConfigurationManifest.Load(manifest).ValidateReferences();

            manifest = WriteManifest(Manifest(new string('0', 64)));
            var error = Assert.Throws<InvalidDataException>(ConfigurationManifest.Load(manifest).ValidateReferences);
            Assert.Contains("/apps/packages/Fixture/packageSha256", error.Message);
            Assert.DoesNotContain("app.zip", error.Message);

            static string Manifest(string hash) => $$"""
                {"schemaVersion":1,"apps":{"packages":{"Fixture":{"packageSha256":"{{hash}}","source":{"file":"app.zip"} } } } }
                """;
        }

        [Fact]
        public void RejectsConflictingAppDigestPinsWithoutDownloading()
        {
            string packageDigest = new string('0', 64);
            string sourceDigest = new string('1', 64);
            string path = WriteManifest($$"""
                {"schemaVersion":1,"apps":{"packages":{"Fixture":{"packageSha256":"{{packageDigest}}",
                 "source":{"url":"https://example.test/app.zip","sha256":"{{sourceDigest}}"} } } } }
                """);

            var error = Assert.Throws<InvalidDataException>(ConfigurationManifest.Load(path).ValidateReferences);
            Assert.Contains("/apps/packages/Fixture/source/sha256", error.Message);
        }

        [Fact]
        public void RejectsAppNamesThatAreNotSingleDirectoryNames()
        {
            string path = WriteManifest("""
                {"schemaVersion":1,"apps":{"packages":{"one/two":null}}}
                """);

            var error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));
            Assert.Contains("/apps/packages/one~1two", error.Message);
        }

        [Fact]
        public void RejectsCaseAliasedAppDirectoriesOnWindows()
        {
            string path = WriteManifest("""
                {"schemaVersion":1,"apps":{"packages":{"Fixture":null,"fixture":null}}}
                """);

            if (OperatingSystem.IsWindows())
            {
                var error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));
                Assert.Contains("/apps/packages/fixture", error.Message);
            }
            else
            {
                ConfigurationManifest.Load(path);
            }
        }

        [Fact]
        public void OfflineValidationRejectsInvalidAppVersionPins()
        {
            string path = WriteManifest("""
                {"schemaVersion":1,"apps":{"packages":{"Fixture":{"version":"fixture-invalid-version",
                 "source":{"url":"https://example.test/app.zip"}}}}}
                """);
            var error = Assert.Throws<InvalidDataException>(ConfigurationManifest.Load(path).ValidateReferences);
            Assert.Contains("/apps/packages/Fixture/version", error.Message);
            Assert.DoesNotContain("fixture-invalid-version", error.Message);

            path = WriteManifest("""
                {"schemaVersion":1,"apps":{"packages":{"Fixture":{"version":"1.2.3",
                 "source":{"url":"https://example.test/app.zip"}}}}}
                """);
            ConfigurationManifest.Load(path).ValidateReferences();
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

        [Theory]
        [InlineData("https://user:fixture-secret@example.test/app.zip")]
        [InlineData("https://example.test/app.zip#fixture-secret")]
        [InlineData("https://[fixture-secret]/app.zip")]
        public void OfflineValidationRejectsInvalidRemotePackageUrlsWithoutEchoingThem(string url)
        {
            string path = WriteManifest($$"""
                {"schemaVersion":1,"apps":{"packages":{"Fixture":{"source":{"url":"{{url}}"} } } } }
                """);

            var error = Assert.Throws<InvalidDataException>(ConfigurationManifest.Load(path).ValidateReferences);
            Assert.Contains("/apps/packages/Fixture/source/url", error.Message);
            Assert.DoesNotContain("fixture-secret", error.Message);
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

        [Fact]
        public void ZonePolicyValidationRejectsAnInvalidNetworkPrefixWithoutEchoingIt()
        {
            string path = WriteManifest("""
                {"schemaVersion":1,"zones":{"policy.test":{"query":{"networkAcl":["192.0.2.0/64"]}}}}
                """);
            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));
            Assert.Contains("/zones/policy.test/query/networkAcl/0", error.Message);
            Assert.DoesNotContain("192.0.2.", error.Message);
        }

        [Theory]
        [InlineData("ttl", 604801)]
        [InlineData("answerTtl", 301)]
        public void CacheManifestRejectsStaleTtlsAboveTheRuntimeLimit(string setting, int ttl)
        {
            string path = WriteManifest($$"""
                {"schemaVersion":1,"dns":{"cache":{"serveStale":{"{{setting}}":{{ttl}} } } } }
                """);

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));
            Assert.Contains("/dns/cache/serveStale/" + setting, error.Message);
        }

        [Fact]
        public void CachePrefetchRejectsAnEnabledPolicyWithZeroTrigger()
        {
            string path = WriteManifest("""
                {"schemaVersion":1,"dns":{"cache":{"prefetch":{"enabled":true,"trigger":0}}}}
                """);
            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));
            Assert.Contains("/dns/cache/prefetch/trigger", error.Message);
        }

        [Fact]
        public void RateLimitManifestRejectsDuplicatePrefixes()
        {
            string path = WriteManifest("""
                {"schemaVersion":1,"dns":{"rateLimits":{"ipv4":[{"prefix":24,"udpLimit":10,"tcpLimit":20},
                    {"prefix":24,"udpLimit":20,"tcpLimit":30}]}}}
                """);

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ConfigurationManifest.Load(path));
            Assert.Contains("/dns/rateLimits/ipv4/1/prefix", error.Message);
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
