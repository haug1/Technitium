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
