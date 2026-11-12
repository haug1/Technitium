using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Dns.ZoneManagers;

namespace DnsServerCore.Configuration
{
    public enum ConfigurationChangeKind
    {
        Add,
        Update,
        Remove
    }

    public sealed record ConfigurationChange(string Path, ConfigurationChangeKind Kind, bool RestartWebService);

    public static class ConfigurationPlan
    {
        private sealed record Setting(string ApiField, JsonElement Default, bool RestartWebService,
            Func<JsonElement, JsonElement> Normalize = null, bool OmitFromExport = false);

        private static readonly Dictionary<string, Setting> _settings = new(StringComparer.Ordinal)
        {
            ["/dns/authoritative/defaultRecordTtl"] = Field("defaultRecordTtl", 3600),
            ["/dns/authoritative/defaultNsRecordTtl"] = Field("defaultNsRecordTtl", 14400),
            ["/dns/authoritative/defaultSoaRecordTtl"] = Field("defaultSoaRecordTtl", 900),
            ["/dns/authoritative/defaultResponsiblePerson"] = new("defaultResponsiblePerson",
                JsonSerializer.SerializeToElement<string>(null), false, NormalizeResponsiblePerson),
            ["/dns/authoritative/minSoaRefresh"] = Field("minSoaRefresh", 300),
            ["/dns/authoritative/minSoaRetry"] = Field("minSoaRetry", 300),
            ["/dns/authoritative/useSoaSerialDateScheme"] = Field("useSoaSerialDateScheme", false),
            ["/dns/checkForUpdates"] = Field("dnsServerEnableCheckForUpdate", true),
            ["/dns/dnssecValidation"] = Field("dnssecValidation", true),
            ["/dns/udpPayloadSize"] = Field("udpPayloadSize", 1232),
            ["/web/httpPort"] = Field("webServiceHttpPort", 5380, restartWebService: true),
            ["/web/tlsPort"] = Field("webServiceTlsPort", 53443, restartWebService: true),
            ["/logging/destination"] = Field("loggingType", "File"),
            ["/logging/noStackTrace"] = Field("noStackTrace", false),
            ["/logging/useLocalTime"] = Field("useLocalTime", false),
            ["/logging/retentionDays"] = Field("maxLogFileDays", 365),
            ["/logging/ignoreResolverLogs"] = Field("ignoreResolverLogs", false),
            ["/logging/logQueries"] = Field("logQueries", false),
            ["/statistics/inMemory"] = Field("enableInMemoryStats", false),
            ["/statistics/retentionDays"] = Field("maxStatFileDays", 365),
            ["/blocklists/updateIntervalHours"] = Field("blockListUpdateIntervalHours", 24),
            ["/blocklists/sources"] = new("blockListUrls", JsonSerializer.SerializeToElement(Array.Empty<string>()),
                false, NormalizeBlockListSources, OmitFromExport: true),
            ["/apps/autoUpdate"] = Field("dnsAppsEnableAutomaticUpdate", true)
        };

        public static IReadOnlyList<ConfigurationChange> Create(ConfigurationManifest manifest, JsonElement currentSettings)
        {
            RequireSettingsObject(currentSettings);

            var changes = new List<ConfigurationChange>();
            foreach (JsonProperty section in manifest.Settings.EnumerateObject())
            {
                if (section.Name is "schemaVersion" or "$schema")
                    continue;

                Compare(section.Value, AppendPath("", section.Name), currentSettings, changes);
            }

            return changes.OrderBy(change => change.Path, StringComparer.Ordinal).ToArray();
        }

        public static JsonObject Export(JsonElement currentSettings)
        {
            RequireSettingsObject(currentSettings);
            var manifest = new JsonObject { ["schemaVersion"] = ConfigurationManifest.CurrentSchemaVersion };

            foreach (var (path, setting) in _settings.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                if (setting.OmitFromExport)
                    continue;

                JsonElement value = GetCurrentSetting(currentSettings, path, setting);
                string[] components = path[1..].Split('/');
                JsonObject section = manifest;
                for (int i = 0; i < components.Length - 1; i++)
                {
                    if (section[components[i]] is not JsonObject child)
                    {
                        child = new JsonObject();
                        section.Add(components[i], child);
                    }

                    section = child;
                }

                section.Add(components[^1], JsonNode.Parse(value.GetRawText()));
            }

            return manifest;
        }

        private static void RequireSettingsObject(JsonElement currentSettings)
        {
            if (currentSettings.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("The server did not return a settings object.");
        }

        private static JsonElement GetCurrentSetting(JsonElement currentSettings, string path, Setting setting)
        {
            if (!currentSettings.TryGetProperty(setting.ApiField, out JsonElement value))
                throw new InvalidDataException($"{path}: The server did not return the current setting.");

            return value;
        }

        private static void Compare(JsonElement desired, string path, JsonElement currentSettings, List<ConfigurationChange> changes)
        {
            if (_settings.TryGetValue(path, out Setting setting))
            {
                JsonElement current = GetCurrentSetting(currentSettings, path, setting);

                JsonElement candidate;
                try
                {
                    candidate = desired.ValueKind == JsonValueKind.Null ? setting.Default : (setting.Normalize?.Invoke(desired) ?? desired);
                }
                catch (Exception ex) when (ex is ArgumentException or FormatException)
                {
                    throw new InvalidDataException($"{path}: Value is invalid for this setting.");
                }
                if (!JsonElement.DeepEquals(current, candidate))
                {
                    ConfigurationChangeKind kind = current.ValueKind == JsonValueKind.Null
                        ? ConfigurationChangeKind.Add
                        : candidate.ValueKind == JsonValueKind.Null ? ConfigurationChangeKind.Remove : ConfigurationChangeKind.Update;
                    changes.Add(new ConfigurationChange(path, kind, setting.RestartWebService));
                }

                return;
            }

            if ((desired.ValueKind == JsonValueKind.Object) && _settings.Keys.Any(field => field.StartsWith(path + "/", StringComparison.Ordinal)))
            {
                foreach (JsonProperty property in desired.EnumerateObject())
                    Compare(property.Value, AppendPath(path, property.Name), currentSettings, changes);

                return;
            }

            throw new InvalidDataException($"{JsonEncodedText.Encode(path)}: Planning for this setting is not implemented.");
        }

        private static JsonElement NormalizeResponsiblePerson(JsonElement value)
        {
            string address = value.GetString();
            return JsonSerializer.SerializeToElement(address.Length == 0 ? null : new MailAddress(address).Address);
        }

        private static JsonElement NormalizeBlockListSources(JsonElement value)
        {
            string[] urls = value.EnumerateArray().Select(item => item.GetString()).ToArray();
            return JsonSerializer.SerializeToElement(BlockListZoneManager.NormalizeBlockListUrls(urls));
        }

        private static Setting Field<T>(string apiField, T defaultValue, bool restartWebService = false)
        {
            return new Setting(apiField, JsonSerializer.SerializeToElement(defaultValue), restartWebService);
        }

        private static string AppendPath(string path, string name)
        {
            return path + "/" + name.Replace("~", "~0", StringComparison.Ordinal).Replace("/", "~1", StringComparison.Ordinal);
        }
    }
}
