using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using DnsServerCore.Dns;
using System.Security.Cryptography;
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

    public sealed record ConfigurationChange(string Path, ConfigurationChangeKind Kind, bool RestartWebService, bool RestartDnsService = false);

    public static class ConfigurationPlan
    {
        private sealed record Setting(string ApiField, JsonElement Default, bool RestartWebService,
            Func<JsonElement, JsonElement> Normalize = null, bool OmitFromExport = false, bool CanApply = false);

        private const string DnsEndpointsPath = "/dns/localEndpoints";
        private const string WebAddressesPath = "/web/localAddresses";

        private static readonly Dictionary<string, Setting> _settings = new(StringComparer.Ordinal)
        {
            [DnsEndpointsPath] = Field("dnsServerLocalEndPoints", new[] { "0.0.0.0:53", "[::]:53" }, canApply: true),
            ["/dns/authoritative/defaultRecordTtl"] = Field("defaultRecordTtl", 3600, canApply: true),
            ["/dns/authoritative/defaultNsRecordTtl"] = Field("defaultNsRecordTtl", 14400, canApply: true),
            ["/dns/authoritative/defaultSoaRecordTtl"] = Field("defaultSoaRecordTtl", 900, canApply: true),
            ["/dns/authoritative/defaultResponsiblePerson"] = new("defaultResponsiblePerson",
                JsonSerializer.SerializeToElement<string>(null), false, NormalizeResponsiblePerson),
            ["/dns/authoritative/minSoaRefresh"] = Field("minSoaRefresh", 300, canApply: true),
            ["/dns/authoritative/minSoaRetry"] = Field("minSoaRetry", 300, canApply: true),
            ["/dns/authoritative/useSoaSerialDateScheme"] = Field("useSoaSerialDateScheme", false, canApply: true),
            ["/dns/checkForUpdates"] = Field("dnsServerEnableCheckForUpdate", true),
            ["/dns/dnssecValidation"] = Field("dnssecValidation", true),
            ["/dns/udpPayloadSize"] = Field("udpPayloadSize", 1232),
            [WebAddressesPath] = Field("webServiceLocalAddresses", Array.Empty<string>(), restartWebService: true),
            ["/web/httpPort"] = Field("webServiceHttpPort", 5380, restartWebService: true),
            ["/web/tlsPort"] = Field("webServiceTlsPort", 53443, restartWebService: true),
            ["/logging/destination"] = Field("loggingType", "File", canApply: true),
            ["/logging/folder"] = Field("logFolder", "logs", canApply: true),
            ["/logging/noStackTrace"] = Field("noStackTrace", false, canApply: true),
            ["/logging/useLocalTime"] = Field("useLocalTime", false, canApply: true),
            ["/logging/retentionDays"] = Field("maxLogFileDays", 365, canApply: true),
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
            return Create(manifest, currentSettings, null);
        }

        internal static IReadOnlyList<ConfigurationChange> Create(ConfigurationManifest manifest, JsonElement currentSettings, LogManager log)
        {
            RequireSettingsObject(currentSettings);

            var changes = new List<ConfigurationChange>();
            foreach (JsonProperty section in manifest.Settings.EnumerateObject())
            {
                if (section.Name is "schemaVersion" or "$schema")
                    continue;

                Compare(section.Value, AppendPath("", section.Name), currentSettings, changes, log);
            }

            return changes.OrderBy(change => change.Path, StringComparer.Ordinal).ToArray();
        }

        internal static string GetRevision(ConfigurationManifest manifest, JsonElement currentSettings, byte[] key)
        {
            var data = new ArrayBufferWriter<byte>();
            using (var writer = new Utf8JsonWriter(data))
            {
                writer.WriteStartArray();
                manifest.Settings.WriteTo(writer);
                writer.WriteStartObject();
                foreach (var (path, setting) in _settings.OrderBy(entry => entry.Key, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(path);
                    GetCurrentSetting(currentSettings, path, setting).WriteTo(writer);
                }
                writer.WriteEndObject();
                if (currentSettings.TryGetProperty("managedSettings", out JsonElement ownership))
                    ownership.WriteTo(writer);
                writer.WriteEndArray();
            }

            // The snapshot can include sensitive URLs. Use a server-local key so the
            // revision cannot be used to guess values from the preview response.
            return Convert.ToHexString(HMACSHA256.HashData(key, data.WrittenSpan));
        }

        internal static Task ApplyAsync(ConfigurationManifest manifest, LogManager log, DnsServer dns, IReadOnlyList<IPEndPoint> endpoints, bool alreadyActive = false)
        {
            CheckApplySupport(manifest);

            manifest.Settings.TryGetProperty("logging", out JsonElement logging);
            JsonElement? destination = GetLoggingValue(logging, "destination");
            JsonElement? noStackTrace = GetLoggingValue(logging, "noStackTrace");
            JsonElement? retention = GetLoggingValue(logging, "retentionDays");
            JsonElement? localTime = GetLoggingValue(logging, "useLocalTime");
            string folder = logging.ValueKind == JsonValueKind.Object && logging.TryGetProperty("folder", out JsonElement folderValue)
                ? GetManifestLogFolder(folderValue, log) : null;

            return dns.ApplyManifestDnsSettingsAsync(endpoints, GetAuthoritativeDefaults(manifest), alreadyActive, writeDnsConfig => log.ApplyManifestSettings(
                destination.HasValue ? Enum.Parse<LoggingType>(destination.Value.GetString()) : null,
                noStackTrace?.GetBoolean(),
                retention.HasValue ? decimal.ToInt32(retention.Value.GetDecimal()) : null,
                localTime?.GetBoolean(),
                folder,
                writeDnsConfig));
        }

        private static DnsServer.AuthoritativeDefaults GetAuthoritativeDefaults(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns) ||
                !dns.TryGetProperty("authoritative", out JsonElement authoritative))
                return default;

            return new DnsServer.AuthoritativeDefaults(ReadTtl("defaultRecordTtl"), ReadTtl("defaultNsRecordTtl"), ReadTtl("defaultSoaRecordTtl"),
                ReadValue("useSoaSerialDateScheme")?.GetBoolean(), ReadTtl("minSoaRefresh"), ReadTtl("minSoaRetry"));

            uint? ReadTtl(string name)
            {
                JsonElement? value = ReadValue(name);
                return value.HasValue ? decimal.ToUInt32(value.Value.GetDecimal()) : null;
            }

            JsonElement? ReadValue(string name)
            {
                if (!authoritative.TryGetProperty(name, out JsonElement value))
                    return null;
                return value.ValueKind == JsonValueKind.Null ? _settings["/dns/authoritative/" + name].Default : value;
            }
        }

        internal static void CheckClusterApplySupport(ConfigurationManifest manifest, bool clusterInitialized)
        {
            if (clusterInitialized && GetAuthoritativeDefaults(manifest).HasValues)
                throw new InvalidDataException("/dns/authoritative: Applying authoritative defaults to a cluster is not implemented.");
        }

        internal static void CheckApplySupport(ConfigurationManifest manifest)
        {
            foreach (JsonProperty section in manifest.Settings.EnumerateObject())
            {
                if (section.Name is "schemaVersion" or "$schema")
                    continue;
                CheckApplySupport(section.Value, AppendPath("", section.Name));
            }
        }

        private static void CheckApplySupport(JsonElement value, string path)
        {
            if (_settings.TryGetValue(path, out Setting setting) && setting.CanApply)
                return;

            if ((value.ValueKind == JsonValueKind.Object) &&
                _settings.Any(entry => entry.Value.CanApply && entry.Key.StartsWith(path + "/", StringComparison.Ordinal)))
            {
                foreach (JsonProperty field in value.EnumerateObject())
                    CheckApplySupport(field.Value, AppendPath(path, field.Name));
                return;
            }

            throw new InvalidDataException($"{JsonEncodedText.Encode(path)}: Applying this setting is not implemented.");
        }

        private static JsonElement? GetLoggingValue(JsonElement logging, string name)
        {
            if ((logging.ValueKind == JsonValueKind.Undefined) || !logging.TryGetProperty(name, out JsonElement value))
                return null;
            return value.ValueKind == JsonValueKind.Null ? _settings["/logging/" + name].Default : value;
        }

        public static JsonObject Export(JsonElement currentSettings)
        {
            return Export(currentSettings, includePreviewOnly: true);
        }

        public static JsonObject Export(JsonElement currentSettings, bool includePreviewOnly)
        {
            RequireSettingsObject(currentSettings);
            var manifest = new JsonObject { ["schemaVersion"] = ConfigurationManifest.CurrentSchemaVersion };

            foreach (var (path, setting) in _settings.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                if (setting.OmitFromExport || (!includePreviewOnly && !setting.CanApply))
                    continue;

                JsonElement value = GetCurrentSetting(currentSettings, path, setting);
                if (path == WebAddressesPath)
                    value = JsonSerializer.SerializeToElement(ReadWebAddresses(value).Select(address => address.ToString()).ToArray());

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

        private static void Compare(JsonElement desired, string path, JsonElement currentSettings, List<ConfigurationChange> changes, LogManager log)
        {
            if (_settings.TryGetValue(path, out Setting setting))
            {
                JsonElement current = GetCurrentSetting(currentSettings, path, setting);

                JsonElement candidate;
                try
                {
                    if ((path == "/logging/folder") && (log is not null))
                    {
                        candidate = JsonSerializer.SerializeToElement(GetManifestLogFolder(desired, log));
                        current = JsonSerializer.SerializeToElement(log.NormalizeLogFolder(current.GetString()));
                    }
                    else if (path == WebAddressesPath)
                    {
                        IReadOnlyList<IPAddress> addresses = DnsWebService.NormalizeWebLocalAddresses(ReadWebAddresses(desired));
                        if (addresses.Count == 0)
                            throw new InvalidDataException("/web/localAddresses: No declared address family is available on this server.");

                        candidate = SortAddresses(addresses.Select(address => address.ToString()));
                        current = SortAddresses(ReadWebAddresses(current).Select(address => address.ToString()));
                    }
                    else if (path == DnsEndpointsPath)
                    {
                        var endpoints = ConfigurationManifest.ReadDnsLocalEndPoints(desired);
                        candidate = SortAddresses(endpoints.Select(endpoint => endpoint.ToString()));
                        current = SortAddresses(current.EnumerateArray().Select(endpoint => endpoint.GetString()));
                    }
                    else
                    {
                        candidate = desired.ValueKind == JsonValueKind.Null ? setting.Default : (setting.Normalize?.Invoke(desired) ?? desired);
                    }
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
                    changes.Add(new ConfigurationChange(path, kind, setting.RestartWebService, path == DnsEndpointsPath));
                }

                return;
            }

            if ((desired.ValueKind == JsonValueKind.Object) && _settings.Keys.Any(field => field.StartsWith(path + "/", StringComparison.Ordinal)))
            {
                foreach (JsonProperty property in desired.EnumerateObject())
                    Compare(property.Value, AppendPath(path, property.Name), currentSettings, changes, log);

                return;
            }

            throw new InvalidDataException($"{JsonEncodedText.Encode(path)}: Planning for this setting is not implemented.");
        }

        private static IPAddress[] ReadWebAddresses(JsonElement value)
        {
            return value.ValueKind == JsonValueKind.Null
                ? Array.Empty<IPAddress>()
                : value.EnumerateArray().Select(item => IPAddress.Parse(item.GetString())).ToArray();
        }

        private static JsonElement SortAddresses(IEnumerable<string> endpoints)
        {
            return JsonSerializer.SerializeToElement(endpoints.OrderBy(endpoint => endpoint, StringComparer.Ordinal).ToArray());
        }

        private static string GetManifestLogFolder(JsonElement value, LogManager log)
        {
            try
            {
                return log.NormalizeLogFolder(value.ValueKind == JsonValueKind.Null ? log.DefaultLogFolder : value.GetString());
            }
            catch (ArgumentException)
            {
                throw new InvalidDataException("/logging/folder: Invalid log directory.");
            }
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

        private static Setting Field<T>(string apiField, T defaultValue, bool restartWebService = false, bool canApply = false)
        {
            return new Setting(apiField, JsonSerializer.SerializeToElement(defaultValue), restartWebService, CanApply: canApply);
        }

        private static string AppendPath(string path, string name)
        {
            return path + "/" + name.Replace("~", "~0", StringComparison.Ordinal).Replace("/", "~1", StringComparison.Ordinal);
        }
    }
}
