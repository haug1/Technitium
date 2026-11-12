using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using DnsServerCore.Dns;
using DnsServerCore.Dns.ResourceRecords;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

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

        private const string BlockListSourcesPath = "/blocklists/sources";
        private const string ServerDomainPath = "/dns/serverDomain";
        private const string DnsEndpointsPath = "/dns/localEndpoints";
        private const string Ipv4SourcePath = "/dns/sourceNetworks/ipv4";
        private const string Ipv6SourcePath = "/dns/sourceNetworks/ipv6";
        private const string WebAddressesPath = "/web/localAddresses";

        private static readonly Dictionary<string, Setting> _settings = new(StringComparer.Ordinal)
        {
            [ServerDomainPath] = Field("dnsServerDomain", DnsServer.DefaultServerDomain, canApply: true),
            [DnsEndpointsPath] = Field("dnsServerLocalEndPoints", new[] { "0.0.0.0:53", "[::]:53" }, canApply: true),
            [Ipv4SourcePath] = Field("dnsServerIPv4SourceAddresses", new[] { "0.0.0.0" }, canApply: true),
            [Ipv6SourcePath] = Field("dnsServerIPv6SourceAddresses", new[] { "::" }, canApply: true),
            ["/dns/authoritative/defaultRecordTtl"] = Field("defaultRecordTtl", 3600, canApply: true),
            ["/dns/authoritative/defaultNsRecordTtl"] = Field("defaultNsRecordTtl", 14400, canApply: true),
            ["/dns/authoritative/defaultSoaRecordTtl"] = Field("defaultSoaRecordTtl", 900, canApply: true),
            ["/dns/authoritative/defaultResponsiblePerson"] = new("defaultResponsiblePerson",
                JsonSerializer.SerializeToElement<string>(null), false, NormalizeResponsiblePerson, CanApply: true),
            ["/dns/authoritative/minSoaRefresh"] = Field("minSoaRefresh", 300, canApply: true),
            ["/dns/authoritative/minSoaRetry"] = Field("minSoaRetry", 300, canApply: true),
            ["/dns/authoritative/useSoaSerialDateScheme"] = Field("useSoaSerialDateScheme", false, canApply: true),
            ["/dns/authoritative/zoneTransferAllowedNetworks"] = Field("zoneTransferAllowedNetworks", Array.Empty<string>(), canApply: true),
            ["/dns/authoritative/notifyAllowedNetworks"] = Field("notifyAllowedNetworks", Array.Empty<string>(), canApply: true),
            ["/dns/checkForUpdates"] = Field("dnsServerEnableCheckForUpdate", true, canApply: true),
            ["/dns/dnssecValidation"] = Field("dnssecValidation", true, canApply: true),
            ["/dns/udpPayloadSize"] = Field("udpPayloadSize", 1232, canApply: true),
            [WebAddressesPath] = Field("webServiceLocalAddresses", Array.Empty<string>(), restartWebService: true, canApply: true),
            ["/web/httpPort"] = Field("webServiceHttpPort", 5380, restartWebService: true, canApply: true),
            ["/web/tlsPort"] = Field("webServiceTlsPort", 53443, restartWebService: true, canApply: true),
            ["/web/tlsEnabled"] = Field("webServiceEnableTls", false, restartWebService: true, canApply: true),
            ["/web/http3Enabled"] = Field("webServiceEnableHttp3", false, restartWebService: true, canApply: true),
            ["/web/redirectHttpToTls"] = Field("webServiceHttpToTlsRedirect", false, restartWebService: true, canApply: true),
            ["/web/httpUnixSocket/enabled"] = Field("webServiceEnableHttpUnixSocket", false, restartWebService: true, canApply: true),
            ["/web/httpUnixSocket/path"] = Field<string>("webServiceHttpUnixSocket", null, restartWebService: true, canApply: true),
            ["/web/tlsUnixSocket/enabled"] = Field("webServiceEnableTlsUnixSocket", false, restartWebService: true, canApply: true),
            ["/web/tlsUnixSocket/path"] = Field<string>("webServiceTlsUnixSocket", null, restartWebService: true, canApply: true),
            ["/web/reverseProxyAcl"] = Field("webServiceReverseProxyAddresses", Array.Empty<string>(), canApply: true),
            ["/web/realIpHeader"] = Field("webServiceRealIpHeader", "X-Real-IP", canApply: true),
            ["/web/frameAncestors"] = Field("webServiceCspFrameAncestorsHeader", "'none'", canApply: true),
            ["/logging/destination"] = Field("loggingType", "File", canApply: true),
            ["/logging/folder"] = Field("logFolder", "logs", canApply: true),
            ["/logging/noStackTrace"] = Field("noStackTrace", false, canApply: true),
            ["/logging/useLocalTime"] = Field("useLocalTime", false, canApply: true),
            ["/logging/retentionDays"] = Field("maxLogFileDays", 365, canApply: true),
            ["/logging/ignoreResolverLogs"] = Field("ignoreResolverLogs", false),
            ["/logging/logQueries"] = Field("logQueries", false),
            ["/statistics/inMemory"] = Field("enableInMemoryStats", false, canApply: true),
            ["/statistics/retentionDays"] = Field("maxStatFileDays", 365, canApply: true),
            ["/blocklists/updateIntervalHours"] = Field("blockListUpdateIntervalHours", 24, canApply: true),
            [BlockListSourcesPath] = new("blockListUrls", JsonSerializer.SerializeToElement<string>(null),
                false, OmitFromExport: true, CanApply: true),
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

                if (section.Name == "zones" && currentSettings.TryGetProperty("manifestZones", out JsonElement zones))
                    CompareZones(section.Value, zones, changes);
                else
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
                if (currentSettings.TryGetProperty("clusterDomain", out JsonElement clusterDomain))
                    clusterDomain.WriteTo(writer);
                if (currentSettings.TryGetProperty("managedSettings", out JsonElement ownership))
                    ownership.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestZones", out JsonElement zones))
                    zones.WriteTo(writer);
                writer.WriteEndArray();
            }

            // The snapshot can include sensitive URLs. Use a server-local key so the
            // revision cannot be used to guess values from the preview response.
            return Convert.ToHexString(HMACSHA256.HashData(key, data.WrittenSpan));
        }

        internal static Task ApplyAsync(ConfigurationManifest manifest, LogManager log, DnsServer dns, IReadOnlyList<IPEndPoint> endpoints, string serverDomain, Action writeCertificate, Action<DnsWebService.WebLiveSettings, Action<Action>> applyWebLiveSettings, bool alreadyActive)
        {
            CheckApplySupport(manifest);

            manifest.Settings.TryGetProperty("logging", out JsonElement logging);
            JsonElement? destination = GetLoggingValue(logging, "destination");
            JsonElement? noStackTrace = GetLoggingValue(logging, "noStackTrace");
            JsonElement? retention = GetLoggingValue(logging, "retentionDays");
            JsonElement? localTime = GetLoggingValue(logging, "useLocalTime");
            string folder = logging.ValueKind == JsonValueKind.Object && logging.TryGetProperty("folder", out JsonElement folderValue)
                ? GetManifestLogFolder(folderValue, log) : null;

            return dns.ApplyManifestDnsSettingsAsync(serverDomain, endpoints, GetSourceNetworks(manifest), GetAuthoritativeDefaults(manifest), GetResolverSettings(manifest), GetStatisticsSettings(manifest), alreadyActive, writeDnsConfig =>
                dns.BlockListZoneManager.ApplyManifestSettings(GetBlockListInterval(manifest), GetBlockListSources(manifest), writeBlockListConfig =>
                    applyWebLiveSettings(GetWebLiveSettings(manifest), writeWebConfig => log.ApplyManifestSettings(
                destination.HasValue ? Enum.Parse<LoggingType>(destination.Value.GetString()) : null,
                noStackTrace?.GetBoolean(),
                retention.HasValue ? decimal.ToInt32(retention.Value.GetDecimal()) : null,
                localTime?.GetBoolean(),
                folder,
                writeDnsConfig, writeCertificate, writeBlockListConfig, writeWebConfig))));
        }

        private static DnsWebService.WebLiveSettings GetWebLiveSettings(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("web", out JsonElement web))
                return default;

            return new DnsWebService.WebLiveSettings(
                web.TryGetProperty("realIpHeader", out JsonElement realIp) ? ConfigurationManifest.ReadWebHeader(realIp, realIp: true) : null,
                web.TryGetProperty("frameAncestors", out JsonElement ancestors) ? ConfigurationManifest.ReadWebHeader(ancestors, realIp: false) : null,
                web.TryGetProperty("reverseProxyAcl", out JsonElement acl) ? ConfigurationManifest.ReadWebReverseProxyAcl(acl) : null);
        }

        private static IReadOnlyList<string> GetBlockListSources(ConfigurationManifest manifest)
        {
            return manifest.Settings.TryGetProperty("blocklists", out JsonElement blocklists) &&
                blocklists.TryGetProperty("sources", out JsonElement value) ? ConfigurationManifest.ReadBlockListSources(value) : null;
        }

        private static int? GetBlockListInterval(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("blocklists", out JsonElement blocklists) ||
                !blocklists.TryGetProperty("updateIntervalHours", out JsonElement value))
                return null;

            return value.ValueKind == JsonValueKind.Null ? 24 : decimal.ToInt32(value.GetDecimal());
        }

        private static DnsServer.SourceNetworks GetSourceNetworks(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns) ||
                !dns.TryGetProperty("sourceNetworks", out JsonElement source))
                return default;

            return new DnsServer.SourceNetworks(
                source.TryGetProperty("ipv4", out JsonElement ipv4)
                    ? ConfigurationManifest.ReadNetworks(ipv4, Ipv4SourcePath, AddressFamily.InterNetwork) : null,
                source.TryGetProperty("ipv6", out JsonElement ipv6)
                    ? ConfigurationManifest.ReadNetworks(ipv6, Ipv6SourcePath, AddressFamily.InterNetworkV6) : null);
        }

        private static DnsServer.AuthoritativeDefaults GetAuthoritativeDefaults(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns) ||
                !dns.TryGetProperty("authoritative", out JsonElement authoritative))
                return default;

            JsonElement? responsible = ReadValue("defaultResponsiblePerson");
            string responsiblePerson = responsible.HasValue
                ? ConfigurationManifest.ReadDefaultResponsiblePerson(responsible.Value) : null;

            return new DnsServer.AuthoritativeDefaults(ReadTtl("defaultRecordTtl"), ReadTtl("defaultNsRecordTtl"), ReadTtl("defaultSoaRecordTtl"),
                ReadValue("useSoaSerialDateScheme")?.GetBoolean(), ReadTtl("minSoaRefresh"), ReadTtl("minSoaRetry"), responsiblePerson,
                ReadNetworks("zoneTransferAllowedNetworks"), ReadNetworks("notifyAllowedNetworks"));

            NetworkAddress[] ReadNetworks(string name)
            {
                return authoritative.TryGetProperty(name, out JsonElement value)
                    ? ConfigurationManifest.ReadNetworks(value, "/dns/authoritative/" + name) : null;
            }


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

        private static DnsServer.ResolverSettings GetResolverSettings(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns))
                return default;

            JsonElement? payload = ReadValue("udpPayloadSize");
            return new DnsServer.ResolverSettings(ReadValue("checkForUpdates")?.GetBoolean(),
                payload.HasValue ? decimal.ToUInt16(payload.Value.GetDecimal()) : null, ReadValue("dnssecValidation")?.GetBoolean());

            JsonElement? ReadValue(string name)
            {
                if (!dns.TryGetProperty(name, out JsonElement value))
                    return null;
                return value.ValueKind == JsonValueKind.Null ? _settings["/dns/" + name].Default : value;
            }
        }

        private static DnsServer.StatisticsSettings GetStatisticsSettings(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("statistics", out JsonElement statistics))
                return default;

            bool? inMemory = statistics.TryGetProperty("inMemory", out JsonElement mode)
                ? mode.ValueKind != JsonValueKind.Null && mode.GetBoolean() : null;
            int? retention = statistics.TryGetProperty("retentionDays", out JsonElement days)
                ? days.ValueKind == JsonValueKind.Null ? 365 : decimal.ToInt32(days.GetDecimal()) : null;
            return new DnsServer.StatisticsSettings(inMemory, retention);
        }

        internal static void CheckClusterApplySupport(ConfigurationManifest manifest, bool clusterInitialized)
        {
            if (!clusterInitialized)
                return;
            if (GetWebListeners(manifest).HasValues)
                throw new InvalidDataException("/web: Applying web listener settings to a cluster is not implemented.");
            if (manifest.GetServerDomain() is not null)
                throw new InvalidDataException("/dns/serverDomain: Applying server domain changes to a cluster is not implemented.");
            if (GetAuthoritativeDefaults(manifest).HasValues)
                throw new InvalidDataException("/dns/authoritative: Applying authoritative defaults to a cluster is not implemented.");
            if (GetBlockListSources(manifest) is not null)
                throw new InvalidDataException("/blocklists/sources: Applying blocklist sources to a cluster is not implemented.");
            if (GetBlockListInterval(manifest).HasValue)
                throw new InvalidDataException("/blocklists/updateIntervalHours: Applying the update interval to a cluster is not implemented.");
            if (GetResolverSettings(manifest).HasValues)
                throw new InvalidDataException("/dns: Applying update checks, UDP payload size, or DNSSEC validation to a cluster is not implemented.");
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
            if ((_settings.TryGetValue(path, out Setting setting) && setting.CanApply) ||
                (value.ValueKind == JsonValueKind.Null && path is "/web/httpUnixSocket" or "/web/tlsUnixSocket"))
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

        internal static DnsWebService.WebListeners GetWebListeners(ConfigurationManifest manifest)
        {
            if (manifest is null || !manifest.Settings.TryGetProperty("web", out JsonElement web))
                return default;

            IReadOnlyList<IPAddress> addresses = web.TryGetProperty("localAddresses", out JsonElement value)
                ? NormalizeWebAddresses(value) : null;
            return new DnsWebService.WebListeners(addresses, ReadPort("httpPort"), ReadPort("tlsPort"),
                ReadValue("tlsEnabled")?.GetBoolean(), ReadValue("http3Enabled")?.GetBoolean(), ReadValue("redirectHttpToTls")?.GetBoolean(),
                ReadSocket("httpUnixSocket"), ReadSocket("tlsUnixSocket"));

            DnsWebService.WebUnixSocket ReadSocket(string name)
            {
                return web.TryGetProperty(name, out JsonElement socket)
                    ? ConfigurationManifest.ReadWebUnixSocket(socket, "/web/" + name) : default;
            }

            int? ReadPort(string name)
            {
                JsonElement? value = ReadValue(name);
                return value.HasValue ? decimal.ToInt32(value.Value.GetDecimal()) : null;
            }

            JsonElement? ReadValue(string name)
            {
                if (!web.TryGetProperty(name, out JsonElement value))
                    return null;
                return value.ValueKind == JsonValueKind.Null ? _settings["/web/" + name].Default : value;
            }
        }

        private static IReadOnlyList<IPAddress> NormalizeWebAddresses(JsonElement value)
        {
            IReadOnlyList<IPAddress> addresses = DnsWebService.NormalizeWebLocalAddresses(ReadWebAddresses(value));
            if (addresses.Count == 0)
                throw new InvalidDataException("/web/localAddresses: No declared address family is available on this server.");
            return addresses;
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

        private static void CompareZones(JsonElement declaredZones, JsonElement currentZones, List<ConfigurationChange> changes)
        {
            foreach (JsonProperty declaration in declaredZones.EnumerateObject())
            {
                string path = AppendPath("/zones", declaration.Name);
                string name = ConfigurationManifest.CanonicalDnsName(declaration.Name, path, allowRoot: true);
                bool exists = currentZones.TryGetProperty(name, out JsonElement current) && current.ValueKind == JsonValueKind.Object && current.TryGetProperty("type", out _);
                if (declaration.Value.ValueKind == JsonValueKind.Null)
                {
                    if (exists)
                    {
                        if (current.GetProperty("clusterProtected").GetBoolean())
                            throw new InvalidDataException($"{path}: A cluster infrastructure zone cannot be deleted.");
                        changes.Add(new ConfigurationChange(path, ConfigurationChangeKind.Remove, false));
                    }
                    continue;
                }

                foreach (JsonProperty field in declaration.Value.EnumerateObject())
                {
                    if (field.Name is not ("type" or "enabled" or "records"))
                        throw new InvalidDataException($"{AppendPath(path, field.Name)}: Planning for this zone setting is not implemented.");
                }

                string type = declaration.Value.TryGetProperty("type", out JsonElement declaredType) ? declaredType.GetString() : null;
                if (!exists)
                {
                    if (type is null)
                        throw new InvalidDataException($"{path}/type: A zone type is required to create a zone.");
                    if (type != "Primary")
                        throw new InvalidDataException($"{path}/type: Preview of creation is currently supported for primary zones.");
                    changes.Add(new ConfigurationChange(path, ConfigurationChangeKind.Add, false));
                    continue;
                }

                if (type is not null && !current.GetProperty("type").ValueEquals(type))
                    throw new InvalidDataException($"{path}/type: The declared type differs from the existing zone type.");

                if (current.TryGetProperty("recordChanges", out JsonElement recordChanges))
                {
                    int index = 0;
                    foreach (JsonElement change in recordChanges.EnumerateArray())
                    {
                        if (change.ValueKind != JsonValueKind.Null)
                            changes.Add(new ConfigurationChange($"{path}/records/{index}", (ConfigurationChangeKind)change.GetInt32(), false));
                        index++;
                    }
                }

                if (declaration.Value.TryGetProperty("enabled", out JsonElement enabled))
                {
                    bool effectiveEnabled = enabled.ValueKind == JsonValueKind.Null || enabled.GetBoolean();
                    if (!effectiveEnabled && current.GetProperty("clusterProtected").GetBoolean())
                        throw new InvalidDataException($"{path}/enabled: A cluster infrastructure zone cannot be disabled.");
                    if (effectiveEnabled != current.GetProperty("enabled").GetBoolean())
                        changes.Add(new ConfigurationChange(path + "/enabled", ConfigurationChangeKind.Update, false));
                }
            }
        }

        internal static ConfigurationChangeKind?[] CompareZoneRecords(string zoneName, string declarationName, string serverDomain,
            JsonElement records, IReadOnlyList<DnsResourceRecord> currentRecords)
        {
            string path = AppendPath("/zones", declarationName) + "/records";
            if (records.ValueKind == JsonValueKind.Null)
                throw new InvalidDataException($"{path}: Planning a record collection reset is not implemented.");

            var changes = new ConfigurationChangeKind?[records.GetArrayLength()];
            var current = currentRecords.ToLookup(record => (record.Name.ToLowerInvariant(), record.Type));
            var matched = new HashSet<DnsResourceRecord>(ReferenceEqualityComparer.Instance);
            var declared = new HashSet<(string Owner, DnsResourceRecordType Type, DnsResourceRecordData Data)>();
            int index = 0;
            foreach (JsonElement record in records.EnumerateArray())
            {
                string recordPath = $"{path}/{index}";
                foreach (JsonProperty field in record.EnumerateObject())
                {
                    if (field.Name is not ("owner" or "type" or "data" or "ttl" or "disabled" or "comments"))
                        throw new InvalidDataException($"{AppendPath(recordPath, field.Name)}: Planning for this record setting is not implemented.");
                }

                (string owner, DnsResourceRecordType type) = ConfigurationManifest.ReadZoneRecordIdentity(zoneName, record, recordPath);
                JsonElement data = record.GetProperty("data");
                DnsResourceRecordData rdata;
                if (data.TryGetProperty("zoneFile", out JsonElement zoneFile))
                    rdata = ConfigurationManifest.ReadZoneFileRecordData(zoneName, owner, type, zoneFile.GetString(), recordPath + "/data/zoneFile").RDATA;
                else if (data.TryGetProperty("rawHex", out JsonElement rawHex))
                    rdata = ConfigurationManifest.ReadRawZoneRecordData(zoneName, owner, type, rawHex.GetString(), recordPath + "/data/rawHex").RDATA;
                else if (data.TryGetProperty("txtBase64", out JsonElement txt))
                {
                    var segments = new List<ArraySegment<byte>>();
                    foreach (JsonElement segment in txt.EnumerateArray())
                        segments.Add(Convert.FromBase64String(segment.GetString()));
                    rdata = new DnsTXTRecordData(segments);
                }
                else
                    throw new InvalidDataException($"{recordPath}/data: Planning for this record data format is not implemented.");

                if (IsGeneratedRecord(zoneName, serverDomain, owner, type, rdata))
                    throw new InvalidDataException($"{recordPath}: This record is managed by the zone lifecycle.");
                if (!declared.Add((owner, type, rdata)))
                    throw new InvalidDataException($"{recordPath}: Duplicate record.");

                DnsResourceRecord existing = current[(owner, type)].FirstOrDefault(candidate => candidate.Class == DnsClass.IN && candidate.RDATA.Equals(rdata));
                if (existing is null)
                {
                    if (current[(owner, type)].Any(IsLeaseRecord))
                        throw new InvalidDataException($"{recordPath}: This record conflicts with a DHCP-maintained record.");
                    changes[index] = ConfigurationChangeKind.Add;
                }
                else
                {
                    if (IsLeaseRecord(existing))
                        throw new InvalidDataException($"{recordPath}: This record is maintained by DHCP.");
                    matched.Add(existing);
                    var metadata = existing.Tag as GenericRecordInfo;
                    if ((record.TryGetProperty("ttl", out JsonElement ttl) && ttl.GetDecimal() != existing.OriginalTtlValue) ||
                        (record.TryGetProperty("disabled", out JsonElement disabled) && disabled.GetBoolean() != (metadata?.Disabled ?? false)) ||
                        (record.TryGetProperty("comments", out JsonElement comments) && comments.GetString() != (metadata?.Comments ?? string.Empty)))
                        changes[index] = ConfigurationChangeKind.Update;
                }
                index++;
            }

            foreach (DnsResourceRecord record in currentRecords)
            {
                if (!matched.Contains(record) && !IsLeaseRecord(record) &&
                    !IsGeneratedRecord(zoneName, serverDomain, record.Name, record.Type, record.RDATA))
                    throw new InvalidDataException($"{path}: An existing record has no known owner. Declare the existing record or omit the collection.");
            }

            return changes;
        }

        private static bool IsGeneratedRecord(string zoneName, string serverDomain, string owner, DnsResourceRecordType type, DnsResourceRecordData data)
        {
            if (type is DnsResourceRecordType.DNSKEY or DnsResourceRecordType.RRSIG or DnsResourceRecordType.NSEC or
                DnsResourceRecordType.NSEC3 or DnsResourceRecordType.NSEC3PARAM)
                return true;

            return owner.Equals(zoneName, StringComparison.OrdinalIgnoreCase) &&
                (type == DnsResourceRecordType.SOA ||
                 (data is DnsNSRecordData ns && ns.NameServer.Equals(serverDomain, StringComparison.OrdinalIgnoreCase)));
        }

        private static bool IsLeaseRecord(DnsResourceRecord record)
        {
            return record.Type is DnsResourceRecordType.A or DnsResourceRecordType.PTR &&
                record.Tag is GenericRecordInfo { Comments: string comments } &&
                comments.StartsWith("Via '", StringComparison.Ordinal) &&
                comments.EndsWith("' DHCP scope", StringComparison.Ordinal);
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
                    else if (path == ServerDomainPath)
                    {
                        string domain = ConfigurationManifest.ReadServerDomain(desired);
                        string existingDomain = current.GetString();
                        if (!string.Equals(domain, existingDomain, StringComparison.OrdinalIgnoreCase) &&
                            currentSettings.TryGetProperty("clusterDomain", out JsonElement clusterDomain))
                        {
                            try
                            {
                                DnsServer.CheckClusterServerDomain(domain, clusterDomain.GetString());
                            }
                            catch (ArgumentException ex)
                            {
                                throw new InvalidDataException($"{path}: {ex.Message}");
                            }
                        }
                        candidate = JsonSerializer.SerializeToElement(domain);
                        current = JsonSerializer.SerializeToElement(existingDomain.ToLowerInvariant());
                    }
                    else if (path == WebAddressesPath)
                    {
                        IReadOnlyList<IPAddress> addresses = NormalizeWebAddresses(desired);

                        candidate = SortAddresses(addresses.Select(address => address.ToString()));
                        current = SortAddresses(ReadWebAddresses(current).Select(address => address.ToString()));
                    }
                    else if (path is Ipv4SourcePath or Ipv6SourcePath)
                    {
                        AddressFamily family = path == Ipv4SourcePath ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
                        NetworkAddress[] networks = ConfigurationManifest.ReadNetworks(desired, path, family);
                        candidate = networks.Length == 0 ? setting.Default : SortAddresses(networks.Select(network => network.ToString()));
                        current = SortAddresses(ConfigurationManifest.ReadNetworks(current, path, family).Select(network => network.ToString()));
                    }
                    else if (path is "/dns/authoritative/zoneTransferAllowedNetworks" or "/dns/authoritative/notifyAllowedNetworks")
                    {
                        candidate = SortAddresses(ConfigurationManifest.ReadNetworks(desired, path).Select(network => network.ToString()));
                        current = SortAddresses(ConfigurationManifest.ReadNetworks(current, path).Select(network => network.ToString()));
                    }
                    else if (path == "/web/reverseProxyAcl")
                    {
                        var rules = ConfigurationManifest.ReadWebReverseProxyAcl(desired);
                        candidate = JsonSerializer.SerializeToElement(rules.Select(rule => rule.ToString()).ToArray());
                    }
                    else if (path is "/web/realIpHeader" or "/web/frameAncestors")
                    {
                        bool realIp = path == "/web/realIpHeader";
                        string value = ConfigurationManifest.ReadWebHeader(desired, realIp);
                        if (realIp && string.Equals(value, current.GetString(), StringComparison.OrdinalIgnoreCase))
                            value = current.GetString();
                        candidate = JsonSerializer.SerializeToElement(value);
                    }
                    else if (path is "/web/httpUnixSocket/path" or "/web/tlsUnixSocket/path")
                    {
                        string socket = ConfigurationManifest.ReadWebUnixSocketPath(desired, path);
                        candidate = JsonSerializer.SerializeToElement(socket.Length == 0 ? null : socket);
                    }
                    else if (path == BlockListSourcesPath)
                    {
                        candidate = NormalizeBlockListSources(desired);
                        current = NormalizeBlockListSources(current);
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

            if (desired.ValueKind == JsonValueKind.Null && path is "/web/httpUnixSocket" or "/web/tlsUnixSocket")
            {
                Compare(desired, path + "/enabled", currentSettings, changes, log);
                Compare(desired, path + "/path", currentSettings, changes, log);
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
            string address = ConfigurationManifest.ReadDefaultResponsiblePerson(value);
            return JsonSerializer.SerializeToElement(address.Length == 0 ? null : address);
        }

        private static JsonElement NormalizeBlockListSources(JsonElement value)
        {
            IReadOnlyList<string> sources = ConfigurationManifest.ReadBlockListSources(value);
            return JsonSerializer.SerializeToElement(sources.Count == 0 ? null : sources);
        }

        private static Setting Field<T>(string apiField, T defaultValue, bool restartWebService = false, bool canApply = false)
        {
            return new Setting(apiField, JsonSerializer.SerializeToElement(defaultValue), restartWebService, CanApply: canApply);
        }

        internal static string AppendPath(string path, string name)
        {
            return path + "/" + name.Replace("~", "~0", StringComparison.Ordinal).Replace("/", "~1", StringComparison.Ordinal);
        }
    }
}
