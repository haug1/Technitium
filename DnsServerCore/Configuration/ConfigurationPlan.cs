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
using TechnitiumLibrary.Net.Proxy;

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
        private const string ForwardingServersPath = "/dns/forwarding/servers";
        private const string ExcludedPortsPath = "/dns/udpSocketPool/excludedPorts";
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
            ["/dns/clientSubnet/enabled"] = Field("eDnsClientSubnet", false, canApply: true),
            ["/dns/clientSubnet/ipv4PrefixLength"] = Field("eDnsClientSubnetIPv4PrefixLength", 24, canApply: true),
            ["/dns/clientSubnet/ipv6PrefixLength"] = Field("eDnsClientSubnetIPv6PrefixLength", 56, canApply: true),
            ["/dns/clientSubnet/ipv4Override"] = Field<string>("eDnsClientSubnetIpv4Override", null, canApply: true),
            ["/dns/clientSubnet/ipv6Override"] = Field<string>("eDnsClientSubnetIpv6Override", null, canApply: true),
            ["/dns/recursion/mode"] = Field("recursion", nameof(DnsServerRecursion.AllowOnlyForPrivateNetworks), canApply: true),
            ["/dns/recursion/networkAcl"] = Field("recursionNetworkACL", Array.Empty<string>(), canApply: true),
            ["/dns/recursion/randomizeName"] = Field("randomizeName", false, canApply: true),
            ["/dns/recursion/qnameMinimization"] = Field("qnameMinimization", true, canApply: true),
            ["/dns/recursion/locallyServedDnsZones"] = Field("locallyServedDnsZones", true, canApply: true),
            ["/dns/recursion/retries"] = Field("resolverRetries", 2, canApply: true),
            ["/dns/recursion/timeoutMs"] = Field("resolverTimeout", 1500, canApply: true),
            ["/dns/recursion/concurrency"] = Field("resolverConcurrency", 2, canApply: true),
            ["/dns/recursion/maxStackCount"] = Field("resolverMaxStackCount", 16, canApply: true),
            ["/dns/cache/saveToDisk"] = Field("saveCache", true, canApply: true),
            ["/dns/cache/serveStale/enabled"] = Field("serveStale", true, canApply: true),
            ["/dns/cache/serveStale/ttl"] = Field("serveStaleTtl", 259200u, canApply: true),
            ["/dns/cache/serveStale/answerTtl"] = Field("serveStaleAnswerTtl", 30u, canApply: true),
            ["/dns/cache/serveStale/resetTtl"] = Field("serveStaleResetTtl", 30u, canApply: true),
            ["/dns/cache/serveStale/maxWaitMs"] = Field("serveStaleMaxWaitTime", 1800, canApply: true),
            ["/dns/cache/maximumEntries"] = Field("cacheMaximumEntries", 10000L, canApply: true),
            ["/dns/cache/minimumRecordTtl"] = Field("cacheMinimumRecordTtl", 10u, canApply: true),
            ["/dns/cache/maximumRecordTtl"] = Field("cacheMaximumRecordTtl", 604800u, canApply: true),
            ["/dns/cache/negativeRecordTtl"] = Field("cacheNegativeRecordTtl", 300u, canApply: true),
            ["/dns/cache/failureRecordTtl"] = Field("cacheFailureRecordTtl", 10u, canApply: true),
            ["/dns/cache/prefetch/enabled"] = Field("enableCachePrefetch", true, canApply: true),
            ["/dns/cache/prefetch/eligibility"] = Field("cachePrefetchEligibility", 2, canApply: true),
            ["/dns/cache/prefetch/trigger"] = Field("cachePrefetchTrigger", 9, canApply: true),
            ["/dns/blocking/enabled"] = Field("configuredEnableBlocking", true, canApply: true),
            ["/dns/blocking/allowTxtReport"] = Field("allowTxtBlockingReport", true, canApply: true),
            ["/dns/blocking/bypassNetworks"] = Field("blockingBypassList", Array.Empty<string>(), canApply: true),
            ["/dns/blocking/responseType"] = Field("blockingType", nameof(DnsServerBlockingType.NxDomain), canApply: true),
            ["/dns/blocking/answerTtl"] = Field("blockingAnswerTtl", 30u, canApply: true),
            ["/dns/blocking/customAddresses"] = Field("customBlockingAddresses", Array.Empty<string>(), canApply: true),
            [ForwardingServersPath] = Field("configuredForwarders", Array.Empty<object>(), canApply: true),
            ["/dns/forwarding/concurrent"] = Field("concurrentForwarding", true, canApply: true),
            ["/dns/forwarding/retries"] = Field("forwarderRetries", 3, canApply: true),
            ["/dns/forwarding/timeoutMs"] = Field("forwarderTimeout", 2000, canApply: true),
            ["/dns/forwarding/concurrency"] = Field("forwarderConcurrency", 2, canApply: true),
            ["/dns/rateLimits/ipv4"] = new("qpmPrefixLimitsIPv4", SerializeRateLimits(DnsServer.DefaultRateLimitIpv4), false, CanApply: true),
            ["/dns/rateLimits/ipv6"] = new("qpmPrefixLimitsIPv6", SerializeRateLimits(DnsServer.DefaultRateLimitIpv6), false, CanApply: true),
            ["/dns/rateLimits/sampleMinutes"] = Field("qpmLimitSampleMinutes", 5, canApply: true),
            ["/dns/rateLimits/udpTruncationPercentage"] = Field("qpmLimitUdpTruncationPercentage", 50, canApply: true),
            ["/dns/rateLimits/bypassNetworks"] = Field("qpmLimitBypassList", Array.Empty<string>(), canApply: true),
            ["/dns/tuning/clientTimeoutMs"] = Field("clientTimeout", 2000, canApply: true),
            ["/dns/tuning/tcpSendTimeoutMs"] = Field("tcpSendTimeout", 10000, canApply: true),
            ["/dns/tuning/tcpReceiveTimeoutMs"] = Field("tcpReceiveTimeout", 10000, canApply: true),
            ["/dns/tuning/quicIdleTimeoutMs"] = Field("quicIdleTimeout", 60000, canApply: true),
            ["/dns/tuning/quicMaxInboundStreams"] = Field("quicMaxInboundStreams", 100, canApply: true),
            ["/dns/tuning/listenBacklog"] = Field("listenBacklog", 100, canApply: true),
            ["/dns/tuning/udpSendBufferKiB"] = Field("udpSendBufferSizeKB", 2048, canApply: true),
            ["/dns/tuning/udpReceiveBufferKiB"] = Field("udpReceiveBufferSizeKB", 2048, canApply: true),
            ["/dns/tuning/maxConcurrentResolutionsPerCore"] = Field("maxConcurrentResolutionsPerCore", (ushort)100, canApply: true),
            ["/dns/dnssecValidation"] = Field("dnssecValidation", true, canApply: true),
            ["/dns/ipv6Mode"] = Field("ipv6Mode", nameof(IPv6Mode.Disabled), canApply: true),
            ["/dns/udpSocketPool/enabled"] = Field("enableUdpSocketPool", DnsServer.DefaultUdpSocketPoolEnabled, canApply: true),
            [ExcludedPortsPath] = Field("socketPoolExcludedPorts", Array.Empty<ushort>(), canApply: true),
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
            ["/dns/listeners/udpProxy/enabled"] = Field("enableDnsOverUdpProxy", false, canApply: true),
            ["/dns/listeners/udpProxy/port"] = Field("dnsOverUdpProxyPort", 538, canApply: true),
            ["/dns/listeners/tcpProxy/enabled"] = Field("enableDnsOverTcpProxy", false, canApply: true),
            ["/dns/listeners/tcpProxy/port"] = Field("dnsOverTcpProxyPort", 538, canApply: true),
            ["/dns/listeners/http/enabled"] = Field("enableDnsOverHttp", false, canApply: true),
            ["/dns/listeners/http/port"] = Field("dnsOverHttpPort", 80, canApply: true),
            ["/dns/listeners/tls/enabled"] = Field("enableDnsOverTls", false, canApply: true),
            ["/dns/listeners/tls/port"] = Field("dnsOverTlsPort", 853, canApply: true),
            ["/dns/listeners/https/enabled"] = Field("enableDnsOverHttps", false, canApply: true),
            ["/dns/listeners/https/port"] = Field("dnsOverHttpsPort", 443, canApply: true),
            ["/dns/listeners/quic/enabled"] = Field("enableDnsOverQuic", false, canApply: true),
            ["/dns/listeners/quic/port"] = Field("dnsOverQuicPort", 853, canApply: true),
            ["/dns/listeners/https/http3Enabled"] = Field("enableDnsOverHttp3", false, canApply: true),
            ["/dns/listeners/http/unixSocket/enabled"] = Field("enableDnsOverHttpUnixSocket", false, canApply: true),
            ["/dns/listeners/http/unixSocket/path"] = Field<string>("dnsOverHttpUnixSocket", null, canApply: true),
            ["/dns/listeners/https/unixSocket/enabled"] = Field("enableDnsOverHttpsUnixSocket", false, canApply: true),
            ["/dns/listeners/https/unixSocket/path"] = Field<string>("dnsOverHttpsUnixSocket", null, canApply: true),
            [ConfigurationDnsCertificate.Path + "/path"] = Field<string>("dnsTlsCertificatePath", null, canApply: true),
            ["/dns/listeners/useClientSubnetAsSource"] = Field("enableEDnsClientSubnetSourceAddress", false, canApply: true),
            ["/dns/listeners/http/helpRedirect"] = Field("enableDnsOverHttpHelpRedirect", true, canApply: true),
            ["/dns/listeners/http/realIpHeader"] = Field("dnsOverHttpRealIpHeader", "X-Real-IP", canApply: true),
            ["/dns/listeners/reverseProxyAcl"] = Field("dnsReverseProxyNetworkACL", Array.Empty<string>(), canApply: true),
            ["/web/rootPath"] = Field<string>("webServiceRootPath", null, restartWebService: true),
            ["/web/useSelfSignedCertificate"] = Field("webServiceUseSelfSignedTlsCertificate", false, restartWebService: true, canApply: true),
            [ConfigurationWebCertificate.Path + "/path"] = Field<string>("webServiceTlsCertificatePath", null, canApply: true),
            ["/web/reverseProxyAcl"] = Field("webServiceReverseProxyAddresses", Array.Empty<string>(), canApply: true),
            ["/web/realIpHeader"] = Field("webServiceRealIpHeader", "X-Real-IP", canApply: true),
            ["/web/frameAncestors"] = Field("webServiceCspFrameAncestorsHeader", "'none'", canApply: true),
            ["/logging/destination"] = Field("loggingType", "File", canApply: true),
            ["/logging/folder"] = Field("logFolder", "logs", canApply: true),
            ["/logging/noStackTrace"] = Field("noStackTrace", false, canApply: true),
            ["/logging/useLocalTime"] = Field("useLocalTime", false, canApply: true),
            ["/logging/retentionDays"] = Field("maxLogFileDays", 365, canApply: true),
            ["/logging/ignoreResolverLogs"] = Field("ignoreResolverLogs", false, canApply: true),
            ["/logging/logQueries"] = Field("logQueries", false, canApply: true),
            ["/statistics/inMemory"] = Field("enableInMemoryStats", false, canApply: true),
            ["/statistics/retentionDays"] = Field("maxStatFileDays", 365, canApply: true),
            ["/blocklists/updateIntervalHours"] = Field("blockListUpdateIntervalHours", 24, canApply: true),
            [BlockListSourcesPath] = new("blockListUrls", JsonSerializer.SerializeToElement<string>(null),
                false, OmitFromExport: true, CanApply: true),
            ["/apps/autoUpdate"] = Field("dnsAppsEnableAutomaticUpdate", true, canApply: true)
        };

        public static IReadOnlyList<ConfigurationChange> Create(ConfigurationManifest manifest, JsonElement currentSettings)
        {
            return Create(manifest, currentSettings, null);
        }

        internal static IReadOnlyList<ConfigurationChange> Create(ConfigurationManifest manifest, JsonElement currentSettings, LogManager log)
        {
            RequireSettingsObject(currentSettings);

            ValidateProxyAndForwarders(manifest, currentSettings);
            DnsServer.DnsBindings bindings = GetDnsBindings(manifest);
            DnsServer.DnsBindings currentBindings = ReadCurrentDnsBindings(currentSettings);
            bool hasCertificate = currentSettings.TryGetProperty("dnsListenerCertificateLoaded", out JsonElement loaded) && loaded.GetBoolean();
            if (currentSettings.TryGetProperty("manifestDnsCertificate", out JsonElement certificate))
            {
                hasCertificate = certificate.GetProperty("desiredFile").ValueKind != JsonValueKind.Null;
                if (!hasCertificate && ConfigurationDnsCertificate.HasSecureBindings(bindings, currentBindings))
                    throw new InvalidDataException($"{ConfigurationDnsCertificate.Path}: Disable the secure DNS listeners before removing their certificate.");
            }
            if (bindings != default)
                ValidateDnsBindings(bindings, currentBindings, hasCertificate);
            int? declaredWebTlsPort = manifest.Settings.TryGetProperty("web", out JsonElement web) &&
                web.TryGetProperty("tlsPort", out JsonElement tlsPort)
                ? tlsPort.ValueKind == JsonValueKind.Null ? _settings["/web/tlsPort"].Default.GetInt32() : decimal.ToInt32(tlsPort.GetDecimal())
                : null;
            var changes = new List<ConfigurationChange>();
            foreach (JsonProperty section in manifest.Settings.EnumerateObject())
            {
                if (section.Name is "schemaVersion" or "$schema")
                    continue;

                if (section.Name == "zones" && currentSettings.TryGetProperty("manifestZones", out JsonElement zones))
                    CompareZones(section.Value, zones, changes);
                else if (section.Name == "auth")
                {
                    foreach (JsonProperty authSection in section.Value.EnumerateObject())
                    {
                        if (authSection.Name == "ldap" && currentSettings.TryGetProperty("manifestLdap", out JsonElement ldap))
                            ConfigurationLdap.Compare(ldap, changes);
                        else if (authSection.Name == "sso" && currentSettings.TryGetProperty("manifestSso", out JsonElement sso))
                            ConfigurationSso.Compare(sso, changes);
                        else if (authSection.Name == "permissions" && currentSettings.TryGetProperty("manifestPermissions", out _))
                            continue;
                        else if (authSection.Name == "staticSessions" && currentSettings.TryGetProperty("manifestStaticSessions", out JsonElement staticSessions))
                        {
                            foreach (JsonProperty change in staticSessions.GetProperty("changes").EnumerateObject())
                                changes.Add(new ConfigurationChange(change.Name, (ConfigurationChangeKind)change.Value.GetInt32(), false));
                        }
                        else if ((authSection.Name is "groups" or "users") &&
                            currentSettings.TryGetProperty(authSection.Name == "groups" ? "manifestGroups" : "manifestUsers", out JsonElement snapshot))
                        {
                            foreach (JsonProperty change in snapshot.GetProperty("changes").EnumerateObject())
                                changes.Add(new ConfigurationChange(change.Name, (ConfigurationChangeKind)change.Value.GetInt32(), false));
                        }
                        else
                            throw new InvalidDataException($"{AppendPath("/auth", authSection.Name)}: Planning for this setting is not implemented.");
                    }
                }
                else if (section.Name == "dhcp" && currentSettings.TryGetProperty("manifestDhcpScopes", out JsonElement scopes))
                    ConfigurationDhcp.Compare(section.Value, scopes, changes);
                else
                    Compare(section.Value, AppendPath("", section.Name), currentSettings, changes, log, declaredWebTlsPort);
            }

            if (currentSettings.TryGetProperty("manifestPermissions", out JsonElement permissions))
            {
                foreach (JsonProperty change in permissions.GetProperty("changes").EnumerateObject())
                    changes.Add(new ConfigurationChange(change.Name, (ConfigurationChangeKind)change.Value.GetInt32(), false));
            }

            return changes.OrderBy(change => change.Path, StringComparer.Ordinal).ToArray();
        }

        private static void ValidateProxyAndForwarders(ConfigurationManifest manifest, JsonElement snapshot)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns))
                return;

            IReadOnlyList<NameServerAddress> servers = GetForwardingPolicy(manifest).Servers;
            NetProxyType proxyType = snapshot.TryGetProperty("proxy", out JsonElement currentProxy) && currentProxy.ValueKind == JsonValueKind.Object && currentProxy.TryGetProperty("type", out JsonElement currentType)
                ? Enum.Parse<NetProxyType>(currentType.GetString()) : NetProxyType.None;
            if (dns.TryGetProperty("proxy", out JsonElement proxy) && proxy.TryGetProperty("type", out JsonElement type))
            {
                NetProxyType candidate = type.ValueKind == JsonValueKind.Null ? NetProxyType.None : Enum.Parse<NetProxyType>(type.GetString());
                if (candidate != proxyType && servers is null && snapshot.TryGetProperty("configuredForwarders", out JsonElement currentServers))
                    servers = ConfigurationManifest.ReadForwardingServers(currentServers);
                proxyType = candidate;
            }
            DnsServer.ValidateForwardingServers(servers, proxyType);
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
                if (currentSettings.TryGetProperty("proxy", out JsonElement proxy))
                {
                    if (manifest.Settings.TryGetProperty("dns", out JsonElement dns) && dns.TryGetProperty("proxy", out _))
                        proxy.WriteTo(writer);
                    else if (proxy.ValueKind == JsonValueKind.Object && proxy.TryGetProperty("type", out JsonElement proxyType))
                        proxyType.WriteTo(writer);
                }
                if (currentSettings.TryGetProperty("dnsListenerCertificateLoaded", out JsonElement dnsCertificate))
                    dnsCertificate.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestDnsCertificate", out JsonElement certificate))
                    certificate.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestWebCertificate", out JsonElement webCertificate))
                    webCertificate.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestProxyPassword", out JsonElement proxyPassword))
                    proxyPassword.WriteTo(writer);
                if (currentSettings.TryGetProperty("clusterDomain", out JsonElement clusterDomain))
                    clusterDomain.WriteTo(writer);
                if (currentSettings.TryGetProperty("managedSettings", out JsonElement ownership))
                    ownership.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestZones", out JsonElement zones))
                    zones.WriteTo(writer);
                foreach (string field in new[] { "allowZones", "blockZones" })
                {
                    if (currentSettings.TryGetProperty(field, out JsonElement domains))
                        domains.WriteTo(writer);
                }
                if (currentSettings.TryGetProperty("manifestTsigKeys", out JsonElement tsigKeys))
                    tsigKeys.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestDhcpScopes", out JsonElement scopes))
                    scopes.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestDhcpOwnership", out JsonElement dhcpOwnership))
                    dhcpOwnership.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestZoneOwnership", out JsonElement zoneOwnership))
                    zoneOwnership.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestSsoOwnership", out JsonElement ssoOwnership))
                    ssoOwnership.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestSso", out JsonElement sso))
                    sso.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestLdap", out JsonElement ldap))
                    ldap.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestLdapOwnership", out JsonElement ldapOwnership))
                    ldapOwnership.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestGroupOwnership", out JsonElement groupOwnership))
                    groupOwnership.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestGroups", out JsonElement groups))
                    groups.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestUserOwnership", out JsonElement userOwnership))
                    userOwnership.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestUsers", out JsonElement users))
                    users.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestPermissionOwnership", out JsonElement permissionOwnership))
                    permissionOwnership.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestStaticSessions", out JsonElement staticSessions))
                    staticSessions.WriteTo(writer);
                if (currentSettings.TryGetProperty("manifestPermissions", out JsonElement permissions))
                    permissions.WriteTo(writer);
                writer.WriteEndArray();
            }

            // The snapshot can include sensitive URLs. Use a server-local key so the
            // revision cannot be used to guess values from the preview response.
            return Convert.ToHexString(HMACSHA256.HashData(key, data.WrittenSpan));
        }

        internal static Task ApplyAsync(ConfigurationManifest manifest, LogManager log, DnsServer dns, IReadOnlyList<IPEndPoint> endpoints, string serverDomain, int webTlsPort, Action writeCertificate, Action<DnsWebService.WebLiveSettings, Action<Action>> applyWebLiveSettings, bool alreadyActive, bool listenerTuningStaged, bool dnsBindingsStaged, ConfigurationProxy.Candidate proxy, ConfigurationDnsCertificate.Candidate certificate, ConfigurationTsig.Candidate tsig, Action writeResources, string[] resourceFiles, Action<Action> commitZones)
        {
            CheckApplySupport(manifest);

            manifest.Settings.TryGetProperty("logging", out JsonElement logging);
            JsonElement? destination = GetLoggingValue(logging, "destination");
            JsonElement? noStackTrace = GetLoggingValue(logging, "noStackTrace");
            JsonElement? retention = GetLoggingValue(logging, "retentionDays");
            JsonElement? localTime = GetLoggingValue(logging, "useLocalTime");
            string folder = logging.ValueKind == JsonValueKind.Object && logging.TryGetProperty("folder", out JsonElement folderValue)
                ? GetManifestLogFolder(folderValue, log) : null;

            return dns.ApplyManifestDnsSettingsAsync(serverDomain, endpoints, GetSourceNetworks(manifest), GetAuthoritativeDefaults(manifest), GetResolverSettings(manifest), GetStatisticsSettings(manifest), GetAppAutoUpdate(manifest), GetOutboundSocketSettings(manifest, webTlsPort), GetClientSubnetSettings(manifest), GetDnsLoggingSettings(logging), GetRecursionPolicy(manifest), GetCachePolicy(manifest), GetBlockingPolicy(manifest), GetForwardingPolicy(manifest), GetRateLimitPolicy(manifest), GetDnsTuning(manifest), GetDnsListenerPolicy(manifest), GetDnsBindings(manifest), certificate, proxy, tsig, alreadyActive, listenerTuningStaged, dnsBindingsStaged, manifest, writeDnsConfig =>
                dns.BlockListZoneManager.ApplyManifestSettings(GetBlockListInterval(manifest), GetBlockListSources(manifest), writeBlockListConfig =>
                    dns.AllowedZoneManager.ApplyManifestList(ConfigurationDomainLists.Read(manifest, "allowZones"), writeAllowed =>
                    dns.BlockedZoneManager.ApplyManifestList(ConfigurationDomainLists.Read(manifest, "blockZones"), writeBlocked =>
                    applyWebLiveSettings(GetWebLiveSettings(manifest), writeWebConfig => commitZones(() => log.ApplyManifestSettings(
                destination.HasValue ? Enum.Parse<LoggingType>(destination.Value.GetString()) : null,
                noStackTrace?.GetBoolean(),
                retention.HasValue ? decimal.ToInt32(retention.Value.GetDecimal()) : null,
                localTime?.GetBoolean(),
                folder,
                writeDnsConfig, writeCertificate, writeBlockListConfig, writeWebConfig, writeAllowed, writeBlocked, writeResources, resourceFiles)))))));
        }

        internal static DnsServer.DnsBindings GetDnsBindings(ConfigurationManifest manifest)
        {
            if (manifest is null || !manifest.Settings.TryGetProperty("dns", out JsonElement dns) ||
                !dns.TryGetProperty("listeners", out JsonElement listeners))
                return default;

            return new DnsServer.DnsBindings(
                Read("udpProxy/enabled") is JsonElement udpProxyEnabled ? udpProxyEnabled.GetBoolean() : null,
                Read("udpProxy/port") is JsonElement udpProxyPort ? decimal.ToInt32(udpProxyPort.GetDecimal()) : null,
                Read("tcpProxy/enabled") is JsonElement tcpProxyEnabled ? tcpProxyEnabled.GetBoolean() : null,
                Read("tcpProxy/port") is JsonElement tcpProxyPort ? decimal.ToInt32(tcpProxyPort.GetDecimal()) : null,
                Read("http/enabled") is JsonElement httpEnabled ? httpEnabled.GetBoolean() : null,
                Read("http/port") is JsonElement httpPort ? decimal.ToInt32(httpPort.GetDecimal()) : null,
                Read("tls/enabled") is JsonElement tlsEnabled ? tlsEnabled.GetBoolean() : null,
                Read("tls/port") is JsonElement tlsPort ? decimal.ToInt32(tlsPort.GetDecimal()) : null,
                Read("https/enabled") is JsonElement httpsEnabled ? httpsEnabled.GetBoolean() : null,
                Read("https/port") is JsonElement httpsPort ? decimal.ToInt32(httpsPort.GetDecimal()) : null,
                Read("quic/enabled") is JsonElement quicEnabled ? quicEnabled.GetBoolean() : null,
                Read("quic/port") is JsonElement quicPort ? decimal.ToInt32(quicPort.GetDecimal()) : null,
                Read("https/http3Enabled") is JsonElement http3Enabled ? http3Enabled.GetBoolean() : null,
                Read("http/unixSocket/enabled") is JsonElement httpSocketEnabled ? httpSocketEnabled.GetBoolean() : null,
                Read("http/unixSocket/path") is JsonElement httpSocketPath ? ConfigurationManifest.ReadWebUnixSocketPath(httpSocketPath, "/dns/listeners/http/unixSocket/path") : null,
                Read("https/unixSocket/enabled") is JsonElement httpsSocketEnabled ? httpsSocketEnabled.GetBoolean() : null,
                Read("https/unixSocket/path") is JsonElement httpsSocketPath ? ConfigurationManifest.ReadWebUnixSocketPath(httpsSocketPath, "/dns/listeners/https/unixSocket/path") : null);

            JsonElement? Read(string path)
            {
                JsonElement value = listeners;
                foreach (string segment in path.Split('/'))
                {
                    if (!value.TryGetProperty(segment, out value))
                        return null;
                    if (value.ValueKind == JsonValueKind.Null)
                        return _settings["/dns/listeners/" + path].Default;
                }
                return value;
            }
        }

        private static DnsServer.DnsBindings ReadCurrentDnsBindings(JsonElement snapshot)
        {
            return new DnsServer.DnsBindings(
                Read("udpProxy/enabled").GetBoolean(),
                Read("udpProxy/port").GetInt32(),
                Read("tcpProxy/enabled").GetBoolean(),
                Read("tcpProxy/port").GetInt32(),
                Read("http/enabled").GetBoolean(),
                Read("http/port").GetInt32(),
                Read("tls/enabled").GetBoolean(),
                Read("tls/port").GetInt32(),
                Read("https/enabled").GetBoolean(),
                Read("https/port").GetInt32(),
                Read("quic/enabled").GetBoolean(),
                Read("quic/port").GetInt32(),
                Read("https/http3Enabled").GetBoolean(),
                Read("http/unixSocket/enabled").GetBoolean(),
                Read("http/unixSocket/path").GetString() ?? "",
                Read("https/unixSocket/enabled").GetBoolean(),
                Read("https/unixSocket/path").GetString() ?? "");

            JsonElement Read(string path)
            {
                Setting setting = _settings["/dns/listeners/" + path];
                return snapshot.TryGetProperty(setting.ApiField, out JsonElement value) ? value : setting.Default;
            }
        }

        internal static void ValidateDnsCertificateAndBindings(ConfigurationDnsCertificate.Candidate certificate, DnsServer.DnsBindings bindings,
            DnsServer.DnsBindings current, bool hasCertificate)
        {
            if (certificate.Certificate is DnsServer.DnsCertificate desired)
            {
                hasCertificate = desired.Context is not null;
                if (!hasCertificate && ConfigurationDnsCertificate.HasSecureBindings(bindings, current))
                    throw new InvalidDataException($"{ConfigurationDnsCertificate.Path}: Disable the secure DNS listeners before removing their certificate.");
            }
            ValidateDnsBindings(bindings, current, hasCertificate);
        }

        internal static void ValidateDnsBindings(DnsServer.DnsBindings candidate, DnsServer.DnsBindings current, bool hasCertificate)
        {
            ValidateSocket(candidate.HttpSocketEnabled, candidate.HttpSocketPath, current.HttpSocketEnabled, current.HttpSocketPath, "http");
            ValidateSocket(candidate.HttpsSocketEnabled, candidate.HttpsSocketPath, current.HttpsSocketEnabled, current.HttpsSocketPath, "https");

            if (candidate.QuicEnabled == true || candidate.Http3Enabled == true)
            {
                try
                {
                    DnsServer.ValidateQuicSupport();
                }
                catch (DnsServerException)
                {
                    throw new InvalidDataException("/dns/listeners: QUIC is unavailable on this host.");
                }
            }

            if (candidate.Http3Enabled == true || (candidate.HttpsEnabled.HasValue && (candidate.Http3Enabled ?? current.Http3Enabled) == true))
            {
                if ((candidate.HttpsEnabled ?? current.HttpsEnabled) != true)
                    throw new InvalidDataException("/dns/listeners/https/http3Enabled: DNS-over-HTTPS must be enabled.");
            }

            if (!hasCertificate && (candidate.TlsEnabled == true || candidate.HttpsEnabled == true ||
                candidate.HttpsSocketEnabled == true || candidate.QuicEnabled == true || candidate.Http3Enabled == true))
                throw new InvalidDataException("/dns/listeners/certificate: An enabled secure DNS listener requires a loaded certificate.");

            static void ValidateSocket(bool? enabled, string path, bool? currentEnabled, string currentPath, string protocol)
            {
                if ((enabled is null && path is null) || (enabled ?? currentEnabled) != true)
                    return;
                if (!DnsServer.IsUnixDomainSocketSupported())
                    throw new InvalidDataException($"/dns/listeners/{protocol}/unixSocket/enabled: Unix domain sockets are unavailable on this host.");
                if (string.IsNullOrEmpty(path ?? currentPath))
                    throw new InvalidDataException($"/dns/listeners/{protocol}/unixSocket/path: A path is required when the socket is enabled.");
            }
        }

        private static DnsServer.DnsListenerPolicy GetDnsListenerPolicy(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns) || !dns.TryGetProperty("listeners", out JsonElement listeners))
                return default;

            listeners.TryGetProperty("http", out JsonElement http);
            return new DnsServer.DnsListenerPolicy(
                listeners.TryGetProperty("useClientSubnetAsSource", out JsonElement source) ? source.ValueKind == JsonValueKind.True : null,
                http.ValueKind == JsonValueKind.Object && http.TryGetProperty("helpRedirect", out JsonElement help) ? help.ValueKind != JsonValueKind.False : null,
                http.ValueKind == JsonValueKind.Object && http.TryGetProperty("realIpHeader", out JsonElement header) ? ConfigurationManifest.ReadDnsRealIpHeader(header) : null,
                listeners.TryGetProperty("reverseProxyAcl", out JsonElement acl) ? ConfigurationManifest.ReadNetworkAcl(acl, "/dns/listeners/reverseProxyAcl") : null);
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

        internal static DnsServer.DnsTuning GetDnsTuning(ConfigurationManifest manifest)
        {
            if (manifest is null || !manifest.Settings.TryGetProperty("dns", out JsonElement dns) || !dns.TryGetProperty("tuning", out JsonElement tuning))
                return default;

            return new DnsServer.DnsTuning(Read("clientTimeoutMs"), Read("tcpSendTimeoutMs"), Read("tcpReceiveTimeoutMs"),
                Read("quicIdleTimeoutMs"), Read("quicMaxInboundStreams"), Read("listenBacklog"), Read("udpSendBufferKiB"),
                Read("udpReceiveBufferKiB"), (ushort?)Read("maxConcurrentResolutionsPerCore"));

            int? Read(string field)
            {
                if (!tuning.TryGetProperty(field, out JsonElement value))
                    return null;
                return value.ValueKind == JsonValueKind.Null ? _settings["/dns/tuning/" + field].Default.GetInt32() : decimal.ToInt32(value.GetDecimal());
            }
        }

        private static DnsServer.RateLimitPolicy GetRateLimitPolicy(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns) || !dns.TryGetProperty("rateLimits", out JsonElement limits))
                return default;

            return new DnsServer.RateLimitPolicy(
                limits.TryGetProperty("ipv4", out JsonElement ipv4) ? ConfigurationManifest.ReadRateLimitTable(ipv4, ipv6: false) : null,
                limits.TryGetProperty("ipv6", out JsonElement ipv6) ? ConfigurationManifest.ReadRateLimitTable(ipv6, ipv6: true) : null,
                Read("sampleMinutes"), Read("udpTruncationPercentage"),
                limits.TryGetProperty("bypassNetworks", out JsonElement networks)
                    ? ConfigurationManifest.ReadNetworks(networks, "/dns/rateLimits/bypassNetworks") : null);

            int? Read(string field)
            {
                if (!limits.TryGetProperty(field, out JsonElement value))
                    return null;
                return value.ValueKind == JsonValueKind.Null ? _settings["/dns/rateLimits/" + field].Default.GetInt32() : decimal.ToInt32(value.GetDecimal());
            }
        }

        internal static ConfigurationProxy.Candidate PrepareProxy(ConfigurationManifest manifest, DnsServer dns)
        {
            ConfigurationProxy.Candidate proxy = ConfigurationProxy.Prepare(manifest, dns.Proxy);
            NetProxyType previous = dns.Proxy?.Type ?? NetProxyType.None;
            NetProxyType effective = proxy.Managed == 0 ? previous : proxy.Proxy?.Type ?? NetProxyType.None;
            DnsServer.ValidateForwardingServers(GetForwardingPolicy(manifest).Servers ?? (effective != previous ? dns.Forwarders : null), effective);
            return proxy;
        }

        private static DnsServer.ForwardingPolicy GetForwardingPolicy(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns) || !dns.TryGetProperty("forwarding", out JsonElement forwarding))
                return default;

            return new DnsServer.ForwardingPolicy(forwarding.TryGetProperty("servers", out JsonElement servers)
                ? ConfigurationManifest.ReadForwardingServers(servers) : null,
                Read("concurrent")?.GetBoolean(), ReadInt("retries"), ReadInt("timeoutMs"), ReadInt("concurrency"));

            JsonElement? Read(string field)
            {
                if (!forwarding.TryGetProperty(field, out JsonElement value))
                    return null;
                return value.ValueKind == JsonValueKind.Null ? _settings["/dns/forwarding/" + field].Default : value;
            }

            int? ReadInt(string field)
            {
                JsonElement? value = Read(field);
                return value.HasValue ? decimal.ToInt32(value.Value.GetDecimal()) : null;
            }
        }

        private static DnsServer.BlockingPolicy GetBlockingPolicy(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns) || !dns.TryGetProperty("blocking", out JsonElement blocking))
                return default;

            JsonElement? ttl = Read("answerTtl");
            JsonElement? response = Read("responseType");
            return new DnsServer.BlockingPolicy(Read("enabled")?.GetBoolean(), Read("allowTxtReport")?.GetBoolean(),
                Read("bypassNetworks") is JsonElement bypass ? ConfigurationManifest.ReadNetworks(bypass, "/dns/blocking/bypassNetworks") : null,
                response.HasValue ? Enum.Parse<DnsServerBlockingType>(response.Value.GetString()) : null,
                ttl.HasValue ? decimal.ToUInt32(ttl.Value.GetDecimal()) : null,
                Read("customAddresses") is JsonElement addresses ? ReadBlockingAddresses(addresses) : null);

            JsonElement? Read(string field)
            {
                if (!blocking.TryGetProperty(field, out JsonElement value))
                    return null;
                return value.ValueKind == JsonValueKind.Null ? _settings["/dns/blocking/" + field].Default : value;
            }
        }

        private static IPAddress[] ReadBlockingAddresses(JsonElement value)
        {
            return value.ValueKind == JsonValueKind.Null ? [] :
                DnsServer.NormalizeBlockingAddresses(value.EnumerateArray().Select(address => IPAddress.Parse(address.GetString())));
        }

        private static DnsServer.CachePolicy GetCachePolicy(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns) || !dns.TryGetProperty("cache", out JsonElement cache))
                return default;

            cache.TryGetProperty("serveStale", out JsonElement stale);
            DnsServer.CachePolicy prefetch = cache.TryGetProperty("prefetch", out JsonElement prefetchElement)
                ? ReadCachePrefetch(prefetchElement) : default;
            return prefetch with
            {
                SaveToDisk = Read(cache, "saveToDisk", "saveToDisk") is JsonElement saveToDisk ? saveToDisk.GetBoolean() : null,
                ServeStale = Read(stale, "enabled", "serveStale/enabled") is JsonElement serveStale ? serveStale.GetBoolean() : null,
                StaleTtl = Read(stale, "ttl", "serveStale/ttl") is JsonElement staleTtl ? decimal.ToUInt32(staleTtl.GetDecimal()) : null,
                StaleAnswerTtl = Read(stale, "answerTtl", "serveStale/answerTtl") is JsonElement staleAnswerTtl ? decimal.ToUInt32(staleAnswerTtl.GetDecimal()) : null,
                StaleResetTtl = Read(stale, "resetTtl", "serveStale/resetTtl") is JsonElement staleResetTtl ? decimal.ToUInt32(staleResetTtl.GetDecimal()) : null,
                StaleMaxWait = Read(stale, "maxWaitMs", "serveStale/maxWaitMs") is JsonElement staleMaxWait ? decimal.ToInt32(staleMaxWait.GetDecimal()) : null,
                MaximumEntries = Read(cache, "maximumEntries", "maximumEntries") is JsonElement maximumEntries ? decimal.ToInt64(maximumEntries.GetDecimal()) : null,
                MinimumRecordTtl = Read(cache, "minimumRecordTtl", "minimumRecordTtl") is JsonElement minimumRecordTtl ? decimal.ToUInt32(minimumRecordTtl.GetDecimal()) : null,
                MaximumRecordTtl = Read(cache, "maximumRecordTtl", "maximumRecordTtl") is JsonElement maximumRecordTtl ? decimal.ToUInt32(maximumRecordTtl.GetDecimal()) : null,
                NegativeRecordTtl = Read(cache, "negativeRecordTtl", "negativeRecordTtl") is JsonElement negativeRecordTtl ? decimal.ToUInt32(negativeRecordTtl.GetDecimal()) : null,
                FailureRecordTtl = Read(cache, "failureRecordTtl", "failureRecordTtl") is JsonElement failureRecordTtl ? decimal.ToUInt32(failureRecordTtl.GetDecimal()) : null,
            };

            static JsonElement? Read(JsonElement section, string field, string path)
            {
                if (section.ValueKind != JsonValueKind.Object || !section.TryGetProperty(field, out JsonElement value))
                    return null;
                return value.ValueKind == JsonValueKind.Null ? _settings["/dns/cache/" + path].Default : value;
            }
        }

        private static DnsServer.CachePolicy ReadCachePrefetch(JsonElement value)
        {
            return new DnsServer.CachePolicy
            {
                PrefetchEnabled = Read("enabled")?.GetBoolean(),
                PrefetchEligibility = ReadInt("eligibility"),
                PrefetchTrigger = ReadInt("trigger")
            };

            JsonElement? Read(string name)
            {
                if (!value.TryGetProperty(name, out JsonElement field))
                    return null;
                return field.ValueKind == JsonValueKind.Null ? _settings["/dns/cache/prefetch/" + name].Default : field;
            }

            int? ReadInt(string name)
            {
                JsonElement? field = Read(name);
                return field.HasValue ? decimal.ToInt32(field.Value.GetDecimal()) : null;
            }
        }

        private static DnsServer.RecursionPolicy GetRecursionPolicy(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns) || !dns.TryGetProperty("recursion", out JsonElement recursion))
                return default;

            DnsServerRecursion? mode = recursion.TryGetProperty("mode", out JsonElement value)
                ? value.ValueKind == JsonValueKind.Null ? DnsServerRecursion.AllowOnlyForPrivateNetworks : Enum.Parse<DnsServerRecursion>(value.GetString())
                : null;
            NetworkAccessControl[] acl = recursion.TryGetProperty("networkAcl", out JsonElement rules)
                ? ConfigurationManifest.ReadNetworkAcl(rules, "/dns/recursion/networkAcl") : null;
            return new DnsServer.RecursionPolicy(mode, acl,
                Read("randomizeName")?.GetBoolean(), Read("qnameMinimization")?.GetBoolean(), Read("locallyServedDnsZones")?.GetBoolean(),
                ReadInt("retries"), ReadInt("timeoutMs"), ReadInt("concurrency"), ReadInt("maxStackCount"));

            JsonElement? Read(string field)
            {
                if (!recursion.TryGetProperty(field, out JsonElement setting))
                    return null;
                return setting.ValueKind == JsonValueKind.Null ? _settings["/dns/recursion/" + field].Default : setting;
            }

            int? ReadInt(string field)
            {
                JsonElement? setting = Read(field);
                return setting.HasValue ? decimal.ToInt32(setting.Value.GetDecimal()) : null;
            }
        }

        private static DnsServer.ClientSubnetSettings GetClientSubnetSettings(ConfigurationManifest manifest)
        {
            return manifest.Settings.TryGetProperty("dns", out JsonElement dns) && dns.TryGetProperty("clientSubnet", out JsonElement subnet)
                ? ReadClientSubnetSettings(subnet) : default;
        }

        private static DnsServer.ClientSubnetSettings ReadClientSubnetSettings(JsonElement subnet)
        {
            bool? enabled = subnet.TryGetProperty("enabled", out JsonElement value)
                ? value.ValueKind != JsonValueKind.Null && value.GetBoolean() : null;
            bool hasIpv4 = subnet.TryGetProperty("ipv4Override", out JsonElement ipv4);
            bool hasIpv6 = subnet.TryGetProperty("ipv6Override", out JsonElement ipv6);
            return new DnsServer.ClientSubnetSettings(enabled, ReadPrefix("ipv4PrefixLength", 24), ReadPrefix("ipv6PrefixLength", 56),
                hasIpv4, hasIpv4 ? ConfigurationManifest.ReadNetwork(ipv4.GetString(), "/dns/clientSubnet/ipv4Override", AddressFamily.InterNetwork) : null,
                hasIpv6, hasIpv6 ? ConfigurationManifest.ReadNetwork(ipv6.GetString(), "/dns/clientSubnet/ipv6Override", AddressFamily.InterNetworkV6) : null);

            byte? ReadPrefix(string name, byte defaultValue)
            {
                if (!subnet.TryGetProperty(name, out JsonElement value))
                    return null;
                return value.ValueKind == JsonValueKind.Null ? defaultValue : decimal.ToByte(value.GetDecimal());
            }
        }

        private static DnsServer.OutboundSocketSettings GetOutboundSocketSettings(ConfigurationManifest manifest, int webTlsPort)
        {
            if (!manifest.Settings.TryGetProperty("dns", out JsonElement dns))
                return default;

            IPv6Mode? ipv6 = dns.TryGetProperty("ipv6Mode", out JsonElement mode)
                ? mode.ValueKind == JsonValueKind.Null ? IPv6Mode.Disabled : Enum.Parse<IPv6Mode>(mode.GetString())
                : null;
            if (!dns.TryGetProperty("udpSocketPool", out JsonElement socketPool))
                return new DnsServer.OutboundSocketSettings(ipv6, null);

            bool? pool = socketPool.TryGetProperty("enabled", out JsonElement enabled)
                ? enabled.ValueKind == JsonValueKind.Null ? DnsServer.DefaultUdpSocketPoolEnabled : enabled.GetBoolean()
                : null;
            ushort[] ports = socketPool.TryGetProperty("excludedPorts", out JsonElement excludedPorts)
                ? ReadExcludedPorts(excludedPorts, webTlsPort) : null;
            return new DnsServer.OutboundSocketSettings(ipv6, pool, ports);
        }

        private static ushort[] ReadExcludedPorts(JsonElement value, int? webTlsPort = null)
        {
            return value.ValueKind == JsonValueKind.Null
                ? webTlsPort.HasValue ? [checked((ushort)webTlsPort.Value)] : []
                : value.EnumerateArray().Select(port => decimal.ToUInt16(port.GetDecimal())).Distinct().Order().ToArray();
        }

        private static bool? GetAppAutoUpdate(ConfigurationManifest manifest)
        {
            if (!manifest.Settings.TryGetProperty("apps", out JsonElement apps) ||
                !apps.TryGetProperty("autoUpdate", out JsonElement value))
                return null;

            return value.ValueKind == JsonValueKind.Null || value.GetBoolean();
        }

        internal static void CheckClusterApplySupport(ConfigurationManifest manifest, bool clusterInitialized)
        {
            if (!clusterInitialized)
                return;
            if (ConfigurationPermissions.TryGetDeclaration(manifest, out _))
                throw new InvalidDataException("/auth/permissions: Applying permissions to a cluster is not implemented.");
            if (ConfigurationUsers.TryGetDeclaration(manifest, out _))
                throw new InvalidDataException("/auth/users: Applying user settings to a cluster is not implemented.");
            if (ConfigurationGroups.TryGetDeclaration(manifest, out _))
                throw new InvalidDataException("/auth/groups: Applying group settings to a cluster is not implemented.");
            if (ConfigurationSso.IsDeclared(manifest))
                throw new InvalidDataException("/auth/sso: Applying SSO settings to a cluster is not implemented.");
            if (ConfigurationLdap.IsDeclared(manifest))
                throw new InvalidDataException("/auth/ldap: Applying LDAP settings to a cluster is not implemented.");
            if (manifest.Settings.TryGetProperty("zones", out JsonElement zones) && zones.EnumerateObject().Any())
                throw new InvalidDataException("/zones: Applying zones to a cluster is not implemented.");
            if (manifest.Settings.TryGetProperty("allowZones", out _) || manifest.Settings.TryGetProperty("blockZones", out _))
                throw new InvalidDataException("Applying explicit allow and block lists to a cluster is not implemented.");
            if (ConfigurationTsig.TryGetDeclaration(manifest, out _))
                throw new InvalidDataException("/dns/tsigKeys: Applying TSIG keys to a cluster is not implemented.");
            if (ConfigurationWebCertificate.IsDeclared(manifest))
                throw new InvalidDataException("/web/certificate: Applying web certificate settings to a cluster is not implemented.");
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
            if (GetAppAutoUpdate(manifest).HasValue)
                throw new InvalidDataException("/apps/autoUpdate: Applying app automatic updates to a cluster is not implemented.");
            if (GetDnsTuning(manifest) != default)
                throw new InvalidDataException("/dns/tuning: Applying DNS tuning to a cluster is not implemented.");
            if (GetRateLimitPolicy(manifest) != default)
                throw new InvalidDataException("/dns/rateLimits: Applying query-rate limits to a cluster is not implemented.");
            if (ConfigurationProxy.TryGetDeclaration(manifest, out JsonElement proxy) && proxy.EnumerateObject().Any())
                throw new InvalidDataException("/dns/proxy: Applying outbound proxy settings to a cluster is not implemented.");
            if (GetForwardingPolicy(manifest) != default)
                throw new InvalidDataException("/dns/forwarding: Applying forwarding policy to a cluster is not implemented.");
            if (GetBlockingPolicy(manifest) != default)
                throw new InvalidDataException("/dns/blocking: Applying blocking policy to a cluster is not implemented.");
            if (GetRecursionPolicy(manifest) != default)
                throw new InvalidDataException("/dns/recursion: Applying recursion policy to a cluster is not implemented.");
            if (GetClientSubnetSettings(manifest) != default)
                throw new InvalidDataException("/dns/clientSubnet: Applying EDNS Client Subnet settings to a cluster is not implemented.");
            if (GetResolverSettings(manifest).HasValues)
                throw new InvalidDataException("/dns: Applying update checks, UDP payload size, or DNSSEC validation to a cluster is not implemented.");
        }

        internal static string ReadWebRoot(ConfigurationManifest manifest, LogManager log = null)
        {
            if (manifest is null || !manifest.Settings.TryGetProperty("web", out JsonElement web) ||
                !web.TryGetProperty("rootPath", out JsonElement value))
                return null;

            return NormalizeWebRoot(value, log);
        }

        private static string NormalizeWebRoot(JsonElement value, LogManager log)
        {
            string path = value.GetString();
            if (string.IsNullOrWhiteSpace(path))
                return "";

            try
            {
                path = log is null ? Path.GetFullPath(path) : log.ConvertToAbsolutePath(path);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException)
            {
                throw new InvalidDataException("/web/rootPath: Invalid directory path.");
            }
            if (!Directory.Exists(path))
                throw new InvalidDataException("/web/rootPath: The directory does not exist on the server.");
            return Path.TrimEndingDirectorySeparator(path);
        }

        internal static void CheckApplySupport(ConfigurationManifest manifest)
        {
            if (manifest.FilePath is null && manifest.Settings.TryGetProperty("web", out JsonElement web) && web.TryGetProperty("rootPath", out _))
                throw new InvalidDataException("/web/rootPath: Changing the served directory requires a local startup manifest.");

            foreach (JsonProperty section in manifest.Settings.EnumerateObject())
            {
                if (section.Name is "schemaVersion" or "$schema")
                    continue;
                CheckApplySupport(section.Value, AppendPath("", section.Name));
            }
        }

        private static void CheckApplySupport(JsonElement value, string path)
        {
            if (path == "/zones")
            {
                foreach (JsonProperty zone in value.EnumerateObject())
                {
                    string zonePath = AppendPath(path, zone.Name);
                    if (zone.Value.ValueKind == JsonValueKind.Null)
                        continue;
                    foreach (JsonProperty field in zone.Value.EnumerateObject())
                    {
                        if (ConfigurationZonePolicies.IsPolicy(field.Name))
                        {
                            foreach (JsonProperty option in field.Value.EnumerateObject())
                            {
                                if (option.Name != "mode" && option.Name != (field.Name == "notify" ? "nameServers" : "networkAcl") &&
                                    !(field.Name == "transfer" && option.Name == "tsigKeys") &&
                                    !(field.Name == "updates" && option.Name == "securityPolicies"))
                                    throw new InvalidDataException($"{AppendPath(AppendPath(zonePath, field.Name), option.Name)}: Applying this zone setting is not implemented.");
                            }
                            continue;
                        }
                        if (field.Name is "enabled" or "records" or "permissions" ||
                            (field.Name == "type" && field.Value.ValueEquals("Primary")))
                            continue;
                        throw new InvalidDataException($"{AppendPath(zonePath, field.Name)}: Applying this zone setting is not implemented.");
                    }
                }
                return;
            }

            if (path is ConfigurationSso.Path or ConfigurationLdap.Path or ConfigurationGroups.Path or ConfigurationUsers.Path or ConfigurationPermissions.Path or ConfigurationStaticSessions.Path or "/dhcp/scopes" or "/allowZones" or "/blockZones" or ConfigurationTsig.Path or "/web/rootPath" or "/dns/proxy" or ConfigurationDnsCertificate.Path or ConfigurationWebCertificate.Path || (_settings.TryGetValue(path, out Setting setting) && setting.CanApply) ||
                (value.ValueKind == JsonValueKind.Null && path is "/web/httpUnixSocket" or "/web/tlsUnixSocket" or "/dns/listeners/http/unixSocket" or "/dns/listeners/https/unixSocket"))
                return;

            if ((value.ValueKind == JsonValueKind.Object) &&
                (path is "/auth" or "/dhcp" || _settings.Any(entry => entry.Value.CanApply && entry.Key.StartsWith(path + "/", StringComparison.Ordinal))))
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

        private static DnsServer.DnsLoggingSettings GetDnsLoggingSettings(JsonElement logging)
        {
            return new DnsServer.DnsLoggingSettings(GetLoggingValue(logging, "ignoreResolverLogs")?.GetBoolean(),
                GetLoggingValue(logging, "logQueries")?.GetBoolean());
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
                if (path == ForwardingServersPath && ConfigurationManifest.ReadForwardingServers(value).Any(server =>
                    server.DoHEndPoint is Uri uri && (uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)))
                    continue;
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

            foreach (string field in new[] { "allowZones", "blockZones" })
            {
                if (currentSettings.TryGetProperty(field, out JsonElement domains))
                    manifest.Add(field, JsonSerializer.SerializeToNode(domains.EnumerateArray().Select(item =>
                        item.GetString() is { Length: > 0 } name ? name : ".")));
            }

            if (currentSettings.TryGetProperty("tsigKeys", out JsonElement keys) && keys.GetArrayLength() > 0)
            {
                string catalogKey = currentSettings.TryGetProperty("clusterDomain", out JsonElement clusterDomain)
                    ? ConfigurationTsig.GetCatalogKey(clusterDomain.GetString()) : null;
                JsonObject exportedKeys = ConfigurationTsig.Export(keys, catalogKey);
                if (exportedKeys.Count > 0)
                    manifest["dns"]!.AsObject().Add("tsigKeys", exportedKeys);
            }

            if (currentSettings.TryGetProperty("proxy", out JsonElement currentProxy))
            {
                var proxy = new JsonObject();
                foreach (string field in new[] { "type", "address", "port", "username", "bypass" })
                {
                    if (currentProxy.ValueKind == JsonValueKind.Object && currentProxy.TryGetProperty(field, out JsonElement value))
                        proxy.Add(field, JsonNode.Parse(value.GetRawText()));
                }
                if (proxy["type"] is JsonValue type && type.GetValue<string>() != nameof(NetProxyType.None) && !proxy.ContainsKey("username"))
                    proxy.Add("username", null);
                if (currentProxy.ValueKind == JsonValueKind.Null)
                    proxy.Add("type", nameof(NetProxyType.None));
                if (proxy.Count > 0)
                    manifest["dns"]!.AsObject().Add("proxy", proxy);
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

            if (path is "/dns/rateLimits/ipv4" or "/dns/rateLimits/ipv6")
                return SerializeRateLimits(ConfigurationManifest.ReadRateLimitTable(value, path.EndsWith("ipv6", StringComparison.Ordinal)));

            if (path == ExcludedPortsPath)
                return JsonSerializer.SerializeToElement(ReadExcludedPorts(value));

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
                    if (field.Name is not ("type" or "enabled" or "records" or "permissions") && !ConfigurationZonePolicies.IsPolicy(field.Name))
                        throw new InvalidDataException($"{AppendPath(path, field.Name)}: Planning for this zone setting is not implemented.");
                }

                string type = declaration.Value.TryGetProperty("type", out JsonElement declaredType) ? declaredType.GetString() : null;
                if (!exists)
                {
                    if (type is null)
                        throw new InvalidDataException($"{path}/type: A zone type is required to create a zone.");
                    if (type != "Primary")
                        throw new InvalidDataException($"{path}/type: Preview of creation is currently supported for primary zones.");
                    ConfigurationZonePolicies.Compare(name, path, declaration.Value, current, changes);
                    changes.Add(new ConfigurationChange(path, ConfigurationChangeKind.Add, false));
                    continue;
                }

                if (type is not null && !current.GetProperty("type").ValueEquals(type))
                    throw new InvalidDataException($"{path}/type: The declared type differs from the existing zone type.");

                ConfigurationZonePolicies.Compare(name, path, declaration.Value, current, changes);

                if (current.TryGetProperty("recordChanges", out JsonElement recordChanges))
                {
                    int index = 0;
                    bool removesRecords = false;
                    foreach (JsonElement change in recordChanges.EnumerateArray())
                    {
                        if (change.ValueKind != JsonValueKind.Null)
                        {
                            var kind = (ConfigurationChangeKind)change.GetInt32();
                            if (kind == ConfigurationChangeKind.Remove)
                                removesRecords = true;
                            else
                                changes.Add(new ConfigurationChange($"{path}/records/{index}", kind, false));
                        }
                        index++;
                    }
                    if (removesRecords)
                        changes.Add(new ConfigurationChange($"{path}/records", ConfigurationChangeKind.Remove, false));
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

        internal sealed record ZoneRecordEdit(string Owner, DnsResourceRecordType Type, DnsResourceRecordData Data,
            DnsResourceRecord Existing, uint? Ttl, bool? Disabled, string Comments, uint? ExpiryTtl, IPAddress[] Glue, ConfigurationChangeKind? Kind);

        internal static ConfigurationChangeKind?[] CompareZoneRecords(string zoneName, string declarationName, string serverDomain,
            JsonElement records, IReadOnlyList<DnsResourceRecord> currentRecords, bool ownsRecords) =>
            PrepareZoneRecordEdits(zoneName, declarationName, serverDomain, records, currentRecords, ownsRecords).Select(edit => edit.Kind).ToArray();

        internal static IReadOnlyList<ZoneRecordEdit> PrepareZoneRecordEdits(string zoneName, string declarationName, string serverDomain,
            JsonElement records, IReadOnlyList<DnsResourceRecord> currentRecords, bool ownsRecords)
        {
            string path = AppendPath("/zones", declarationName) + "/records";
            var changes = new List<ZoneRecordEdit>();
            var current = currentRecords.ToLookup(record => (record.Name.ToLowerInvariant(), record.Type));
            var matched = new HashSet<DnsResourceRecord>(ReferenceEqualityComparer.Instance);
            var declared = new HashSet<(string Owner, DnsResourceRecordType Type, DnsResourceRecordData Data)>();
            int index = 0;
            foreach (JsonElement record in records.ValueKind == JsonValueKind.Null ? [] : records.EnumerateArray().ToArray())
            {
                string recordPath = $"{path}/{index}";
                foreach (JsonProperty field in record.EnumerateObject())
                {
                    if (field.Name is not ("owner" or "type" or "data" or "ttl" or "disabled" or "comments" or "expiryTtl" or "glue"))
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
                uint? ttl = record.TryGetProperty("ttl", out JsonElement ttlValue) ? decimal.ToUInt32(ttlValue.GetDecimal()) : null;
                bool? disabled = record.TryGetProperty("disabled", out JsonElement disabledValue) ? disabledValue.GetBoolean() : null;
                string comments = record.TryGetProperty("comments", out JsonElement commentsValue) ? commentsValue.GetString() : null;
                uint? expiry = record.TryGetProperty("expiryTtl", out JsonElement expiryValue) ? decimal.ToUInt32(expiryValue.GetDecimal()) : null;
                IPAddress[] glue = null;
                if (record.TryGetProperty("glue", out JsonElement glueValue))
                {
                    if (rdata is not DnsNSRecordData ns)
                        throw new InvalidDataException($"{recordPath}/glue: Glue addresses require an NS record.");
                    glue = glueValue.EnumerateArray().Select(address => IPAddress.Parse(address.GetString())).ToArray();
                    if (glue.Length > 0 && owner == zoneName && (ns.NameServer.Equals(zoneName, StringComparison.OrdinalIgnoreCase) ||
                        zoneName.Length == 0 || ns.NameServer.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase)))
                        throw new InvalidDataException($"{recordPath}/glue: Use separate address records for in-zone apex name servers.");
                }
                ConfigurationChangeKind? kind = null;
                if (existing is null)
                {
                    if (current[(owner, type)].Any(IsLeaseRecord))
                        throw new InvalidDataException($"{recordPath}: This record conflicts with a DHCP-maintained record.");
                    kind = ConfigurationChangeKind.Add;
                }
                else
                {
                    if (IsLeaseRecord(existing))
                        throw new InvalidDataException($"{recordPath}: This record is maintained by DHCP.");
                    matched.Add(existing);
                    var metadata = existing.Tag as GenericRecordInfo;
                    if ((ttl.HasValue && ttl.Value != existing.OriginalTtlValue) ||
                        (disabled.HasValue && disabled.Value != (metadata?.Disabled ?? false)) ||
                        (comments is not null && comments != (metadata?.Comments ?? string.Empty)) ||
                        (expiry.HasValue && expiry.Value != (metadata?.ExpiryTtl ?? 0u)) ||
                        (glue is not null && !glue.Select(address => address.ToString()).SequenceEqual(
                            (metadata as NSRecordInfo)?.GlueRecords?.Select(address => address.RDATA.ToString()) ?? [], StringComparer.Ordinal)))
                        kind = ConfigurationChangeKind.Update;
                }
                changes.Add(new ZoneRecordEdit(owner, type, rdata, existing, ttl, disabled, comments, expiry, glue, kind));
                index++;
            }

            foreach (DnsResourceRecord record in currentRecords)
            {
                if (!matched.Contains(record) && !IsLeaseRecord(record) &&
                    !IsGeneratedRecord(zoneName, serverDomain, record.Name, record.Type, record.RDATA))
                {
                    if (!ownsRecords)
                        throw new InvalidDataException($"{path}: An existing record has no known owner. Declare the existing record or omit the collection.");

                    changes.Add(new ZoneRecordEdit(record.Name.ToLowerInvariant(), record.Type, record.RDATA,
                        record, null, null, null, null, null, ConfigurationChangeKind.Remove));
                }
            }

            return changes;
        }

        internal static bool IsGeneratedRecord(string zoneName, string serverDomain, string owner, DnsResourceRecordType type, DnsResourceRecordData data)
        {
            if (type is DnsResourceRecordType.DNSKEY or DnsResourceRecordType.RRSIG or DnsResourceRecordType.NSEC or
                DnsResourceRecordType.NSEC3 or DnsResourceRecordType.NSEC3PARAM)
                return true;

            return owner.Equals(zoneName, StringComparison.OrdinalIgnoreCase) &&
                (type == DnsResourceRecordType.SOA ||
                 (data is DnsNSRecordData ns && ns.NameServer.Equals(serverDomain, StringComparison.OrdinalIgnoreCase)));
        }

        internal static bool IsLeaseRecord(DnsResourceRecord record)
        {
            return record.Type is DnsResourceRecordType.A or DnsResourceRecordType.PTR &&
                record.Tag is GenericRecordInfo { Comments: string comments } &&
                comments.StartsWith("Via '", StringComparison.Ordinal) &&
                comments.EndsWith("' DHCP scope", StringComparison.Ordinal);
        }

        private static void Compare(JsonElement desired, string path, JsonElement currentSettings, List<ConfigurationChange> changes, LogManager log, int? declaredWebTlsPort)
        {
            if (path is "/allowZones" or "/blockZones")
            {
                ConfigurationDomainLists.Compare(desired, path, currentSettings, changes);
                return;
            }

            if (path == ConfigurationTsig.Path)
            {
                ConfigurationTsig.Compare(currentSettings, changes);
                return;
            }

            if (path == ConfigurationWebCertificate.Path)
            {
                ConfigurationWebCertificate.Compare(desired, currentSettings, changes);
                return;
            }

            if (path == ConfigurationDnsCertificate.Path)
            {
                ConfigurationDnsCertificate.Compare(desired, currentSettings,
                    ConfigurationDnsCertificate.HasSecureBindings(default, ReadCurrentDnsBindings(currentSettings)), changes);
                return;
            }

            if (path == "/dns/proxy")
            {
                ConfigurationProxy.Compare(desired, currentSettings, changes);
                return;
            }

            if (path == "/dns/cache/prefetch")
            {
                DnsServer.CachePolicy prefetch = DnsServer.NormalizeCachePrefetch(ReadCachePrefetch(desired),
                    currentSettings.GetProperty("cachePrefetchTrigger").GetInt32());
                ComparePrefetch("enabled", prefetch.PrefetchEnabled);
                ComparePrefetch("eligibility", prefetch.PrefetchEligibility);
                ComparePrefetch("trigger", prefetch.PrefetchTrigger);
                return;

                void ComparePrefetch<T>(string field, T? value) where T : struct
                {
                    if (value.HasValue)
                        Compare(JsonSerializer.SerializeToElement(value.Value), path + "/" + field, currentSettings, changes, log, declaredWebTlsPort);
                }
            }

            if (path == "/dns/clientSubnet")
            {
                DnsServer.ClientSubnetSettings subnet = ReadClientSubnetSettings(desired);
                foreach (JsonProperty field in desired.EnumerateObject())
                {
                    JsonElement value = field.Value;
                    if (field.Name == "ipv4Override" && subnet.Ipv4Override is not null)
                    {
                        byte prefix = subnet.Ipv4Prefix ?? currentSettings.GetProperty("eDnsClientSubnetIPv4PrefixLength").GetByte();
                        value = JsonSerializer.SerializeToElement(DnsServer.NormalizeClientSubnetOverride(subnet.Ipv4Override, prefix).ToString());
                    }
                    else if (field.Name == "ipv6Override" && subnet.Ipv6Override is not null)
                    {
                        byte prefix = subnet.Ipv6Prefix ?? currentSettings.GetProperty("eDnsClientSubnetIPv6PrefixLength").GetByte();
                        value = JsonSerializer.SerializeToElement(DnsServer.NormalizeClientSubnetOverride(subnet.Ipv6Override, prefix).ToString());
                    }
                    Compare(value, AppendPath(path, field.Name), currentSettings, changes, log, declaredWebTlsPort);
                }
                return;
            }

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
                    else if (path is "/dns/authoritative/zoneTransferAllowedNetworks" or "/dns/authoritative/notifyAllowedNetworks" or "/dns/blocking/bypassNetworks" or "/dns/rateLimits/bypassNetworks")
                    {
                        candidate = SortAddresses(ConfigurationManifest.ReadNetworks(desired, path).Select(network => network.ToString()));
                        current = SortAddresses(ConfigurationManifest.ReadNetworks(current, path).Select(network => network.ToString()));
                    }
                    else if (path == ForwardingServersPath)
                    {
                        NameServerAddress[] servers = ConfigurationManifest.ReadForwardingServers(desired);
                        candidate = SerializeForwardingServers(servers);
                        current = SerializeForwardingServers(ConfigurationManifest.ReadForwardingServers(current));
                    }
                    else if (path is "/dns/rateLimits/ipv4" or "/dns/rateLimits/ipv6")
                    {
                        candidate = SerializeRateLimits(ConfigurationManifest.ReadRateLimitTable(desired, path.EndsWith("ipv6", StringComparison.Ordinal)));
                    }
                    else if (path == "/dns/blocking/customAddresses")
                    {
                        candidate = JsonSerializer.SerializeToElement(ReadBlockingAddresses(desired).Select(address => address.ToString()));
                    }
                    else if (path is "/dns/recursion/networkAcl" or "/dns/listeners/reverseProxyAcl")
                    {
                        var rules = ConfigurationManifest.ReadNetworkAcl(desired, path);
                        candidate = JsonSerializer.SerializeToElement(rules.Select(rule => rule.ToString()).ToArray());
                    }
                    else if (path == "/web/reverseProxyAcl")
                    {
                        var rules = ConfigurationManifest.ReadWebReverseProxyAcl(desired);
                        candidate = JsonSerializer.SerializeToElement(rules.Select(rule => rule.ToString()).ToArray());
                    }
                    else if (path == "/web/rootPath")
                    {
                        string directory = NormalizeWebRoot(desired, log);
                        candidate = JsonSerializer.SerializeToElement(directory.Length == 0 ? null : directory);
                    }
                    else if (path == "/dns/listeners/http/realIpHeader")
                    {
                        string header = ConfigurationManifest.ReadDnsRealIpHeader(desired);
                        candidate = JsonSerializer.SerializeToElement(string.Equals(header, current.GetString(), StringComparison.OrdinalIgnoreCase) ? current.GetString() : header);
                    }
                    else if (path is "/web/realIpHeader" or "/web/frameAncestors")
                    {
                        bool realIp = path == "/web/realIpHeader";
                        string value = ConfigurationManifest.ReadWebHeader(desired, realIp);
                        if (realIp && string.Equals(value, current.GetString(), StringComparison.OrdinalIgnoreCase))
                            value = current.GetString();
                        candidate = JsonSerializer.SerializeToElement(value);
                    }
                    else if (path is "/web/httpUnixSocket/path" or "/web/tlsUnixSocket/path" or "/dns/listeners/http/unixSocket/path" or "/dns/listeners/https/unixSocket/path")
                    {
                        string socket = ConfigurationManifest.ReadWebUnixSocketPath(desired, path);
                        candidate = JsonSerializer.SerializeToElement(socket.Length == 0 ? null : socket);
                    }
                    else if (path == ExcludedPortsPath)
                    {
                        int? tlsPort = desired.ValueKind == JsonValueKind.Null
                            ? declaredWebTlsPort ?? currentSettings.GetProperty("webServiceTlsPort").GetInt32() : null;
                        candidate = JsonSerializer.SerializeToElement(ReadExcludedPorts(desired, tlsPort));
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
                    bool restartDns = path == DnsEndpointsPath || path.StartsWith("/dns/listeners/", StringComparison.Ordinal) &&
                        path.EndsWith("/enabled", StringComparison.Ordinal) || path is
                        "/dns/tuning/tcpSendTimeoutMs" or "/dns/tuning/tcpReceiveTimeoutMs" or "/dns/tuning/quicIdleTimeoutMs" or
                        "/dns/listeners/https/http3Enabled" or "/dns/listeners/http/unixSocket/path" or "/dns/listeners/https/unixSocket/path" or
                        "/dns/listeners/udpProxy/port" or "/dns/listeners/tcpProxy/port" or "/dns/listeners/http/port" or
                        "/dns/listeners/tls/port" or "/dns/listeners/https/port" or "/dns/listeners/quic/port" or
                        "/dns/tuning/quicMaxInboundStreams" or "/dns/tuning/listenBacklog" or "/dns/tuning/udpSendBufferKiB" or "/dns/tuning/udpReceiveBufferKiB";
                    changes.Add(new ConfigurationChange(path, kind, setting.RestartWebService, restartDns));
                }

                return;
            }

            if (desired.ValueKind == JsonValueKind.Null && path is "/web/httpUnixSocket" or "/web/tlsUnixSocket" or "/dns/listeners/http/unixSocket" or "/dns/listeners/https/unixSocket")
            {
                Compare(desired, path + "/enabled", currentSettings, changes, log, declaredWebTlsPort);
                Compare(desired, path + "/path", currentSettings, changes, log, declaredWebTlsPort);
                return;
            }

            if ((desired.ValueKind == JsonValueKind.Object) && _settings.Keys.Any(field => field.StartsWith(path + "/", StringComparison.Ordinal)))
            {
                foreach (JsonProperty property in desired.EnumerateObject())
                    Compare(property.Value, AppendPath(path, property.Name), currentSettings, changes, log, declaredWebTlsPort);

                return;
            }

            throw new InvalidDataException($"{JsonEncodedText.Encode(path)}: Planning for this setting is not implemented.");
        }

        private static JsonElement SerializeRateLimits(IReadOnlyDictionary<int, (int Udp, int Tcp)> limits)
        {
            return JsonSerializer.SerializeToElement(limits.OrderByDescending(entry => entry.Key)
                .Select(entry => new { prefix = entry.Key, udpLimit = entry.Value.Udp, tcpLimit = entry.Value.Tcp }));
        }

        private static JsonElement SerializeForwardingServers(IEnumerable<NameServerAddress> servers)
        {
            return JsonSerializer.SerializeToElement(servers.Select(server => new { address = server.ToString(), transport = server.Protocol.ToString() }));
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
