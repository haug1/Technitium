# Declarative settings inventory

This inventory maps existing configuration inputs to proposed manifest paths. Defaults refer to a fresh configuration before environment overrides. Activation describes the current service behavior. Cluster scope describes current configuration transfer, which the manifest policy must account for.

## Web service

These settings are node-local. The settings API reads and writes them through `settings/get` and `settings/set`. `webservice.config` stores them. Without a persisted web root override, the server reads the web root from the environment at each web service start. The reader supplies the default proxy ACL for versions before 2, disables missing Unix socket settings, and supplies the default frame policy before version 3. [Settings API](DnsServerCore/WebServiceSettingsApi.cs#L182) · [Web service persistence](DnsServerCore/DnsWebService.cs#L472) · [Web root](DnsServerCore/DnsWebService.cs#L1817)

The environment aliases in this table start with `DNS_SERVER_WEB_SERVICE_`. Persisted settings use the environment aliases on initial creation when no legacy configuration was loaded.

| Proposed manifest path | API field | Environment suffix | Type and default | Validation, dependencies, and activation |
| --- | --- | --- | --- | --- |
| `web.localAddresses` | `webServiceLocalAddresses` | `LOCAL_ADDRESSES` | IP address array, `0.0.0.0` and `::` | Empty selects wildcard addresses. Use Kestrel address normalization. Restart web listeners. |
| `web.httpPort` | `webServiceHttpPort` | `HTTP_PORT` | Port, 5380 | Must bind on the selected addresses. Restart web listeners. |
| `web.tlsPort` | `webServiceTlsPort` | `HTTPS_PORT` | Port, 53443 | Must bind when HTTPS is enabled. Restart web listeners. |
| `web.httpUnixSocket.enabled` | `webServiceEnableHttpUnixSocket` | | Boolean, false | Requires OS socket support. Restart web listeners. |
| `web.httpUnixSocket.path` | `webServiceHttpUnixSocket` | | Optional socket path, unset | Blank clears the path. Binding requires the corresponding enable flag and a usable path. Restart web listeners. |
| `web.tlsUnixSocket.enabled` | `webServiceEnableTlsUnixSocket` | | Boolean, false | Requires OS socket support. The listener also needs a loaded certificate. Restart web listeners. |
| `web.tlsUnixSocket.path` | `webServiceTlsUnixSocket` | | Optional socket path, unset | Blank clears the path. Binding requires the corresponding enable flag and a usable path. Restart web listeners. |
| `web.tlsEnabled` | `webServiceEnableTls` | `ENABLE_HTTPS` | Boolean, false | Requires a configured or generated certificate. Clustering requires TLS. Restart web listeners. |
| `web.http3Enabled` | `webServiceEnableHttp3` | | Boolean, false | Requires QUIC support when enabling and a TLS listener to serve HTTP/3. Restart web listeners. |
| `web.redirectHttpToTls` | `webServiceHttpToTlsRedirect` | `HTTP_TO_TLS_REDIRECT` | Boolean, false | Redirect depends on TLS availability. Restart web service. |
| `web.useSelfSignedCertificate` | `webServiceUseSelfSignedTlsCertificate` | `USE_SELF_SIGNED_CERT` | Boolean, false | Existing API checks or generates the certificate after updating settings. Generated key material stays local. |
| `web.reverseProxyAcl` | `webServiceReverseProxyAddresses` | `REVERSE_PROXY_ADDRESSES` | Ordered ACL, default below | Up to 255 entries. Empty clears the ACL. Applies live to proxy trust and real IP handling. |
| `web.realIpHeader` | `webServiceRealIpHeader` | | String, `X-Real-IP` | Blank selects the default. API rejects spaces and values longer than 255 characters. Applies live. |
| `web.frameAncestors` | `webServiceCspFrameAncestorsHeader` | | String, `'none'` | Blank selects the default. API rejects values longer than 255 characters. Applies live. |
| `web.certificate.path` | `webServiceTlsCertificatePath` | `TLS_CERTIFICATE_PATH` | Optional path, unset | Up to 255 characters. Resolves relative to the config directory. Empty removes the certificate. The loader validates the certificate and updates the TLS context. |
| `web.certificate.password` | `webServiceTlsCertificatePassword` | `TLS_CERTIFICATE_PASSWORD` | Optional secret reference, unset | Resolved password is limited to 255 characters and used with the certificate path. The API's masked placeholder means retain the current password. Export a reference or a missing-input marker. |
| `web.rootPath` | `webServiceRootPath` (read only) | `WWW_FOLDER_PATH` | Directory path, installation `www` directory | Set with a local startup manifest. A nonexistent declared directory fails startup. A missing environment directory uses the installed web root. |

Default reverse proxy ACL order is `127.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, deny `2000::/3`, allow `::/0`. Certificate timestamps, the generated certificate, and the loaded TLS context are derived or local state. The legacy disabled-zone list is handled during startup migration and belongs to zone enabled state. [Web defaults](DnsServerCore/DnsWebService.cs#L105) · [Legacy migration](DnsServerCore/DnsWebServiceLegacy.cs#L46) · [TLS activation](DnsServerCore/DnsWebService.cs#L2760)

## Logging and statistics

These settings are node-local and apply live through the settings API. Logging destination and retention settings are stored in `log.config`. Query logging, resolver logging, and statistics options are stored in `dns.config` and skipped during cluster transfer. The environment aliases apply on initial creation of the corresponding configuration file. [Log persistence](DnsServerCore/LogManager.cs#L340) · [DNS config reader](DnsServerCore/Dns/DnsServer.cs#L1198) · [Settings API](DnsServerCore/WebServiceSettingsApi.cs#L1688)

| Proposed manifest path | API field or alias | Environment input | Type and default | Validation and dependencies |
| --- | --- | --- | --- | --- |
| `logging.destination` | `loggingType`, legacy `enableLogging` | | Enum, `File` | `None`, `File`, `Console`, `FileAndConsole`. Legacy false maps to `None` and true to `File`. |
| `logging.folder` | `logFolder` | `DNS_SERVER_LOG_FOLDER_PATH` | Path, portable `logs`, Windows service ProgramData log folder, Unix service `/var/log/technitium/dns` | Up to 255 characters. Relative paths use the config directory. Empty API input selects `logs`. |
| `logging.noStackTrace` | `noStackTrace` | | Boolean, false | Version 1 log files default to false. |
| `logging.useLocalTime` | `useLocalTime` | `DNS_SERVER_LOG_USING_LOCAL_TIME` | Boolean, false | Controls log timestamps. |
| `logging.retentionDays` | `maxLogFileDays` | `DNS_SERVER_LOG_MAX_LOG_FILE_DAYS` | Integer days, 365 | Nonnegative. Zero disables age-based cleanup. |
| `logging.ignoreResolverLogs` | `ignoreResolverLogs` | | Boolean, false | Disables the resolver logger when true. |
| `logging.logQueries` | `logQueries` | | Boolean, false | Enables the DNS query logger when true. |
| `statistics.inMemory` | `enableInMemoryStats` | `DNS_SERVER_STATS_ENABLE_IN_MEMORY_STATS` | Boolean, false | Changes stats persistence behavior. |
| `statistics.retentionDays` | `maxStatFileDays` | `DNS_SERVER_STATS_MAX_STAT_FILE_DAYS` | Integer days, 365 | Nonnegative. Zero disables age-based cleanup. |

Log files, counters, and statistics files remain in their runtime stores.

## Blocklist sources and scheduling

Sources and scheduling are cluster-wide and apply live. The blocklist manager persists them in `blocklist.config`. The older DNS configuration also contained source URLs, and the initial DNS configuration accepts `DNS_SERVER_BLOCK_LIST_URLS` before the dedicated blocklist file is loaded. [Blocklist persistence](DnsServerCore/Dns/ZoneManagers/BlockListZoneManager.cs#L154) · [DNS environment defaults](DnsServerCore/Dns/DnsServer.cs#L540) · [Settings API](DnsServerCore/WebServiceSettingsApi.cs#L1546)

| Proposed manifest path | API field | Type and default | Validation and dependencies |
| --- | --- | --- | --- |
| `blocklists.sources` | `blockListUrls` | Ordered string array, empty | Up to 255 entries of at most 255 characters. The manager validates URIs, accepts `!`-prefixed allowlist URLs and `#` comments, and deduplicates identical URL entries. |
| `blocklists.updateIntervalHours` | `blockListUpdateIntervalHours` | Integer hours, 24 | Range 0–168. Zero disables automatic updates. A positive interval needs at least one source to schedule downloads. |

Downloaded lists, update timestamps, the next scheduled refresh, and temporary blocking pauses are runtime state. DNS blocking policy and individually allowed and blocked names have separate configuration paths.

## DNS identity, authoritative defaults, and basic transport

These fields are read and written by the settings API and stored in `dns.config`. The reader accepts versions 1–7. Versions before 2 supply default NS and SOA TTLs, versions before 3 translate the stored IPv6 preference flag, and versions before 4 default server update checks to enabled. In the table, **local** means the DNS config reader preserves the destination value during cluster transfer. [DNS config reader](DnsServerCore/Dns/DnsServer.cs#L652) · [DNS config writer](DnsServerCore/Dns/DnsServer.cs#L1226) · [Settings API](DnsServerCore/WebServiceSettingsApi.cs#L516) · [Zone defaults](DnsServerCore/Dns/ZoneManagers/AuthZoneManager.cs#L57)

| Proposed manifest path | API field or alias | Environment input | Type and default | Scope, validation, and activation |
| --- | --- | --- | --- | --- |
| `dns.serverDomain` | `dnsServerDomain` | `DNS_SERVER_DOMAIN` | DNS name, lowercase hostname or `dns-server-1` when unusable | Local. Reject IP literals, normalize IDNs, and require a cluster-domain suffix for a cluster node. Updates zone metadata and may regenerate a self-signed web certificate. |
| `dns.localEndpoints` | `dnsServerLocalEndPoints` | | Endpoint array, `0.0.0.0:53` and `[::]:53` | Local. Accept interface-aware endpoints. Empty selects defaults and port 0 in API input selects 53. Port 853 is reserved for DNS-over-TLS. Changes restart DNS listeners. |
| `dns.sourceNetworks.ipv4` | `dnsServerIPv4SourceAddresses` | | IPv4 network array, empty | Local. Up to 255 entries of the correct family. Changes outbound address selection live. |
| `dns.sourceNetworks.ipv6` | `dnsServerIPv6SourceAddresses` | | IPv6 network array, empty | Local. Up to 255 entries of the correct family. Changes outbound address selection live. |
| `dns.authoritative.defaultRecordTtl` | `defaultRecordTtl` | | Unsigned seconds, 3600 | Cluster-wide. Use the DNS TTL parser for legacy API input. Applies live. |
| `dns.authoritative.defaultNsRecordTtl` | `defaultNsRecordTtl` | | Unsigned seconds, 14400 | Cluster-wide. Use the DNS TTL parser for legacy API input. Applies live. |
| `dns.authoritative.defaultSoaRecordTtl` | `defaultSoaRecordTtl` | | Unsigned seconds, 900 | Cluster-wide. Use the DNS TTL parser for legacy API input. Applies live. |
| `dns.authoritative.defaultResponsiblePerson` | `defaultResponsiblePerson` | | Optional email address, unset | Cluster-wide. Up to 255 characters and parsed as a mail address. Empty clears the override. Effective fallback uses `hostadmin@` and the server domain. Applies live. |
| `dns.authoritative.useSoaSerialDateScheme` | `useSoaSerialDateScheme` | | Boolean, false | Cluster-wide. Default used when creating a primary zone. Applies live. |
| `dns.authoritative.minSoaRefresh` | `minSoaRefresh` | | Unsigned seconds, 300 | Cluster-wide. Use the DNS TTL parser for legacy API input. Applies live. |
| `dns.authoritative.minSoaRetry` | `minSoaRetry` | | Unsigned seconds, 300 | Cluster-wide. Use the DNS TTL parser for legacy API input. Applies live. |
| `dns.authoritative.zoneTransferAllowedNetworks` | `zoneTransferAllowedNetworks` | | Network array, empty | Cluster-wide. Up to 255 network entries. Empty clears the list. Applies live. |
| `dns.authoritative.notifyAllowedNetworks` | `notifyAllowedNetworks` | | Network array, empty | Cluster-wide. Up to 255 network entries. Empty clears the list. Applies live. |
| `dns.checkForUpdates` | `dnsServerEnableCheckForUpdate` | | Boolean, true | Cluster-wide. Applies live. |
| `apps.autoUpdate` | `dnsAppsEnableAutomaticUpdate` | | Boolean, true | Cluster-wide. Applies live through the app manager. |
| `dns.ipv6Mode` | `ipv6Mode`, legacy `preferIPv6` | `DNS_SERVER_IPV6_MODE`, legacy `DNS_SERVER_PREFER_IPV6` | Enum, `Disabled` | Local. `Disabled`, `Enabled`, or `Preferred`. Explicit mode takes precedence over the legacy flag, which maps true to `Preferred` and false to `Disabled`. May rebuild the UDP socket pool asynchronously. |
| `dns.udpSocketPool.enabled` | `enableUdpSocketPool` | | Boolean, true on Windows and false elsewhere | Local. Creates or disposes outbound UDP socket pools asynchronously. |
| `dns.udpSocketPool.excludedPorts` | `socketPoolExcludedPorts` | | Unsigned 16-bit port array, seeded with web TLS port on fresh web config | Local. Empty clears exclusions. The client connection library applies the settings to pooled outbound sockets. |
| `dns.udpPayloadSize` | `udpPayloadSize` | | Integer bytes, 1232 | Cluster-wide. Range 512–4096. Applies live. |
| `dns.dnssecValidation` | `dnssecValidation` | | Boolean, true | Cluster-wide. Enabling flushes cached unvalidated responses. Applies live. |
| `dns.clientSubnet.enabled` | `eDnsClientSubnet` | | Boolean, false | Cluster-wide. Disabling schedules deletion of cached client-subnet data. Applies live. |
| `dns.clientSubnet.ipv4PrefixLength` | `eDnsClientSubnetIPv4PrefixLength` | | Integer bits, 24 | Cluster-wide. Range 0–32. Applies live. |
| `dns.clientSubnet.ipv6PrefixLength` | `eDnsClientSubnetIPv6PrefixLength` | | Integer bits, 56 | Cluster-wide. Range 0–64. Applies live. |
| `dns.clientSubnet.ipv4Override` | `eDnsClientSubnetIpv4Override` | | Optional IPv4 network, unset | Cluster-wide. Must be IPv4. A host address uses the configured IPv4 prefix length. Empty clears the override. Applies live. |
| `dns.clientSubnet.ipv6Override` | `eDnsClientSubnetIpv6Override` | | Optional IPv6 network, unset | Cluster-wide. Must be IPv6. A host address uses the configured IPv6 prefix length. Empty clears the override. Applies live. |

## DNS rate limits and listener tuning

These fields persist in `dns.config` and transfer across the cluster. Changes are live unless the activation column calls for a DNS listener restart. Older DNS config versions before 3 supply 2048 KiB for each UDP buffer. [Defaults](DnsServerCore/Dns/DnsServer.cs#L169) · [Persistence reader](DnsServerCore/Dns/DnsServer.cs#L793) · [API activation](DnsServerCore/WebServiceSettingsApi.cs#L709)

| Proposed manifest path | API field | Type and default | Validation and activation |
| --- | --- | --- | --- |
| `dns.rateLimits.ipv4` | `qpmPrefixLimitsIPv4` | Prefix limits, /32 at 600 and /24 at 6000 queries/minute for both UDP and TCP | Unique prefixes 0–32, up to 255 entries, nonnegative protocol limits. |
| `dns.rateLimits.ipv6` | `qpmPrefixLimitsIPv6` | Prefix limits, /128 at 600, /64 at 1200, /56 at 6000 queries/minute for both UDP and TCP | Unique prefixes 0–128, up to 255 entries, nonnegative protocol limits. |
| `dns.rateLimits.sampleMinutes` | `qpmLimitSampleMinutes` | Integer minutes, 5 | Range 1–60. |
| `dns.rateLimits.udpTruncationPercentage` | `qpmLimitUdpTruncationPercentage` | Integer percent, 50 | Range 0–100. Controls the share of rate-limited UDP queries that receive a truncated response. |
| `dns.rateLimits.bypassNetworks` | `qpmLimitBypassList` | Network array, empty | Up to 255 entries. Empty clears the list. |
| `dns.tuning.clientTimeoutMs` | `clientTimeout` | Integer milliseconds, 2000 | Range 1000–10000. |
| `dns.tuning.tcpSendTimeoutMs` | `tcpSendTimeout` | Integer milliseconds, 10000 | Range 1000–90000. Restart DNS listeners. |
| `dns.tuning.tcpReceiveTimeoutMs` | `tcpReceiveTimeout` | Integer milliseconds, 10000 | Range 1000–90000. Restart DNS listeners. |
| `dns.tuning.quicIdleTimeoutMs` | `quicIdleTimeout` | Integer milliseconds, 60000 | Range 1000–90000. Restart DNS listeners. |
| `dns.tuning.quicMaxInboundStreams` | `quicMaxInboundStreams` | Integer stream count, 100 | The setter accepts 0–1000. Restart DNS listeners. |
| `dns.tuning.listenBacklog` | `listenBacklog` | Integer connection count, 100 | The setter passes the value to the listener. Restart DNS listeners. |
| `dns.tuning.udpSendBufferKiB` | `udpSendBufferSizeKB` | Integer KiB, 2048 | Range 8–65536. Restart DNS listeners. |
| `dns.tuning.udpReceiveBufferKiB` | `udpReceiveBufferSizeKB` | Integer KiB, 2048 | Range 8–65536. Restart DNS listeners. |
| `dns.tuning.maxConcurrentResolutionsPerCore` | `maxConcurrentResolutionsPerCore` | Unsigned 16-bit count, 100 | At least 1. Reconfigures the resolver task pool live. |

## Optional DNS listeners

These fields persist in `dns.config`. They are node-local under current cluster transfer. DNS port fields below accept 0–65535 in their setters, subject to protocol-specific exclusions. Listener flags, ports, and socket paths trigger a DNS listener restart when changed. [Persistence reader](DnsServerCore/Dns/DnsServer.cs#L833) · [API activation](DnsServerCore/WebServiceSettingsApi.cs#L1084) · [Property validators](DnsServerCore/Dns/DnsServer.cs#L7434)

| Proposed manifest path | API field or alias | Type and default | Validation, dependencies, and activation |
| --- | --- | --- | --- |
| `dns.listeners.useClientSubnetAsSource` | `enableEDnsClientSubnetSourceAddress` | Boolean, false | Applies live. |
| `dns.listeners.udpProxy.enabled` | `enableDnsOverUdpProxy` | Boolean, false | Uses the UDP proxy port. |
| `dns.listeners.udpProxy.port` | `dnsOverUdpProxyPort` | Port, 538 | Must bind when the listener is enabled. |
| `dns.listeners.tcpProxy.enabled` | `enableDnsOverTcpProxy` | Boolean, false | Uses the TCP proxy port. |
| `dns.listeners.tcpProxy.port` | `dnsOverTcpProxyPort` | Port, 538 | Must bind when the listener is enabled. |
| `dns.listeners.http.enabled` | `enableDnsOverHttp` | Boolean, false | Initial environment input is `DNS_SERVER_OPTIONAL_PROTOCOL_DNS_OVER_HTTP`. |
| `dns.listeners.http.port` | `dnsOverHttpPort` | Port, 80 | Excludes ports 53 and 853. |
| `dns.listeners.http.unixSocket.enabled` | `enableDnsOverHttpUnixSocket` | Boolean, false | Requires OS Unix socket support and a usable socket path. |
| `dns.listeners.http.unixSocket.path` | `dnsOverHttpUnixSocket` | Optional socket path, unset | Blank clears the path. |
| `dns.listeners.https.unixSocket.enabled` | `enableDnsOverHttpsUnixSocket` | Boolean, false | Requires OS Unix socket support, a usable socket path, and a certificate. |
| `dns.listeners.https.unixSocket.path` | `dnsOverHttpsUnixSocket` | Optional socket path, unset | Blank clears the path. |
| `dns.listeners.tls.enabled` | `enableDnsOverTls` | Boolean, false | Requires a loaded DNS TLS certificate for the listener. |
| `dns.listeners.tls.port` | `dnsOverTlsPort` | Port, 853 | Excludes port 53. |
| `dns.listeners.https.enabled` | `enableDnsOverHttps` | Boolean, false | Requires a loaded DNS TLS certificate for the listener. |
| `dns.listeners.https.port` | `dnsOverHttpsPort` | Port, 443 | Excludes ports 53 and 853. |
| `dns.listeners.https.http3Enabled` | `enableDnsOverHttp3` | Boolean, false | Requires QUIC support and a TLS listener. |
| `dns.listeners.quic.enabled` | `enableDnsOverQuic` | Boolean, false | Requires QUIC support and a loaded DNS TLS certificate. |
| `dns.listeners.quic.port` | `dnsOverQuicPort` | Port, 853 | Excludes port 53. |
| `dns.listeners.http.helpRedirect` | `enableDnsOverHttpHelpRedirect` | Boolean, true | Controls the DoH help redirect. Applies live. |
| `dns.listeners.reverseProxyAcl` | `dnsReverseProxyNetworkACL`, legacy `reverseProxyNetworkACL` | Ordered ACL, empty | Up to 255 entries. Empty clears the list. Applies live. |
| `dns.listeners.http.realIpHeader` | `dnsOverHttpRealIpHeader` | String, `X-Real-IP` | Empty selects the default. Rejects spaces and values longer than 255 characters. Applies live. |
| `dns.listeners.certificate.path` | `dnsTlsCertificatePath` | Optional certificate path, unset | Resolve relative to config directory. Empty removes the certificate. A listener restart may be needed when a certificate becomes available or is removed. |
| `dns.listeners.certificate.password` | `dnsTlsCertificatePassword` | Optional secret reference, unset | Supplied with the certificate path. The legacy masked placeholder retains the current password. Export a reference or missing-input marker. |

Versions before 4 omit the HTTP Unix socket settings and help redirect, and versions before 5 omit HTTPS Unix socket settings. Certificate timestamps and loaded TLS contexts are derived state.

## DNS recursion, forwarding, and outbound proxy

These fields persist in `dns.config`, transfer across the cluster, and apply live. Older files before version 4 default locally served DNS zones to enabled. The current forwarder reader upgrades the legacy `HttpsJson` transport to `Https`. [Persistence reader](DnsServerCore/Dns/DnsServer.cs#L1010) · [Initial environment settings](DnsServerCore/Dns/DnsServer.cs#L504) · [Settings API](DnsServerCore/WebServiceSettingsApi.cs#L1361)

| Proposed manifest path | API field or alias | Type and default | Validation and dependencies |
| --- | --- | --- | --- |
| `dns.recursion.mode` | `recursion` | Enum, `AllowOnlyForPrivateNetworks` | `Deny`, `Allow`, `AllowOnlyForPrivateNetworks`, or `UseSpecifiedNetworkACL`. Initial environment input is `DNS_SERVER_RECURSION`. |
| `dns.recursion.networkAcl` | `recursionNetworkACL` | Ordered ACL, empty | Up to 255 entries. Initial input `DNS_SERVER_RECURSION_NETWORK_ACL` takes precedence over legacy `DNS_SERVER_RECURSION_DENIED_NETWORKS` and `DNS_SERVER_RECURSION_ALLOWED_NETWORKS`, which are converted to an ACL. |
| `dns.recursion.randomizeName` | `randomizeName` | Boolean, false | Controls randomized DNS query name case. |
| `dns.recursion.qnameMinimization` | `qnameMinimization` | Boolean, true | Controls iterative resolution query minimization. |
| `dns.recursion.locallyServedDnsZones` | `locallyServedDnsZones` | Boolean, true | Controls local handling of special-use DNS zones. |
| `dns.recursion.retries` | `resolverRetries` | Integer count, 2 | Range 1–10. |
| `dns.recursion.timeoutMs` | `resolverTimeout` | Integer milliseconds, 1500 | Range 1000–10000. |
| `dns.recursion.concurrency` | `resolverConcurrency` | Integer count, 2 | Range 1–4. |
| `dns.recursion.maxStackCount` | `resolverMaxStackCount` | Integer count, 16 | Range 10–30. |
| `dns.proxy.type` | `proxyType` | Enum, `None` | `None`, `Http`, or `Socks5`. Changing the type rebuilds the proxy configuration. |
| `dns.proxy.address` | `proxyAddress` | Optional host or address, unset | Used when the proxy is enabled. |
| `dns.proxy.port` | `proxyPort` | Optional integer port, unset | Required with an enabled proxy. |
| `dns.proxy.username` | `proxyUsername` | Optional string, unset | Up to 255 UTF-8 bytes. Credential creation depends on username presence. |
| `dns.proxy.password` | `proxyPassword` | Optional secret reference, unset | Resolved password up to 255 UTF-8 bytes. Export a reference or missing-input marker. |
| `dns.proxy.bypass` | `proxyBypass` | Bypass entry array, empty | Entries use the network library's bypass parser. Storage uses a byte-sized count. |
| `dns.forwarding.servers` | `forwarders`, `forwarderProtocol` | Ordered nameserver array with transport per entry, empty | Use nameserver address parsing. The API and initial environment inputs `DNS_SERVER_FORWARDERS` and `DNS_SERVER_FORWARDER_PROTOCOL` use a shared transport. Empty removes the configured forwarders. Storage uses a byte-sized count. QUIC needs platform support. HTTP proxy is incompatible with UDP and QUIC forwarding. |
| `dns.forwarding.concurrent` | `concurrentForwarding` | Boolean, true | Controls concurrent use of configured forwarders. |
| `dns.forwarding.retries` | `forwarderRetries` | Integer count, 3 | Range 1–10. |
| `dns.forwarding.timeoutMs` | `forwarderTimeout` | Integer milliseconds, 2000 | Range 1000–10000. |
| `dns.forwarding.concurrency` | `forwarderConcurrency` | Integer count, 2 | Range 1–10. |

## DNS cache

These fields persist in `dns.config`, apply live, and remain local during cluster transfer. Versions before 6 contain two discarded sampling fields. Versions before 7 infer whether prefetch is enabled from the trigger value. Cache contents are runtime data. [Persistence reader](DnsServerCore/Dns/DnsServer.cs#L1034) · [Cache defaults](DnsServerCore/Dns/ZoneManagers/CacheZoneManager.cs#L40) · [Settings API](DnsServerCore/WebServiceSettingsApi.cs#L1428)

| Proposed manifest path | API field | Type and default | Validation and dependencies |
| --- | --- | --- | --- |
| `dns.cache.saveToDisk` | `saveCache` | Boolean, true | Disabling deletes the on-disk cache. |
| `dns.cache.serveStale.enabled` | `serveStale` | Boolean, true | Enables stale answers. |
| `dns.cache.serveStale.ttl` | `serveStaleTtl` | Unsigned seconds, 259200 | Maximum 604800. Use the DNS TTL parser for legacy API input. |
| `dns.cache.serveStale.answerTtl` | `serveStaleAnswerTtl` | Unsigned seconds, 30 | Maximum 300. Use the DNS TTL parser for legacy API input. |
| `dns.cache.serveStale.resetTtl` | `serveStaleResetTtl` | Unsigned seconds, 30 | Range 10–900. |
| `dns.cache.serveStale.maxWaitMs` | `serveStaleMaxWaitTime` | Integer milliseconds, 1800 | Range 0–1800. |
| `dns.cache.maximumEntries` | `cacheMaximumEntries` | Signed 64-bit count, 10000 | Nonnegative. Zero disables the entry limit. |
| `dns.cache.minimumRecordTtl` | `cacheMinimumRecordTtl` | Unsigned seconds, 10 | Use the DNS TTL parser for legacy API input. |
| `dns.cache.maximumRecordTtl` | `cacheMaximumRecordTtl` | Unsigned seconds, 604800 | Use the DNS TTL parser for legacy API input. |
| `dns.cache.negativeRecordTtl` | `cacheNegativeRecordTtl` | Unsigned seconds, 300 | Use the DNS TTL parser for legacy API input. |
| `dns.cache.failureRecordTtl` | `cacheFailureRecordTtl` | Unsigned seconds, 10 | Use the DNS TTL parser for legacy API input. |
| `dns.cache.prefetch.enabled` | `enableCachePrefetch` | Boolean, true | Enabling with an existing zero trigger restores the default trigger when the manifest omits it. A manifest cannot explicitly enable prefetch with a zero trigger. |
| `dns.cache.prefetch.eligibility` | `cachePrefetchEligibility` | Integer seconds, 2 | Minimum 2. |
| `dns.cache.prefetch.trigger` | `cachePrefetchTrigger` | Integer seconds, 9 | Nonnegative. Zero disables prefetch. |

## DNS blocking policy and TSIG

These fields persist in `dns.config`, apply live, and transfer across the cluster. The effective blocking status can include a temporary pause and should be exported from the persisted policy. [DNS defaults](DnsServerCore/Dns/DnsServer.cs#L237) · [Settings API](DnsServerCore/WebServiceSettingsApi.cs#L1290) · [Blocking persistence](DnsServerCore/Dns/DnsServer.cs#L1105)

| Proposed manifest path | API field | Type and default | Validation and dependencies |
| --- | --- | --- | --- |
| `dns.blocking.enabled` | `enableBlocking` | Boolean, true | Initial environment input is `DNS_SERVER_ENABLE_BLOCKING`. |
| `dns.blocking.allowTxtReport` | `allowTxtBlockingReport` | Boolean, true | Initial environment input is `DNS_SERVER_ALLOW_TXT_BLOCKING_REPORT`. |
| `dns.blocking.bypassNetworks` | `blockingBypassList` | Network array, empty | Up to 255 entries. Empty clears the list. |
| `dns.blocking.responseType` | `blockingType` | Enum, `NxDomain` | `AnyAddress`, `NxDomain`, or `CustomAddress`. |
| `dns.blocking.answerTtl` | `blockingAnswerTtl` | Unsigned seconds, 30 | Use the DNS TTL parser for legacy API input. Updates the blocking SOA. |
| `dns.blocking.customAddresses` | `customBlockingAddresses` | IP address array, empty | IPv4 or IPv6 for custom address mode. Legacy API skips invalid addresses. Storage uses a byte-sized count. |
| `dns.tsigKeys` | `tsigKeys` | Named keys with algorithm and secret reference, empty | Up to 255 keys. Normalize DNS names, require unique names, and validate algorithms and secrets with the TSIG implementation. The legacy API can generate a secret from empty input. The cluster catalog key is lifecycle-managed and cannot be removed through settings. |

## DHCP scopes and reservations

Scopes are keyed by their case-sensitive name and are node-local. The DHCP API reads and writes them through `dhcp/scopes/*`. The server reads versions 1–10 and writes version 10 of `scopes/<name>.scope`. Scope changes apply through the DHCP manager without restarting the DNS or web services. Enabling a scope can open DHCP listeners. DHCP configuration is excluded from cluster transfer. [Scope API](DnsServerCore/WebServiceDhcpApi.cs#L375) · [Scope persistence](DnsServerCore/Dhcp/Scope.cs#L124) · [DHCP lifecycle](DnsServerCore/Dhcp/DhcpServer.cs#L1454) · [Cluster transfer](DnsServerCore/Cluster/ClusterManager.cs#L866)

Defaults below describe a scope created through the API. On initial creation of the scopes directory, the server seeds a disabled `Default` scope for 192.168.1.1–192.168.1.254 with mask 255.255.255.0, an exclusion for .1–.10, router .1, domain `home`, local DNS enabled, a one-day lease, and client identifier override enabled. [Scope defaults](DnsServerCore/Dhcp/Scope.cs#L45) · [Initial scope](DnsServerCore/Dhcp/DhcpServer.cs#L94)

| Proposed manifest path under `dhcp.scopes.<name>` | API field or operation | Type and default | Validation and dependencies |
| --- | --- | --- | --- |
| Resource key | `name`, `newName` | Scope name, required | Filename-safe name. The legacy API uses `newName` to rename; the manifest must define how identity changes are applied. |
| `enabled` | `enable` and `disable` | Boolean, true for API-created scopes | Activation requires a usable network interface and can fail on bind. |
| `startingAddress` | `startingAddress` | IPv4 address, required for creation | Range start must precede end and differ from the network address. Validate range overlap against other scopes. |
| `endingAddress` | `endingAddress` | IPv4 address, required for creation | Range end must follow start and differ from the broadcast address. |
| `subnetMask` | `subnetMask` | IPv4 subnet mask, required for creation | Determines network and broadcast addresses. Validate with the address range. |
| `leaseTime.days` | `leaseTimeDays` | Integer days, 1 | Range 0–999. |
| `leaseTime.hours` | `leaseTimeHours` | Integer hours, 0 | Range 0–23. |
| `leaseTime.minutes` | `leaseTimeMinutes` | Integer minutes, 0 | Range 0–59. |
| `offerDelayMs` | `offerDelayTime` | Unsigned 16-bit milliseconds, 0 | Applied before sending an offer. |
| `pingCheck.enabled` | `pingCheckEnabled` | Boolean, false | Enables address checks before offering a lease. |
| `pingCheck.timeoutMs` | `pingCheckTimeout` | Unsigned 16-bit milliseconds, 1000 | Used when ping checks are enabled. |
| `pingCheck.retries` | `pingCheckRetries` | Unsigned 8-bit count, 2 | Used when ping checks are enabled. |
| `domainName` | `domainName` | Optional DNS name, unset | Normalize and validate as a DNS name. Used for DHCP domain option and DNS updates. |
| `domainSearchList` | `domainSearchList` | DNS name array, empty | Normalize and validate each name. Legacy API accepts a comma-separated list. |
| `dnsUpdates.enabled` | `dnsUpdates` | Boolean, true | Controls lease-driven DNS updates for a scope with a domain name. |
| `dnsUpdates.overwriteDynamicRecords` | `dnsOverwriteForDynamicLease` | Boolean, false | Controls replacement of an existing DNS record for a dynamic lease. |
| `dnsUpdates.ttl` | `dnsTtl` | Unsigned seconds, 900 | Use the DNS TTL parser for legacy API input. |
| `boot.serverAddress` | `serverAddress` | Optional IPv4 address, unset | Uses the DHCP server address when absent. |
| `boot.serverHostName` | `serverHostName` | Optional string, unset | The setter accepts up to 63 characters. |
| `boot.fileName` | `bootFileName` | Optional string, unset | The setter accepts up to 127 characters. |
| `routerAddress` | `routerAddress` | Optional IPv4 address, unset | Supplies the router option when present. |
| `dns.useThisServer` | `useThisDnsServer` | Boolean, false | The API ignores supplied DNS servers while enabled. Resolved server addresses are derived. |
| `dns.servers` | `dnsServers` | IPv4 address array, empty | Used when the local DNS flag is false. |
| `winsServers` | `winsServers` | IPv4 address array, empty | Legacy API accepts comma-separated addresses. |
| `ntp.servers` | `ntpServers` | IPv4 address array, empty | Addresses may be supplemented by resolving configured names. |
| `ntp.serverDomainNames` | `ntpServerDomainNames` | DNS name array, empty | Normalize and validate names. Resolved addresses are derived. |
| `staticRoutes` | `staticRoutes` | Route array, empty | Each entry contains a destination, mask, and router. Use the classless route parser. |
| `vendorInfo` | `vendorInfo` | Map from vendor identifier to encoded payload, empty | Unique vendor identifiers. Legacy payload accepts hexadecimal or text input. |
| `capwapAcIpAddresses` | `capwapAcIpAddresses` | IPv4 address array, empty | Supplies CAPWAP controller addresses. |
| `tftpServerAddresses` | `tftpServerAddresses` | IPv4 address array, empty | Supplies TFTP server addresses. |
| `genericOptions` | `genericOptions` | Option array with byte code and hexadecimal payload, empty | Use DHCP option parsing and validate encoded lengths before persistence. |
| `exclusions` | `exclusions` | Address range array, empty | Both ends must fall within the scope. |
| `reservations` | `reservedLeases`, `addReservedLease`, `removeReservedLease` | Map keyed by normalized MAC address, empty | Each entry has an IPv4 address and optional hostname and comments. The bulk setter validates scope membership. Dedicated add rejects duplicate client identifiers. |
| `allowOnlyReservedLeases` | `allowOnlyReservedLeases` | Boolean, false | Disables dynamic address allocation. |
| `blockLocallyAdministeredMacAddresses` | `blockLocallyAdministeredMacAddresses` | Boolean, false | Blocks dynamic allocation to clients using locally administered addresses. |
| `ignoreClientIdentifierOption` | `ignoreClientIdentifierOption` | Boolean, true for API-created scopes | Uses the MAC address for allocation. Changing identity rules can affect renewal. |

Active leases are persisted in the same scope files as settings. Reconciliation must preserve them unless an explicit scope operation requires otherwise. Offers, allocation cursors, interface bindings, and lease timestamps are runtime state. Lease conversion to or from a reservation is a runtime operation that also changes configured reservations. [Reservation setters](DnsServerCore/Dhcp/Scope.cs#L2152) · [Lease persistence](DnsServerCore/Dhcp/Scope.cs#L1796)

## Authoritative zone definitions and options

Use the normalized zone name as the resource key under `zones.<name>`. Zone settings are stored in `zones/<name>.zone` with record data. The zone file writer uses version 4, and the zone metadata writer uses version 14. Changes apply live through the zone manager and can trigger transfer or notification work. Clustering provisions catalog members through DNS. The configuration transfer ZIP carries selected DNSSEC keys for signed primary member zones, while catalog and zone transfer handle the replicated zone data. [Zone creation API](DnsServerCore/WebServiceZonesApi.cs#L1579) · [Options API](DnsServerCore/WebServiceZonesApi.cs#L3369) · [Zone file writer](DnsServerCore/Dns/ZoneManagers/AuthZoneManager.cs#L588) · [Zone metadata writer](DnsServerCore/Dns/Zones/AuthZoneInfo.cs#L1194) · [Cluster transfer](DnsServerCore/DnsWebService.cs#L713)

| Proposed manifest path under `zones.<name>` | API field or operation | Type and default | Validation and dependencies |
| --- | --- | --- | --- |
| Resource key | `zone`, legacy `domain` | DNS name, required | Normalize name and IDN form. Represent the root explicitly. Reject duplicate canonical names. |
| `type` | `type`, zone conversion | Enum, `Primary` on API creation | Supports Primary, Secondary, Stub, Forwarder, SecondaryForwarder, Catalog, and SecondaryCatalog. Validate type transitions against zone manager capabilities. |
| `enabled` | `disabled`, enable and disable | Boolean, true for new zones | Inverse of the API flag. Special and catalog-managed zones have additional restrictions. |
| `catalog.name` | `catalog` | Optional zone reference, unset | Must reference a compatible catalog. Membership changes can provision or remove secondary catalog members. |
| `catalog.overrideQueryAccess` | `overrideCatalogQueryAccess` | Boolean, false | Applies to eligible catalog member types and controls inheritance. |
| `catalog.overrideZoneTransfer` | `overrideCatalogZoneTransfer` | Boolean, false | Applies to primary, secondary, and forwarder zones with compatible membership. |
| `catalog.overrideNotify` | `overrideCatalogNotify` | Boolean, false | Primary and forwarder zones can override inherited notification settings. |
| Catalog-provisioned transfer override | `overrideCatalogPrimaryNameServers` in zone options response | Boolean, false | Persisted for secondary zones. Reconcile its catalog source and derived state before exposing a local override. |
| `primary.servers` | `primaryNameServerAddresses` | Nameserver array, unset unless required by creation | Secondary-family and stub zones use nameserver parsing. Stub uses UDP. An unset list can permit discovery for eligible zones. |
| `primary.transferProtocol` | `primaryZoneTransferProtocol`, creation alias `zoneTransferProtocol` | Enum, TCP at secondary creation | Validate supported transfer protocols and QUIC platform support. |
| `primary.tsigKey` | `primaryZoneTransferTsigKeyName`, creation alias `tsigKeyName` | Optional TSIG key name, unset | Reference a configured key by normalized name. |
| `primary.validateZone` | `validateZone` | Boolean, false | Applies to secondary zones. A catalog-provisioned value comes from the catalog. |
| `query.mode` | `queryAccess` | Query access enum, Allow in the base zone | Supports deny, unrestricted, private networks, zone nameservers, ACL, and combined nameservers plus ACL. Inherited or zone-specific rules can change effective access. |
| `query.networkAcl` | `queryAccessNetworkACL` | Ordered ACL, unset | Empty clears the local ACL. Applies when selected by the query policy. |
| `transfer.mode` | `zoneTransfer` | Transfer policy enum, AllowOnlyZoneNameServers for new primary zones and Deny in the base zone | Supports deny, unrestricted, zone nameservers, ACL, and combined nameservers plus ACL. Catalog inheritance can supply the effective policy. |
| `transfer.networkAcl` | `zoneTransferNetworkACL` | Ordered ACL, unset | Empty clears the local ACL. Used by the selected transfer policy. |
| `transfer.tsigKeys` | `zoneTransferTsigKeyNames` | TSIG key name set, unset | Trim and normalize names. Empty clears the list. |
| `notify.mode` | `notify` | Notify enum, ZoneNameServers for new primary zones and None in the base zone | Supports none, zone nameservers, specified nameservers, both, and separate catalog/member destinations for catalog zones. |
| `notify.nameServers` | `notifyNameServers` | IP address array, unset | Used when the notify mode targets explicit servers. |
| `notify.secondaryCatalogNameServers` | `notifySecondaryCatalogsNameServers` | IP address array, unset | Applies to catalog zones. |
| `updates.mode` | `update` | Update policy enum, Deny | Supports deny, unrestricted, zone nameservers, ACL, and combined nameservers plus ACL. Applies to primary, secondary, forwarder, and secondary forwarder zones. |
| `updates.networkAcl` | `updateNetworkACL` | Ordered ACL, unset | Empty clears the local list. |
| `updates.securityPolicies` | `updateSecurityPolicies` | Map of TSIG key to DNS name and allowed record types, unset | Applies to primary and forwarder zones. Names and type lists use the dynamic update policy validators. |
| `permissions` | `zones/permissions/get`, `zones/permissions/set` | User and group permission maps | Stored in `auth.config`. Reuse permission flags and administrative protections. |
| SOA serial policy | `useSoaSerialDateScheme` | Boolean, inherited from the server when creating a primary zone | Persisted as SOA record metadata. Map to the operator-managed SOA record instead of a duplicate setting. |

Creation-time `initializeForwarder` controls whether the API creates an initial FWD record. Its `forwarder`, `protocol`, `dnssecValidation`, and `proxyType`, `proxyAddress`, `proxyPort`, `proxyUsername`, and `proxyPassword` parameters belong to that record. A proxy password must use a secret reference.

Transfer expiry, IXFR history, validation failures, last modification timestamps, and catalog-derived member data belong to runtime state. Use source zone and catalog settings to recreate the intended topology. Preserve the destination's replicated records during reconciliation.

## Explicit allow and block entries

`allowZones` and `blockZones` are sets of normalized DNS names, each initially empty. They map to the `allowed/*` and `blocked/*` APIs, including the bulk `allowedZones` and `blockedZones` inputs. Both apply live and transfer across the cluster. The blocked manager reads legacy `custom-blocked.config` when present. Downloaded blocklist contents belong to the blocklist cache. [Allow and block APIs](DnsServerCore/WebServiceOtherZonesApi.cs#L184) · [Allow persistence](DnsServerCore/Dns/ZoneManagers/AllowedZoneManager.cs#L123) · [Block persistence](DnsServerCore/Dns/ZoneManagers/BlockedZoneManager.cs#L123)

## Authoritative records and DNSSEC

`zones.<name>.records` holds operator-managed records. Use canonical owner name, record type, and normalized RDATA to identify entries, so an RRset can contain several records of the same type. Name and RDATA changes replace the corresponding identity. Apply changes through the zone manager to enforce owner containment, record type rules, and singleton or RRset constraints. The zone file stores each record with its authoritative metadata. Changes take effect live. [Record add](DnsServerCore/WebServiceZonesApi.cs#L3797) · [Record update](DnsServerCore/WebServiceZonesApi.cs#L4613) · [Zone persistence](DnsServerCore/Dns/ZoneManagers/AuthZoneManager.cs#L588)

| Manifest field | API field or alias | Type, default, and validation |
| --- | --- | --- |
| `owner` | `domain`, `newDomain` | Canonical DNS name, required. The API's `zone` selects the enclosing zone. |
| `type` | `type` | Record type, required. Preserve numeric unknown types. |
| `ttl` | `ttl` | Unsigned seconds. Use the effective NS, SOA, or general zone default when creating a record without an explicit TTL. Export the effective value. |
| `disabled` | `disable` | Boolean, false. Applies where the record supports disabling. |
| `comments` | `comments` | Optional string, unset. |
| `expiryTtl` | `expiryTtl` | Unsigned seconds, 0 for no expiry. Last-modified timestamp and expiry timer are runtime state. |
| `glue` | `glue` | Address array, empty. Associated with NS RDATA. |
| `useSerialDateScheme` | `useSerialDateScheme`, creation `useSoaSerialDateScheme` | Boolean on the SOA record, defaults to the server's authoritative setting for new primary zones. |
| `autoIpv4Hint`, `autoIpv6Hint` | `autoIpv4Hint`, `autoIpv6Hint` | Booleans, false. Generated hints follow address records when enabled. |

Record data is required unless the existing type permits empty fields. Use the existing RDATA constructors and zone parser for normalization and validation. The table identifies API inputs for the structured fields. Update inputs with `new` prefixes select the replacement value for the same field.

| Record type | Data fields and legacy API inputs |
| --- | --- |
| A, AAAA | `ipAddress` or `value`, validated against the type's address family. Resolve the API-only `request-ip-address` input before exporting. |
| NS, CNAME, PTR, DNAME, ANAME | DNS target from `nameServer`, `cname`, `ptrName`, `dname`, or `aname`. These also accept `value`. |
| SOA | `primaryNameServer`, `responsiblePerson`, `serial`, `refresh`, `retry`, `expire`, and `minimum`. Export numeric values in seconds where applicable. |
| MX | `preference`, `exchange` or `value`. |
| TXT | Ordered byte strings from `characterStringsBase64`. Legacy `text` or `value` with `splitText` is an input alias. Preserve chunk boundaries and bytes. |
| RP | `mailbox`, `txtDomain`, defaulting to the root. |
| SRV | `priority`, `weight`, `port`, `target` or `value`. |
| NAPTR | `naptrOrder`, `naptrPreference`, `naptrFlags`, `naptrServices`, `naptrRegexp`, `naptrReplacement`. |
| DS | `keyTag`, `algorithm`, `digestType`, hexadecimal `digest` or `value`. |
| SSHFP | `sshfpAlgorithm`, `sshfpFingerprintType`, hexadecimal `sshfpFingerprint`. |
| TLSA | `tlsaCertificateUsage`, `tlsaSelector`, `tlsaMatchingType`, `tlsaCertificateAssociationData`. |
| SVCB, HTTPS | `svcPriority`, `svcTargetName`, `svcParams`. Keep automatically generated hints derived when the corresponding flags are enabled. |
| URI | `uriPriority`, `uriWeight`, `uri`. |
| CAA | `flags`, `tag`, `value`. |
| FWD | `forwarder` or `value`, `protocol` (UDP), `forwarderPriority` (0), `dnssecValidation` (false), `proxyType`, `proxyAddress`, `proxyPort`, `proxyUsername`, `proxyPassword`. Password uses a secret reference. Legacy API defaults to the server proxy where supported. |
| APP | `appName` or `value`, `classPath`, `recordData` (empty). Treat plugin-owned data as opaque and provide a reference when it contains secrets. |
| Other record types | Use standard zone-file RDATA where supported, or lossless raw RDATA for numeric unknown types. Legacy fallback uses `rdata`. |

`overwrite`, `ptr`, `createPtrZone`, and `updateSvcbHints` control API operations. Reproduce the resulting configuration through the relevant records or auto-hint flags. Generated signing records, replicated records, and records maintained by runtime services need source-aware export and reconciliation so applying the manifest preserves live state.

`zones.<name>.dnssec` describes signing intent for eligible primary zones. The signing and key lifecycle APIs validate algorithms, key formats, and state transitions. Keys are stored with zone metadata. Preserve existing key identity on reapply so a signing policy does not create a new key each time. [Signing API](DnsServerCore/WebServiceZonesApi.cs#L2124) · [Key management](DnsServerCore/WebServiceZonesApi.cs#L2580) · [Zone metadata](DnsServerCore/Dns/Zones/AuthZoneInfo.cs#L1223)

| Manifest field under `dnssec` | API field or operation | Type, default, and validation |
| --- | --- | --- |
| `enabled` | sign and unsign | Boolean, false for new primary zones. |
| `dnsKeyTtl` | `dnsKeyTtl`, DNSKEY TTL update `ttl` | Unsigned seconds, 3600 on signing. |
| `proof.type` | `nxProof`, NSEC/NSEC3 conversions | Enum, NSEC by default. |
| `proof.iterations`, `proof.saltLength` | `iterations`, `saltLength` | Unsigned 16-bit and 8-bit values, both default 0. Apply only to NSEC3 and validate with the signing manager. Salt contents are generated state. |
| `keys` | signing and add-key inputs | Named keys with role, algorithm, hash or curve, applicable key size, and optional private-key reference. Maps `keyType`, `algorithm`, `hashAlgorithm`, `curve`, `keySize`, `kskKeySize`, `zskKeySize`, `pemKskPrivateKey`, `pemZskPrivateKey`, and `pemPrivateKey`. Use the existing supported algorithm combinations. |
| `keys.<id>.rolloverDays` | `zskRolloverDays`, `rolloverDays` | 0–365 days for ZSKs, with 0 disabling automatic rollover. Initial signing defaults to 30 for a generated ZSK and 0 for an imported ZSK. |

Publish, rollover, retire, and delete are lifecycle operations. Current key state, state-change timestamps, computed key tags, signatures, and denial records are derived or operational state. Private key material stays in referenced inputs.

## Authentication, users, groups, and permissions

`auth.config` version 4 stores users, groups, permission grants, sessions, OIDC SSO, and LDAP settings. Cluster transfer replaces users and groups and synchronizes global permission grants. Per-zone permissions also follow zone and catalog lifecycle rules. The manifest must preserve working administrative access and keep authentication state such as sessions, issued tokens, and prior login metadata in the existing store. [Auth writer](DnsServerCore/Auth/AuthManager.cs#L805) · [Cluster restore](DnsServerCore/Auth/AuthManager.cs#L746) · [User API](DnsServerCore/WebServiceAuthApi.cs#L1122) · [Permission API](DnsServerCore/WebServiceAuthApi.cs#L1665)

| Proposed manifest path | API field or source | Type, default, and validation |
| --- | --- | --- |
| `auth.users.<username>` | `user`, `newUser`, local/SSO creation, LDAP signup | Named user, no additional users by default. Normalize through the username validator and enforce uniqueness. The built-in `admin` user and reserved group membership have lifecycle protections. |
| `auth.users.<username>.type` | Local, SSO, or LDAP user creation path | Enum, Local for local creation. Distinguish local credentials from externally authenticated identities. |
| `auth.users.<username>.displayName` | `displayName` | String, username on creation. Up to 255 characters. |
| `auth.users.<username>.externalIdentifier` | `ssoIdentifier` | Required external identifier for explicitly provisioned SSO users. LDAP uses the directory username. |
| `auth.users.<username>.password` | `pass`, `newPass`, bootstrap environment inputs | Secret reference for local users. Initial admin bootstrap uses `DNS_SERVER_ADMIN_PASSWORD` before `DNS_SERVER_ADMIN_PASSWORD_FILE`, then falls back to the built-in credential. Password hash, salt, and derived metadata remain in auth storage. |
| `auth.users.<username>.passwordIterations` | `iterations` | Integer 100000–1000000, default 100000 for new or changed local passwords. |
| `auth.users.<username>.totp.enabled` | `totpEnabled`, 2FA operations | Boolean, false. Supported for local and LDAP users. Enabling requires valid enrollment material. |
| `auth.users.<username>.totp.enrollment` | Existing TOTP enrollment state | Optional secret reference for enrollment material. Preserve the destination's enrollment when unmanaged. Export a reference or a missing-input marker. |
| `auth.users.<username>.disabled` | `disabled` | Boolean, false. Apply built-in user and administrative access protections. |
| `auth.users.<username>.sessionTimeoutSeconds` | `sessionTimeoutSeconds`, user profile setter | Integer seconds, 1800. Range 0–604800. |
| `auth.users.<username>.groups` | `memberOfGroups`, group-side `members` | Group name set. Keep one canonical membership representation. Built-in membership and external provider mappings can supply effective groups. |
| `auth.groups.<name>` | `group`, `newGroup` | Named group. Preserve built-in groups. Names must be unique, nonempty, and at most 255 characters. |
| `auth.groups.<name>.description` | `description` | String, empty. Up to 255 characters. |
| `auth.permissions.<section>.users`, `auth.permissions.<section>.groups` | `section`, `userPermissions`, `groupPermissions` | Principal-to-permission maps. Reuse View, Modify, and Delete flags and built-in grants. Zone-level grants map to the zone resource. |
| `auth.staticSessions` | `DNS_SERVER_AUTH_STATIC_SESSIONS` | Optional node-local map of configured credential references, empty. Each entry names an existing user and supplies a unique token through a reference. The legacy environment input uses a 64-character token. Generated sessions and API tokens are runtime state. |

Local user and group changes apply through the authentication manager. OIDC enablement, authority, metadata, client configuration, and scope changes can restart the web service. LDAP settings affect subsequent authentication requests. On a fresh installation, provider environment inputs use the prefixes `DNS_SERVER_SSO_` and `DNS_SERVER_LDAP_` below. These provider settings are persisted and participate in cluster config transfer. [Provider defaults and bootstrap](DnsServerCore/Auth/AuthManager.cs#L260) · [OIDC API](DnsServerCore/WebServiceAuthApi.cs#L1829) · [LDAP API](DnsServerCore/WebServiceAuthApi.cs#L2080)

| Proposed manifest path | API field | Environment suffix | Type, default, and validation |
| --- | --- | --- | --- |
| `auth.sso.enabled` | `ssoEnabled` | `ENABLED` | Boolean, false. Effective sign-in depends on usable provider configuration. |
| `auth.sso.authority` | `ssoAuthority` | `AUTHORITY` | Optional HTTP or HTTPS URI, unset. Up to 255 characters. |
| `auth.sso.clientId` | `ssoClientId` | `CLIENT_ID` | Optional string, unset. Up to 255 characters. |
| `auth.sso.clientSecret` | `ssoClientSecret` | `CLIENT_SECRET`, `CLIENT_SECRET_FILE` | Optional secret reference, unset. Inline environment input takes precedence over the file. Masked API placeholder retains the existing secret. |
| `auth.sso.metadataAddress` | `ssoMetadataAddress` | `METADATA_ADDRESS` | Optional HTTP or HTTPS URI, unset. Up to 255 characters. |
| `auth.sso.scopes` | `ssoScopes` | `SCOPES` | Set, defaults to `openid`, `profile`, and `email`. Empty selects defaults. The setter supplies mandatory `openid` and `profile`. Up to 255 entries. |
| `auth.sso.allowSignup` | `ssoAllowSignup` | `ALLOW_SIGNUP` | Boolean, false. |
| `auth.sso.allowSignupOnlyForMappedUsers` | `ssoAllowSignupOnlyForMappedUsers` | `ALLOW_SIGNUP_ONLY_FOR_MAPPED_USERS` | Boolean, true. Applies to signup when enabled. |
| `auth.sso.groupMap` | `ssoGroupMap` | `GROUP_MAP` | Map of external to local groups, unset. Up to 255 mappings. Validate referenced local groups. |
| `auth.ldap.enabled` | `ldapEnabled` | `ENABLED` | Boolean, false. Requires a usable directory configuration. |
| `auth.ldap.server` | `ldapServer` | `SERVER` | Optional directory host, unset. Up to 255 characters. |
| `auth.ldap.port` | `ldapPort` | `PORT` | Integer port, 389. Range 1–65535. |
| `auth.ldap.sslOption` | `ldapSslOption` | `SSL_OPTION` | Enum, None. Also accepts StartTLS or LDAPS. |
| `auth.ldap.ignoreSslErrors` | `ldapIgnoreSslErrors` | `IGNORE_SSL_ERRORS` | Boolean, false. Applies to TLS certificate validation. |
| `auth.ldap.bindUsername` | `ldapBindUsername` | `BIND_USERNAME` | Optional string, unset. Up to 255 characters. |
| `auth.ldap.bindPassword` | `ldapBindPassword` | `BIND_PASSWORD`, `BIND_PASSWORD_FILE` | Optional secret reference, unset. Inline environment input takes precedence over the file. Masked API placeholder retains the existing secret. |
| `auth.ldap.searchBase` | `ldapSearchBase` | `SEARCH_BASE` | Optional directory base, unset. Up to 255 characters. |
| `auth.ldap.userSearchFilter` | `ldapUserSearchFilter` | `USER_SEARCH_FILTER` | Optional filter, unset. Up to 255 characters. |
| `auth.ldap.groupAttribute` | `ldapGroupAttribute` | `GROUP_ATTRIBUTE` | Optional attribute name, unset. Up to 255 characters. |
| `auth.ldap.allowSignup` | `ldapAllowSignup` | `ALLOW_SIGNUP` | Boolean, false. |
| `auth.ldap.allowSignupOnlyForMappedUsers` | `ldapAllowSignupOnlyForMappedUsers` | `ALLOW_SIGNUP_ONLY_FOR_MAPPED_USERS` | Boolean, true. Applies to signup when enabled. |
| `auth.ldap.groupMap` | `ldapGroupMap` | `GROUP_MAP` | Map of external to local groups, unset. Up to 255 mappings. Validate referenced local groups. |

## DNS apps

App packages and configuration live under `apps/<name>/`. The app manager applies install, update, uninstall, and configuration changes live. Cluster configuration transfer can carry app packages and configuration. The existing global update flag is mapped to `apps.autoUpdate` in the DNS settings. [App API](DnsServerCore/WebServiceAppsApi.cs#L280) · [Installation](DnsServerCore/Dns/Applications/DnsApplicationManager.cs#L396) · [Configuration](DnsServerCore/Dns/Applications/DnsApplication.cs#L231) · [Cluster transfer](DnsServerCore/DnsWebService.cs#L811)

| Proposed manifest path | API field or source | Type, default, and validation |
| --- | --- | --- |
| `apps.packages.<name>` | `name` on app install, update, and uninstall | Named package, no apps by default. Reuse the app manager's folder-name validation and enforce unique names. |
| `apps.packages.<name>.source` | `url` or uploaded ZIP | Optional package reference for existing installs, required to install a missing package. The download API uses HTTPS. An installed package's ZIP can be reused when available, and the original URL is not reliably persisted. |
| `apps.packages.<name>.version` | Installed app version in list response and package assembly | Optional version for existing apps. Verify the version against the installed or supplied package. Reconcile explicit pins with the global automatic update flag. |
| `apps.packages.<name>.configuration` | `config` in the app config API | Optional native text or file reference. Default comes from the package when present. The manager calls each loaded implementation's initializer and saves `dnsApp.config`; empty clears the file if the app accepts it. Use file or secret references for sensitive app settings. |

App-owned configuration stays opaque to the server's schema and is validated by the app. Package installation must preserve any existing app configuration unless the manifest explicitly manages it. App caches, downloaded data, logs, and derived version information remain app state.

## Clustering

`cluster.config` version 1 persists the cluster domain, intervals, last sync timestamp, and a membership list. Node entries store an ID, URL, IP addresses, role, and state. Cluster lifecycle APIs initialize, join, leave, and promote nodes. The manifest should express the intended topology and use those operations so it preserves membership identities, certificates, and the cluster catalog. [Cluster persistence](DnsServerCore/Cluster/ClusterManager.cs#L346) · [Node persistence](DnsServerCore/Cluster/ClusterNode.cs#L692) · [Cluster API](DnsServerCore/WebServiceClusterApi.cs#L230)

| Proposed manifest path | API field or operation | Type, default, and validation |
| --- | --- | --- |
| `cluster.bootstrap.role` | Initialize primary or initialize and join secondary | Explicit role for an uninitialized instance. A fresh server starts without a cluster. Existing promotion, leave, and delete operations change topology and require explicit intent. |
| `cluster.domain` | `clusterDomain` | DNS name, required for initialization. Normalize the domain and validate compatibility with the cluster zones and node names. The domain is fixed after initialization. |
| `cluster.node.addresses` | `ipAddresses`, bootstrap aliases `primaryNodeIpAddresses` and `secondaryNodeIpAddresses` | Node-local IP address array, required to initialize or join. The node URL derives from the DNS server domain and TLS listener port. Updates publish the advertised addresses through the cluster manager. |
| `cluster.bootstrap.primaryUrl` | `primaryNodeUrl` | Primary URL for a joining secondary. Use the primary's DNS hostname. Validate compatibility with the primary returned by the cluster. |
| `cluster.bootstrap.primaryAddress` or `cluster.bootstrap.primaryAddresses` | `primaryNodeIpAddress` or `primaryNodeIpAddresses` | Optional IP address or ordered list of up to ten addresses, unset. Allows the join to contact the primary before cluster DNS resolution is available. |
| `cluster.bootstrap.username` | `primaryNodeUsername` | Required account name for join. The account must be able to perform the primary-side operation. |
| `cluster.bootstrap.password`, `cluster.bootstrap.totp` | `primaryNodePassword`, `primaryNodeTotp` | Join credential references. Password required by the existing join API, TOTP conditional. Resolve on use and keep credential material out of exported topology. |
| `cluster.bootstrap.ignoreCertificateErrors` | `ignoreCertificateErrors` | Boolean, false. Applies to the initial join connection. |
| `cluster.heartbeatRefreshSeconds` | `heartbeatRefreshIntervalSeconds` | Integer seconds, 30. Range 10–300. Only the primary updates cluster options. |
| `cluster.heartbeatRetrySeconds` | `heartbeatRetryIntervalSeconds` | Integer seconds, 10. Range 10–300. Only the primary updates cluster options. |
| `cluster.configRefreshSeconds` | `configRefreshIntervalSeconds` | Integer seconds, 900. Range 30–3600 and greater than the heartbeat refresh interval. |
| `cluster.configRetrySeconds` | `configRetryIntervalSeconds` | Integer seconds, 60. Range 30–3600. Only the primary updates cluster options. |

Remote member URLs and addresses are synchronized topology. Updating them maps to cluster node lifecycle operations with the relevant node identity. Node IDs, current membership state, last-seen and last-sync timestamps, generated cluster credentials, and certificate material are managed by the cluster. TLS must be available for cluster communication. Preserve node-local DNS listeners, web service, logging, and DHCP settings across transfers. [Options validation](DnsServerCore/Cluster/ClusterManager.cs#L885) · [Join lifecycle](DnsServerCore/Cluster/ClusterManager.cs#L1313)

## Host startup inputs

The console and Windows service select the configuration directory before loading settings. Console portable mode influences the default log directory, and `--stop-if-bind-fails` controls listener startup failure handling. Keep these as host inputs so the server can find the manifest before interpreting its fields. Container mounts, exposed ports, service-manager settings, and installer options belong to deployment configuration. [Console startup](DnsServerApp/Program.cs#L30) · [Windows startup](DnsServerWindowsService/DnsServiceWorker.cs#L33)
