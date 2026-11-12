# Declarative settings inventory

This inventory maps existing configuration inputs to proposed manifest paths. Defaults refer to a fresh configuration before environment overrides. Activation describes the current service behavior. Cluster scope describes current configuration transfer, which the manifest policy must account for.

## Web service

These settings are node-local. The settings API reads and writes them through `settings/get` and `settings/set`. `webservice.config` stores them except for the web root, which is read from the environment on each web service start. The reader supplies the default proxy ACL for versions before 2, disables missing Unix socket settings, and supplies the default frame policy before version 3. [Settings API](DnsServerCore/WebServiceSettingsApi.cs#L182) · [Web service persistence](DnsServerCore/DnsWebService.cs#L472) · [Web root](DnsServerCore/DnsWebService.cs#L1817)

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
| `web.rootPath` | | `WWW_FOLDER_PATH` | Directory path, installation `www` directory | A missing directory falls back to the installed web root. Takes effect on web service start. |

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
| `dns.proxy.username` | `proxyUsername` | Optional string, unset | Up to 255 characters. Credential creation depends on username presence. |
| `dns.proxy.password` | `proxyPassword` | Optional secret reference, unset | Resolved password up to 255 characters. Export a reference or missing-input marker. |
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
| `dns.cache.serveStale.ttl` | `serveStaleTtl` | Unsigned seconds, 259200 | Use the DNS TTL parser for legacy API input. |
| `dns.cache.serveStale.answerTtl` | `serveStaleAnswerTtl` | Unsigned seconds, 30 | Use the DNS TTL parser for legacy API input. |
| `dns.cache.serveStale.resetTtl` | `serveStaleResetTtl` | Unsigned seconds, 30 | Range 10–900. |
| `dns.cache.serveStale.maxWaitMs` | `serveStaleMaxWaitTime` | Integer milliseconds, 1800 | Range 0–1800. |
| `dns.cache.maximumEntries` | `cacheMaximumEntries` | Signed 64-bit count, 10000 | Nonnegative. Zero disables the entry limit. |
| `dns.cache.minimumRecordTtl` | `cacheMinimumRecordTtl` | Unsigned seconds, 10 | Use the DNS TTL parser for legacy API input. |
| `dns.cache.maximumRecordTtl` | `cacheMaximumRecordTtl` | Unsigned seconds, 604800 | Use the DNS TTL parser for legacy API input. |
| `dns.cache.negativeRecordTtl` | `cacheNegativeRecordTtl` | Unsigned seconds, 300 | Use the DNS TTL parser for legacy API input. |
| `dns.cache.failureRecordTtl` | `cacheFailureRecordTtl` | Unsigned seconds, 10 | Use the DNS TTL parser for legacy API input. |
| `dns.cache.prefetch.enabled` | `enableCachePrefetch` | Boolean, true | Enabling with a trigger below 1 restores the default trigger. |
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
