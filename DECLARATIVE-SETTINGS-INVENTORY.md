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
