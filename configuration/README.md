# Declarative configuration

The [JSON Schema](technitium.schema.json) describes the proposed version 1 manifest. See the [settings inventory](../DECLARATIVE-SETTINGS-INVENTORY.md) for existing defaults, aliases, validation, and service effects. The [example manifests](examples) show a minimal manifest, named resources, and secret references.

Use `dotnet run --project DnsServerApp/DnsServerApp.csproj -- config validate path/to/technitium.json` to check the manifest's schema and references. This command uses `technitium.json` in the current directory when the path is omitted. Effective settings and platform-specific validation will run against the candidate configuration during planning.

## Ownership and updates

The applied manifest defines ownership. Preview and validation leave ownership and settings untouched. Apply updates ownership only after activation succeeds, and recovery restores the previous ownership together with the last working settings.

| Manifest input | Effective setting after successful apply | Ownership |
| --- | --- | --- |
| Field omitted | Keep the existing value. On a fresh instance, use the server's normal initialization rules. | Unmanaged. Removing a field from a later manifest releases ownership and keeps its last effective value. |
| Explicit scalar or reference | Use the declared value after validation and normalization. | Own the field. |
| `null` on a setting that permits it | Reset to its fresh-config default for the current host without using environment overrides. Optional values with no default become unset. | Own the reset value. |
| Nonempty list | Replace the operator-managed entries in that field. Preserve the sequence when it has meaning. | Own the collection. |
| Empty list | Replace the operator-managed entries with an empty list, then apply the field's existing normalization rules. For example, empty DNS listener endpoints select default endpoints. | Own the collection. |
| Named map with object entries | Create a missing entry or update its declared fields. Unmentioned keys stay in place. Validate required creation inputs against the effective entry. | Own each declared entry's existence and its declared fields. |
| Empty named map | Keep all existing entries. Previously managed keys absent from the map become unmanaged. | Own no entries in that map. |
| `null` at a named map entry | Remove that entry if it exists. Reapplying the deletion is a no-op. | Own the entry's absence until the declaration is removed. |
| `null` on a named map where the schema permits it | Reset the whole map to its default. Include removals in the preview. | Own map membership. |

Named keys use the subsystem's identity rules. Zones and TSIG keys use canonical DNS names, scope names use the DHCP manager's case-sensitive keys, and reservations use normalized MAC addresses within the scope. Users, groups, apps, and permission entries use the identities accepted by their managers. Reject duplicate keys after normalization, even when their JSON spellings differ. A rename is an explicit resource change. Reconciliation preserves runtime-owned data. In a record collection, replicated, generated, and lease-maintained records stay under their existing owners. If the server cannot determine whether an existing record is operator-managed, preview reports a conflict before any mutation.

## Competing writers

Evaluate the entire proposed change against the active ownership policy before calling setters or persistence routines. Reject a mixed request as a unit if any part would change a managed value. An equal normalized value is permitted and skips the managed setter. Report conflicting paths with the response and expose the managed paths for inspection through the settings API and admin console. Changes made by the server's existing runtime and lifecycle operations follow their documented invariants.

| Source | Expected result |
| --- | --- |
| UI or settings API | Unmanaged changes proceed. A change to a managed field or managed resource membership fails before any part of the request takes effect. |
| Backup restore | Compare the selected restore fields against ownership. Apply an allowed restore through the existing manager. A conflict rejects the restore before modifying the selected stores. |
| Cluster transfer | The primary owns cluster-wide declarations. A secondary can declare node-local values. Transfers preserve node-local settings and reject ownership conflicts before changing the selected stores. |
| Cluster bootstrap | Check the current topology against the declared bootstrap intent. A matching initialized role is a no-op. Report an incompatible existing topology as a conflict. |

An explicitly declared value takes precedence over the corresponding existing setting or legacy environment variable. If `DNS_SERVER_DOMAIN=old.example.test` conflicts with declared `dns.serverDomain=primary.example.test`, validation reports the conflict by field and environment-variable name. Local validation checks its own environment. Remote preview and startup report conflicts from the server environment. The declared value is the candidate. Omitting that field preserves the existing domain on an initialized server and lets the normal legacy environment handling supply it on a fresh server. Releasing ownership allows later API changes without restoring an older value.

## Validation examples

| Input | Expected result |
| --- | --- |
| `{"schemaVersion":1}` | Valid. No settings are owned. |
| `{"schemaVersion":2}` | Reject with an unsupported version diagnostic at `schemaVersion`. |
| `{"schemaVersion":1,"dns":{"retryCount":2}}` | Reject unknown field `dns.retryCount`. |
| `{"schemaVersion":1,"logging":{"logQueries":true,"logQueries":false}}` | Reject the duplicate key at `logging.logQueries` before reading the last value. |
| `{"schemaVersion":1,"zones":{"EXAMPLE.test":{},"example.test":{}}}` | Reject the duplicate canonical zone key. |
| `{"schemaVersion":1,"logging":{"retentionDays":null}}` | Valid reset. The retention setting becomes 365 days and remains managed. |
| `{"schemaVersion":1,"dhcp":{"scopes":{"Lab":null}}}` | Preview reports deletion if the scope exists. Apply reconciles that explicit deletion. |
| `{"schemaVersion":1,"web":{"certificate":{"password":{"environment":"MISSING_CERT_PASSWORD"}}}}` | The reference has valid JSON shape. Validation fails when the referenced value is missing and reports `web.certificate.password` without printing secret material. |

Secret references select one environment variable or one file. Resolve relative reference paths from the manifest's directory. Settings that are server paths, such as a TLS certificate path, use the owning manager's path rules. Preview, diagnostics, and exports report references or missing-input markers and keep resolved values out of their output.

## Previewing changes

Run `dotnet run --project DnsServerApp/DnsServerApp.csproj -- config plan path/to/technitium.json https://dns.example.test` against a running instance. Set `TECHNITIUM_CONFIG_API_TOKEN` to a token with Settings view permission. The command accepts HTTP for loopback development instances.

The current preview covers the DNS server domain, DNS listener endpoints and source networks, authoritative DNS defaults, selected DNS options, web listener addresses, ports, proxy ACL, and headers, logging settings, statistics, blocklist sources and scheduling, and the app auto-update flag. It reports changed field paths, DNS and web restarts, and a revision for the manifest and server snapshot. Values stay out of the response. A service restart invalidates earlier revisions. A declaration outside this set returns an error before producing a preview.

## Exporting supported settings

Run `dotnet run --project DnsServerApp/DnsServerApp.csproj -- config export https://dns.example.test > technitium.json` with the same token. The command writes stable manifest JSON for fields supported by apply and reports the partial export on standard error. Use `--include-preview-only` after the server URL to include additional fields for inspection. The export omits blocklist source URLs because they can contain credentials. Supply `blocklists.sources` separately when migrating a server that uses them.

To reproduce the exported settings, validate the file, preview it against the destination, then apply using the destination revision. Check the declared DNS listener addresses and log directory against the destination host before applying.

## Applying DNS, web, logging, and blocklist settings

Run `dotnet run --project DnsServerApp/DnsServerApp.csproj -- config apply path/to/technitium.json https://dns.example.test <revision>` with the revision printed by `config plan` and a token with Settings modify permission. Generate a new preview if the revision becomes stale.

This implementation applies `dns.serverDomain`, `dns.localEndpoints`, the IPv4 and IPv6 `dns.sourceNetworks` lists, the three `dns.authoritative` record TTL defaults, SOA serial format, minimum SOA refresh and retry intervals, SOA responsible person, zone-transfer and NOTIFY network allowlists, `dns.checkForUpdates`, `dns.udpPayloadSize`, `dns.dnssecValidation`, `web.realIpHeader`, `web.frameAncestors`, `web.reverseProxyAcl`, `logging.destination`, `logging.folder`, `logging.noStackTrace`, `logging.retentionDays`, `logging.useLocalTime`, `blocklists.sources`, and `blocklists.updateIntervalHours` together. The server domain, authoritative defaults, update checks, EDNS UDP payload size, DNSSEC validation, and blocklist settings can be applied on standalone servers. Other declarations are rejected before mutation. The server persists the values and their ownership in `dns.config`, `log.config`, `webservice.config`, and `blocklist.config`. A failed DNS bind restores the previous listeners and rejects the apply. Applying a manifest that omits a previously managed field releases ownership and keeps the current value. The Settings screen displays managed manifest paths for the selected server. The settings API returns the same paths in `managedSettings`. Settings edits and backup restores that would change an owned value are rejected before other settings in the request are changed. If a backup uses a combined configuration format whose listener values cannot be verified (versions 6–27), release DNS listener ownership before restoring it. Combined backup versions 23–27 require releasing ownership of the default record TTL before restore. Combined formats leave the separate NS and SOA TTL defaults unchanged. Release ownership of the blocklist sources and update interval before restoring DNS settings from a combined backup. Versions 25–27 require releasing ownership of the UDP payload size before restore, and versions 26–27 require releasing ownership of DNSSEC validation.

The reverse-proxy ACL uses first-match rule order. An empty array trusts no IP-based proxies, while `null` restores the server’s default ACL.

### Startup

Place `technitium.json` in the server's configuration directory to reconcile the supported DNS, web, logging, and blocklist settings at startup. The console host and Windows service both use this path. Startup rejects invalid manifests and unsupported sections before opening listeners. The server binds the declared DNS listeners before committing values and ownership.

The startup file takes effect again at the next restart. Update that file when changing the desired startup settings. With no startup file, the server continues with persisted values and ownership. To release all managed settings, apply or start with a manifest containing only `schemaVersion`.

If the process stops during manifest persistence, the next startup restores the previous DNS and logging configuration and ownership before loading settings. Startup then reconciles the startup manifest if one is present.
