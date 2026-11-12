# Declarative configuration implementation plan

Use a versioned `technitium.json` manifest to configure a fresh server, preview changes to an existing server, and reproduce its settings on another instance. Start with JSON and the .NET parser, and publish a JSON Schema for editor validation and autocomplete. Make manifest management opt-in and use the existing configuration stores for persistence in the first release.

Technitium loads settings across several managers at startup. The DNS settings API saves changes to multiple files and can restart listeners. Cluster configuration transfer uses the backup and restore code. Use the same domain rules and lifecycle operations for file-based configuration, the UI, and the API. [Startup](DnsServerCore/DnsWebService.cs#L2904) · [Settings API](DnsServerCore/WebServiceSettingsApi.cs#L480) · [Cluster transfer](DnsServerCore/Cluster/ClusterManager.cs#L866)

## 1. Inventory every setting and define the schema

Build a field inventory from the persistence readers, settings APIs, and environment variable handling. For each setting, record its type, default, validation, secret handling, cluster scope, and restart requirements. Use the inventory as the release coverage checklist. [API documentation](APIDOCS.md) · [Environment variables](EnvironmentVariables.md)

| Area | Manifest coverage |
| --- | --- |
| DNS and web service | Listeners, TLS, recursion, forwarders, cache, DNSSEC validation, rate limits, and logging settings |
| Zones and blocking | Authoritative zone definitions, zone options and permissions, operator-managed records, allow and block entries, and blocklist sources |
| DHCP | Scopes, options, enabled state, and reservations |
| Authentication | Users, groups, permissions, and SSO settings |
| DNS apps | App identity, package version and source, and app-owned configuration in its native format |
| Clustering | Cluster-wide settings, node-local settings, and explicit bootstrap or join configuration |

Keep leases, sessions, issued tokens, caches, logs, statistics, downloaded blocklist contents, and replicated zone contents in their existing runtime stores. Use references for secrets and key material. A reproducible deployment consists of the manifest and its referenced inputs.

## 2. Define ownership and update semantics

- Require `schemaVersion`. Reject unsupported versions, unknown fields, and duplicate keys with diagnostics that identify the manifest path and offending field.
- Omitted settings remain unmanaged. Explicit values take ownership. Define how to reset a setting to its default and how to update collections by stable identity, such as zone name, scope name, or app ID. Require explicit deletion or explicit ownership of the whole collection before removing entries.
- Preserve current environment variable behavior for unmanaged settings. Use manifest values for managed settings and surface conflicts with legacy environment variables during validation.
- Reject UI and API writes that would change managed fields while manifest management is active. Accept changes to unmanaged fields and show which values the manifest owns. Apply the same ownership checks to backup restores and cluster transfers.

## 3. Build the parser, planner, and apply path

1. Add typed configuration models and a JSON Schema. Normalize values and reuse existing parsers and validators for DNS names, addresses, networks, records, and DHCP options. Extract shared validation from HTTP handlers where necessary.
2. Implement `config validate`, `config plan`, `config apply`, and `config export` in the console host. Share startup configuration logic between the console app and Windows service. Produce stable, reviewable exports with secret references or explicit markers for values that need to be supplied. [Console entry point](DnsServerApp/Program.cs#L30) · [Windows service](DnsServerWindowsService/DnsServiceWorker.cs#L41)
3. Build the plan from a snapshot of current settings. Show additions, updates, deletions, and required restarts with sensitive values redacted. Validate the complete candidate before making changes. Reject stale plans if settings changed after preview. Applying an identical manifest twice should produce no changes on the second apply.
4. Stage durable changes, apply them in dependency order, and reuse existing restart paths. Keep a recoverable snapshot or journal for interrupted writes and failed restarts. Give external operations such as app installation and cluster membership changes explicit steps with defined failure and retry behavior.

## 4. Deliver in slices and verify full coverage

1. **Core settings.** Ship validation, preview, apply, and export for DNS, web service, logging, and blocklists. Verify startup, live changes, listener restart failure, and behavior without a manifest.
2. **Zones and DHCP.** Add resource reconciliation. Verify records, permissions, reservations, explicit deletion, and preservation of runtime state such as active leases and replicated zone data.
3. **Authentication, apps, and clustering.** Add secret resolution, validate that changes preserve administrative access, verify app package and configuration handling, and enforce which node can apply cluster-wide settings. Test mixed-version cluster behavior before enabling cluster-wide apply.
4. **Migration and release.** Document the existing-server workflow of export, supply secret references, validate, preview, and apply. Verify that export and apply reproduce all supported settings on a clean instance. Test legacy backup and restore, interrupted apply recovery, and upgrades from existing installations.

## Release criteria

- Every operator-settable field in the inventory has a documented manifest representation.
- An exported configuration reproduces the intended settings when applied with its referenced inputs.
- Applying the same manifest a second time produces no changes.
- Failed validation or activation leaves the last working configuration recoverable.
