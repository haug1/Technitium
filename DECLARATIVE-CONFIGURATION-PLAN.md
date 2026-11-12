# Declarative configuration implementation plan

Use a versioned `technitium.json` manifest to configure a fresh server, preview changes to an existing server, and reproduce its settings on another instance. Start with JSON and the .NET parser, and publish a JSON Schema for editor validation and autocomplete. Make manifest management opt-in and use the existing configuration stores for persistence in the first release.

Technitium loads settings across several managers at startup. The DNS settings API saves changes to multiple files and can restart listeners. Cluster configuration transfer uses the backup and restore code. Use the same domain rules and lifecycle operations for file-based configuration, the UI, and the API. [Startup](DnsServerCore/DnsWebService.cs#L2904) · [Settings API](DnsServerCore/WebServiceSettingsApi.cs#L480) · [Cluster transfer](DnsServerCore/Cluster/ClusterManager.cs#L866)

Use the [settings inventory](DECLARATIVE-SETTINGS-INVENTORY.md) as the release coverage checklist. The [schema](configuration/technitium.schema.json), [example manifests](configuration/examples), and [ownership rules](configuration/README.md) define the manifest contract. Update those artifacts together as implementation exposes details that need to be clarified.

## 1. Build the parser, planner, and apply path

1. Add typed configuration models and a JSON Schema. Normalize values and reuse existing parsers and validators for DNS names, addresses, networks, records, and DHCP options. Extract shared validation from HTTP handlers where necessary.
2. Implement `config validate`, `config plan`, `config apply`, and `config export` in the console host. Share startup configuration logic between the console app and Windows service. Produce stable, reviewable exports with secret references or explicit markers for values that need to be supplied. [Console entry point](DnsServerApp/Program.cs#L30) · [Windows service](DnsServerWindowsService/DnsServiceWorker.cs#L41)
3. Build the plan from a snapshot of current settings. Show additions, updates, deletions, and required restarts with sensitive values redacted. Validate the complete candidate before making changes. Reject stale plans if settings changed after preview. Applying an identical manifest twice should produce no changes on the second apply.
4. Stage durable changes, apply them in dependency order, and reuse existing restart paths. Keep a recoverable snapshot or journal for interrupted writes and failed restarts. Give external operations such as app installation and cluster membership changes explicit steps with defined failure and retry behavior.

### Acceptance criteria

- **Parser.** The published schema validates the example manifests. Runtime validation rejects invalid structure and cross-field combinations, points to the failing field or resource, and redacts sensitive values. Shared validators enforce the same domain rules for equivalent API and manifest inputs.
- **Commands and startup.** The four documented commands work from the console host, and the console and Windows service use the same manifest startup logic. Validation and preview leave persisted and live settings untouched. Exports of the same settings are stable and represent secrets as references or explicit missing inputs.
- **Planner.** Tests verify that preview reports additions, updates, removals, and required restarts. Applying a plan after its input settings change fails before mutation. Applying the same manifest twice produces an empty second plan and triggers no restart.
- **Apply and recovery.** Tests exercise interrupted persistence and a failed listener restart, and verify that the last working settings and service are recoverable. Document and test retry behavior for each supported external operation.

## 2. Deliver in slices and verify full coverage

Extend the existing regression suite alongside each delivery slice. Cover observable outcomes for validation, migration, idempotence, and recovery. [Local test instructions](build.md#regression-tests)

1. **Core settings.** Ship validation, preview, apply, and export for DNS, web service, logging, and blocklists. Verify startup, live changes, listener restart failure, and behavior without a manifest.
2. **Zones and DHCP.** Add resource reconciliation. Verify records, permissions, reservations, explicit deletion, and preservation of runtime state such as active leases and replicated zone data.
3. **Authentication, apps, and clustering.** Add secret resolution, validate that changes preserve administrative access, verify app package and configuration handling, and enforce which node can apply cluster-wide settings. Test mixed-version cluster behavior before enabling cluster-wide apply.
4. **Migration and release.** Document the existing-server workflow of export, supply secret references, validate, preview, and apply. Verify that export and apply reproduce all supported settings on a clean instance. Test legacy backup and restore, interrupted apply recovery, and upgrades from existing installations.

### Acceptance criteria

1. **Core settings.** A fixture applies and exports settings from DNS, web service, logging, and blocklists. Tests verify the effective values on a fresh start and after reload, a live update where supported, recovery from a failed listener restart, and existing behavior when startup has no manifest.
2. **Zones and DHCP.** Tests exercise creation, updates, and explicit deletion through the manifest, and verify DNS responses, zone permissions, scope settings, and reservations. Active leases and replicated zone data survive reconciliation.
3. **Authentication, apps, and clustering.** Tests verify that missing secrets fail before changes, an administrator can still sign in after apply, and a pinned app package loads its declared configuration. Two-node tests verify that only the authorized node applies cluster-wide settings, node-local settings are preserved, and unsupported mixed-version operations fail before partial changes.
4. **Migration and release.** Follow the documented export-to-apply workflow from an existing installation onto a clean instance and compare effective settings against the inventory. Include an older DNS configuration fixture, a legacy backup restore, and an interrupted apply recovery. The regression suite passes locally and in CI.

## Release criteria

- Every operator-settable field in the inventory has a documented manifest representation.
- An exported configuration reproduces the intended settings when applied with its referenced inputs.
- Applying the same manifest a second time produces no changes.
- Failed validation or activation leaves the last working configuration recoverable.
