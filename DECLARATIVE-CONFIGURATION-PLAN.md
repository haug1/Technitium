# Declarative configuration implementation plan

A versioned `technitium.json` manifest should reproduce the operator-controlled settings of an existing server on a fresh instance. Use the [settings inventory](DECLARATIVE-SETTINGS-INVENTORY.md) as the release checklist and keep the [schema](configuration/technitium.schema.json), [examples](configuration/examples), and [migration guide](configuration/README.md) aligned.

## 1. Close configuration and export gaps

- Preserve the complete apex NS record set when the source replaces its generated default name server. Give operators explicit control over that replacement while keeping the existing behavior for manifests that leave the generated record implicit.
- Audit the inventory against the schema, preview, apply, and export. Close gaps where an operator-controlled value is lost or a valid source configuration cannot be represented. Use the same domain rules for equivalent manifest and API inputs.

**Acceptance.** Migrating a zone with a replaced apex NS set serves the same name servers and TTLs on a clean destination. A manifest that leaves the default implicit still gets a generated name server. Every operator-settable field in the inventory has a documented manifest representation and a migration path.

## 2. Verify clean-instance migration and recovery

- Follow the documented export, supply inputs, validate, preview, and apply workflow against a clean destination. Compare effective settings across DNS, web, logging, blocklists, zones, DHCP, authentication, apps, and clustering. Supply referenced secrets and copy host-local files as required.
- Verify representative upgrades from existing stores, legacy backup restore, and recovery after interrupted persistence or failed listener activation. Check that external app and cluster operations can be retried as documented.

**Acceptance.** The destination reproduces the source settings with its supplied inputs. A second apply reports no changes and causes no restart. Invalid or stale previews fail before mutation. Failed writes or activation leave the last working configuration recoverable. Include the older DNS configuration fixture and verify that active DHCP leases and replicated zone data survive reconciliation.

## 3. Verify the release candidate

- Run the full local regression suite and confirm the Linux regression workflow passes on the same revision.
- Run the manual **Configuration integration tests** and **Windows manifest tests** workflows for release verification. Verify that the Windows service and console host share the manifest startup behavior. [Verification commands](build.md#regression-tests)

**Acceptance.** The release candidate passes schema and CLI checks, startup with and without a manifest, the Linux regression suite, and Windows manifest checks. The integration workflow verifies HTTPS package retry, same-build cluster propagation and failover, and mixed-version rejection before partial changes. Two-node checks verify that only the authorized node applies cluster-wide settings and that node-local settings survive synchronization.
