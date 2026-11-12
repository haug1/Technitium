# Declarative configuration implementation plan

A versioned `technitium.json` manifest should reproduce the operator-controlled settings of an existing server on a fresh instance. Use the [settings inventory](DECLARATIVE-SETTINGS-INVENTORY.md) as the release checklist and keep the [schema](configuration/technitium.schema.json), [examples](configuration/examples), and [migration guide](configuration/README.md) aligned.

## 1. Close configuration and export gaps

- Audit the inventory against the schema, preview, apply, and export. Close gaps where an operator-controlled value is lost or a valid source configuration cannot be represented. Use the same domain rules for equivalent manifest and API inputs.
- Preserve the local NOTIFY and dynamic-update settings that the zone options API accepts on catalog-provisioned replicas. Apply them after catalog transfer supplies membership and records.

**Acceptance.** Every operator-settable field in the inventory has a documented manifest representation and a migration path.

## 2. Verify the release candidate

- Run the full local regression suite and confirm the Linux regression workflow passes on the same revision.
- Run the manual **Configuration integration tests** and **Windows manifest tests** workflows for release verification. Verify that the Windows service and console host share the manifest startup behavior. [Verification commands](build.md#regression-tests)

**Acceptance.** The release candidate passes schema and CLI checks, startup with and without a manifest, the Linux regression suite, and Windows manifest checks. The integration workflow verifies HTTPS package retry, same-build cluster propagation and failover, and mixed-version rejection before partial changes. Two-node checks verify that only the authorized node applies cluster-wide settings and that node-local settings survive synchronization.
