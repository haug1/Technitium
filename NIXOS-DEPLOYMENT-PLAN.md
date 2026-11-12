# NixOS deployment plan

## 1. Package the fork for ARM64

Extend the existing flake with an `aarch64-linux` package built from this repository. Pin the build dependencies and provide the executable expected by the Nixpkgs Technitium service.

**Acceptance.** The flake builds the ARM64 package from a clean checkout. The packaged executable validates the minimal manifest and starts with an isolated state directory on ARM64.

## 2. Wire the manifest into NixOS

Export a flake module that builds on the Nixpkgs service. Add a `settings` attribute set for the full [manifest schema](configuration/technitium.schema.json), use Technitium's validator, and restart the service when the generated manifest changes. Preserve writable service state and reference secrets through runtime files.

**Acceptance.** A NixOS test verifies DNS over UDP and TCP, an observable settings change after a configuration switch, and state persistence after reboot. It also verifies startup with a runtime secret reference while keeping its value out of the Nix store. The deployment example explains firewall settings and how generation rollback interacts with persisted settings.

## 3. Pilot on the Raspberry Pi 4

Provide an example host configuration and a short deployment checklist. The user deploys to their Pi, checks the service from a LAN client, and shares feedback before using it as the LAN's resolver. Address issues found during the pilot and provide revised steps for retesting.

**Acceptance.** The user confirms the Pi answers DNS over UDP and TCP, a manifest change takes effect after `nixos-rebuild switch`, and the service and state survive a reboot. Resolve and retest any deployment blockers the user reports.
