# NixOS deployment plan

## 1. Pilot on the Raspberry Pi 4

Use the [example host configuration](nix/README.md) and prepare a short checklist for the Pi. The user deploys to their Pi, checks the service from a LAN client, and shares feedback before using it as the LAN's resolver. Address issues found during the pilot and provide revised steps for retesting.

**Acceptance.** The user confirms the Pi answers DNS over UDP and TCP, a manifest change takes effect after `nixos-rebuild switch`, and the service and state survive a reboot. Resolve and retest any deployment blockers the user reports.
