# Deploy Technitium on NixOS

On a 64-bit NixOS host, add this repository as an input in your system flake. The URL below uses SSH to access the private repository. Commit your system's lock file to pin the package.

```nix
# In your system flake
inputs.technitium.url = "git+ssh://git@github.com/haug1/Technitium.git?ref=master";

# Include in the host's nixosSystem modules list
# inputs.technitium.nixosModules.default
```

Add the following to the host configuration.

```nix
{
  services.technitium-dns-server = {
    enable = true;
    openFirewall = true;
    firewallTCPPorts = [ 53 ];
    firewallUDPPorts = [ 53 ];
    settings = {
      dns.serverDomain = "resolver.home.arpa";
      web.localAddresses = [ "127.0.0.1" "::1" ];
      web.httpPort = 5380;
    };
  };
}
```

Use the [manifest schema](../configuration/technitium.schema.json) for all application settings. The module supplies `schemaVersion = 1`, validates the generated JSON with the packaged executable, and installs it as `technitium.json` in the persistent service state directory. Back up any existing manifest before enabling the module. After `nixos-rebuild switch`, check the service with `systemctl status technitium-dns-server` and query it from a client with `dig @PI_IP example.org` and `dig @PI_IP example.org +tcp`.

The example opens only UDP and TCP port 53. Set `openFirewall = false` to manage access with interface-specific NixOS firewall rules. For the loopback-only web console, forward port 5380 over SSH and browse to `http://localhost:5380`.

For secrets, use a runtime file provided by your secret manager. For example, add the following to the host configuration after provisioning a root-readable `/run/secrets/technitium-tsig` containing a base64 key.

```nix
{
  systemd.services.technitium-dns-server.serviceConfig.LoadCredential = [
    "tsig:/run/secrets/technitium-tsig"
  ];
  services.technitium-dns-server.settings.dns.tsigKeys."transfer.home.arpa" = {
    algorithm = "hmac-sha256";
    secret.file = "/run/credentials/technitium-dns-server.service/tsig";
  };
}
```

Keep plaintext values outside the Nix store. Restart the service after rotating a credential at the same path.

Rolling back a NixOS generation restores its package and manifest. Mutable state, including zones created through the UI or API, stays on disk. A field omitted from the restored manifest keeps its current value and releases manifest ownership. Declare the intended values explicitly in each generation when they need to roll back together.

Build the package with `nix build .#technitium-dns-server`. On an x86-64 Linux builder with KVM, run `nix build .#checks.x86_64-linux.nixos-deployment -L` for the deployment test. The manual **NixOS deployment tests** workflow runs the VM test and the native ARM64 package check.
