# Deploy Technitium on NixOS

On a 64-bit NixOS host, add this repository as an input in your system flake. Commit your system's lock file to pin the package.

```nix
# In your system flake
inputs.technitium.url = "github:haug1/Technitium";

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

## Raspberry Pi 4 example

Use this host module in place of the example above. It forwards DNS to Quad9 over TLS, refreshes the Steven Black adware and malware list every two hours, and disables per-query logging.

```nix
{
  services.technitium-dns-server = {
    enable = true;
    openFirewall = true;
    firewallTCPPorts = [ 53 5380 53443 ];
    firewallUDPPorts = [ 53 ];

    settings = {
      web = {
        tlsEnabled = true;
        tlsPort = 53443;
        useSelfSignedCertificate = true;
        redirectHttpToTls = true;
      };
      logging.logQueries = false;
      blocklists = {
        sources = [ "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" ];
        updateIntervalHours = 2;
      };
      dns.forwarding.servers = [
        { address = "dns.quad9.net:853 (9.9.9.9)"; transport = "Tls"; }
        { address = "dns.quad9.net:853 (149.112.112.112)"; transport = "Tls"; }
      ];
    };
  };

  nix.settings = {
    extra-substituters = [ "https://haug1.cachix.org" ];
    extra-trusted-public-keys = [
      "haug1.cachix.org-1:Ym4B56y5dovvptCL3MUXk/f7TSMt6SJ/I2I3Kf+XdqQ="
    ];
  };
}
```

Use the dashboard ports on a trusted LAN. HTTP on port 5380 redirects to HTTPS on port 53443. Expect a browser warning for the self-signed certificate. For the first build, configure the cache URL and public key in the running Nix setup if you want Nix to substitute an already published build.

## Secrets and rollback

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
