technitiumModule:
{
  name = "technitium-deployment";
  globalTimeout = 300;

  nodes.server =
    { pkgs, lib, ... }:
    {
      imports = [ technitiumModule ];
      environment.systemPackages = [ pkgs.dig pkgs.jq ];

      services.technitium-dns-server = {
        enable = true;
        openFirewall = true;
        firewallTCPPorts = [ 53 ];
        settings = {
          web.httpPort = lib.mkDefault 5380;
          dns.tsigKeys."deployment.test" = {
            algorithm = "hmac-sha256";
            secret.file = "/run/credentials/technitium-dns-server.service/tsig";
          };
          zones."managed.test".type = "Primary";
        };
      };

      specialisation.changed.configuration.services.technitium-dns-server.settings.web.httpPort =
        lib.mkForce 5381;

      systemd.services.test-credential = {
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          RuntimeDirectory = "test-credential";
          UMask = "0077";
        };
        script = ''
          ${lib.getExe pkgs.openssl} rand -base64 32 | tr -d '\n' > /run/test-credential/tsig
        '';
      };

      systemd.services.technitium-dns-server = {
        requires = [ "test-credential.service" ];
        after = [ "test-credential.service" ];
        serviceConfig.LoadCredential = "tsig:/run/test-credential/tsig";
      };
    };

  nodes.client = { pkgs, ... }: {
    environment.systemPackages = [ pkgs.dig ];
  };

  testScript = ''
    service = "technitium-dns-server.service"
    start_all()
    server.wait_for_unit(service)
    server.wait_for_open_port(5380)
    for transport in ("+notcp +ignore", "+tcp"):
        client.wait_until_succeeds(f"dig @server managed.test SOA {transport} +short | grep -q .")

    # The secret is generated at boot. Verify the loaded key with a signed DNS query.
    server.succeed(
        "key=$(mktemp); chmod 600 \"$key\"; "
        "trap 'rm -f \"$key\"' EXIT; "
        "printf 'key \"deployment.test\" { algorithm hmac-sha256; secret \"%s\"; };\\n' "
        "\"$(cat /run/test-credential/tsig)\" > \"$key\"; "
        "dig -k \"$key\" @127.0.0.1 managed.test SOA | grep -q 'status: NOERROR'"
    )

    # Create a zone outside the manifest and verify that it survives the switch and reboot.
    server.succeed(
        "token=$(curl -fsS 'http://localhost:5380/api/user/login?user=admin&pass=admin' "
        "| jq -er .token); "
        "curl -fsS -H \"Authorization: Bearer $token\" "
        "'http://localhost:5380/api/zones/create?zone=persisted.test&type=Primary' "
        "| jq -e '.status == \"ok\"'"
    )
    client.wait_until_succeeds("dig @server persisted.test SOA +short | grep -q .")
    server.succeed("/run/current-system/specialisation/changed/bin/switch-to-configuration test")
    server.wait_for_open_port(5381)
    server.fail("curl -fsS --max-time 2 http://localhost:5380/")
    client.wait_until_succeeds("dig @server persisted.test SOA +short | grep -q .")
    server.shutdown()
    server.start()
    server.wait_for_unit(service)
    server.wait_for_open_port(5380)
    client.wait_until_succeeds("dig @server persisted.test SOA +short | grep -q .")
  '';
}
