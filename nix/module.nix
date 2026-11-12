self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.technitium-dns-server;
  json = pkgs.formats.json { };
  manifest = json.generate "technitium.json" ({ schemaVersion = 1; } // cfg.settings);
  executable = lib.getExe cfg.package;
in
{
  options.services.technitium-dns-server.settings = lib.mkOption {
    type = lib.types.attrsOf json.type;
    default = { };
    description = ''
      Technitium startup manifest, validated by the server executable.
      The module supplies schemaVersion 1 by default. Refer to runtime
      files for secrets and keep secret values out of this option.
    '';
  };

  config = lib.mkIf cfg.enable {
    services.technitium-dns-server.package =
      lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.technitium-dns-server;

    systemd.services.technitium-dns-server = {
      restartTriggers = [ manifest ];
      serviceConfig.ExecStart = lib.mkForce "${executable} --stop-if-bind-fails $STATE_DIRECTORY";

      preStart = ''
        cd "$STATE_DIRECTORY"
        candidate="$(mktemp .technitium.XXXXXXXX.json)"
        trap 'rm -f -- "$candidate"' EXIT
        cp -- ${manifest} "$candidate"
        ${executable} config validate "$candidate"
        mv -T -- "$candidate" technitium.json
      '';
    };
  };
}
