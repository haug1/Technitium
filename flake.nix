{
  description = "Technitium DNS Server packages and development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      forLinux = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
    in
    {
      packages = forLinux (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          technitium-dns-server = pkgs.technitium-dns-server.overrideAttrs (previous: {
            src = self;
            # The pinned Nixpkgs package provides the upstream dependencies.
            buildInputs =
              previous.buildInputs
              ++ map pkgs.dotnetCorePackages.fetchNupkg (nixpkgs.lib.importJSON ./nix/manifest-nuget-deps.json);
          });
        in
        {
          inherit technitium-dns-server;
          default = technitium-dns-server;
        }
      );

      nixosModules.default = import ./nix/module.nix self;

      checks.x86_64-linux.nixos-deployment =
        nixpkgs.legacyPackages.x86_64-linux.testers.runNixOSTest (
          import ./nix/deployment-test.nix self.nixosModules.default
        );

      devShells = forLinux (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.dotnetCorePackages.sdk_10_0
              pkgs.dig
              pkgs.git
            ];

            shellHook = ''
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.libmsquic ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            '';
          };
        }
      );
    };
}
