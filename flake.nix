{
  description = "rust project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.cargo
            pkgs.rustc
            pkgs.openssl
            pkgs.pkg-config
          ];

          shellHook = ''
            ${pkgs.cowsay}/bin/cowsay "entered dev env!" | ${pkgs.lolcat}/bin/lolcat -F 0.5
          '';
        };

        packages = rec {
          pescan = let
            manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
          in pkgs.rustPlatform.buildRustPackage {
            pname = manifest.name;
            version = manifest.version;
            cargoLock.lockFile = ./Cargo.lock;
            src = pkgs.lib.cleanSource ./.;
          };

          dockerImage = pkgs.dockerTools.buildLayeredImage {
            name = "pescan";
            tag = "latest";
            created = "2025-03-20";

            contents = [
              pescan
            ];

            config.Cmd = [ "/bin/pescan" ];
          };
        };
      });
}
