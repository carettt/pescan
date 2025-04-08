{
  description = "static analysis tool for PE files via API import analysis";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, fenix, naersk, ... }: let
    buildSystem = "x86_64-linux";
    hostSystem = "x86_64-w64-mingw32";
    rustTarget = "x86_64-pc-windows-gnu";

    pkgs = nixpkgs.legacyPackages.${buildSystem};
    hostPkgs = pkgs.pkgsCross.mingwW64;

    toolchain = with fenix.packages.${buildSystem}; combine [
      stable.minimalToolchain
      targets.${rustTarget}.stable.rust-std
    ];
    naerskOverride = naersk.lib.${buildSystem}.override {
      cargo = toolchain;
      rustc = toolchain;
    };
  in {
    devShells.${buildSystem}.default = pkgs.mkShell (let
      toolchain = fenix.packages.${buildSystem}.stable.defaultToolchain;
    in {
      nativeBuildInputs = [
        toolchain
        pkgs.openssl
        pkgs.pkg-config
      ];

      shellHook = ''
        ${pkgs.cowsay}/bin/cowsay "entered dev env!" | ${pkgs.lolcat}/bin/lolcat -F 0.5
      '';
    });

    packages = {
      ${buildSystem} = rec {
        default = naerskOverride.buildPackage {
          src = ./.;
          strictDeps = true;
        };

        dockerImage = pkgs.dockerTools.buildLayeredImage {
          name = "pescan";
          tag = "latest";
          created = "2025-04-06";

          contents = [ default pkgs.cacert ];

          config= {
            Env = [ "PESCAN_DOCKER=true" ];
            Entrypoint = [ "${default}/bin/pescan" ];
          };
        };
      };

      ${hostSystem}.default = naerskOverride.buildPackage {
        src = ./.;
        strictDeps = true;

        depsBuildBuild = [
          hostPkgs.stdenv.cc
          hostPkgs.windows.pthreads
        ];

        CARGO_BUILD_TARGET = "x86_64-pc-windows-gnu";
      };
    };
  };
}
