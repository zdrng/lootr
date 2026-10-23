{
  description = "lootr - show which secrets and credentials the current user can reach";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  # Official Rust release binaries (hash-pinned by flake.lock) with the
  # standard libraries of the release targets. Used only by the `release`
  # shell; development uses nixpkgs' toolchain.
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            }
          )
        );

      # The release compiler is pinned explicitly (not "latest"), so a
      # flake.lock update cannot change release binaries unnoticed.
      releaseRust = "1.98.1";
      releaseTargets = [
        "x86_64-unknown-linux-musl"
        "aarch64-unknown-linux-musl"
        "x86_64-apple-darwin"
        "aarch64-apple-darwin"
      ];
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.rust-analyzer
            pkgs.cargo-deny
            pkgs.cargo-audit
            pkgs.cargo-geiger
            pkgs.cargo-fuzz
            pkgs.cargo-vet
            pkgs.git
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];

          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };

        # Release builds (scripts/release.sh, .github/workflows/release.yml).
        # Linux musl binaries are compiled and linked by zig (cargo-zigbuild):
        # static, for both architectures, from any host. macOS binaries are
        # linked by the system's /usr/bin/cc (Xcode), so they only reference
        # system libraries.
        release = pkgs.mkShellNoCC {
          packages = [
            (pkgs.rust-bin.stable.${releaseRust}.minimal.override { targets = releaseTargets; })
            pkgs.cargo-zigbuild
            pkgs.zig
            pkgs.cargo-cyclonedx
            pkgs.coreutils
            pkgs.gnutar
            pkgs.gzip
            pkgs.git
          ];
        };
      });

      packages = forAllSystems (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "lootr";
          version = (pkgs.lib.importTOML ./Cargo.toml).package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          # The fixture snapshots contain the absolute path of the developer
          # checkout, which differs inside the Nix sandbox.
          checkFlags = [ "--skip=every_test_environment_matches_its_expected_report" ];
          meta.mainProgram = "lootr";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
