{
  description = "build halo2 backend";

  inputs = {
    nixpkgs = {
      url = "github:NixOS/nixpkgs/nixos-22.11";
    };

    flake-utils = {
      url = "github:numtide/flake-utils";
    };

    inputs.flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };

    crane = {
      url = "github:ipetkov/crane";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
        flake-compat.follows = "flake-compat";
        rust-overlay.follows = "rust-overlay";
      };
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane, ... } @ inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rust_toolchain = pkgs.rust-bin.nightly."2022-10-28".default.override {
          extensions = [ "rust-src" ];
          targets = [ "wasm32-unknown-unknown" ];
        };

        crane_lib = (crane.mkLib pkgs).overrideToolchain rust_toolchain;

        common_args = {
          src = crane_lib.cleanCargoSource (crane_lib.path ./.);
        };

        noir_halo2_pse_naitive_args = common_args // {
          pname = "noir-halo2-backend-pse-native";
        };

        noir_halo2_pse_naitive_cargo_artifacts = crane_lib.buildDepsOnly noir_halo2_pse_naitive_args;

        noir_halo2_pse_naitive = crane_lib.buildPackage (noir_halo2_pse_naitive_args // {

          cargoArtifacts = noir_halo2_pse_naitive_cargo_artifacts;

          doCheck = false;
        });
      in
      {
        checks = {
          cargo-clippy = crane_lib.cargoClippy (noir_halo2_pse_naitive_args // {
            inherit noir_halo2_pse_naitive_cargo_artifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          cargo-fmt = crane_lib.cargoFmt (common_args);

          cargo-nextest = crane_lib.cargoNextest (noir_halo2_pse_naitive_args // {
            inherit noir_halo2_pse_naitive_cargo_artifacts;
            package = "noir_halo2_backend_pse";
            test-threads = 1;
          });

          packages = {
            default = noir_halo2_pse_naitive;
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = builtins.attrValues self.checks.${system};

            nativeBuildInputs = with pkgs; [
              cargo
              rustc
            ];
          };
        };
      });
}
