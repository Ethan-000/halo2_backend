{
  description = "build halo2 backend";

  inputs = {
    nixpkgs = {
      url = "github:NixOS/nixpkgs/nixos-22.11";
    };

    flake-utils = {
      url = "github:numtide/flake-utils";
    };

    flake-compat = {
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

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rust_toolchain = pkgs.rust-bin.nightly."2022-10-28".default.override {
          extensions = [ "rust-src" ];
          targets = [ "wasm32-unknown-unknown" ]
            ++ pkgs.lib.optional (pkgs.hostPlatform.isx86_64 && pkgs.hostPlatform.isLinux) "x86_64-unknown-linux-gnu"
            ++ pkgs.lib.optional (pkgs.hostPlatform.isAarch64 && pkgs.hostPlatform.isLinux) "aarch64-unknown-linux-gnu"
            ++ pkgs.lib.optional (pkgs.hostPlatform.isx86_64 && pkgs.hostPlatform.isDarwin) "x86_64-apple-darwin"
            ++ pkgs.lib.optional (pkgs.hostPlatform.isAarch64 && pkgs.hostPlatform.isDarwin) "aarch64-apple-darwin";
        };

        crane_lib = (crane.mkLib pkgs).overrideToolchain rust_toolchain;

        common_args = {
          src = crane_lib.cleanCargoSource (crane_lib.path ./.);
        };

        extraBuildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.libiconv
          pkgs.darwin.apple_sdk.frameworks.Security
        ];

        noir_halo2_pse_naitive_args = common_args // {
          pname = "noir_halo2_backend_pse_naitive";

          buildInputs = [] ++ extraBuildInputs;
        };

        noir_halo2_pse_wasm_args = common_args // {
          pname = "noir_halo2_backend_pse_wasm";

          cargoExtraArgs = "--target wasm32-unknown-unknown";

          buildInputs = [] ++ extraBuildInputs;
        };

        noir_halo2_pse_naitive_cargo_artifacts = crane_lib.buildDepsOnly noir_halo2_pse_naitive_args;
        noir_halo2_pse_wasm_cargo_artifacts = crane_lib.buildDepsOnly noir_halo2_pse_wasm_args;

        noir_halo2_pse_naitive = crane_lib.buildPackage (noir_halo2_pse_naitive_args // {

          cargoArtifacts = noir_halo2_pse_naitive_cargo_artifacts;

          doCheck = false;
        });

        noir_halo2_pse_wasm = crane_lib.buildPackage (noir_halo2_pse_wasm_args // {

          cargoArtifacts = noir_halo2_pse_wasm_cargo_artifacts;

          doCheck = false;
        });
      in
      {
        checks = {
          cargo-fmt = crane_lib.cargoFmt (noir_halo2_pse_naitive_args);
          cargo-clippy = crane_lib.cargoClippy (noir_halo2_pse_naitive_args // {
            cargoArtifacts = noir_halo2_pse_naitive_cargo_artifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });
        };

        packages = {
          default = noir_halo2_pse_naitive;
          wasm = noir_halo2_pse_wasm;
        };

        devShells.default = pkgs.mkShell ( {
          inputsFrom = builtins.attrValues self.checks.${system};

          nativeBuildInputs = with pkgs; [
            git
            cargo
            rustc
            rust_toolchain
          ];
        });
      });
}
