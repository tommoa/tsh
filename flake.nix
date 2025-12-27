{
  description = "tsh - a Zig project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    zls.url = "github:zigtools/zls";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, zig-overlay, zls, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ zig-overlay.overlays.default ];
        };

        # Use master Zig since 0.15.2 is very recent
        zig = pkgs.zigpkgs.master;

      in {
        packages.default = pkgs.stdenvNoCC.mkDerivation {
          pname = "tsh";
          version = "0.0.0";
          src = ./.;

          nativeBuildInputs = [ zig ];

          dontConfigure = true;
          dontInstall = true;

          buildPhase = ''
            mkdir -p .cache
            zig build --cache-dir $(pwd)/.zig-cache --global-cache-dir $(pwd)/.cache -Doptimize=ReleaseSafe --prefix $out
          '';
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            zig
            zls.packages.${system}.default
          ];
        };
      });
}
