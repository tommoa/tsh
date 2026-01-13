{
  description = "tsh - a Zig project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    zls.url = "github:zigtools/zls";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      zig-overlay,
      zls,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ zig-overlay.overlays.default ];
        };
        zig = zig-overlay.packages.${system}."0.15.2";
        target =
          if pkgs.stdenv.isLinux then
            "x86_64-linux-musl"
          else if pkgs.stdenv.isDarwin then
            "aarch64-macos"
          else
            "";

      in
      {
        packages.default = pkgs.stdenvNoCC.mkDerivation {
          pname = "tsh";
          version = "0.0.0";
          src = ./.;

          nativeBuildInputs = [ zig ];

          dontConfigure = true;
          dontInstall = true;

          buildPhase = ''
            mkdir -p .cache
            zig build --cache-dir $(pwd)/.zig-cache --global-cache-dir $(pwd)/.cache -Doptimize=ReleaseSafe ${
              if target != "" then "-Dtarget=${target}" else ""
            } --prefix $out
          '';
        };

        devShells.tsh = pkgs.mkShell {
          buildInputs = [
            zig
            zls.packages.${system}.default
          ];
        };
      }
    );
}
