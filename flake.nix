{
  description = "Haskell MuSig2 Library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    git-hooks.url = "github:cachix/git-hooks.nix";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      git-hooks,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        lib = "musig2";

        pkgs = import nixpkgs {
          inherit system;
          config.allowBroken = true;
        };
        hlib = pkgs.haskell.lib;
        hpkgs = pkgs.haskell.packages.ghc984.extend (
          new: old: {
            ${lib} = new.callCabal2nix lib ./. { };
            # tests are broken somehow in these deps
            ppad-sha512 = hlib.dontCheck old.ppad-sha512;
            ppad-sha256 = hlib.dontCheck old.ppad-sha256;
            ppad-hmac-drbg = hlib.dontCheck old.ppad-hmac-drbg;
            ppad-secp256k1 = hlib.dontCheck old.ppad-secp256k1;
          }
        );

        inherit (pkgs.stdenv) cc;
        inherit (hpkgs) ghc;
        cabal = hpkgs.cabal-install;
      in
      rec {
        packages.default = hpkgs.${lib};

        devShells.default = hpkgs.shellFor {
          packages = p: [
            (hlib.doBenchmark p.${lib})
          ];

          buildInputs = [
            cabal
            cc
            hpkgs.haskell-language-server
            hpkgs.fourmolu
            hpkgs.cabal-fmt
            hpkgs.hlint
            pkgs.just
          ]
          ++ checks.pre-commit-check.enabledPackages;

          inputsFrom = builtins.attrValues self.packages.${system};

          doBenchmark = true;

          shellHook = checks.pre-commit-check.shellHook + ''
            PS1="[${lib}] \w$ "
            echo "entering ${system} shell, using"
            echo "cc:    $(${cc}/bin/cc --version)"
            echo "ghc:   $(${ghc}/bin/ghc --version)"
            echo "cabal: $(${cabal}/bin/cabal --version)"
          '';
        };

        checks = {
          pre-commit-check = git-hooks.lib.${system}.run {
            src = ./.;
            hooks = {
              # Nix
              nixfmt-rfc-style.enable = true;
              statix.enable = true;
              flake-checker = {
                enable = true;
                args = [
                  "--check-outdated"
                  "false" # don't check for nixpkgs
                ];
              };

              # Haskell
              fourmolu.enable = true;
              cabal-fmt.enable = true;
              hlint.enable = true;

              # Tin-foil hat
              zizmor.enable = true;
            };
          };
        };
      }
    );
}
