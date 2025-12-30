{
  description = "Haskell MuSig2 Library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    git-hooks.url = "github:cachix/git-hooks.nix";

    # TODO: remove these once ppad-secp256k1 0.5.0+ is released in a stable Nix release, probably 26.05.
    ppad-secp256k1-src = {
      url = "https://hackage.haskell.org/package/ppad-secp256k1-0.5.2/ppad-secp256k1-0.5.2.tar.gz";
      flake = false;
    };
    ppad-fixed-src = {
      url = "https://hackage.haskell.org/package/ppad-fixed-0.1.3/ppad-fixed-0.1.3.tar.gz";
      flake = false;
    };
    ppad-base16-src = {
      url = "https://hackage.haskell.org/package/ppad-base16-0.2.1/ppad-base16-0.2.1.tar.gz";
      flake = false;
    };
    ppad-sha256-src = {
      url = "https://hackage.haskell.org/package/ppad-sha256-0.2.4/ppad-sha256-0.2.4.tar.gz";
      flake = false;
    };
    ppad-hmac-drbg-src = {
      url = "https://hackage.haskell.org/package/ppad-hmac-drbg-0.1.3/ppad-hmac-drbg-0.1.3.tar.gz";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      git-hooks,
      ppad-secp256k1-src,
      ppad-fixed-src,
      ppad-base16-src,
      ppad-sha256-src,
      ppad-hmac-drbg-src,
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
        # GHC 9.10.3 is Nix 25.11's default
        hpkgs = pkgs.haskell.packages.ghc9103.extend (
          new: old: {
            ${lib} = new.callCabal2nix lib ./. { };
            # tests are broken somehow in these deps
            ppad-sha512 = hlib.dontCheck old.ppad-sha512;
            ppad-sha256 = hlib.dontCheck (new.callCabal2nix "ppad-sha256" ppad-sha256-src { });
            ppad-hmac-drbg = hlib.dontCheck (new.callCabal2nix "ppad-hmac-drbg" ppad-hmac-drbg-src { });
            ppad-fixed = hlib.dontCheck (new.callCabal2nix "ppad-fixed" ppad-fixed-src { });
            ppad-base16 = hlib.dontCheck (new.callCabal2nix "ppad-base16" ppad-base16-src { });
            ppad-secp256k1 = hlib.dontCheck (new.callCabal2nix "ppad-secp256k1" ppad-secp256k1-src { });
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
              cabal2nix.enable = true;
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
