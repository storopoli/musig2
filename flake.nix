{
  description = "Haskell MuSig2 Library";

  inputs = {
    # Like the ppad flakes (and git-hooks.nix) we track nixpkgs-unstable: it is
    # the channel Hydra gates on both Linux and Darwin, and Dependabot keeps the
    # lock fresh without a manual branch switch every release.
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Keep the ppad stack pinned to Hackage releases: nixpkgs still carries
    # ppad-secp256k1 0.5.4 / ppad-fixed 0.1.3 (below our bounds) and marks
    # ppad-sha256 / ppad-sha512 broken.
    ppad-secp256k1-src = {
      url = "https://hackage.haskell.org/package/ppad-secp256k1-0.5.11/ppad-secp256k1-0.5.11.tar.gz";
      flake = false;
    };
    ppad-fixed-src = {
      url = "https://hackage.haskell.org/package/ppad-fixed-0.2.2/ppad-fixed-0.2.2.tar.gz";
      flake = false;
    };
    ppad-base16-src = {
      url = "https://hackage.haskell.org/package/ppad-base16-0.3.1/ppad-base16-0.3.1.tar.gz";
      flake = false;
    };
    ppad-sha256-src = {
      url = "https://hackage.haskell.org/package/ppad-sha256-0.3.7/ppad-sha256-0.3.7.tar.gz";
      flake = false;
    };
    ppad-sha512-src = {
      url = "https://hackage.haskell.org/package/ppad-sha512-0.2.6/ppad-sha512-0.2.6.tar.gz";
      flake = false;
    };
    ppad-hmac-drbg-src = {
      url = "https://hackage.haskell.org/package/ppad-hmac-drbg-0.3.1/ppad-hmac-drbg-0.3.1.tar.gz";
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
      ppad-sha512-src,
      ppad-hmac-drbg-src,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        lib = "musig2";

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;
        # GHC 9.10 is nixpkgs' default GHC and our lowest supported version.
        hpkgs = pkgs.haskell.packages.ghc910.extend (
          new: old: {
            ${lib} = new.callCabal2nix lib ./. { };
            # tests are broken somehow in these deps
            ppad-sha512 = hlib.dontCheck (new.callCabal2nix "ppad-sha512" ppad-sha512-src { });
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
            pkgs.llvmPackages.llvm
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
              nixfmt.enable = true;
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
