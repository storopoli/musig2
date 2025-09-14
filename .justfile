
alias b := build
alias l := lint
alias t := test
alias fmt := format

default:
    just --list

# Build all projects
build:
    cabal build all

# Lint with `hlint`
lint:
    hlint .

# Run tests
test:
    cabal test

# Clean build artifacts
clean:
    cabal clean

# Install dependencies
deps:
    cabal build --dependencies-only all

# Instantiate a `ghci` REPL for the project
repl:
    cabal repl musig2

# Format workspace
format: format-hs format-cabal format-nix

# Format all Haskell files (if `fourmolu` is installed)
format-hs:
    #!/usr/bin/env bash
    if command -v fourmolu &> /dev/null; then
        fourmolu -i lib
        fourmolu -i test
        fourmolu -i bench
    else
        echo "fourmolu not installed, skipping format"
    fi

# Format all Cabal files (if `cabal-fmt` is installed)
format-cabal:
    #!/usr/bin/env bash
    if command -v cabal-fmt &> /dev/null; then
        cabal-fmt -i musig2.cabal
    else
        echo "cabal-fmt not installed, skipping format"
    fi

# Format all Nix files (if `nixfmt-rfc-style` is installed)
format-nix:
    #!/usr/bin/env bash
    if command -v nixfmt &> /dev/null; then
        nixfmt flake.nix
    else
        echo "nixfmt not installed, skipping format"
    fi
