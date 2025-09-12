
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

# Format all Haskell files (if `fourmolu` is installed)
format:
    #!/usr/bin/env bash
    if command -v fourmolu &> /dev/null; then
        fourmolu -i lib
        fourmolu -i test
        fourmolu -i bench
    else
        echo "fourmolu not installed, skipping format"
    fi

