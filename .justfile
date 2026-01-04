
alias b := build
alias l := lint
alias t := test
alias fmt := format
alias bench := benchmark

default:
    just --list

# Build all projects
[group('build')]
build:
    cabal build all

# Install dependencies
[group('build')]
deps:
    cabal build --dependencies-only all

# Instantiate a `ghci` REPL for the project
[group('build')]
repl:
    cabal repl musig2

# Clean build artifacts
[group('build')]
clean:
    cabal clean

# Run tests
[group('test')]
test:
    cabal test

# Test documentation coverage and quality
[group('test')]
test-docs:
    #!/usr/bin/env bash
    set -e
    output=$(cabal haddock 2>&1)
    echo "$output"
    if echo "$output" | grep -q "Missing documentation"; then
        echo "❌ Documentation test failed: missing documentation found"
        exit 1
    fi
    if echo "$output" | grep -q " 0% "; then
        echo "❌ Documentation test failed: 0% coverage found"
        exit 1
    fi
    echo "✅ Documentation test passed"

# Lint with `hlint`
[group('lint')]
lint:
    hlint .

# Format workspace
[group('format')]
format: format-hs format-cabal format-nix

# Format all Haskell files (if `fourmolu` is installed)
[group('format')]
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
[group('format')]
format-cabal:
    #!/usr/bin/env bash
    if command -v cabal-fmt &> /dev/null; then
        cabal-fmt -i musig2.cabal
    else
        echo "cabal-fmt not installed, skipping format"
    fi

# Format all Nix files (if `nixfmt-rfc-style` is installed)
[group('format')]
format-nix:
    #!/usr/bin/env bash
    if command -v nixfmt &> /dev/null; then
        nixfmt flake.nix
    else
        echo "nixfmt not installed, skipping format"
    fi

# Builds the documentation with `haddock` and opens in the browser.
[group('docs')]
doc:
    cabal haddock --open

# Publish docs to Hackage
[group('docs')]
publish-docs:
    #!/usr/bin/env sh
    set -e

    dir=$(mktemp -d dist-docs.XXXXXX)
    trap 'rm -r "$dir"' EXIT

    # assumes cabal 2.4 or later
    cabal v2-haddock --builddir="$dir" --haddock-for-hackage --enable-doc

    cabal upload -d --publish $dir/*-docs.tar.gz

# Run benchmarks
[group('benchmark')]
benchmark:
    cabal bench musig2-bench

# Run benchmarks with HTML output
[group('benchmark')]
benchmark-html:
    cabal bench musig2-bench --benchmark-options="--output benchmark_results.html"

# Run specific benchmark group (e.g., just benchmark-group key_aggregation)
[group('benchmark')]
benchmark-group GROUP:
    cabal bench musig2-bench --benchmark-options="-m pattern {{GROUP}}"

# List all available benchmarks
[group('benchmark')]
benchmark-list:
    cabal bench musig2-bench --benchmark-options="-l"
