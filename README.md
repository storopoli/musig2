# MuSig2 Haskell Library

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```console
$ nix develop
```

Then do e.g.:

```console
$ cabal repl musig2
```

to get a REPL for the main library.

[musig2]: https://eprint.iacr.org/2020/1261
[bip327]: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
