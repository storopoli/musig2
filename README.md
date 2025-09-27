# musig2

[![](https://img.shields.io/hackage/v/musig2?color=blue)](https://hackage.haskell.org/package/musig2)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-musig2-lightblue)](https://hackage-content.haskell.org/package/musig2/docs/Crypto-Curve-Secp256k1-MuSig2.html)

A pure Haskell implementation of [BIP-0327][bip327] [MuSig2 multi-signature
scheme][musig2] on [secp256k1][ppad-secp256k1]. The library implements partial
signatures with tweak support following best practices and guidelines
from [BIP-0327][bip327].

## Usage

A sample GHCi session:

```haskell
> -- pragmas and b16 import for illustration only; not required
> :set -XOverloadedStrings
> :set -XBangPatterns
> import qualified Data.ByteString.Base16 as B16
>
> -- import qualified
> import qualified Crypto.Curve.Secp256k1.MuSig2 as MuSig2
> import qualified Crypto.Curve.Secp256k1 as Secp256k1
>
> -- secret keys for a 2-of-2 multisig
> let sec1 = MuSig2.SecKey 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
> let sec2 = MuSig2.SecKey 0x68E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
>
> -- derive public keys
> let pub1 = Secp256k1.derive_pub 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
> let pub2 = Secp256k1.derive_pub 0x68E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
> let pubkeys = [pub1, pub2]
>
> -- create key aggregation context
> let keyagg_ctx = MuSig2.mkKeyAggContext pubkeys Nothing
> let agg_pk = MuSig2.aggregatedPubkey keyagg_ctx
>
> -- message to sign
> let msg = "i approve of this message"
>
> -- generate nonces for each signer
> let params1 = MuSig2.defaultSecNonceGenParams pub1
> let params2 = MuSig2.defaultSecNonceGenParams pub2
> secnonce1 <- MuSig2.secNonceGen params1
> secnonce2 <- MuSig2.secNonceGen params2
> let pubnonce1 = MuSig2.publicNonce secnonce1
> let pubnonce2 = MuSig2.publicNonce secnonce2
> let pubnonces = [pubnonce1, pubnonce2]
>
> -- aggregate nonces and create session context
> let Just aggnonce = MuSig2.aggNonces pubnonces
> let session_ctx = MuSig2.mkSessionContext aggnonce pubkeys [] msg
>
> -- each signer creates a partial signature
> let psig1 = MuSig2.sign secnonce1 sec1 session_ctx
> let psig2 = MuSig2.sign secnonce2 sec2 session_ctx
> let psigs = [psig1, psig2]
>
> -- aggregate partial signatures into final signature
> let final_sig = MuSig2.aggPartials psigs session_ctx
>
> -- verify the aggregated signature
> Secp256k1.verify_schnorr msg agg_pk final_sig
True
```

## Documentation

Haddocks (API documentation, etc.) are hosted at [hackage][hackage].

## Security

`musig2` passes all test vectors specified in the [BIP-0327][bip327],
while also checking for key properties using [`QuickCheck`][quickcheck].
All elliptic curve and modular arithmetic operations are deferred to
the [`ppad-secp256k1`][ppad-secp256k1] package.

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
[ppad-secp256k1]: https://github.com/ppad-tech/secp256k1
[hackage]: https://hackage.haskell.org/package/musig2
[quickcheck]: https://hackage.haskell.org/package/QuickCheck
[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
