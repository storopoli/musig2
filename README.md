# musig2

[![](https://img.shields.io/hackage/v/musig2?color=blue)](https://hackage.haskell.org/package/musig2)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-musig2-lightblue)](https://hackage-content.haskell.org/package/musig2/docs/Crypto-Curve-Secp256k1-MuSig2.html)

A pure Haskell implementation of [BIP-0327][bip327] [MuSig2 multi-signature
scheme][musig2] on [secp256k1][ppad-secp256k1]. The library implements partial
signatures with tweak support following best practices and guidelines
from [BIP-0327][bip327].

## Usage

Two signers produce one BIP-340 signature for their aggregate key. Public
values travel between signers as bytes (`encode`/`decode`, in the BIP-0327
formats); decoding validates them.

<!-- example start -->
```haskell
{-# LANGUAGE OverloadedStrings #-}

import Control.Exception (Exception, throwIO)
import qualified Crypto.Curve.Secp256k1.MuSig2 as MuSig2
import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NE

-- | Throws the error of a 'Left'.
orThrow :: (Exception e) => Either e a -> IO a
orThrow = either throwIO pure

-- | Two signers sign a message; returns whether the signature verifies.
example :: IO Bool
example = do
  -- Each signer has a secret key and publishes its public key.
  -- (Fixed keys for the example only: never hard-code real keys.)
  sk1 <- orThrow (MuSig2.secKeyFromBytes (BS.replicate 32 0x11))
  sk2 <- orThrow (MuSig2.secKeyFromBytes (BS.replicate 32 0x22))
  let pk1 = MuSig2.secKeyPubKey sk1
      pk2 = MuSig2.secKeyPubKey sk2

  -- Everyone aggregates the same list of public keys, here sorted.
  keyAggCtx <- orThrow (MuSig2.keyAgg (MuSig2.keySort (pk1 :| [pk2])))
  let aggKey = MuSig2.aggXOnlyPubKey keyAggCtx
      msg = "i approve of this message"

  -- Each signer generates a fresh nonce and publishes the public part.
  (secNonce1, pubNonce1) <- MuSig2.nonceGen pk1 MuSig2.noNonceInputs >>= orThrow
  (secNonce2, pubNonce2) <- MuSig2.nonceGen pk2 MuSig2.noNonceInputs >>= orThrow

  -- Values travel as bytes; decoding validates them.
  received <- orThrow (MuSig2.decode (MuSig2.encode pubNonce2))

  -- Everyone aggregates the public nonces and opens the same session.
  let session = MuSig2.newSession keyAggCtx (MuSig2.nonceAgg (pubNonce1 :| [received])) msg

  -- Each signer signs once with its nonce and publishes its partial signature.
  -- 'sign' consumes the secret nonce: signing again with it fails.
  psig1 <- MuSig2.sign secNonce1 sk1 session >>= orThrow
  psig2 <- MuSig2.sign secNonce2 sk2 session >>= orThrow

  -- The aggregator checks each partial signature, then aggregates them.
  let valid =
        MuSig2.partialSigVerify session pk1 pubNonce1 psig1
          && MuSig2.partialSigVerify session pk2 pubNonce2 psig2
      signature = MuSig2.partialSigAgg session (psig1 :| [psig2])

  -- The result is an ordinary BIP-340 signature for the aggregate key.
  pure (valid && MuSig2.verify aggKey msg signature)
```
<!-- example end -->

A Taproot output key is the aggregate key tweaked with `applyTaprootTweak`;
tweaks live in the key aggregation context only, and sessions are opened on
the tweaked context:

<!-- taproot start -->
```haskell
-- | Three signers spend a Taproot output by key path.
taprootExample :: IO Bool
taprootExample = do
  sks <- traverse (orThrow . MuSig2.secKeyFromBytes . BS.replicate 32) (0x33 :| [0x44, 0x55])
  let pks = fmap MuSig2.secKeyPubKey sks

  -- The internal key is the aggregate key; the output key commits to the
  -- script tree's merkle root ('Nothing' for a key-path-only output, BIP-86).
  internal <- orThrow (MuSig2.keyAgg (MuSig2.keySort pks))
  output <- orThrow (MuSig2.applyTaprootTweak (Just (BS.replicate 32 0xAB)) internal)
  let outputKey = MuSig2.aggXOnlyPubKey output
      sighash = BS.replicate 32 0x01

  -- Binding the nonces to the key and message adds protection against bad randomness.
  let inputs sk =
        MuSig2.noNonceInputs
          { MuSig2.nonceSecKey = Just sk
          , MuSig2.nonceAggPubKey = Just outputKey
          , MuSig2.nonceMessage = Just sighash
          }
  nonces <- traverse (\sk -> MuSig2.nonceGen (MuSig2.secKeyPubKey sk) (inputs sk) >>= orThrow) sks

  -- Sessions are opened on the tweaked context: the tweak lives in the context only.
  let session = MuSig2.newSession output (MuSig2.nonceAgg (fmap snd nonces)) sighash
  psigs <- traverse (\(sk, (secNonce, _)) -> MuSig2.sign secNonce sk session >>= orThrow) (NE.zip sks nonces)
  let signature = MuSig2.partialSigAgg session psigs
  pure (MuSig2.verify outputKey sighash signature)
```
<!-- taproot end -->

Both examples are compiled and run by the test suite (`test/Example.hs`),
which also checks that this README shows them verbatim.

Upgrading from 0.2? The [CHANGELOG](CHANGELOG) lists every renamed and
removed function.

## Documentation

Haddocks (API documentation, etc.) are hosted at [hackage][hackage].

## Security

Read the security considerations in the
[module documentation][haddock] before using the library. Secret nonces are
one-shot: `sign` atomically consumes the nonce (and zero-fills its buffer)
before anything else, so a second `sign` with the same nonce, from any copy
or thread, fails with `SecNonceAlreadyUsed`. The
`Crypto.Curve.Secp256k1.MuSig2.Unsafe` module holds the escape hatches this
cannot cover (caller-supplied randomness, counters, exporting secret nonces).
Arithmetic on secret keys and nonces is constant-time (fixed-width
Montgomery arithmetic from `ppad-fixed`); the module documentation lists the
remaining caveats.

The API is hard to misuse by construction: every value of an exported type is
valid (decoders and smart constructors check points, scalar ranges and
lengths), secret keys and nonces have no `Show`, `Eq`, `Ord` or encoding,
and errors carry no secrets.

The test suite runs the official [BIP-0327][bip327] test vectors, loaded
from the upstream JSON files, with exact-output assertions; invalid-encoding
vectors check that decoding fails for exactly the contribution the vector
blames, including the `DeterministicSign` vectors. [`QuickCheck`][quickcheck] properties run complete
multi-signer sessions with random tweaks (plain, x-only and Taproot) and check
the final signature with BIP-340 verification.
Elliptic curve operations are done by the
[`ppad-secp256k1`][ppad-secp256k1] package.

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
[haddock]: https://hackage-content.haskell.org/package/musig2/docs/Crypto-Curve-Secp256k1-MuSig2.html
[quickcheck]: https://hackage.haskell.org/package/QuickCheck
[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
