{- |
Module: Crypto.Curve.Secp256k1.MuSig2
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

[BIP-327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
[MuSig2](https://eprint.iacr.org/2020/1261) multi-signatures on secp256k1:
\(n\) signers produce one ordinary
[BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
Schnorr signature for their aggregate public key, in two rounds.

1. Key aggregation: everyone runs 'keyAgg' on the same list of public keys
   (optionally sorted with 'keySort') and applies the same tweaks, e.g.
   'applyTaprootTweak'.
2. Round one: each signer runs 'nonceGen' and sends its t'PubNonce' to the
   others (or to a coordinator), who aggregate them with 'nonceAgg'.
3. Round two: everyone opens the same 'Session' with 'newSession'; each signer
   runs 'sign' once and sends its 'PartialSignature'.
4. The aggregator checks each partial signature with 'partialSigVerify' and
   combines them with 'partialSigAgg'. Anyone can check the result with
   'verify' against 'aggXOnlyPubKey'.

Values sent between signers are encoded and decoded with 'Encode', in the
BIP-327 byte formats. Decoding validates: every value of a type exported here
is valid by construction.

== Security considerations

* __Use each nonce once.__ Signing twice with the same t'SecNonce', in any
  sessions, lets the other signers compute your secret key. t'SecNonce' cannot
  be encoded, shown, compared or rebuilt from its parts, and 'nonceGen'
  always draws fresh randomness, but this version does not stop you from
  keeping a t'SecNonce' value and passing it to 'sign' twice: 'sign' is pure.
  Generate a new nonce for every session, drop it after 'sign', and never
  sign again with a nonce after a 'SignError'.

* __Verify partial signatures.__ 'partialSigAgg' does not check its inputs;
  run 'partialSigVerify' on every partial signature you did not make, so a
  wrong one is attributed to its signer instead of producing an invalid
  signature. 'sign' checks its own result.

* __Non-constant-time arithmetic.__ Elliptic curve multiplications involving
  secrets are constant-time (they are done by @ppad-secp256k1@), but the
  scalar arithmetic on secret keys and nonces (e.g. \(k_1 + b k_2\) and
  \(k + e a d\) in 'sign', and the reductions in nonce generation) uses
  Haskell's arbitrary-precision 'Integer', whose running time depends on the
  values. An attacker able to measure timings or caches on the same machine
  may learn information about secrets.

* __No secret zeroization.__ Secret keys and nonces are not zeroized after
  use: Haskell's garbage collector may copy them and keeps them in memory
  until they are collected.

* __Randomness.__ 'nonceGen' reads 32 bytes from the operating system's
  random number generator (@getrandom@ on Linux, via the @entropy@ package).
  Passing the optional t'NonceInputs' adds protection should it fail.

== Usage

Two signers (this example is compiled and run by the test suite; it needs
the @OverloadedStrings@ language extension):

> import Control.Exception (Exception, throwIO)
> import qualified Crypto.Curve.Secp256k1.MuSig2 as MuSig2
> import qualified Data.ByteString as BS
> import Data.List.NonEmpty (NonEmpty (..))
> import qualified Data.List.NonEmpty as NE

> -- | Throws the error of a 'Left'.
> orThrow :: (Exception e) => Either e a -> IO a
> orThrow = either throwIO pure
>
> -- | Two signers sign a message; returns whether the signature verifies.
> example :: IO Bool
> example = do
>   -- Each signer has a secret key and publishes its public key.
>   -- (Fixed keys for the example only: never hard-code real keys.)
>   sk1 <- orThrow (MuSig2.secKeyFromBytes (BS.replicate 32 0x11))
>   sk2 <- orThrow (MuSig2.secKeyFromBytes (BS.replicate 32 0x22))
>   let pk1 = MuSig2.secKeyPubKey sk1
>       pk2 = MuSig2.secKeyPubKey sk2
>
>   -- Everyone aggregates the same list of public keys, here sorted.
>   keyAggCtx <- orThrow (MuSig2.keyAgg (MuSig2.keySort (pk1 :| [pk2])))
>   let aggKey = MuSig2.aggXOnlyPubKey keyAggCtx
>       msg = "i approve of this message"
>
>   -- Each signer generates a fresh nonce and publishes the public part.
>   (secNonce1, pubNonce1) <- MuSig2.nonceGen pk1 MuSig2.noNonceInputs >>= orThrow
>   (secNonce2, pubNonce2) <- MuSig2.nonceGen pk2 MuSig2.noNonceInputs >>= orThrow
>
>   -- Values travel as bytes; decoding validates them.
>   received <- orThrow (MuSig2.decode (MuSig2.encode pubNonce2))
>
>   -- Everyone aggregates the public nonces and opens the same session.
>   let session = MuSig2.newSession keyAggCtx (MuSig2.nonceAgg (pubNonce1 :| [received])) msg
>
>   -- Each signer signs once with its nonce and publishes its partial signature.
>   -- 'sign' consumes the secret nonce: signing again with it fails.
>   psig1 <- MuSig2.sign secNonce1 sk1 session >>= orThrow
>   psig2 <- MuSig2.sign secNonce2 sk2 session >>= orThrow
>
>   -- The aggregator checks each partial signature, then aggregates them.
>   let valid =
>         MuSig2.partialSigVerify session pk1 pubNonce1 psig1
>           && MuSig2.partialSigVerify session pk2 pubNonce2 psig2
>       signature = MuSig2.partialSigAgg session (psig1 :| [psig2])
>
>   -- The result is an ordinary BIP-340 signature for the aggregate key.
>   pure (valid && MuSig2.verify aggKey msg signature)

== Taproot

A Taproot output key is the aggregate key tweaked with 'applyTaprootTweak':

> -- | Three signers spend a Taproot output by key path.
> taprootExample :: IO Bool
> taprootExample = do
>   sks <- traverse (orThrow . MuSig2.secKeyFromBytes . BS.replicate 32) (0x33 :| [0x44, 0x55])
>   let pks = fmap MuSig2.secKeyPubKey sks
>
>   -- The internal key is the aggregate key; the output key commits to the
>   -- script tree's merkle root ('Nothing' for a key-path-only output, BIP-86).
>   internal <- orThrow (MuSig2.keyAgg (MuSig2.keySort pks))
>   output <- orThrow (MuSig2.applyTaprootTweak (Just (BS.replicate 32 0xAB)) internal)
>   let outputKey = MuSig2.aggXOnlyPubKey output
>       sighash = BS.replicate 32 0x01
>
>   -- Binding the nonces to the key and message adds protection against bad randomness.
>   let inputs sk =
>         MuSig2.noNonceInputs
>           { MuSig2.nonceSecKey = Just sk
>           , MuSig2.nonceAggPubKey = Just outputKey
>           , MuSig2.nonceMessage = Just sighash
>           }
>   nonces <- traverse (\sk -> MuSig2.nonceGen (MuSig2.secKeyPubKey sk) (inputs sk) >>= orThrow) sks
>
>   -- Sessions are opened on the tweaked context: the tweak lives in the context only.
>   let session = MuSig2.newSession output (MuSig2.nonceAgg (fmap snd nonces)) sighash
>   psigs <- traverse (\(sk, (secNonce, _)) -> MuSig2.sign secNonce sk session >>= orThrow) (NE.zip sks nonces)
>   let signature = MuSig2.partialSigAgg session psigs
>   pure (MuSig2.verify outputKey sighash signature)
-}
module Crypto.Curve.Secp256k1.MuSig2 (
  -- * Keys
  SecKey,
  secKeyFromBytes,
  secKeyToBytes,
  secKeyPubKey,
  PubKey,
  pubKeyFromPoint,
  pubKeyPoint,
  XOnlyPubKey,
  pubKeyXOnly,

  -- * Encodings
  Encode (..),

  -- * Key aggregation
  KeyAggContext,
  keySort,
  keyAgg,
  aggPubKey,
  aggXOnlyPubKey,
  keyAggPubKeys,
  signerIndex,

  -- ** Tweaks
  Tweak,
  tweakFromBytes,
  applyPlainTweak,
  applyXOnlyTweak,
  applyTaprootTweak,

  -- * Nonces
  SecNonce,
  PubNonce,
  AggNonce,
  NonceInputs (..),
  noNonceInputs,
  nonceGen,
  nonceAgg,

  -- * Signing
  Session,
  newSession,
  sessionKeyAgg,
  PartialSignature,
  sign,
  deterministicSign,
  partialSigVerify,
  partialSigAgg,
  Signature,
  verify,

  -- * Errors
  DecodeError (..),
  KeyAggError (..),
  NonceGenError (..),
  SignError (..),
) where

import Crypto.Curve.Secp256k1.MuSig2.Internal.Error (DecodeError (..), KeyAggError (..), NonceGenError (..), SignError (..))
import Crypto.Curve.Secp256k1.MuSig2.Internal.KeyAgg (
  KeyAggContext,
  aggPubKey,
  aggXOnlyPubKey,
  applyPlainTweak,
  applyTaprootTweak,
  applyXOnlyTweak,
  keyAgg,
  keyAggPubKeys,
  keySort,
  signerIndex,
 )
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (NonceInputs (..), SecNonce, noNonceInputs, nonceAgg, nonceGen)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Session (Session, deterministicSign, newSession, partialSigAgg, partialSigVerify, sessionKeyAgg, sign, verify)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Types (
  AggNonce,
  Encode (..),
  PartialSignature,
  PubKey,
  PubNonce,
  SecKey,
  Signature,
  Tweak,
  XOnlyPubKey,
  pubKeyFromPoint,
  pubKeyPoint,
  pubKeyXOnly,
  secKeyFromBytes,
  secKeyPubKey,
  secKeyToBytes,
  tweakFromBytes,
 )
