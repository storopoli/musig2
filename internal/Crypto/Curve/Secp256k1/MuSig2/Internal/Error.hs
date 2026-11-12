{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Error
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

Error types. None of them carries secret data.

Not part of the public API; "Crypto.Curve.Secp256k1.MuSig2" re-exports them.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Error (
  DecodeError (..),
  KeyAggError (..),
  NonceGenError (..),
  SignError (..),
) where

import Control.DeepSeq (NFData (..), rwhnf)
import Control.Exception (Exception)

-- | Why a byte string (or a @ppad-secp256k1@ point) is not a valid value of the requested type.
data DecodeError
  = -- | The input has the wrong length.
    InvalidLength
      { expectedLength :: !Int
      -- ^ Length of the encoding, in bytes.
      , actualLength :: !Int
      -- ^ Length of the input, in bytes.
      }
  | {- | Not the encoding of a point on the curve: unknown prefix byte, an
    x-coordinate that is not below the field size or not on the curve, or
    (for 'Crypto.Curve.Secp256k1.MuSig2.pubKeyFromPoint') a point that does
    not satisfy the curve equation.
    -}
    InvalidPoint
  | -- | The point at infinity where a finite point is required.
    PointAtInfinity
  | -- | A scalar that is not below the group order \(n\).
    ScalarOutOfRange
  | -- | A scalar that must be non-zero (a secret key or nonce) is zero.
    ScalarZero
  deriving (Eq, Show)

instance Exception DecodeError

instance NFData DecodeError where
  rnf = rwhnf

-- | Key aggregation and tweaking failures.
data KeyAggError
  = -- | More than \(2^{32} - 1\) public keys.
    TooManyPublicKeys
  | -- | The aggregate public key is the point at infinity (the keys cancel out).
    AggPubKeyAtInfinity
  | -- | Applying a tweak gave the point at infinity.
    TweakResultAtInfinity
  | -- | The BIP-341 Taproot tweak hash is not below the group order (negligible probability).
    TaprootTweakOutOfRange
  | -- | The Taproot merkle root is not 32 bytes; carries the actual length.
    InvalidMerkleRootLength !Int
  deriving (Eq, Show)

instance Exception KeyAggError

instance NFData KeyAggError where
  rnf = rwhnf

-- | Invalid inputs to nonce generation.
data NonceGenError
  = -- | The optional secret key does not belong to the signer's public key.
    NonceSecKeyMismatch
  | -- | The extra input is longer than \(2^{32} - 1\) bytes.
    NonceExtraInputTooLong
  | {- | The message is longer than \(2^{64} - 1\) bytes (BIP-327's limit; a
    'Data.ByteString.ByteString' cannot be that long on 64-bit platforms).
    -}
    NonceMessageTooLong
  deriving (Eq, Show)

instance Exception NonceGenError

instance NFData NonceGenError where
  rnf = rwhnf

{- | Signing failures. After any of them, discard the secret nonce: never try
to sign again with it.
-}
data SignError
  = -- | The secret nonce was generated for a different public key than the secret key's.
    SecNonceKeyMismatch
  | -- | The secret key's public key is not one of the session's public keys.
    SignerNotInSession
  | {- | The partial signature did not pass verification before being returned
    (a bug or a fault, e.g. a bit flip). Never retry with the same nonce.
    -}
    SelfVerificationFailed
  deriving (Eq, Show)

instance Exception SignError

instance NFData SignError where
  rnf = rwhnf
