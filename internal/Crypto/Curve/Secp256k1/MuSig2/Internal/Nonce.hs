{-# LANGUAGE BangPatterns #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

BIP-327 @NonceGen@, @NonceAgg@ and the nonce derivation of
@DeterministicSign@, and the one-shot t'SecNonce'.

The representation of t'SecNonce' is private to this module: everything else
reads its public parts through 'secNoncePubKey', 'secNoncePubNonce',
'secNonceAggPubKey' and 'secNonceMessage', and its secret scalars only
through 'claimSecNonce', which consumes it.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (
  -- * Secret nonces
  SecNonce,
  secNoncePubKey,
  secNoncePubNonce,
  secNonceAggPubKey,
  secNonceMessage,
  claimSecNonce,
  secNonceIsUsed,
  peekSecNonce,
  newSecNonce,
  secNonceFromScalars,
  secNonceFromBytes,
  secNonceToBytes,
  pubNonceFromScalars,

  -- * Generation
  NonceInputs (..),
  noNonceInputs,
  validateNonceInputs,
  nonceGen,
  nonceGenWithRand,
  nonceGenCounter,
  nonceGenScalars,
  deterministicNonceScalars,

  -- * Aggregation
  nonceAgg,
) where

import Control.DeepSeq (NFData (..), rwhnf)
import Control.Monad (when)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Error (DecodeError (..), NonceGenError (..))
import Crypto.Curve.Secp256k1.MuSig2.Internal.Hash (hashAux, hashDetNonce, hashNonce)
import Crypto.Curve.Secp256k1.MuSig2.Internal.OneShot (OneShot, claimOneShot, isClaimed, newOneShot, peekOneShot)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Point (mulGSecret, sumPoints)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (SecScalar, secScalarFromBytes, secScalarFromBytesModQ, secScalarToBytes)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Types (
  AggNonce (..),
  Encode (..),
  PubKey (..),
  PubNonce (..),
  SecKey (..),
  XOnlyPubKey (..),
  expectLength,
  mkAggNonce,
  mkPubNonce,
 )
import Data.Bits (Bits, shiftR, xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty)
import Data.Maybe (fromMaybe)
import Data.Word (Word64, Word8)
import System.Entropy (getEntropy)

{- | A secret nonce: two secret scalars \(0 < k_1, k_2 < n\), bound to the
signer's public key (and, optionally, to an aggregate key and a message),
with the matching public nonce.

The scalars live in a pinned buffer that can be read once: signing (or
exporting) the nonce marks it used and zero-fills the buffer. Copies of a
t'SecNonce' share that buffer, so they are used up together.

Deliberately has no 'Show', 'Eq', 'Ord', 'Encode' or other instance that
could copy, compare or leak it.
-}
data SecNonce = MkSecNonce
  { snSecret :: !OneShot
  -- ^ @bytes(32, k1) || bytes(32, k2)@.
  , snPubKey :: !PubKey
  , snPubNonce :: !PubNonce
  , snAggPubKey :: !(Maybe XOnlyPubKey)
  -- ^ The aggregate key the nonce was generated for, if any.
  , snMessage :: !(Maybe ByteString)
  -- ^ The message the nonce was generated for, if any.
  }

instance NFData SecNonce where
  rnf (MkSecNonce s pk pn apk m) = rwhnf s `seq` rnf pk `seq` rnf pn `seq` rnf apk `seq` rnf m

-- | The public key the nonce was generated for.
secNoncePubKey :: SecNonce -> PubKey
secNoncePubKey = snPubKey

-- | The public nonce \((k_1 \cdot G, k_2 \cdot G)\).
secNoncePubNonce :: SecNonce -> PubNonce
secNoncePubNonce = snPubNonce

-- | The aggregate key given to nonce generation, if any.
secNonceAggPubKey :: SecNonce -> Maybe XOnlyPubKey
secNonceAggPubKey = snAggPubKey

-- | The message given to nonce generation, if any.
secNonceMessage :: SecNonce -> Maybe ByteString
secNonceMessage = snMessage

{- | Consumes the nonce: atomically marks it used, zero-fills its buffer and
returns the scalars \((k_1, k_2)\). 'Nothing' if it was used before (through
any copy, from any thread).

The bytes go straight to constant-time t'SecScalar's (they are below \(n\),
so the reduction leaves them unchanged).
-}
claimSecNonce :: SecNonce -> IO (Maybe (SecScalar, SecScalar))
claimSecNonce sn = do
  claimed <- claimOneShot (snSecret sn)
  case claimed of
    Nothing -> pure Nothing
    Just bytes -> do
      let !k1 = secScalarFromBytesModQ (BS.take 32 bytes)
          !k2 = secScalarFromBytesModQ (BS.drop 32 bytes)
      pure (Just (k1, k2))

-- | Whether the nonce has been used.
secNonceIsUsed :: SecNonce -> IO Bool
secNonceIsUsed = isClaimed . snSecret

{- | The 64 bytes of the nonce's buffer, without consuming it (all zero after
use). For tests only.
-}
peekSecNonce :: SecNonce -> IO ByteString
peekSecNonce = peekOneShot . snSecret

{- | A fresh secret nonce from its parts, unchecked.

Precondition: \(0 < k_1, k_2 < n\) and the public nonce is
\((k_1 \cdot G, k_2 \cdot G)\).
-}
newSecNonce :: SecScalar -> SecScalar -> PubKey -> PubNonce -> Maybe XOnlyPubKey -> Maybe ByteString -> IO SecNonce
newSecNonce k1 k2 pk pn apk m = do
  secret <- newOneShot (secScalarToBytes k1 <> secScalarToBytes k2)
  pure (MkSecNonce secret pk pn apk m)

-- | The public nonce \((k_1 \cdot G, k_2 \cdot G)\); 'Nothing' if either scalar is zero.
pubNonceFromScalars :: SecScalar -> SecScalar -> Maybe PubNonce
pubNonceFromScalars k1 k2 = mkPubNonce <$> mulGSecret k1 <*> mulGSecret k2

-- | A fresh secret nonce from its scalars (both must be non-zero), not bound to a session.
secNonceFromScalars :: SecScalar -> SecScalar -> PubKey -> IO (Either DecodeError SecNonce)
secNonceFromScalars k1 k2 pk = case pubNonceFromScalars k1 k2 of
  Nothing -> pure (Left ScalarZero)
  Just pn -> Right <$> newSecNonce k1 k2 pk pn Nothing Nothing

{- | A fresh secret nonce from the 97-byte BIP-327 encoding
@bytes(32, k1) || bytes(32, k2) || pk@. The scalars are range-checked in
constant time (see 'secScalarFromBytes').
-}
secNonceFromBytes :: ByteString -> IO (Either DecodeError SecNonce)
secNonceFromBytes b = case parts of
  Left err -> pure (Left err)
  Right (k1, k2, pk) -> secNonceFromScalars k1 k2 pk
 where
  parts = do
    expectLength 97 b
    pk <- decode (BS.drop 64 b)
    k1 <- secScalarFromBytes (BS.take 32 b)
    k2 <- secScalarFromBytes (BS.take 32 (BS.drop 32 b))
    Right (k1, k2, pk)

{- | Consumes the nonce and returns its 97-byte BIP-327 encoding; 'Nothing' if
it was used before.
-}
secNonceToBytes :: SecNonce -> IO (Maybe ByteString)
secNonceToBytes sn = fmap (<> pubKeyBytes (snPubKey sn)) <$> claimOneShot (snSecret sn)

{- | The optional inputs of BIP-327 @NonceGen@. Each one that is given is
hashed into the nonce, as extra protection should the random number
generator fail.
-}
data NonceInputs = NonceInputs
  { nonceSecKey :: !(Maybe SecKey)
  {- ^ The signer's secret key. Stricter than BIP-327, which hashes in any 32
  bytes: it must be a valid secret key (as every t'SecKey' is) belonging to
  the public key passed to 'nonceGen', or nonce generation fails with
  'NonceSecKeyMismatch'.
  -}
  , nonceAggPubKey :: !(Maybe XOnlyPubKey)
  {- ^ The x-only aggregate public key. When given, the nonce can only sign
  in a session whose 'Crypto.Curve.Secp256k1.MuSig2.aggXOnlyPubKey' is this
  key.
  -}
  , nonceMessage :: !(Maybe ByteString)
  {- ^ The message to be signed. When given, the nonce can only sign this
  message.
  -}
  , nonceExtraInput :: !(Maybe ByteString)
  -- ^ Any other data, e.g. a session identifier or a counter.
  }

-- | No optional inputs: the nonce depends only on fresh randomness and the public key.
noNonceInputs :: NonceInputs
noNonceInputs = NonceInputs Nothing Nothing Nothing Nothing

-- | Checks the inputs of @NonceGen@.
validateNonceInputs :: PubKey -> NonceInputs -> Either NonceGenError ()
validateNonceInputs pk inputs = do
  case nonceSecKey inputs of
    Just sk | secKeyPub sk /= pk -> Left NonceSecKeyMismatch
    _ -> Right ()
  when (maybe False ((> 0xFFFFFFFFFFFFFFFF) . toInteger . BS.length) (nonceMessage inputs)) (Left NonceMessageTooLong)
  when (maybe False ((> 0xFFFFFFFF) . toInteger . BS.length) (nonceExtraInput inputs)) (Left NonceExtraInputTooLong)

{- | BIP-327 @NonceGen@ with fresh randomness from the operating system
(@getrandom@ on Linux, via the @entropy@ package).
-}
nonceGen :: PubKey -> NonceInputs -> IO (Either NonceGenError (SecNonce, PubNonce))
nonceGen pk inputs = case validateNonceInputs pk inputs of
  Left err -> pure (Left err)
  Right () -> loop
 where
  loop = do
    rand <- getEntropy 32
    let (k1, k2) = nonceGenScalars rand pk inputs
    case pubNonceFromScalars k1 k2 of
      -- k1 = 0 or k2 = 0: probability ~2^-127, draw again.
      Nothing -> loop
      Just pn -> do
        sn <- newSecNonce k1 k2 pk pn (nonceAggPubKey inputs) (nonceMessage inputs)
        pure (Right (sn, pn))

{- | BIP-327 @NonceGen@ with the given 32 random bytes. Deterministic: the
same bytes and inputs give the same nonce scalars.

In 'IO' although deterministic: each call creates exactly one fresh
t'SecNonce'. A pure version would build the handle inside a thunk, and GHC
may evaluate a thunk twice when two threads force it at the same time,
creating two independent handles for the same scalars.
-}
nonceGenWithRand :: ByteString -> PubKey -> NonceInputs -> IO (Either NonceGenError (SecNonce, PubNonce))
nonceGenWithRand rand pk inputs = case scalars of
  Left err -> pure (Left err)
  Right (k1, k2, pn) -> do
    sn <- newSecNonce k1 k2 pk pn (nonceAggPubKey inputs) (nonceMessage inputs)
    pure (Right (sn, pn))
 where
  scalars = do
    validateNonceInputs pk inputs
    when (BS.length rand /= 32) (Left (InvalidRandLength (BS.length rand)))
    let (k1, k2) = nonceGenScalars rand pk inputs
    pn <- maybe (Left NonceIsZero) Right (pubNonceFromScalars k1 k2)
    Right (k1, k2, pn)

{- | Counter-based nonce generation, as libsecp256k1's
@secp256k1_musig_nonce_gen_counter@ (BIP-327 @CounterNonceGen@): @NonceGen@
with the secret key always hashed in and the random bytes
@bytes(8, counter) || bytes(24, 0)@. The 'nonceSecKey' of the inputs is
ignored.
-}
nonceGenCounter :: SecKey -> Word64 -> NonceInputs -> IO (Either NonceGenError (SecNonce, PubNonce))
nonceGenCounter sk counter inputs =
  nonceGenWithRand (bigEndian 8 counter <> BS.replicate 24 0) (secKeyPub sk) inputs{nonceSecKey = Just sk}

{- | The scalars \((k_1, k_2)\) of BIP-327 @NonceGen@ (reduced modulo \(n\),
possibly zero) for 32 random bytes and validated inputs.
-}
nonceGenScalars :: ByteString -> PubKey -> NonceInputs -> (SecScalar, SecScalar)
nonceGenScalars rand pk inputs = (k 0, k 1)
 where
  rand' = case nonceSecKey inputs of
    Nothing -> rand
    Just sk -> BS.packZipWith xor (secScalarToBytes (secKeyScalar sk)) (hashAux [rand])
  pkBytes = pubKeyBytes pk
  aggpk = maybe BS.empty xOnlyBytes (nonceAggPubKey inputs)
  msgPrefixed = case nonceMessage inputs of
    Nothing -> [BS.singleton 0]
    Just m -> [BS.singleton 1, bigEndian 8 (BS.length m), m]
  extra = fromMaybe BS.empty (nonceExtraInput inputs)
  -- Chunks, not one concatenation: the message and the extra input may be
  -- long, and are hashed twice.
  prefix =
    [ rand'
    , bigEndian 1 (BS.length pkBytes)
    , pkBytes
    , bigEndian 1 (BS.length aggpk)
    , aggpk
    ]
      ++ msgPrefixed
      ++ [bigEndian 4 (BS.length extra), extra]
  k :: Word8 -> SecScalar
  k i = secScalarFromBytesModQ (hashNonce (prefix ++ [BS.singleton i]))

{- | The scalars \((k_1, k_2)\) of BIP-327 @DeterministicSign@ (reduced
modulo \(n\), possibly zero):

\[
k_i = int(hash_{MuSig/deterministic/nonce}(sk' \| aggothernonce \| aggpk \| bytes(8, len(m)) \| m \| bytes(1, i - 1))) \bmod n
\]

where \(sk' = sk \oplus hash_{MuSig/aux}(rand)\) if the 32 bytes @rand@
are given and \(sk\) otherwise.
-}
deterministicNonceScalars ::
  -- | \(sk\).
  SecKey ->
  -- | @aggothernonce@.
  AggNonce ->
  -- | @aggpk@: the x-only aggregate key, after the tweaks.
  XOnlyPubKey ->
  -- | \(m\).
  ByteString ->
  -- | @rand@ (32 bytes).
  Maybe ByteString ->
  (SecScalar, SecScalar)
deterministicNonceScalars sk aggOther aggpk msg rand = (k 0, k 1)
 where
  skBytes = secScalarToBytes (secKeyScalar sk)
  sk' = maybe skBytes (BS.packZipWith xor skBytes . hashAux . pure) rand
  prefix = [sk', aggNonceBytes aggOther, xOnlyBytes aggpk, bigEndian 8 (BS.length msg), msg]
  k :: Word8 -> SecScalar
  k i = secScalarFromBytesModQ (hashDetNonce (prefix ++ [BS.singleton i]))

-- | @bytes(n, x)@: the \(n\)-byte big-endian encoding of a length or counter.
bigEndian :: (Integral a, Bits a) => Int -> a -> ByteString
bigEndian n x = BS.pack [fromIntegral (x `shiftR` (8 * j)) | j <- [n - 1, n - 2 .. 0]]

-- | BIP-327 @NonceAgg@: sums the first and the second points. Either sum may be infinity.
nonceAgg :: NonEmpty PubNonce -> AggNonce
nonceAgg pns = mkAggNonce (sumPoints (fmap pubNonceR1 pns)) (sumPoints (fmap pubNonceR2 pns))
