{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

BIP-327 @NonceGen@ and @NonceAgg@.

The representation of t'SecNonce' is private to this module: everything else
goes through 'secNonceScalars', 'secNoncePubKey' and 'secNoncePubNonce', so
the representation can change (e.g. to a one-shot mutable buffer) without
touching the rest of the library.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (
  -- * Secret nonces
  SecNonce,
  secNonceScalars,
  secNoncePubKey,
  secNoncePubNonce,
  secNonceFromScalars,
  secNonceFromBytes,
  secNonceToBytes,

  -- * Generation
  NonceInputs (..),
  noNonceInputs,
  validateNonceInputs,
  nonceGen,
  nonceGenWithRand,

  -- * Aggregation
  nonceAgg,
) where

import Control.DeepSeq (NFData (..))
import Control.Monad (when)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Error (DecodeError (..), NonceGenError (..))
import Crypto.Curve.Secp256k1.MuSig2.Internal.Hash (hashAux, hashNonce)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Point (mulGSecret, sumPoints)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (bytesToInteger, curveOrder, hashToScalar, integerToBytes32)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Types (
  AggNonce,
  Encode (..),
  PubKey (..),
  PubNonce (..),
  SecKey (..),
  XOnlyPubKey (..),
  expectLength,
  mkAggNonce,
  mkPubNonce,
 )
import Data.Bits (shiftR, xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty)
import Data.Maybe (fromMaybe)
import Data.Word (Word8)
import System.Entropy (getEntropy)

{- | A secret nonce: two secret scalars \(0 < k_1, k_2 < n\), bound to the
signer's public key, with the matching public nonce.

Deliberately has no 'Show', 'Eq', 'Ord', 'Encode' or other instance that
could copy, compare or leak it.
-}
data SecNonce = SecNonce
  { snK1 :: !Integer
  , snK2 :: !Integer
  , snPubKey :: !PubKey
  , snPubNonce :: !PubNonce
  }

instance NFData SecNonce where
  rnf (SecNonce k1 k2 pk pn) = rnf k1 `seq` rnf k2 `seq` rnf pk `seq` rnf pn

-- | The secret scalars \((k_1, k_2)\).
secNonceScalars :: SecNonce -> (Integer, Integer)
secNonceScalars sn = (snK1 sn, snK2 sn)

-- | The public key the nonce was generated for.
secNoncePubKey :: SecNonce -> PubKey
secNoncePubKey = snPubKey

-- | The public nonce \((k_1 \cdot G, k_2 \cdot G)\).
secNoncePubNonce :: SecNonce -> PubNonce
secNoncePubNonce = snPubNonce

-- | A secret nonce from its scalars; both must be in \([1, n)\).
secNonceFromScalars :: Integer -> Integer -> PubKey -> Either DecodeError SecNonce
secNonceFromScalars k1 k2 pk = do
  r1 <- point k1
  r2 <- point k2
  Right (SecNonce k1 k2 pk (mkPubNonce r1 r2))
 where
  point k
    | k == 0 = Left ScalarZero
    | k < 0 || k >= curveOrder = Left ScalarOutOfRange
    | otherwise = maybe (Left ScalarOutOfRange) Right (mulGSecret k)

-- | The 97-byte BIP-327 encoding @bytes(k1) || bytes(k2) || pk@.
secNonceFromBytes :: ByteString -> Either DecodeError SecNonce
secNonceFromBytes b = do
  expectLength 97 b
  pk <- decode (BS.drop 64 b)
  secNonceFromScalars (bytesToInteger (BS.take 32 b)) (bytesToInteger (BS.take 32 (BS.drop 32 b))) pk

-- | The 97-byte BIP-327 encoding of a secret nonce.
secNonceToBytes :: SecNonce -> ByteString
secNonceToBytes sn = integerToBytes32 (snK1 sn) <> integerToBytes32 (snK2 sn) <> pubKeyBytes (snPubKey sn)

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
  -- ^ The x-only aggregate public key.
  , nonceMessage :: !(Maybe ByteString)
  -- ^ The message to be signed.
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
    case nonceGenWithRand rand pk inputs of
      Right (Just result) -> pure (Right result)
      -- k1 = 0 or k2 = 0: probability ~2^-127, draw again.
      Right Nothing -> loop
      Left err -> pure (Left err)

{- | BIP-327 @NonceGen@ with the given 32 random bytes. Deterministic: the
same bytes and inputs give the same nonce, so the bytes must never repeat.

'Nothing' if the bytes are not 32 long or if \(k_1 = 0\) or \(k_2 = 0\).
-}
nonceGenWithRand :: ByteString -> PubKey -> NonceInputs -> Either NonceGenError (Maybe (SecNonce, PubNonce))
nonceGenWithRand rand pk inputs = do
  validateNonceInputs pk inputs
  Right $
    if BS.length rand /= 32
      then Nothing
      else either (const Nothing) (\sn -> Just (sn, snPubNonce sn)) (secNonceFromScalars (k 0) (k 1) pk)
 where
  rand' = case nonceSecKey inputs of
    Nothing -> rand
    Just sk -> BS.packZipWith xor (integerToBytes32 (secKeyScalar sk)) (hashAux rand)
  pkBytes = pubKeyBytes pk
  aggpk = maybe BS.empty xOnlyBytes (nonceAggPubKey inputs)
  msgPrefixed = case nonceMessage inputs of
    Nothing -> BS.singleton 0
    Just m -> BS.singleton 1 <> bigEndian 8 (BS.length m) <> m
  extra = fromMaybe BS.empty (nonceExtraInput inputs)
  prefix =
    BS.concat
      [ rand'
      , bigEndian 1 (BS.length pkBytes)
      , pkBytes
      , bigEndian 1 (BS.length aggpk)
      , aggpk
      , msgPrefixed
      , bigEndian 4 (BS.length extra)
      , extra
      ]
  k :: Word8 -> Integer
  k i = hashToScalar (hashNonce (prefix <> BS.singleton i))

-- | @bytes(n, x)@: the \(n\)-byte big-endian encoding of a length.
bigEndian :: Int -> Int -> ByteString
bigEndian n x = BS.pack [fromIntegral (x `shiftR` (8 * j)) | j <- [n - 1, n - 2 .. 0]]

-- | BIP-327 @NonceAgg@: sums the first and the second points. Either sum may be infinity.
nonceAgg :: NonEmpty PubNonce -> AggNonce
nonceAgg pns = mkAggNonce (sumPoints (fmap pubNonceR1 pns)) (sumPoints (fmap pubNonceR2 pns))
