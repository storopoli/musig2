{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}
{-# OPTIONS_GHC -Wno-x-partial #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

Internal MuSig2 functions - not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal (
  -- Pubkey functions
  aggPublicKeys,
  -- Key aggregation
  computeKeyAggCoef,
  getSecondKey,
  -- utils/misc
  isEvenPub,
  bytesToInteger,
  integerToBytes32,
  xorByteStrings,
  encodeLen,
  hashTag,
  hashProjectivesTag,
) where

import Crypto.Curve.Secp256k1 (Projective, Pub, add, modQ, mul, serialize_point, _CURVE_ZERO)
import Crypto.Hash.SHA256 (hash)
import Data.Bits (shiftR, xor, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder (toLazyByteString, word64BE)
import qualified Data.ByteString.Lazy as BSL
import Data.Foldable (Foldable (fold), find, toList)
import qualified Data.Foldable as F
import Data.Maybe (fromMaybe)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Traversable ()

{- | Aggregates a 'Traversable' of 'Pub'keys using the
[Key Aggregation algorithm in BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).

The algorith can be briefly described as

\[
f(pk_1, \dots, pk_u) = a_i \cdot pk_i
\]

where \(pk_i\) is the \(i\)th participant's public key and \(a_i\) is the
respective public key aggregation coefficient.

== WARNING

'aggPublicKeys' do not sort the keys and aggregates public keys according to the
ordering of the 'Traversable' provided.
-}
aggPublicKeys :: (Traversable t) => t Pub -> Maybe Pub
aggPublicKeys pks
  | Seq.null pksSeq = Nothing
  | otherwise = Just $ fold1WithDefault _CURVE_ZERO (Seq.zipWith aggPk coefs pksSeq)
 where
  pksSeq = Seq.fromList (toList pks)
  coefs = fmap (`computeKeyAggCoef` pksSeq) pksSeq
  aggPk i p = mul p i -- mul takes first point then scalar
  -- Safe fold1 that handles empty sequences
  fold1WithDefault def xs = case Seq.viewl xs of
    Seq.EmptyL -> def
    x Seq.:< xs' -> F.foldl' add x xs'

{- | Computes the key aggregation coefficient from:

1. Desired key to compute the key aggregation coefficient
2. 'Seq' of 'Pub'keys
-}
computeKeyAggCoef :: Pub -> Seq Pub -> Integer
computeKeyAggCoef pk pks =
  let pk2 = getSecondKey pks
      hashKeys = hashProjectivesTag "KeyAgg list" pks
      taggedHash = hashTag "KeyAgg coefficient" (hashKeys <> serialize_point pk)
   in if pk == pk2 then 1 else modQ $ bytesToInteger taggedHash

{- | Returns the first second key that is different from the first key in
a 'Seq' of 'Pub'keys.

Returns the point at infinity, i.e. zero'th point of monoidal identity.
-}
getSecondKey :: Seq Pub -> Pub
getSecondKey pks =
  case Seq.viewl pks of
    Seq.EmptyL -> _CURVE_ZERO
    pk1 Seq.:< _ ->
      let pk2 = find (/= pk1) pks
       in fromMaybe _CURVE_ZERO pk2

-- | "Taghashes" a 'Seq' of 'Projective's by concatenating all their 'ByteString' representations together.
hashProjectivesTag :: ByteString -> Seq Projective -> ByteString
hashProjectivesTag tag ps = hashTag tag $ fold byteStrings
 where
  byteStrings = fmap serialize_point ps

{- | Tagged hashes used in [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).

Takes a tag and a string.
-}
hashTag :: ByteString -> ByteString -> ByteString
hashTag t s = hash (taggedHash <> taggedHash <> s)
 where
  taggedHash = hash t

-- | Converts a SHA-256 'ByteString' to an 'Integer'.
bytesToInteger :: ByteString -> Integer
bytesToInteger = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | Converts an 'Integer' to a 32-byte big-endian 'ByteString'.
integerToBytes32 :: Integer -> ByteString
integerToBytes32 i = BS.pack $ reverse [fromInteger (i `shiftR` (8 * j)) .&. 0xff | j <- [0 .. 31]]

-- | @XOR@s two 'ByteString's of same length.
xorByteStrings :: ByteString -> ByteString -> ByteString
xorByteStrings = BS.packZipWith xor

-- | Returns the 8-byte big-endian encoding of the length of a 'ByteString'.
encodeLen :: ByteString -> ByteString
encodeLen bs = BSL.toStrict . toLazyByteString . word64BE . fromIntegral $ BS.length bs

-- | Checks if a 'Pub'key is even.
isEvenPub :: Pub -> Bool
isEvenPub pub = case BS.unpack (serialize_point pub) of
  (0x02 : _) -> True -- even y-coordinate
  (0x03 : _) -> False -- odd y-coordinate
  _ -> error "musig2 (isEvenPub): invalid compressed point format"
