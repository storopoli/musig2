{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}
{-# OPTIONS_HADDOCK prune #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

MuSig2 signing Haskell library.
TODO: add description
-}
module Crypto.Curve.Secp256k1.MuSig2 (
  -- Pubkey functions
  sortPubkeys,
  aggPubkeys,
  -- derived instances
  Monoid,
  Semigroup,
  -- utils/misc
  isEvenPub,
)
where

import Crypto.Curve.Secp256k1 (Projective, Pub, add, modQ, mul, serialize_point, _CURVE_ZERO)
import Crypto.Hash.SHA256 (hash)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (find, sort)
import Data.Maybe (fromMaybe)
import GHC.List (foldl')

-- | Manual 'Ord' implementation of 'Projective' for lexicography sorting.
instance Ord Projective where
  compare x y = compare (serialize_point x) (serialize_point y)

-- | 'Semigroup' implementation of 'Projective' for algebraic sound combination of points.
instance Semigroup Projective where
  (<>) :: Projective -> Projective -> Projective
  (<>) = add

-- | 'Monoid' implementation of 'Projective' for algebraic sound combination of points.
instance Monoid Projective where
  mempty :: Projective
  mempty = _CURVE_ZERO

-- | Lexicographically 'sort's a 'List' of 'Pub'keys.
sortPubkeys :: [Pub] -> [Pub]
sortPubkeys = sort

{- | Aggregates a 'List' of 'Pub'keys using the
[Key Aggregation algorithm in BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).

The algorith can be briefly described as

\[
f(pk_1, \dots, pk_u) = a_i \cdot pk_i
\]

where \(pk_i\) is the \(i\)th participant's public key and \(a_i\) is the
respective public key aggregation coefficient.

== WARNING

'aggPubKeys' do not sort the keys and aggregates public keys according to the
ordering of the 'List' provided.
-}
aggPubkeys :: [Pub] -> Maybe Pub
aggPubkeys [] = Nothing
aggPubkeys pks = pure $ weightedFoldMap aggPk (<>) pks
 where
  coefs = map (`computeKeyAggCoef` pks) pks
  weightedFoldMap f op xs = foldr1 op (zipWith f coefs xs)
  aggPk i p = mul p i -- mul takes first point then scalar

-- INTERNAL FUNCTIONS

{- | Computes the key aggregation coefficient from:

1. Desired key to compute the key aggregation coefficient
2. 'List' of 'Pub'keys
-}
computeKeyAggCoef :: Pub -> [Pub] -> Integer
computeKeyAggCoef pk pks =
  let pk2 = getSecondKey pks
      hashKeys = hashProjectivesTag "KeyAgg list" pks
      taggedHash = hashTag "KeyAgg coefficient" (hashKeys <> serialize_point pk)
   in if pk == pk2 then 1 else modQ $ bytesToInteger taggedHash

{- | Returns the first second key that is different from the first key in
a 'List' of 'Pub'keys.

Returns the point at infinity, i.e. zero'th point of monoidal identity.
-}
getSecondKey :: [Pub] -> Pub
getSecondKey pks =
  let pk1 = head pks
      pk2 = find (/= pk1) pks
   in fromMaybe _CURVE_ZERO pk2

-- | "Taghashes" a 'List' of 'Projective's by concatenating all their 'ByteString' representations together.
hashProjectivesTag :: ByteString -> [Projective] -> ByteString
hashProjectivesTag tag ps = hashTag tag $ foldl' (<>) "" byteStrings
 where
  byteStrings = map serialize_point ps

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

-- | Checks if a |Pub|key is even.
isEvenPub :: Pub -> Bool
isEvenPub pub = case BS.unpack (serialize_point pub) of
  (0x02 : _) -> True -- even y-coordinate
  (0x03 : _) -> False -- odd y-coordinate
  _ -> error "Invalid compressed point format"
