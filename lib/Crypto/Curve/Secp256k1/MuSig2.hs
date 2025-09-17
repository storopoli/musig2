{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}
{-# OPTIONS_GHC -Wno-x-partial #-}
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
  -- main interfaces
  KeyAggContext (..),
  mkKeyAggContext,
  Tweak (..),
  -- Pubkey functions
  sortPubkeys,
  aggPubkeys,
  -- tweak functions
  applyTweak,
  -- derived instances
  Monoid,
  Semigroup,
  -- utils/misc
  isEvenPub,
  bytesToInteger,
  hashTag,
)
where

import Crypto.Curve.Secp256k1 (Projective, Pub, add, modQ, mul, neg, serialize_point, _CURVE_G, _CURVE_Q, _CURVE_ZERO)
import Crypto.Hash.SHA256 (hash)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (find, sort)
import Data.Maybe (fromMaybe)
import Data.Word (Word32)
import GHC.List (foldl')

-- | Key aggregation context that holds the aggregated public key and a tweak, if applicable.
data KeyAggContext = KeyAggContext
  { q :: Projective
  -- ^ Point representing the potentially tweaked aggregate public key: an elliptic curve point.
  , publicKeys :: [Pub]
  -- ^ Ordered |List| of |Pub|keys.
  , coefficients :: [Integer]
  -- ^ |List| of aggregation coefficients.
  , tacc :: Maybe Tweak
  -- ^ accumulated tweak: an integer with \(0 \leq tacc < n\) where \(n\) is the curve order. |Nothing| means \(0\).
  , gacc :: Bool
  -- ^ parity accumulator: |False| means \(g = 1\), |True| means \(g = n-1\) where \(n\) is the curve order.
  }

{- | Creates a 'KeyAggContext' from a 'List' of 'Pub'keys.

The order in which the 'Pub'keys are presented will be preserved.
A specific ordering of 'Pub'keys will uniquely determine the aggregated 'Pub'key.

If the same keys are provided again in a different sorting order, a different
aggregated 'Pub'key will result. It is recommended to sort keys ahead of time
using 'sortPubkey' before creating a 'KeyAggContext'.


== NOTE

Internally it validates if all keys and the resulting aggregated key are not
points at infinity, if the optional tweak is within the curve order, and if
the length of the list of keys is not bigger than 32 bits.
-}
mkKeyAggContext :: [Pub] -> Maybe Tweak -> KeyAggContext
mkKeyAggContext pks mTweak
  | null pks = error "mkKeyAggContext: empty public key list"
  | length pks > fromIntegral (maxBound :: Word32) = error "mkKeyAggContext: too many public keys (max 2^32 - 1)"
  | _CURVE_ZERO `elem` pks = error "mkKeyAggContext: public key at point of infinity"
  | maybe False ((< 0) . getTweak) mTweak = error "mkKeyAggContext: tweak must be non-negative"
  | maybe False ((>= _CURVE_Q) . getTweak) mTweak = error "mkKeyAggContext: The tweak must be less than n"
  | otherwise = case aggPubkeys pks of
      Nothing -> error "mkKeyAggContext: failed to aggregate public keys"
      Just aggPk
        | aggPk == _CURVE_ZERO -> error "mkKeyAggContext: aggregated public key is point at infinity"
        | otherwise ->
            let coeffs' = map (`computeKeyAggCoef` pks) pks
                baseCtx = KeyAggContext aggPk pks coeffs' Nothing False
             in case mTweak of
                  Nothing -> baseCtx
                  Just tweak -> applyTweak baseCtx tweak

-- | Tweak that can be added to an aggregated 'Pub'key.
data Tweak
  = -- | X-only tweak required by Taproot tweaking to add script paths to a Taproot output.
    -- See [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).
    XOnlyTweak Integer
  | -- | Plain tweak that can be used to derive child aggregated 'Pub'keys per
    -- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
    PlainTweak Integer
  deriving (Read, Show, Eq, Ord)

-- | Retrieves the 'Integer' from 'Tweak'.
getTweak :: Tweak -> Integer
getTweak (XOnlyTweak int) = int
getTweak (PlainTweak int) = int

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

You should probably be using the recommended 'mkKeyAggContext'.
-}
aggPubkeys :: [Pub] -> Maybe Pub
aggPubkeys [] = Nothing
aggPubkeys pks = pure $ weightedFoldMap aggPk (<>) pks
 where
  coefs = map (`computeKeyAggCoef` pks) pks
  weightedFoldMap f op xs = foldr1 op (zipWith f coefs xs)
  aggPk i p = mul p i -- mul takes first point then scalar

-- | Applies a tweak to a KeyAggContext and returns a new KeyAggContext following [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
applyTweak :: KeyAggContext -> Tweak -> KeyAggContext
applyTweak ctx newTweak =
  let pubkey = q ctx
      mAccTweak = tacc ctx
      gaccIn = gacc ctx
      accTweakVal = maybe 0 getTweak mAccTweak
   in case newTweak of
        PlainTweak t ->
          -- Plain tweak: Q' = Q + t*G, tacc' = tacc + t, gacc' = gacc
          let tweakedPk = add pubkey (mul _CURVE_G t)
              newAccTweak = modQ (accTweakVal + t)
           in if tweakedPk == _CURVE_ZERO
                then error "applyTweak: the result of tweaking cannot be infinity"
                else ctx{q = tweakedPk, tacc = Just (PlainTweak newAccTweak)}
        XOnlyTweak t ->
          if isEvenPub pubkey
            then
              -- If pubkey has even Y, behave like plain tweak: Q' = Q + t*G, tacc' = tacc + t, gacc' = gacc
              let tweakedPk = add pubkey (mul _CURVE_G t)
                  newAccTweak = modQ (accTweakVal + t)
               in if tweakedPk == _CURVE_ZERO
                    then error "applyTweak: the result of tweaking cannot be infinity"
                    else ctx{q = tweakedPk, tacc = Just (XOnlyTweak newAccTweak)}
            else
              -- If pubkey has odd Y: Q' = t*G - Q, tacc' = t - tacc, gacc' = !gacc
              let tweakedPk = add (mul _CURVE_G t) (neg pubkey) -- t*G - Q
                  newAccTweak = modQ (t - accTweakVal)
               in if tweakedPk == _CURVE_ZERO
                    then error "applyTweak: the result of tweaking cannot be infinity"
                    else ctx{q = tweakedPk, tacc = Just (PlainTweak newAccTweak), gacc = not gaccIn}

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
