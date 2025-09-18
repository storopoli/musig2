{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}
{-# OPTIONS_GHC -Wno-x-partial #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

MuSig2 signing Haskell library.
TODO: add description
-}
module Crypto.Curve.Secp256k1.MuSig2 (
  -- Key aggregation
  KeyAggContext (..),
  mkKeyAggContext,
  -- tweak functions
  applyTweak,
  Tweak (..),
  sortPublicKeys,
  -- nonces
  SecNonce (..),
  mkSecNonce,
  PubNonce (..),
  publicNonce,
) where

import Crypto.Curve.Secp256k1 (Projective, Pub, add, modQ, mul, neg, serialize_point, _CURVE_G, _CURVE_Q, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2.Internal
import Data.Foldable (toList)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Traversable ()
import Data.Word (Word32)
import System.Random (newStdGen, uniformR)

-- | Key aggregation context that holds the aggregated public key and a tweak, if applicable.
data KeyAggContext = KeyAggContext
  { q :: Projective
  -- ^ Point representing the potentially tweaked aggregate public key: an elliptic curve point.
  , publicKeys :: Seq Pub
  -- ^ Ordered 'Seq' of 'Pub'keys.
  , coefficients :: Seq Integer
  -- ^ 'Seq' of aggregation coefficients.
  , tacc :: Maybe Tweak
  -- ^ accumulated tweak: an integer with \(0 \leq tacc < n\) where \(n\) is the curve order. 'Nothing' means \(0\).
  , gacc :: Bool
  -- ^ parity accumulator: 'False' means \(g = 1\), 'True' means \(g = n-1\) where \(n\) is the curve order.
  }

{- | Creates a 'KeyAggContext' from a 'Traversable' of 'Pub'keys.

The order in which the 'Pub'keys are presented will be preserved.
A specific ordering of 'Pub'keys will uniquely determine the aggregated 'Pub'key.

If the same keys are provided again in a different sorting order, a different
aggregated 'Pub'key will result. It is recommended to sort keys ahead of time
using 'sortPublicKeys' before creating a 'KeyAggContext'.


== NOTE

Internally it validates if all keys and the resulting aggregated key are not
points at infinity, if the optional tweak is within the curve order, and if
the length of the collection of keys is not bigger than 32 bits.
-}
mkKeyAggContext :: (Traversable t) => t Pub -> Maybe Tweak -> KeyAggContext
mkKeyAggContext pks mTweak
  | Seq.null pks' = error "musig2 (mkKeyAggContext): empty public key collection"
  | Seq.length pks' > fromIntegral (maxBound :: Word32) = error "musig2 (mkKeyAggContext): too many public keys (max 2^32 - 1)"
  | _CURVE_ZERO `elem` pks' = error "musig2 (mkKeyAggContext): public key at point of infinity"
  | maybe False ((< 0) . getTweak) mTweak = error "musig2 (mkKeyAggContext): tweak must be non-negative"
  | maybe False ((>= _CURVE_Q) . getTweak) mTweak = error "musig2 (mkKeyAggContext): tweak must be less than n"
  | otherwise = case aggPublicKeys pks' of
      Nothing -> error "musig2 (mkKeyAggContext): failed to aggregate public keys"
      Just aggPk
        | aggPk == _CURVE_ZERO -> error "musig2 (mkKeyAggContext): aggregated public key is point at infinity"
        | otherwise ->
            let coeffs' = fmap (`computeKeyAggCoef` pks') pks'
                baseCtx = KeyAggContext aggPk pks' coeffs' Nothing False
             in case mTweak of
                  Nothing -> baseCtx
                  Just tweak -> applyTweak baseCtx tweak
 where
  pks' = Seq.fromList (toList pks)

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
                then error "musig2 (applyTweak): result of tweaking cannot be infinity"
                else ctx{q = tweakedPk, tacc = Just (PlainTweak newAccTweak)}
        XOnlyTweak t ->
          if isEvenPub pubkey
            then
              -- If pubkey has even Y, behave like plain tweak: Q' = Q + t*G, tacc' = tacc + t, gacc' = gacc
              let tweakedPk = add pubkey (mul _CURVE_G t)
                  newAccTweak = modQ (accTweakVal + t)
               in if tweakedPk == _CURVE_ZERO
                    then error "musig2 (applyTweak): result of tweaking cannot be infinity"
                    else ctx{q = tweakedPk, tacc = Just (XOnlyTweak newAccTweak)}
            else
              -- If pubkey has odd Y: Q' = t*G - Q, tacc' = t - tacc, gacc' = !gacc
              let tweakedPk = add (mul _CURVE_G t) (neg pubkey) -- t*G - Q
                  newAccTweak = modQ (t - accTweakVal)
               in if tweakedPk == _CURVE_ZERO
                    then error "musig2 (applyTweak): result of tweaking cannot be infinity"
                    else ctx{q = tweakedPk, tacc = Just (PlainTweak newAccTweak), gacc = not gaccIn}

-- | Manual 'Ord' implementation of 'Projective' for lexicography sorting.
instance Ord Projective where
  compare x y = compare (serialize_point x) (serialize_point y)

-- | 'Data.Semigroup' implementation of 'Projective' for algebraic sound combination of points.
instance Semigroup Projective where
  (<>) :: Projective -> Projective -> Projective
  (<>) = add

-- | 'Data.Monoid' implementation of 'Projective' for algebraic sound combination of points.
instance Monoid Projective where
  mempty :: Projective
  mempty = _CURVE_ZERO

-- | Lexicographically 'sort's a 'Traversable' of 'Pub'keys.
sortPublicKeys :: (Traversable t) => t Pub -> Seq Pub
sortPublicKeys = Seq.sort . Seq.fromList . toList

{- | Secret nonce.

The secret nonce provides randomness, blinding a signer's private key when
signing. It is imperative that the same 'SecNonce' is not used to sign more
than one message with the same key, as this would allow an observer to
compute the private key used to create both signatures.

Please see [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
-}
data SecNonce = SecNonce
  { k1 :: Integer
  -- ^ First secret scalar.
  , k2 :: Integer
  -- ^ Second secret scalar.
  }
  deriving (Read, Eq, Ord)

{- | Generates a 'SecNonce' using the system's underlying Cryptographic Secure
Pseudorandom Number Generator (CSPRNG) using the
[`random`](https://hackage.haskell.org/package/random) package.

== WARNING

Make sure that you have access to a good CSPRNG in your system before calling
this function.
-}
mkSecNonce :: IO SecNonce
mkSecNonce = do
  gen <- newStdGen
  let (k1', gen') = uniformR (1, 2 ^ (256 :: Integer) - 1) gen
      (k2', _) = uniformR (1, 2 ^ (256 :: Integer) - 1) gen'
  pure SecNonce{k1 = k1', k2 = k2'}

{- | Public nonce.

Represents a public nonce derived from a secret nonce. It is composed
of two public points, 'r1' and 'r2', derived by base-point multiplying
the two scalars in a 'SecNonce'.

'PubNonce' can be derived from a 'SecNonce' using 'publicNonce'.
-}
data PubNonce = PubNonce
  { r1 :: Pub
  -- ^ First public point.
  , r2 :: Pub
  -- ^ Second public point.
  }
  deriving (Eq, Ord, Show)

-- | Generates a 'PubNonce' from a 'SecNonce'.
publicNonce :: SecNonce -> PubNonce
publicNonce secNonce =
  let r1' = mul _CURVE_G (k1 secNonce)
      r2' = mul _CURVE_G (k2 secNonce)
   in PubNonce{r1 = r1', r2 = r2'}
