{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Point
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

Helpers on @ppad-secp256k1@ points: the BIP-327 encodings and scalar
multiplication with the right timing properties.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Point (
  -- * Predicates
  isInfinity,
  isValidPoint,

  -- * Encodings
  cbytes,
  cbytesExt,
  hasEvenYBytes,
  infinityBytes,

  -- * Multiplication
  gContext,
  mulPublic,
  mulGPublic,
  mulGSecret,
  sumPoints,
) where

import Crypto.Curve.Secp256k1 (Context, Projective (..), add, mul_vartime, mul_wnaf, precompute, serialize_point, valid, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (SecScalar, modQ, secScalarWider)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BU
import Data.Maybe (fromMaybe)
import qualified Numeric.Montgomery.Secp256k1.Curve as C

{- | Whether a point is the point at infinity: projective coordinates
@(0 : Y : 0)@ with \(Y \neq 0\).

Unlike @p == _CURVE_ZERO@ (which checks only \(Z = 0\)), this rejects invalid
\(Z = 0\) triples such as @(0, 0, 0)@ and @(1, 2, 0)@.
-}
isInfinity :: Projective -> Bool
isInfinity (Projective x y z) = C.eq_vartime z C.zero && C.eq_vartime x C.zero && not (C.eq_vartime y C.zero)

-- | A finite point on the curve (ppad's v'Projective' constructor is exported, so values may be anything).
isValidPoint :: Projective -> Bool
isValidPoint p@(Projective _ _ z) = not (C.eq_vartime z C.zero) && valid p

{- | @cbytes@: 33-byte compressed encoding of a finite point.

Precondition: the point is finite ('serialize_point' encodes infinity as
@02 || 0^32@).
-}
cbytes :: Projective -> ByteString
cbytes = serialize_point

-- | @cbytes_ext@: like 'cbytes', but infinity is 33 zero bytes.
cbytesExt :: Projective -> ByteString
cbytesExt p
  | isInfinity p = infinityBytes
  | otherwise = serialize_point p

-- | The @cbytes_ext@ encoding of infinity: 33 zero bytes.
infinityBytes :: ByteString
infinityBytes = BS.replicate 33 0

-- | Whether a 33-byte compressed encoding has the even-y prefix @0x02@.
hasEvenYBytes :: ByteString -> Bool
hasEvenYBytes b = not (BS.null b) && BU.unsafeHead b == 0x02

{- | Variable-time multiplication by a /public/ scalar, reduced modulo \(n\);
\(0\) gives infinity.
-}
mulPublic :: Projective -> Integer -> Projective
mulPublic p k =
  -- mul_vartime only fails for scalars >= n, which modQ rules out.
  fromMaybe _CURVE_ZERO (mul_vartime p (fromInteger (modQ k)))

-- | Precomputed multiples of the generator, built once on first use.
gContext :: Context
gContext = precompute
{-# NOINLINE gContext #-}

{- | Multiplication of the generator by a public scalar, reduced modulo
\(n\); \(0\) gives infinity.
-}
mulGPublic :: Integer -> Projective
mulGPublic k = case modQ k of
  0 -> _CURVE_ZERO
  -- mul_wnaf only fails for scalars 0 or >= n, which are ruled out.
  k' -> fromMaybe _CURVE_ZERO (mul_wnaf gContext (fromInteger k'))

{- | Constant-time multiplication of the generator by a /secret/ scalar
(ppad's timing-safe wNAF over precomputed multiples); 'Nothing' for zero.
The scalar goes to ppad as a t'Data.Word.Wider.Wider' word, never through
'Integer'.
-}
mulGSecret :: SecScalar -> Maybe Projective
mulGSecret k = mul_wnaf gContext (secScalarWider k)

-- | Strict sum of points.
sumPoints :: (Foldable f) => f Projective -> Projective
sumPoints = foldl' add _CURVE_ZERO
