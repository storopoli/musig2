{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

Scalar arithmetic modulo the secp256k1 group order \(n\).

Everything here uses 'Integer', whose running time depends on the values. That
is fine for public scalars (coefficients, challenges, partial signatures), but
not for secrets. The only functions that touch secret scalars are
'signScalar' (the arithmetic of BIP-327 @Sign@) and 'hashToScalar' when it
reduces nonce hashes; keep it that way so constant-time arithmetic can replace
them in one place.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (
  -- * Group order
  curveOrder,
  fieldSize,
  modQ,

  -- * Conversions
  bytesToInteger,
  integerToBytes32,
  hashToScalar,

  -- * Secret arithmetic
  signScalar,
) where

import Data.Bits (shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

-- | The secp256k1 group order \(n\).
curveOrder :: Integer
curveOrder = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

-- | The secp256k1 field size \(p\).
fieldSize :: Integer
fieldSize = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

-- | Reduction modulo \(n\).
modQ :: Integer -> Integer
modQ x = x `mod` curveOrder

-- | Big-endian bytes to a non-negative 'Integer'.
bytesToInteger :: ByteString -> Integer
bytesToInteger = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | A non-negative 'Integer' below \(2^{256}\) to 32 big-endian bytes.
integerToBytes32 :: Integer -> ByteString
integerToBytes32 i = fst (BS.unfoldrN 32 step 31)
 where
  step :: Int -> Maybe (Word8, Int)
  step j = Just (fromInteger (i `shiftR` (8 * j)), j - 1)

-- | @int(h) mod n@ for a 32-byte hash @h@.
hashToScalar :: ByteString -> Integer
hashToScalar = modQ . bytesToInteger

{- | The scalar of a BIP-327 partial signature:

\[
s = k_1' + b \cdot k_2' + e \cdot a \cdot d \pmod n
\]

where \(k_i' = n - k_i\) when the final nonce \(R\) has odd \(y\) and
\(d = g \cdot gacc \cdot d'\), i.e. \(d'\) negated when
\(g \cdot gacc = -1\).

This is the only place where secret scalars are combined.
-}
signScalar ::
  -- | \(k_1\) (secret).
  Integer ->
  -- | \(k_2\) (secret).
  Integer ->
  -- | \(d'\), the secret key (secret).
  Integer ->
  -- | Negate the nonce (\(R\) has odd \(y\)).
  Bool ->
  -- | Negate the secret key (\(g \cdot gacc = n - 1\)).
  Bool ->
  -- | Nonce coefficient \(b\) (public).
  Integer ->
  -- | \(e \cdot a \bmod n\) (public).
  Integer ->
  -- | \(s\).
  Integer
signScalar k1 k2 d negateNonce negateKey b ea =
  let k = modQ (k1 + b * k2)
      k' = if negateNonce then modQ (curveOrder - k) else k
      d' = if negateKey then curveOrder - d else d
   in modQ (k' + ea * d')
