{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

Scalar arithmetic modulo the secp256k1 group order \(n\).

Two representations, kept apart by type:

* Public scalars (key aggregation coefficients, nonce coefficients,
  challenges, tweaks, partial signatures) are 'Integer's. Arithmetic on
  'Integer' takes time that depends on the values, which is fine for values
  everyone knows.

* Secret scalars (secret keys and nonces) are t'SecScalar's: four 64-bit
  limbs in Montgomery form, with the constant-time arithmetic of
  @ppad-fixed@. They are read from and written to bytes in constant time,
  range-checked with constant-time comparisons that are decided only once
  at the end, and never converted to or from 'Integer'.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (
  -- * Group order
  curveOrder,
  fieldSize,
  modQ,

  -- * Public scalars
  bytesToInteger,
  integerToBytes32,
  hashToScalar,

  -- * Secret scalars
  SecScalar,
  secScalarFromBytes,
  secScalarFromBytesModQ,
  secScalarToBytes,
  secScalarWider,

  -- * Secret arithmetic
  signScalar,

  -- * Constant-time byte conversions
  widerFromBytes,
  widerToBytes,
) where

import Control.DeepSeq (NFData (..))
import Crypto.Curve.Secp256k1.MuSig2.Internal.Error (DecodeError (..))
import Data.Bits (shiftR, unsafeShiftL, unsafeShiftR, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Choice as C
import Data.Word (Word8)
import Data.Word.Limb (Limb (..))
import Data.Word.Wider (Wider (..))
import qualified Data.Word.Wider as W
import Foreign.Ptr (Ptr)
import Foreign.Storable (pokeByteOff)
import GHC.Exts (Word (..))
import qualified Numeric.Montgomery.Secp256k1.Scalar as S

-- Group order ----------------------------------------------------------------

-- | The secp256k1 group order \(n\).
curveOrder :: Integer
curveOrder = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

-- | The secp256k1 field size \(p\).
fieldSize :: Integer
fieldSize = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

-- | Reduction modulo \(n\) (variable-time: public values only).
modQ :: Integer -> Integer
modQ x = x `mod` curveOrder

-- Public scalars -------------------------------------------------------------

-- | Big-endian bytes to a non-negative 'Integer' (variable-time: public values only).
bytesToInteger :: ByteString -> Integer
bytesToInteger = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | A non-negative 'Integer' below \(2^{256}\) to 32 big-endian bytes (variable-time: public values only).
integerToBytes32 :: Integer -> ByteString
integerToBytes32 i = fst (BS.unfoldrN 32 step 31)
 where
  step :: Int -> Maybe (Word8, Int)
  step j = Just (fromInteger (i `shiftR` (8 * j)), j - 1)

-- | @int(h) mod n@ for a 32-byte hash @h@ that is public (variable-time).
hashToScalar :: ByteString -> Integer
hashToScalar = modQ . bytesToInteger

-- Secret scalars -------------------------------------------------------------

{- | A secret scalar modulo \(n\), in the Montgomery form of @ppad-fixed@
(always fully reduced, so in \([0, n)\)).

Every operation on it runs in constant time. Deliberately has no 'Show',
'Eq', 'Ord', 'Num' or other instance that could compare, print or convert it
in variable time.
-}
newtype SecScalar = SecScalar S.Montgomery

instance NFData SecScalar where
  rnf (SecScalar m) = rnf m

-- | \(n\) as four limbs.
orderWider :: Wider
orderWider = W.wider 0xBFD25E8CD0364141 0xBAAEDCE6AF48A03B 0xFFFFFFFFFFFFFFFE 0xFFFFFFFFFFFFFFFF

-- | Zero as four limbs.
zeroWider :: Wider
zeroWider = W.wider 0 0 0 0

{- | A secret scalar from 32 big-endian bytes in \([1, n)\).

Only the length is checked in variable time. The range check compares the
limbs in constant time and decides once, on the combined result; only the
outcome (valid, zero or out of range) is revealed.
-}
secScalarFromBytes :: ByteString -> Either DecodeError SecScalar
secScalarFromBytes b
  | BS.length b /= 32 = Left (InvalidLength 32 (BS.length b))
  | C.decide (C.and (W.gt w zeroWider) (W.lt w orderWider)) = Right $! SecScalar (S.to w)
  | C.decide (W.gt w zeroWider) = Left ScalarOutOfRange
  | otherwise = Left ScalarZero
 where
  w = widerFromBytes b

{- | @int(b) mod n@ as a secret scalar, for exactly 32 bytes @b@: a hash
that becomes a secret nonce, or the stored bytes of a scalar already in
\([0, n)\) (which the reduction leaves unchanged).

The reduction is the conversion into Montgomery form: a Montgomery
multiplication by \(R^2 \bmod n\) followed by one constant-time conditional
subtraction. It is exact for every 256-bit input because
\(b \cdot (R^2 \bmod n) < R \cdot n\).
-}
secScalarFromBytesModQ :: ByteString -> SecScalar
secScalarFromBytesModQ b = SecScalar (S.to (widerFromBytes b))

-- | The 32-byte big-endian encoding of a secret scalar, in constant time.
secScalarToBytes :: SecScalar -> ByteString
secScalarToBytes = widerToBytes . secScalarWider

-- | A secret scalar as a plain 'Wider' word in \([0, n)\), e.g. for @ppad-secp256k1@'s @mul_wnaf@.
secScalarWider :: SecScalar -> Wider
secScalarWider (SecScalar m) = S.retr m

-- | A public 'Integer' in Montgomery form (variable-time in the 'Integer').
publicMontgomery :: Integer -> S.Montgomery
publicMontgomery x = S.to (W.to_vartime (modQ x))

-- | A public flag as a 'C.Choice'.
choice :: Bool -> C.Choice
choice True = C.true# ()
choice False = C.false# ()

-- Secret arithmetic ----------------------------------------------------------

{- | The scalar of a BIP-327 partial signature:

\[
s = k_1' + b \cdot k_2' + e \cdot a \cdot d \pmod n
\]

where \(k_i' = n - k_i\) when the final nonce \(R\) has odd \(y\) and
\(d = g \cdot gacc \cdot d'\), i.e. \(d'\) negated when
\(g \cdot gacc = -1\).

This is the only place where secret scalars are combined. The secrets stay
in Montgomery form throughout: additions, multiplications and the
negations (selected with a constant-time 'S.select', although both flags are
public) run in constant time. Only the result \(s\), the public partial
signature, is converted to an 'Integer'.
-}
signScalar ::
  -- | \(k_1\) (secret).
  SecScalar ->
  -- | \(k_2\) (secret).
  SecScalar ->
  -- | \(d'\), the secret key (secret).
  SecScalar ->
  -- | Negate the nonce (\(R\) has odd \(y\)).
  Bool ->
  -- | Negate the secret key (\(g \cdot gacc = n - 1\)).
  Bool ->
  -- | Nonce coefficient \(b\) (public).
  Integer ->
  -- | \(e \cdot a \bmod n\) (public).
  Integer ->
  -- | \(s\) (public).
  Integer
signScalar (SecScalar k1) (SecScalar k2) (SecScalar d) negateNonce negateKey b ea =
  let k = S.add k1 (S.mul (publicMontgomery b) k2)
      k' = S.select k (S.neg k) (choice negateNonce)
      d' = S.select d (S.neg d) (choice negateKey)
   in W.from_vartime (S.retr (S.add k' (S.mul (publicMontgomery ea) d')))

-- Constant-time byte conversions ---------------------------------------------

{- | The first 32 bytes, big-endian, as a 'Wider' word: shifts and ors with
no branch on the data.

These conversions are vendored instead of @ppad-secp256k1@'s
@unsafe_roll32@ and @unroll32@, which that package exports for testing and
benchmarking only. Precondition: at least 32 bytes (checked; the length is
public).
-}
widerFromBytes :: ByteString -> Wider
widerFromBytes b
  | BS.length b < 32 = error "widerFromBytes: fewer than 32 bytes"
  | otherwise = W.wider (limbAt 24) (limbAt 16) (limbAt 8) (limbAt 0)
 where
  limbAt :: Int -> Word
  limbAt off =
    byteAt off 56
      .|. byteAt (off + 1) 48
      .|. byteAt (off + 2) 40
      .|. byteAt (off + 3) 32
      .|. byteAt (off + 4) 24
      .|. byteAt (off + 5) 16
      .|. byteAt (off + 6) 8
      .|. byteAt (off + 7) 0
  byteAt :: Int -> Int -> Word
  byteAt i s = fromIntegral (BU.unsafeIndex b i) `unsafeShiftL` s

-- | A 'Wider' word as 32 big-endian bytes, with no branch on the data.
widerToBytes :: Wider -> ByteString
widerToBytes (Wider (# Limb w0, Limb w1, Limb w2, Limb w3 #)) = BI.unsafeCreate 32 $ \p -> do
  pokeLimb p 0 (W# w3)
  pokeLimb p 8 (W# w2)
  pokeLimb p 16 (W# w1)
  pokeLimb p 24 (W# w0)
 where
  pokeLimb :: Ptr Word8 -> Int -> Word -> IO ()
  pokeLimb p off w = do
    pokeByte p off (w `unsafeShiftR` 56)
    pokeByte p (off + 1) (w `unsafeShiftR` 48)
    pokeByte p (off + 2) (w `unsafeShiftR` 40)
    pokeByte p (off + 3) (w `unsafeShiftR` 32)
    pokeByte p (off + 4) (w `unsafeShiftR` 24)
    pokeByte p (off + 5) (w `unsafeShiftR` 16)
    pokeByte p (off + 6) (w `unsafeShiftR` 8)
    pokeByte p (off + 7) w
  pokeByte :: Ptr Word8 -> Int -> Word -> IO ()
  pokeByte p off x = pokeByteOff p off (fromIntegral x :: Word8)
