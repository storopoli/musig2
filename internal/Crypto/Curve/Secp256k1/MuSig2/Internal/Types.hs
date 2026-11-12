{-# LANGUAGE MultiWayIf #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Types
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

Keys, nonces, signatures and tweaks, with their BIP-327 byte encodings.

The constructors exported here bypass validation; only this library and its
tests may use them. Every value must satisfy the invariant documented on its
type.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Types (
  -- * Encodings
  Encode (..),
  hexString,

  -- * Public keys
  PubKey (..),
  mkPubKey,
  pubKeyFromPoint,
  pubKeyPoint,
  pubKeyXOnly,
  pubKeyHasEvenY,
  XOnlyPubKey (..),

  -- * Secret keys
  SecKey (..),
  secKeyFromBytes,
  secKeyToBytes,
  secKeyPubKey,

  -- * Tweaks
  Tweak (..),
  tweakFromBytes,

  -- * Nonces
  PubNonce (..),
  mkPubNonce,
  AggNonce (..),
  mkAggNonce,

  -- * Signatures
  PartialSignature (..),
  Signature (..),

  -- * Decoding helpers
  decodeCPoint,
  decodeCPointExt,
  decodeScalar,
  expectLength,
) where

import Control.DeepSeq (NFData (..))
import Crypto.Curve.Secp256k1 (Projective, neg, parse_point, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Error (DecodeError (..))
import Crypto.Curve.Secp256k1.MuSig2.Internal.Point (cbytes, cbytesExt, hasEvenYBytes, infinityBytes, isInfinity, isValidPoint, mulGSecret)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (SecScalar, bytesToInteger, curveOrder, fieldSize, integerToBytes32, secScalarFromBytes, secScalarToBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

-- Encodings ------------------------------------------------------------------

{- | Types with a canonical BIP-327 byte encoding.

@'decode' . 'encode' = 'Right'@, and 'decode' accepts exactly the canonical
encodings: it rejects wrong lengths, invalid points and out-of-range scalars.
Secrets have no instance.
-}
class Encode a where
  -- | The canonical encoding.
  encode :: a -> ByteString

  -- | Parses and validates an encoding.
  decode :: ByteString -> Either DecodeError a

-- | Lower-case hexadecimal.
hexString :: ByteString -> String
hexString = BS.foldr (\w acc -> nibble (w `div` 16) : nibble (w `mod` 16) : acc) []
 where
  nibble :: Word8 -> Char
  nibble n = "0123456789abcdef" !! fromIntegral n

-- | Shows a value as its constructor name applied to its hex encoding.
showsHex :: String -> ByteString -> Int -> ShowS
showsHex name bytes d = showParen (d > 10) (showString name . showString " " . shows (hexString bytes))

-- | Fails unless the input has the given length.
expectLength :: Int -> ByteString -> Either DecodeError ()
expectLength n b
  | BS.length b == n = Right ()
  | otherwise = Left (InvalidLength n (BS.length b))

{- | @cpoint@: exactly 33 bytes, prefix @0x02@ or @0x03@, \(x < p\) on the
curve. Rejects 32-byte (x-only) and 65-byte (uncompressed) forms, which
'parse_point' would accept.
-}
decodeCPoint :: ByteString -> Either DecodeError Projective
decodeCPoint b = do
  expectLength 33 b
  if
    | b == infinityBytes -> Left PointAtInfinity
    | BS.index b 0 /= 0x02 && BS.index b 0 /= 0x03 -> Left InvalidPoint
    | otherwise -> maybe (Left InvalidPoint) Right (parse_point b)

-- | @cpoint_ext@: like 'decodeCPoint', but 33 zero bytes is the point at infinity.
decodeCPointExt :: ByteString -> Either DecodeError Projective
decodeCPointExt b
  | b == infinityBytes = Right _CURVE_ZERO
  | otherwise = decodeCPoint b

-- | A 32-byte big-endian scalar below \(n\) (zero allowed).
decodeScalar :: ByteString -> Either DecodeError Integer
decodeScalar b = do
  expectLength 32 b
  let x = bytesToInteger b
  if x >= curveOrder then Left ScalarOutOfRange else Right x

-- Public keys ----------------------------------------------------------------

{- | A public key: a finite point on the curve.

Caches its 33-byte compressed encoding; 'Eq' and 'Ord' compare that encoding
(the order is the one BIP-327 @KeySort@ uses), and 'Show' prints it in hex.
-}
data PubKey = PubKey
  { pubKeyPt :: !Projective
  -- ^ The point (finite, on the curve).
  , pubKeyBytes :: !ByteString
  -- ^ Its 33-byte compressed encoding.
  }

-- | The public key as a @ppad-secp256k1@ point.
pubKeyPoint :: PubKey -> Projective
pubKeyPoint = pubKeyPt

instance Eq PubKey where
  a == b = pubKeyBytes a == pubKeyBytes b

instance Ord PubKey where
  compare a b = compare (pubKeyBytes a) (pubKeyBytes b)

instance Show PubKey where
  showsPrec d x = showsHex "PubKey" (pubKeyBytes x) d

instance NFData PubKey where
  rnf (PubKey p b) = p `seq` rnf b

instance Encode PubKey where
  encode = pubKeyBytes
  decode b = (`PubKey` b) <$> decodeCPoint b

-- | A t'PubKey' from a point already known to be finite and on the curve.
mkPubKey :: Projective -> PubKey
mkPubKey p = PubKey p (cbytes p)

-- | A t'PubKey' from any point: rejects infinity and points not on the curve.
pubKeyFromPoint :: Projective -> Either DecodeError PubKey
pubKeyFromPoint p
  | isInfinity p = Left PointAtInfinity
  | not (isValidPoint p) = Left InvalidPoint
  | otherwise = Right (mkPubKey p)

-- | Whether the point has an even y-coordinate.
pubKeyHasEvenY :: PubKey -> Bool
pubKeyHasEvenY = hasEvenYBytes . pubKeyBytes

{- | A BIP-340 x-only public key: the finite point with the given
x-coordinate and an even y-coordinate.

'Eq', 'Ord' and 'Show' use the 32-byte encoding.
-}
data XOnlyPubKey = XOnlyPubKey
  { xOnlyPoint :: !Projective
  -- ^ The point with even y.
  , xOnlyBytes :: !ByteString
  -- ^ Its 32-byte x-coordinate.
  }

instance Eq XOnlyPubKey where
  a == b = xOnlyBytes a == xOnlyBytes b

instance Ord XOnlyPubKey where
  compare a b = compare (xOnlyBytes a) (xOnlyBytes b)

instance Show XOnlyPubKey where
  showsPrec d x = showsHex "XOnlyPubKey" (xOnlyBytes x) d

instance NFData XOnlyPubKey where
  rnf (XOnlyPubKey p b) = p `seq` rnf b

instance Encode XOnlyPubKey where
  encode = xOnlyBytes
  decode b = do
    expectLength 32 b
    -- 'parse_point' lifts 32 bytes as a BIP-340 key: x < p, on the curve, even y.
    p <- maybe (Left InvalidPoint) Right (parse_point b)
    Right (XOnlyPubKey p b)

-- | The x-only key of a public key (negated to even y if needed).
pubKeyXOnly :: PubKey -> XOnlyPubKey
pubKeyXOnly pk =
  XOnlyPubKey
    (if pubKeyHasEvenY pk then pubKeyPoint pk else neg (pubKeyPoint pk))
    (BS.drop 1 (pubKeyBytes pk))

-- Secret keys ----------------------------------------------------------------

{- | A secret key \(0 < d < n\), with its public key.

The scalar is a t'SecScalar': it is parsed, encoded and computed with in
constant time, and never held in an 'Integer'.

Deliberately has no 'Show', 'Eq', 'Ord', 'Read', 'Num' or 'Encode' instance.
-}
data SecKey = SecKey
  { secKeyScalar :: !SecScalar
  -- ^ \(d\).
  , secKeyPub :: !PubKey
  -- ^ \(d \cdot G\).
  }

-- | The public key \(d \cdot G\) of a secret key.
secKeyPubKey :: SecKey -> PubKey
secKeyPubKey = secKeyPub

instance NFData SecKey where
  rnf (SecKey d p) = rnf d `seq` rnf p

{- | A secret key from 32 big-endian bytes in \([1, n)\), checked in
constant time (see 'secScalarFromBytes').
-}
secKeyFromBytes :: ByteString -> Either DecodeError SecKey
secKeyFromBytes b = do
  d <- secScalarFromBytes b
  case mulGSecret d of
    Nothing -> Left ScalarZero
    Just p -> Right (SecKey d (mkPubKey p))

-- | The 32-byte big-endian encoding of a secret key, in constant time.
secKeyToBytes :: SecKey -> ByteString
secKeyToBytes = secScalarToBytes . secKeyScalar

-- Tweaks -------------------------------------------------------------------------

{- | A tweak \(0 \le t < n\) (zero allowed, as in BIP-327).

'Eq', 'Ord' and 'Show' use the 32-byte encoding.
-}
newtype Tweak = Tweak
  { tweakScalar :: Integer
  -- ^ \(t\).
  }
  deriving (Eq, Ord)

instance Show Tweak where
  showsPrec d x = showsHex "Tweak" (encode x) d

instance NFData Tweak where
  rnf (Tweak t) = rnf t

instance Encode Tweak where
  encode = integerToBytes32 . tweakScalar
  decode b = Tweak <$> decodeScalar b

-- | 'decode' for t'Tweak'.
tweakFromBytes :: ByteString -> Either DecodeError Tweak
tweakFromBytes = decode

-- Nonces ---------------------------------------------------------------------

{- | A signer's public nonce \((R_1, R_2)\): two finite points.

'Eq', 'Ord' and 'Show' use the 66-byte encoding.
-}
data PubNonce = PubNonce
  { pubNonceR1 :: !Projective
  -- ^ \(R_1\).
  , pubNonceR2 :: !Projective
  -- ^ \(R_2\).
  , pubNonceBytes :: !ByteString
  -- ^ @cbytes(R1) || cbytes(R2)@.
  }

instance Eq PubNonce where
  a == b = pubNonceBytes a == pubNonceBytes b

instance Ord PubNonce where
  compare a b = compare (pubNonceBytes a) (pubNonceBytes b)

instance Show PubNonce where
  showsPrec d x = showsHex "PubNonce" (pubNonceBytes x) d

instance NFData PubNonce where
  rnf (PubNonce r1 r2 b) = r1 `seq` r2 `seq` rnf b

instance Encode PubNonce where
  encode = pubNonceBytes
  decode b = do
    expectLength 66 b
    r1 <- decodeCPoint (BS.take 33 b)
    r2 <- decodeCPoint (BS.drop 33 b)
    Right (PubNonce r1 r2 b)

-- | A t'PubNonce' from two points already known to be finite and on the curve.
mkPubNonce :: Projective -> Projective -> PubNonce
mkPubNonce r1 r2 = PubNonce r1 r2 (cbytes r1 <> cbytes r2)

{- | An aggregate nonce \((R_1, R_2)\); either point may be infinity.

'Eq', 'Ord' and 'Show' use the 66-byte encoding (infinity as 33 zero bytes).
-}
data AggNonce = AggNonce
  { aggNonceR1 :: !Projective
  -- ^ \(R_1\).
  , aggNonceR2 :: !Projective
  -- ^ \(R_2\).
  , aggNonceBytes :: !ByteString
  -- ^ @cbytes_ext(R1) || cbytes_ext(R2)@.
  }

instance Eq AggNonce where
  a == b = aggNonceBytes a == aggNonceBytes b

instance Ord AggNonce where
  compare a b = compare (aggNonceBytes a) (aggNonceBytes b)

instance Show AggNonce where
  showsPrec d x = showsHex "AggNonce" (aggNonceBytes x) d

instance NFData AggNonce where
  rnf (AggNonce r1 r2 b) = r1 `seq` r2 `seq` rnf b

instance Encode AggNonce where
  encode = aggNonceBytes
  decode b = do
    expectLength 66 b
    r1 <- decodeCPointExt (BS.take 33 b)
    r2 <- decodeCPointExt (BS.drop 33 b)
    Right (AggNonce r1 r2 b)

-- | An t'AggNonce' from two points on the curve (or infinity).
mkAggNonce :: Projective -> Projective -> AggNonce
mkAggNonce r1 r2 = AggNonce r1 r2 (cbytesExt r1 <> cbytesExt r2)

-- Signatures -----------------------------------------------------------------

{- | A partial signature \(0 \le s < n\).

'Eq', 'Ord' and 'Show' use the 32-byte encoding.
-}
newtype PartialSignature = PartialSignature
  { partialSigScalar :: Integer
  -- ^ \(s\).
  }
  deriving (Eq, Ord)

instance Show PartialSignature where
  showsPrec d x = showsHex "PartialSignature" (encode x) d

instance NFData PartialSignature where
  rnf (PartialSignature s) = rnf s

instance Encode PartialSignature where
  encode = integerToBytes32 . partialSigScalar
  decode b = PartialSignature <$> decodeScalar b

{- | A 64-byte BIP-340 Schnorr signature @R.x || s@ with \(R.x < p\) and
\(s < n\).

'Eq', 'Ord' and 'Show' use the encoding.
-}
newtype Signature = Signature
  { signatureBytes :: ByteString
  -- ^ The 64 bytes.
  }
  deriving (Eq, Ord)

instance Show Signature where
  showsPrec d x = showsHex "Signature" (signatureBytes x) d

instance NFData Signature where
  rnf (Signature b) = rnf b

instance Encode Signature where
  encode = signatureBytes
  decode b = do
    expectLength 64 b
    if bytesToInteger (BS.take 32 b) >= fieldSize
      then Left InvalidPoint
      else Signature b <$ decodeScalar (BS.drop 32 b)
