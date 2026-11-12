-- | Helpers shared by the test modules.
module Util (
  decodeHex,
  hexOf,
  unsafeRight,
  unsafeDecode,
  secKeyFromInt,
  tweakFromInt,
  psigFromInt,
  secNonceFromInts,
  secScalarFromInt,
  pubNonceFromInts,
  failsWith,
  decodeEach,
  isOnCurveX,
) where

import Crypto.Curve.Secp256k1.MuSig2 (DecodeError, Encode (..), PartialSignature, PubKey, PubNonce, SecKey, SecNonce, Tweak, secKeyFromBytes)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (pubNonceFromScalars, secNonceFromScalars)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (SecScalar, fieldSize, integerToBytes32, secScalarFromBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import Data.Char (toUpper)
import Data.Maybe (fromMaybe)
import Test.Tasty.HUnit (Assertion, (@?=))

-- | Decodes hex; fails the test on invalid input.
decodeHex :: ByteString -> ByteString
decodeHex h = either (error . ("invalid hex in test: " <>)) id (B16.decode h)

-- | Upper-case hex, as in the BIP-327 vector files.
hexOf :: ByteString -> String
hexOf = map toUpper . BC.unpack . B16.encode

unsafeRight :: (Show e) => Either e a -> a
unsafeRight = either (error . show) id

-- | Decodes a hex encoding; fails the test on invalid input.
unsafeDecode :: (Encode a) => ByteString -> a
unsafeDecode = unsafeRight . decode . decodeHex

-- | A secret key from a test scalar in \([1, n)\).
secKeyFromInt :: Integer -> SecKey
secKeyFromInt = unsafeRight . secKeyFromBytes . integerToBytes32

-- | A secret scalar from a test scalar in \([1, n)\).
secScalarFromInt :: Integer -> SecScalar
secScalarFromInt = unsafeRight . secScalarFromBytes . integerToBytes32

-- | The public nonce of two test scalars in \([1, n)\).
pubNonceFromInts :: Integer -> Integer -> PubNonce
pubNonceFromInts k1 k2 = fromMaybe (error "zero nonce") (pubNonceFromScalars (secScalarFromInt k1) (secScalarFromInt k2))

tweakFromInt :: Integer -> Tweak
tweakFromInt = unsafeRight . decode . integerToBytes32

psigFromInt :: Integer -> PartialSignature
psigFromInt = unsafeRight . decode . integerToBytes32

-- | A fresh secret nonce from its scalars; fails the test if they are out of range.
secNonceFromInts :: Integer -> Integer -> PubKey -> IO SecNonce
secNonceFromInts k1 k2 pk = unsafeRight <$> secNonceFromScalars (secScalarFromInt k1) (secScalarFromInt k2) pk

{- | Decodes each byte string in order; the first failure comes with its
position, as BIP-327 blames the signer who sent it.
-}
decodeEach :: (Encode a) => [ByteString] -> Either (Int, DecodeError) [a]
decodeEach = traverse (\(i, b) -> either (Left . (,) i) Right (decode b)) . zip [0 ..]

-- | Whether \(x < p\) is the x-coordinate of a point (Euler's criterion on \(x^3 + 7\)).
isOnCurveX :: Integer -> Bool
isOnCurveX x = x < fieldSize && powMod (x * x * x + 7) ((fieldSize - 1) `div` 2) fieldSize /= fieldSize - 1
 where
  powMod b e m = go (b `mod` m) e 1
   where
    go _ 0 acc = acc
    go base k acc = go (base * base `mod` m) (k `div` 2) (if odd k then acc * base `mod` m else acc)

-- | Runs an action that must fail with exactly the given error.
failsWith :: (Eq e, Show e) => e -> IO (Either e a) -> Assertion
failsWith expected action = action >>= \result -> either Just (const Nothing) result @?= Just expected
