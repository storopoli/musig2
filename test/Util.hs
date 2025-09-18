{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Util (parsePoint, parseScalar, Arbitrary, extractXOnly, decodeHex) where

import Crypto.Curve.Secp256k1 (Projective, Pub, mul, parse_point, serialize_point, _CURVE_G, _CURVE_Q, _CURVE_ZERO)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Maybe (fromJust)
import Test.Tasty.QuickCheck (Arbitrary (..), Gen, choose, frequency)

{- | Parses a 'ByteString' into a 'Pub'key.

This is a test YOLO function that blows up on your face if you don't
supply proper string representations.
-}
parsePoint :: ByteString -> Pub
parsePoint s = case B16.decode s of
  Left _ -> error "cannot decode point"
  Right p -> (fromJust . parse_point) p

-- | Parses a hex 'ByteString' into an 'Integer' scalar.
parseScalar :: ByteString -> Integer
parseScalar = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 . decodeHex

-- | Extracts X-coordinate from compressed point serialization.
extractXOnly :: Pub -> ByteString
extractXOnly = BS.drop 1 . serialize_point

-- | Decodes hex string to 'ByteString'.
decodeHex :: ByteString -> ByteString
decodeHex h = case B16.decode h of
  Right bs -> bs
  Left _ -> error "Invalid hex string in test vector"

{- | 'Arbitrary' instance for 'Projective'.

Generate points as scalar multiples of the generator,
including the identity with low probability (1%).
-}
instance Arbitrary Projective where
  arbitrary :: Gen Projective
  arbitrary =
    frequency
      [ (1, return _CURVE_ZERO) -- Include identity occasionally
      ,
        ( 99
        , do
            scalar <- choose (0, _CURVE_Q)
            return (mul _CURVE_G scalar)
        )
      ]
