{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Util (parsePoint, parseScalar, parsePubNonce, extractXOnly, decodeHex, Rand32 (..), Scalar (..)) where

import Crypto.Curve.Secp256k1 (Projective, Pub, mul, parse_point, serialize_point, _CURVE_G, _CURVE_Q, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2 (PubNonce (..), SecKey (..), SecNonce (..), SecNonceGenParams (..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Maybe (fromJust)
import Test.Tasty.QuickCheck (Arbitrary (..), Gen, choose, frequency, vectorOf)

{- | Parses a 'ByteString' into a 'Pub'key.

This is a test YOLO function that blows up on your face if you don't
supply proper string representations.
-}
parsePoint :: ByteString -> Pub
parsePoint s = case B16.decode s of
  Left p -> error $ "cannot decode point" <> show p
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

-- | Custom 'Gen' for 'ByteString' that generates maximum length of 1,024.
arbitraryBS :: Gen ByteString
arbitraryBS = do
  len <- choose (0, 1024) :: Gen Int -- Limit size to avoid excessive memory use
  BS.pack <$> vectorOf len arbitrary

-- | 'Arbitrary' instance for 'ByteString'.
instance Arbitrary ByteString where
  arbitrary = arbitraryBS

-- | Scalar type for testing secret keys.
newtype Scalar = Scalar Integer deriving (Show, Eq)

-- | 'Arbitrary' instance for 'Scalar' to be within curve order.
instance Arbitrary Scalar where
  arbitrary = Scalar <$> choose (1, _CURVE_Q - 1)

-- | 32-byte 'ByteString' for testing hashes.
newtype Rand32 = Rand32 ByteString deriving (Show, Eq)

-- | 'Arbitrary' instance for 'Rand32'.
instance Arbitrary Rand32 where
  arbitrary = Rand32 . BS.pack <$> vectorOf 32 arbitrary

{- | 'Arbitrary' instance for 'SecNonceGenParams'.

Slightly biased towards 'Just' than 'Nothing'.
-}
instance Arbitrary SecNonceGenParams where
  arbitrary = do
    _pk <- arbitrary
    _sk <- frequency [(2, return Nothing), (3, genMaybeSecKey)]
    _aggpk <- frequency [(2, return Nothing), (3, Just <$> arbitrary)]
    _msg <- frequency [(2, return Nothing), (3, Just <$> arbitraryBS)]
    _extraIn <- frequency [(2, return Nothing), (3, Just <$> arbitraryBS)]
    return SecNonceGenParams{..}
   where
    genMaybeSecKey :: Gen (Maybe SecKey)
    genMaybeSecKey = do
      (Scalar i) <- arbitrary
      return $ Just (SecKey i)

{- | 'Show' instance for 'SecNonceGenParams'.

Should only used for testing purposes, hence why it is only defined in this test module.
-}
instance Show SecNonceGenParams where
  show (SecNonceGenParams _pk _sk _aggpk _msg _extraIn) =
    let showMaybeBS mb = case mb of
          Nothing -> "Nothing"
          Just bs -> "Just (ByteString of length " ++ show (BS.length bs) ++ ")"
        showSk msk = case msk of
          Nothing -> "Nothing"
          Just sk -> "Just " ++ show sk
     in "SecNonceGenParams {_pk = "
          ++ show _pk
          ++ ", _sk = "
          ++ showSk _sk
          ++ ", _aggpk = "
          ++ show _aggpk
          ++ ", _msg = "
          ++ showMaybeBS _msg
          ++ ", _extraIn = "
          ++ showMaybeBS _extraIn
          ++ "}"

-- | 'Arbitrary' instance for 'PubNonce'.
instance Arbitrary PubNonce where
  arbitrary :: Gen PubNonce
  arbitrary = do
    r1' <- arbitrary
    r2' <- arbitrary
    return $ PubNonce{r1 = r1', r2 = r2'}

-- | 'Arbitrary' instace of 'SecNonce'.
instance Arbitrary SecNonce where
  arbitrary = do
    k1 <- choose (1, _CURVE_Q - 1) -- Ensure non-zero
    k2 <- choose (1, _CURVE_Q - 1) -- Ensure non-zero
    return SecNonce{k1 = k1, k2 = k2}

{- | 'Show' instance for 'SecNonce'.

Should only used for testing purposes, hence why it is only defined in this test module.
-}
instance Show SecNonce where
  show (SecNonce k1 k2) =
    "SecNonce { k1=" ++ show k1 ++ ", k2=" ++ show k2 ++ "}"

-- | 'Arbitrary' instace of 'SecKey'.
instance Arbitrary SecKey where
  arbitrary = do
    sk <- choose (1, _CURVE_Q - 1) -- Ensure non-zero
    return (SecKey sk)

{- | 'Show' instance for 'SecKey'.

Should only used for testing purposes, hence why it is only defined in this test module.
-}
instance Show SecKey where
  show (SecKey int) = "SecKey " ++ show int

{- | Parses a 'ByteString' into a 'PubNonce'.

Mostly used to parse BIP327 test vectors.
-}
parsePubNonce :: ByteString -> PubNonce
parsePubNonce bs = PubNonce{r1 = r1', r2 = r2'}
 where
  r1' = parsePoint $ BS.take 66 bs
  r2' = parsePoint $ BS.drop 66 bs
