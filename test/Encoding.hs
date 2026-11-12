{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

{- | Encodings: every 'Encode' instance round-trips, and decoders reject
everything that is not a canonical encoding.
-}
module Encoding (testEncoding) where

import Crypto.Curve.Secp256k1 (Projective (..), _CURVE_G, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2 (
  AggNonce,
  DecodeError (..),
  Encode (..),
  PartialSignature,
  PubKey,
  PubNonce,
  Signature,
  Tweak,
  XOnlyPubKey,
  pubKeyFromPoint,
  pubKeyPoint,
  pubKeyXOnly,
  secKeyFromBytes,
  secKeyPubKey,
  secKeyToBytes,
 )
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (curveOrder, fieldSize, integerToBytes32)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Types (Signature (..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (..))
import Generators
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Util (isOnCurveX)

testEncoding :: TestTree
testEncoding =
  testGroup
    "Encodings"
    [ testGroup
        "round trips"
        [ roundTrip "PubKey" 33 genPubKey
        , roundTrip "XOnlyPubKey" 32 (pubKeyXOnly <$> genPubKey)
        , roundTrip "PubNonce" 66 genPubNonce
        , roundTrip "AggNonce (halves may be infinity)" 66 genAggNonce
        , roundTrip "PartialSignature" 32 genPartialSignature
        , roundTrip "Tweak" 32 genTweak
        , roundTrip "Signature" 64 genSignature
        , testProperty "SecKey through secKeyFromBytes/secKeyToBytes" $
            forAll genNonZeroScalar $ \d ->
              fmap secKeyToBytes (secKeyFromBytes (integerToBytes32 d)) === Right (integerToBytes32 d)
        , testProperty "pubKeyFromPoint . pubKeyPoint" . forAll genPubKey $ \pk ->
            pubKeyFromPoint (pubKeyPoint pk) === Right pk
        , testProperty "Eq and Ord agree with the encoding" . forAll ((,) <$> genPubKey <*> genPubKey) $ \(a, b) ->
            (a == b) === (encode a == encode b) .&&. compare a b === compare (encode a) (encode b)
        ]
    , testGroup
        "wrong lengths"
        [ wrongLength (Proxy :: Proxy PubKey) 33
        , wrongLength (Proxy :: Proxy XOnlyPubKey) 32
        , wrongLength (Proxy :: Proxy PubNonce) 66
        , wrongLength (Proxy :: Proxy AggNonce) 66
        , wrongLength (Proxy :: Proxy PartialSignature) 32
        , wrongLength (Proxy :: Proxy Tweak) 32
        , wrongLength (Proxy :: Proxy Signature) 64
        , testProperty "SecKey" . forAll (lengthOtherThan 32) $ \b ->
            either Just (const Nothing) (secKeyFromBytes b) === Just (InvalidLength 32 (BS.length b))
        , testCase "PubKey rejects the 32-byte x-only and 65-byte uncompressed forms" $ do
            let pk = secKeyPubKey (unsafeSecKey 7)
            decodeAs @PubKey (BS.drop 1 (encode pk)) @?= Left (InvalidLength 33 32)
            decodeAs @PubKey (BS.replicate 65 4) @?= Left (InvalidLength 33 65)
        ]
    , testGroup
        "invalid points"
        [ testProperty "PubKey: prefix other than 02/03" . forAll ((,) <$> genPubKey <*> prefixByte) $ \(pk, p) ->
            decodeAs @PubKey (BS.cons p (BS.drop 1 (encode pk))) === Left InvalidPoint
        , testProperty "PubKey: x not below p" . forAll ((,) <$> elements [2, 3] <*> choose (fieldSize, 2 ^ (256 :: Int) - 1)) $ \(p, x) ->
            decodeAs @PubKey (BS.cons p (integerToBytes32 x)) === Left InvalidPoint
        , testProperty "PubKey: x not on the curve" . forAll ((,) <$> elements [2, 3] <*> offCurveX) $ \(p, x) ->
            decodeAs @PubKey (BS.cons p (integerToBytes32 x)) === Left InvalidPoint
        , testProperty "XOnlyPubKey: x not on the curve or not below p" . forAll (oneof [offCurveX, choose (fieldSize, 2 ^ (256 :: Int) - 1)]) $ \x ->
            decodeAs @XOnlyPubKey (integerToBytes32 x) === Left InvalidPoint
        , testCase "PubKey: infinity (33 zero bytes)" $ decodeAs @PubKey (BS.replicate 33 0) @?= Left PointAtInfinity
        , testProperty "PubNonce: rejects infinity in either half" . forAll genPubNonce $ \pn ->
            decodeAs @PubNonce (BS.replicate 33 0 <> BS.drop 33 (encode pn)) === Left PointAtInfinity
              .&&. decodeAs @PubNonce (BS.take 33 (encode pn) <> BS.replicate 33 0) === Left PointAtInfinity
        , testCase "AggNonce: accepts infinity in both halves" $
            fmap encode (decodeAs @AggNonce (BS.replicate 66 0)) @?= Right (BS.replicate 66 0)
        , testProperty "PubNonce and AggNonce: invalid point in either half" . forAll ((,) <$> genPubNonce <*> offCurveX) $ \(pn, x) ->
            let bad = BS.cons 2 (integerToBytes32 x)
             in decodeAs @PubNonce (bad <> BS.drop 33 (encode pn)) === Left InvalidPoint
                  .&&. decodeAs @AggNonce (BS.take 33 (encode pn) <> bad) === Left InvalidPoint
        , testCase "pubKeyFromPoint: infinity and points off the curve" $ do
            pubKeyFromPoint _CURVE_ZERO @?= Left PointAtInfinity
            pubKeyFromPoint (Projective 1 1 1) @?= Left InvalidPoint
            fmap encode (pubKeyFromPoint _CURVE_G) @?= Right (encode (secKeyPubKey (unsafeSecKey 1)))
        ]
    , testGroup
        "scalars out of range"
        [ testProperty "PartialSignature, Tweak: >= n" . forAll aboveOrder $ \s ->
            decodeAs @PartialSignature (integerToBytes32 s) === Left ScalarOutOfRange
              .&&. decodeAs @Tweak (integerToBytes32 s) === Left ScalarOutOfRange
        , testCase "PartialSignature, Tweak: 0 and n - 1 are valid" $ do
            fmap encode (decodeAs @PartialSignature (integerToBytes32 0)) @?= Right (integerToBytes32 0)
            fmap encode (decodeAs @Tweak (integerToBytes32 (curveOrder - 1))) @?= Right (integerToBytes32 (curveOrder - 1))
        , testProperty "Signature: s >= n" . forAll ((,) <$> choose (0, fieldSize - 1) <*> aboveOrder) $ \(r, s) ->
            decodeAs @Signature (integerToBytes32 r <> integerToBytes32 s) === Left ScalarOutOfRange
        , testProperty "Signature: r >= p" . forAll (choose (fieldSize, 2 ^ (256 :: Int) - 1)) $ \r ->
            decodeAs @Signature (integerToBytes32 r <> integerToBytes32 1) === Left InvalidPoint
        , testProperty "SecKey: >= n" . forAll aboveOrder $ \d ->
            either Just (const Nothing) (secKeyFromBytes (integerToBytes32 d)) === Just ScalarOutOfRange
        , testCase "SecKey: zero" $
            either Just (const Nothing) (secKeyFromBytes (BS.replicate 32 0)) @?= Just ScalarZero
        ]
    ]
 where
  unsafeSecKey d = either (error . show) id (secKeyFromBytes (integerToBytes32 d))
  genSignature = do
    r <- choose (0, fieldSize - 1)
    s <- genScalar
    pure (Signature (integerToBytes32 r <> integerToBytes32 s))
  prefixByte = fromIntegral <$> (choose (0, 255 :: Int) `suchThat` (`notElem` [2, 3]))
  aboveOrder = oneof [pure curveOrder, choose (curveOrder, 2 ^ (256 :: Int) - 1)]
  offCurveX = choose (0, fieldSize - 1) `suchThat` (not . isOnCurveX)

decodeAs :: forall a. (Encode a) => ByteString -> Either DecodeError a
decodeAs = decode

roundTrip :: forall a. (Encode a, Eq a, Show a) => String -> Int -> Gen a -> TestTree
roundTrip name len gen = testProperty name . forAll gen $ \x ->
  decode (encode x) === Right x .&&. BS.length (encode x) === len

lengthOtherThan :: Int -> Gen ByteString
lengthOtherThan n = choose (0, 100) `suchThat` (/= n) >>= genBytes

wrongLength :: forall a. (Encode a, Show a, Eq a) => Proxy a -> Int -> TestTree
wrongLength _ n = testProperty ("length /= " <> show n) . forAll (lengthOtherThan n) $ \b ->
  (decode b :: Either DecodeError a) === Left (InvalidLength n (BS.length b))
