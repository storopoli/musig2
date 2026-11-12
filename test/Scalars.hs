{-# LANGUAGE MultiWayIf #-}

{- | The constant-time secret scalar arithmetic against an 'Integer'
reference modulo \(n\), and the range checks of secret scalars and keys at
their boundaries.
-}
module Scalars (testScalars) where

import Crypto.Curve.Secp256k1 (neg, _CURVE_G)
import Crypto.Curve.Secp256k1.MuSig2 (DecodeError (..), pubKeyPoint, secKeyFromBytes, secKeyPubKey, secKeyToBytes)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (
  bytesToInteger,
  curveOrder,
  integerToBytes32,
  secScalarFromBytes,
  secScalarFromBytesModQ,
  secScalarToBytes,
  signScalar,
  widerFromBytes,
  widerToBytes,
 )
import qualified Data.ByteString as BS
import qualified Data.Word.Wider as W
import Generators (genBytes, genNonZeroScalar, genScalar)
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Util (secScalarFromInt)

testScalars :: TestTree
testScalars =
  testGroup
    "Constant-time scalars"
    [ testGroup
        "byte conversions"
        [ testProperty "widerFromBytes agrees with the Integer decoding" . forAll gen256 $ \x ->
            W.from_vartime (widerFromBytes (integerToBytes32 x)) === x
        , testProperty "widerToBytes . widerFromBytes = id" . forAll (genBytes 32) $ \b ->
            widerToBytes (widerFromBytes b) === b
        , testCase "edge values round-trip" $
            mapM_ (\x -> widerToBytes (widerFromBytes (integerToBytes32 x)) @?= integerToBytes32 x) edges
        ]
    , testGroup
        "reduction modulo n"
        [ testProperty "secScalarFromBytesModQ is int(b) mod n" . forAll gen256 $ \x ->
            reduced x === x `mod` curveOrder
        , testCase "edge values: 0, 1, n - 1, n, n + 1, 2^256 - 2, 2^256 - 1" $
            mapM_ (\x -> reduced x @?= x `mod` curveOrder) edges
        ]
    , testGroup
        "signScalar"
        [ testProperty "agrees with the Integer reference" $
            forAll ((,,) <$> genNonZeroScalar <*> genNonZeroScalar <*> genNonZeroScalar) $ \(k1, k2, d) ->
              forAll ((,,,) <$> arbitrary <*> arbitrary <*> genScalar <*> genScalar) $ \(negNonce, negKey, b, ea) ->
                signScalar (secScalarFromInt k1) (secScalarFromInt k2) (secScalarFromInt d) negNonce negKey b ea
                  === referenceSignScalar k1 k2 d negNonce negKey b ea
        , testCase "k = k1 + b k2 = 0 (negating zero gives zero)" $
            mapM_
              ( \(negNonce, negKey) ->
                  signScalar (secScalarFromInt (curveOrder - 1)) (secScalarFromInt 1) (secScalarFromInt 5) negNonce negKey 1 7
                    @?= referenceSignScalar (curveOrder - 1) 1 5 negNonce negKey 1 7
              )
              [(False, False), (True, False), (False, True), (True, True)]
        , testCase "public coefficients at the edges: 0, 1, n - 1" $
            sequence_
              [ signScalar (secScalarFromInt k1) (secScalarFromInt k2) (secScalarFromInt d) True True b ea
                  @?= referenceSignScalar k1 k2 d True True b ea
              | k1 <- [1, curveOrder - 1]
              , k2 <- [1, curveOrder - 1]
              , d <- [1, curveOrder - 1]
              , b <- [0, 1, curveOrder - 1]
              , ea <- [0, 1, curveOrder - 1]
              ]
        ]
    , testGroup
        "range checks"
        [ testCase "secScalarFromBytes at the boundaries" $ do
            failure (secScalarFromBytes (integerToBytes32 0)) @?= Just ScalarZero
            failure (secScalarFromBytes (integerToBytes32 curveOrder)) @?= Just ScalarOutOfRange
            failure (secScalarFromBytes (integerToBytes32 (2 ^ (256 :: Int) - 1))) @?= Just ScalarOutOfRange
            failure (secScalarFromBytes (BS.replicate 31 1)) @?= Just (InvalidLength 32 31)
            fmap secScalarToBytes (secScalarFromBytes (integerToBytes32 1)) @?= Right (integerToBytes32 1)
            fmap secScalarToBytes (secScalarFromBytes (integerToBytes32 (curveOrder - 1))) @?= Right (integerToBytes32 (curveOrder - 1))
        , testProperty "secScalarFromBytes accepts exactly [1, n)" . forAll gen256 $ \x ->
            fmap secScalarToBytes (secScalarFromBytes (integerToBytes32 x))
              === if
                | x == 0 -> Left ScalarZero
                | x >= curveOrder -> Left ScalarOutOfRange
                | otherwise -> Right (integerToBytes32 x)
        , testCase "secKeyFromBytes: 0, 1, n - 1, n, 2^256 - 1" $ do
            failure (secKeyFromBytes (integerToBytes32 0)) @?= Just ScalarZero
            failure (secKeyFromBytes (integerToBytes32 curveOrder)) @?= Just ScalarOutOfRange
            failure (secKeyFromBytes (integerToBytes32 (2 ^ (256 :: Int) - 1))) @?= Just ScalarOutOfRange
            let one = secKeyFromBytes (integerToBytes32 1)
                minusOne = secKeyFromBytes (integerToBytes32 (curveOrder - 1))
            fmap secKeyToBytes one @?= Right (integerToBytes32 1)
            fmap secKeyToBytes minusOne @?= Right (integerToBytes32 (curveOrder - 1))
            fmap (pubKeyPoint . secKeyPubKey) one @?= Right _CURVE_G
            fmap (pubKeyPoint . secKeyPubKey) minusOne @?= Right (neg _CURVE_G)
        ]
    ]
 where
  reduced x = bytesToInteger (secScalarToBytes (secScalarFromBytesModQ (integerToBytes32 x)))
  failure :: Either e a -> Maybe e
  failure = either Just (const Nothing)

-- | A 256-bit value, uniform or one of the 'edges'.
gen256 :: Gen Integer
gen256 = frequency [(1, elements edges), (4, choose (0, 2 ^ (256 :: Int) - 1)), (2, choose (curveOrder, 2 ^ (256 :: Int) - 1))]

-- | Boundary values for 256-bit inputs.
edges :: [Integer]
edges = [0, 1, curveOrder - 1, curveOrder, curveOrder + 1, 2 ^ (256 :: Int) - 2, 2 ^ (256 :: Int) - 1]

-- | The 'Integer' arithmetic 'signScalar' replaced.
referenceSignScalar :: Integer -> Integer -> Integer -> Bool -> Bool -> Integer -> Integer -> Integer
referenceSignScalar k1 k2 d negateNonce negateKey b ea =
  let k = (k1 + b * k2) `mod` curveOrder
      k' = if negateNonce then (curveOrder - k) `mod` curveOrder else k
      d' = if negateKey then curveOrder - d else d
   in (k' + ea * d') `mod` curveOrder
