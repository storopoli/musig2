{-# LANGUAGE OverloadedStrings #-}

module AggNonces (testAggNonces) where

import Crypto.Curve.Secp256k1 (_CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2 (PubNonce (..), aggNonces)
import Test.Tasty
import Test.Tasty.HUnit
import Util (parsePoint, parsePubNonce, unsafeRight)

-- | Input 'PubNonce's from BIP-0327 test vectors
inputPubNonces :: [PubNonce]
inputPubNonces =
  map
    parsePubNonce
    [ "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641"
    , "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833"
    , "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    , "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    ]

-- | Test vector data: (input 'PubNonce' indices, expected 'PubNonce' result).
testVectors :: [([Int], PubNonce)]
testVectors =
  [ ([0, 1], parsePubNonce "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8")
  , -- Sum of second points encoded in the nonces is point at infinity which is serialized as 33 zero bytes.
    ([2, 3], PubNonce (parsePoint "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B") _CURVE_ZERO)
  ]

-- | Creates test case from vector data.
makeTestCase :: Int -> ([Int], PubNonce) -> TestTree
makeTestCase i (indices, expected) =
  testCase ("BIP-0327 test vector " <> show (i + 1)) $
    unsafeRight aggNonce @=? expected
 where
  selectedNonces = map (inputPubNonces !!) indices
  aggNonce = aggNonces selectedNonces

-- | Test vectors from [BIP-0327 `nonce_agg_vectors.json`](https://github.com/bitcoin/bips/blob/master/bip-0327/vectors/nonce_agg_vectors.json).
testAggNonces :: TestTree
testAggNonces =
  testGroup "aggregating pubkeys" $
    zipWith makeTestCase [0 ..] testVectors
