{-# LANGUAGE OverloadedStrings #-}

module AggPubkeys (testAggPubkeys) where

import Crypto.Curve.Secp256k1 (Pub)
import Crypto.Curve.Secp256k1.MuSig2 (MuSig2Error (..), Tweak (..), aggregatedPubkey, mkKeyAggContext)
import Data.ByteString (ByteString)
import Test.Tasty
import Test.Tasty.HUnit
import Util (decodeHex, extractXOnly, parsePoint, unsafeRight)

-- | Input public keys from BIP-0327 test vectors
inputPubkeys :: [Pub]
inputPubkeys =
  map
    parsePoint
    [ "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    , "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
    , "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"
    , "020000000000000000000000000000000000000000000000000000000000000005"
    , "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
    , "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    , "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
    ]

-- | Test vector data: (input key indices, expected x-only result).
testVectors :: [([Int], ByteString)]
testVectors =
  [ ([0, 1, 2], decodeHex "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C")
  , ([2, 1, 0], decodeHex "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B")
  , ([0, 0, 0], decodeHex "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935")
  , ([0, 0, 1, 1], decodeHex "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E")
  ]

-- | Tweak test vectors from BIP-0327.
tweaks :: [Integer]
tweaks =
  [ 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 -- curve order (invalid)
  , 0x252E4BD67410A76CDF933D30EAA1608214037F1B105A013ECCD3C5C184A6110B -- tweak that causes infinity
  ]

invalidTweakOutOfRange :: Integer
invalidTweakOutOfRange = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

-- | Error test cases: (key indices, tweak index, is_xonly, expected error).
errorTestVectors :: [([Int], Int, Bool, MuSig2Error)]
errorTestVectors =
  [ ([0, 1], 0, True, TweakOutOfRange invalidTweakOutOfRange)
  , ([6], 1, False, TweakResultAtInfinity)
  ]

-- | Creates test case from vector data.
makeTestCase :: Int -> ([Int], ByteString) -> TestTree
makeTestCase i (indices, expected) =
  testCase ("BIP-0327 test vector " <> show (i + 1)) $
    extractXOnly aggPk @=? expected
 where
  selectedKeys = map (inputPubkeys !!) indices
  keyAggCtx = unsafeRight $ mkKeyAggContext selectedKeys Nothing
  aggPk = aggregatedPubkey keyAggCtx

-- | Creates error test case from vector data.
makeErrorTestCase :: Int -> ([Int], Int, Bool, MuSig2Error) -> TestTree
makeErrorTestCase i (keyIndices, tweakIndex, isXOnly, expectedMsg) =
  testCase ("BIP-0327 error test vector " <> show (i + 1)) $ do
    case mkKeyAggContext selectedKeys (Just tweak) of
      Left err -> err @?= expectedMsg
      Right _ -> assertFailure "Expected error but got success"
 where
  selectedKeys = map (inputPubkeys !!) keyIndices
  tweakVal = tweaks !! tweakIndex
  tweak = if isXOnly then XOnlyTweak tweakVal else PlainTweak tweakVal

-- | Test vectors from [BIP-0327 `key_agg_vectors.json`](https://github.com/bitcoin/bips/blob/master/bip-0327/vectors/key_agg_vectors.json).
testAggPubkeys :: TestTree
testAggPubkeys =
  testGroup "aggregating pubkeys" $
    zipWith makeTestCase [0 ..] testVectors
      <> zipWith makeErrorTestCase [0 ..] errorTestVectors
