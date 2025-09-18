{-# LANGUAGE OverloadedStrings #-}

module ApplyTweaks (testApplyTweaks) where

import Crypto.Curve.Secp256k1 (Pub, parse_point)
import Crypto.Curve.Secp256k1.MuSig2 (KeyAggContext (..), Tweak (..), applyTweak, mkKeyAggContext)
import Crypto.Curve.Secp256k1.MuSig2.Internal (bytesToInteger, hashTag)
import Data.ByteString (ByteString)
import Data.Maybe (fromJust)
import Test.Tasty
import Test.Tasty.HUnit
import Util (decodeHex, extractXOnly, parsePoint)

-- | Computes taproot tweak from pubkey and merkle root.
computeTaprootTweak :: Pub -> ByteString -> Integer
computeTaprootTweak pubkey merkleRoot =
  let pubkeyXOnly = extractXOnly pubkey
      tweakHash = hashTag "TapTweak" (pubkeyXOnly <> merkleRoot)
   in bytesToInteger tweakHash

-- | Test pubkeys from the Rust's `musig2` crate `test_aggregation_context_tweaks`.
testPubkeys :: [Pub]
testPubkeys =
  map
    parsePoint
    [ "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
    , "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    , "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
    ]

-- | Test case: Sequence of tweaks matching `test_aggregation_context_tweaks` from Rust's `musig2` crate.
testTweakSequence :: TestTree
testTweakSequence =
  testCase "Tweak sequence" $ do
    let keyAggCtx1 = mkKeyAggContext testPubkeys Nothing

    -- Apply first X-only tweak
    let tweak1 = XOnlyTweak 0xE8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB
        keyAggCtx2 = applyTweak keyAggCtx1 tweak1

    -- Apply second X-only tweak
    let tweak2 = XOnlyTweak 0xAE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455
        keyAggCtx3 = applyTweak keyAggCtx2 tweak2

    -- Apply third plain tweak
    let tweak3 = PlainTweak 0xF52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0
        keyAggCtx4 = applyTweak keyAggCtx3 tweak3

    -- Apply fourth plain tweak
    let tweak4 = PlainTweak 0x1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D
        finalKeyAggCtx = applyTweak keyAggCtx4 tweak4
        finalAggPk = q finalKeyAggCtx
        expected = fromJust $ parse_point $ decodeHex "0269434B39A026A4AAC9E6C1AEBDD3993FFA581C8F7F21B6FAAE15608057F5CE85"

    expected @=? finalAggPk

-- | Test case: Taproot tweak with merkle root matching `test_aggregation_context_tweaks` from Rust's `musig2` crate.
testTaprootTweak :: TestTree
testTaprootTweak =
  testCase "Taproot tweak with merkle root" $ do
    let keyAggCtx = mkKeyAggContext testPubkeys Nothing
        originalPk = q keyAggCtx
        merkleRootBytes = decodeHex "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        -- Compute proper taproot tweak hash
        taprootTweakValue = computeTaprootTweak originalPk merkleRootBytes
        taprootTweak = XOnlyTweak taprootTweakValue
        tweakedCtx = applyTweak keyAggCtx taprootTweak
        tweakedPk = q tweakedCtx
        expected = fromJust $ parse_point $ decodeHex "024650cca5e389f62e960f66ca0400927a7727fc6e84b9c38a1fd9a80271377ceb"

    expected @=? tweakedPk

-- | Test vectors the Rust's `musig2` crate `test_aggregation_context_tweaks`.
testApplyTweaks :: TestTree
testApplyTweaks =
  testGroup
    "applying tweaks"
    [ testTweakSequence
    , testTaprootTweak
    ]
