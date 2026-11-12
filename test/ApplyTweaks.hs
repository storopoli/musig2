{-# LANGUAGE OverloadedStrings #-}

-- | Tweak test vectors from the Rust @musig2@ crate (@test_aggregation_context_tweaks@).
module ApplyTweaks (testApplyTweaks) where

import Control.Monad ((>=>))
import Crypto.Curve.Secp256k1.MuSig2 (PubKey, aggPubKey, applyPlainTweak, applyTaprootTweak, applyXOnlyTweak, encode, keyAgg)
import Data.List.NonEmpty (NonEmpty (..))
import Test.Tasty
import Test.Tasty.HUnit
import Util (decodeHex, hexOf, tweakFromInt, unsafeDecode, unsafeRight)

testPubkeys :: NonEmpty PubKey
testPubkeys =
  fmap
    unsafeDecode
    ( "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
        :| [ "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
           , "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
           ]
    )

testApplyTweaks :: TestTree
testApplyTweaks =
  testGroup
    "applying tweaks (Rust musig2 crate vectors)"
    [ testCase "x-only, x-only, plain, plain" $ do
        let tweaks =
              applyXOnlyTweak (tweakFromInt 0xE8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB)
                >=> applyXOnlyTweak (tweakFromInt 0xAE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455)
                >=> applyPlainTweak (tweakFromInt 0xF52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0)
                >=> applyPlainTweak (tweakFromInt 0x1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D)
            ctx = unsafeRight (keyAgg testPubkeys >>= tweaks)
        hexOf (encode (aggPubKey ctx)) @?= "0269434B39A026A4AAC9E6C1AEBDD3993FFA581C8F7F21B6FAAE15608057F5CE85"
    , testCase "Taproot tweak with a merkle root" $ do
        let ctx = unsafeRight (keyAgg testPubkeys >>= applyTaprootTweak (Just (decodeHex "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")))
        hexOf (encode (aggPubKey ctx)) @?= "024650CCA5E389F62E960F66CA0400927A7727FC6E84B9C38A1FD9A80271377CEB"
    ]
