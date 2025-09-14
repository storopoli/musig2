{-# LANGUAGE OverloadedStrings #-}

module ParityPub (testParityPub) where

import Crypto.Curve.Secp256k1.MuSig2 (isEvenPub)
import Test.Tasty
import Test.Tasty.HUnit
import Util (parsePoint)

-- | Some examples from [BIP327 test vectors](https://github.com/bitcoin/bips/tree/master/bip-0327/vectors).
testParityPub :: TestTree
testParityPub =
  testGroup
    "isEvenPub"
    [ testCase "Even compressed key" $ assertBool "Pubkey is even" (isEvenPub $ parsePoint "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8")
    , testCase "Odd compressed key" $ assertBool "Pubkey is not even" (not $ isEvenPub $ parsePoint "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
    , testCase "X-only key" $ assertBool "X-only pubkeys are always even" (isEvenPub $ parsePoint "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B")
    ]
