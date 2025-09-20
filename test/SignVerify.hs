{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-x-partial #-}

module SignVerify (testSignVerify) where

import Control.Exception (ErrorCall (..), evaluate, try)
import Crypto.Curve.Secp256k1 (Pub)
import Crypto.Curve.Secp256k1.MuSig2 (PubNonce (..), SecKey (..), SecNonce (..), aggNonces, mkSessionContext, partialSigVerify, sign)
import Crypto.Curve.Secp256k1.MuSig2.Internal (bytesToInteger)
import Data.ByteString (ByteString)
import Data.List (isInfixOf)
import Data.Maybe (fromJust)
import Test.Tasty
import Test.Tasty.HUnit
import Util (decodeHex, parsePoint, parsePubNonce)

-- | Input public keys from BIP327 test vectors
inputPubkeys :: [Pub]
inputPubkeys =
  map
    parsePoint
    [ "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
    , "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    , "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661"
    , "020000000000000000000000000000000000000000000000000000000000000007"
    ]

-- | Public nonces from BIP327 test vectors
inputPubNonces :: [PubNonce]
inputPubNonces =
  map
    parsePubNonce
    [ "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
    , "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    , "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046"
    , "0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
    , "0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
    ]

-- | Messages from BIP327 test vectors
testMessages :: [ByteString]
testMessages =
  [ decodeHex "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"
  , ""
  , decodeHex "2626262626262626262626262626262626262626262626262626262626262626262626262626"
  ]

-- | Valid test vector data: (key indices, nonce indices, msg index, signer index, expected signature)
validTestVectors :: [([Int], [Int], Int, Int, ByteString)]
validTestVectors =
  [ ([0, 1, 2], [0, 1, 2], 0, 0, decodeHex "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB")
  , ([1, 0, 2], [1, 0, 2], 0, 1, decodeHex "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52")
  , ([1, 2, 0], [1, 2, 0], 0, 2, decodeHex "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900")
  , ([0, 1, 2], [0, 1, 2], 1, 0, decodeHex "D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D") -- Empty message
  , ([0, 1, 2], [0, 1, 2], 2, 0, decodeHex "E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C") -- 38-byte message
  ]

-- | Invalid test vector data: (signature, key indices, nonce indices, msg index, signer index, expected to fail)
invalidTestVectors :: [(ByteString, [Int], [Int], Int, Int, String)]
invalidTestVectors =
  [ (decodeHex "FED54434AD4CFE953FC527DC6A5E5BE8F6234907B7C187559557CE87A0541C46", [0, 1, 2], [0, 1, 2], 0, 0, "Wrong signature (negation of valid signature)")
  , (decodeHex "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB", [0, 1, 2], [0, 1, 2], 0, 1, "Wrong signer")
  ]

-- | Error test vector data: (signature, key indices, nonce indices, msg index, signer index, expected error message)
errorTestVectors :: [(ByteString, [Int], [Int], Int, Int, String)]
errorTestVectors =
  [ (decodeHex "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB", [0, 1, 2], [4, 1, 2], 0, 0, "Invalid pubnonce")
  , (decodeHex "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB", [3, 1, 2], [0, 1, 2], 0, 0, "Invalid pubkey")
  , (decodeHex "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", [0, 1, 2], [0, 1, 2], 0, 0, "Signature exceeds group size")
  ]

-- | Valid secret key from BIP327 test vectors
testSecKey :: SecKey
testSecKey = SecKey $ bytesToInteger $ decodeHex "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671"

-- | Invalid secret nonce with k1 = 0 (from BIP327 test vectors secnonce index 1)
invalidSecNonce :: SecNonce
invalidSecNonce = SecNonce{k1 = 0, k2 = 0}

-- | Creates test case from valid test vector data
makeValidTestCase :: Int -> ([Int], [Int], Int, Int, ByteString) -> TestTree
makeValidTestCase i (keyIndices, nonceIndices, msgIndex, signerIndex, expectedSig) =
  testCase ("BIP327 valid test vector " <> show (i + 1)) $ do
    let selectedKeys = map (inputPubkeys !!) keyIndices
        selectedNonces = map (inputPubNonces !!) nonceIndices
        msg = testMessages !! msgIndex
        signature = bytesToInteger expectedSig

    -- Test that the valid signature verifies
    let result = partialSigVerify signature selectedNonces selectedKeys [] msg signerIndex
    assertBool "Valid signature should verify" result

-- | Creates test case from invalid test vector data
makeInvalidTestCase :: Int -> (ByteString, [Int], [Int], Int, Int, String) -> TestTree
makeInvalidTestCase i (sigBytes, keyIndices, nonceIndices, msgIndex, signerIndex, comment) =
  testCase ("BIP327 invalid test vector " <> show (i + 1) <> ": " <> comment) $ do
    let selectedKeys = map (inputPubkeys !!) keyIndices
        selectedNonces = map (inputPubNonces !!) nonceIndices
        msg = testMessages !! msgIndex
        signature = bytesToInteger sigBytes

    -- Test that the invalid signature fails verification
    let result = partialSigVerify signature selectedNonces selectedKeys [] msg signerIndex
    assertBool ("Invalid signature should not verify: " <> comment) (not result)

-- | Creates test case from error test vector data
makeErrorTestCase :: Int -> (ByteString, [Int], [Int], Int, Int, String) -> TestTree
makeErrorTestCase i (sigBytes, keyIndices, nonceIndices, msgIndex, signerIndex, comment) =
  testCase ("BIP327 error test vector " <> show (i + 1) <> ": " <> comment) $ do
    let selectedKeys = map (inputPubkeys !!) keyIndices
        selectedNonces = map (inputPubNonces !!) nonceIndices
        msg = testMessages !! msgIndex
        signature = bytesToInteger sigBytes

    -- Test that this causes an error during verification
    result <- try $ evaluate $ partialSigVerify signature selectedNonces selectedKeys [] msg signerIndex
    case result of
      Left (ErrorCall _) -> return () -- Expected error
      Right _ -> assertFailure ("Expected error but verification succeeded: " <> comment)

-- | Test case for invalid secret nonce (k1 = 0) from BIP327 sign_error_test_cases
testInvalidSecNonce :: TestTree
testInvalidSecNonce =
  testCase "BIP327 sign error: first secnonce value is out of range" $ do
    let selectedKeys = take 3 inputPubkeys -- [0, 1, 2]
        selectedNonces = take 3 inputPubNonces -- [0, 1, 2]
        msg = head testMessages -- msg_index 0
        aggNonce = fromJust $ aggNonces selectedNonces
        ctx = mkSessionContext aggNonce selectedKeys [] msg

    result <- try $ evaluate $ sign invalidSecNonce testSecKey ctx
    case result of
      Left (ErrorCall errMsg) ->
        assertBool
          ("Expected error message containing 'first secret scalar k1 is zero', got: " ++ errMsg)
          ("first secret scalar k1 is zero" `isInfixOf` errMsg)
      Right _ -> assertFailure "Expected error but signing succeeded"

-- | Test vectors from [BIP327 `sign_verify_vectors.json`](https://github.com/bitcoin/bips/blob/master/bip-0327/vectors/sign_verify_vectors.json)
testSignVerify :: TestTree
testSignVerify =
  testGroup "sign and verify" $
    zipWith makeValidTestCase [0 ..] validTestVectors
      <> zipWith makeInvalidTestCase [0 ..] invalidTestVectors
      <> zipWith makeErrorTestCase [0 ..] errorTestVectors
      <> [testInvalidSecNonce]
