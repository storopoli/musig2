{-# LANGUAGE OverloadedStrings #-}

module SignVerify (testSignVerify) where

import Crypto.Curve.Secp256k1 (Pub, derive_pub, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2 (MuSig2Error (..), PubNonce, SecKey (..), aggNonces, mkSecNonce, mkSessionContext, partialSigVerify, publicNonce, sign)
import Crypto.Curve.Secp256k1.MuSig2.Internal (bytesToInteger)
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import Test.Tasty
import Test.Tasty.HUnit
import Util (decodeHex, parsePoint, parsePubNonce, unsafeMkSecNonce, unsafeRight)

-- | Input public keys from BIP-0327 test vectors.
inputPubkeys :: [Pub]
inputPubkeys =
  map
    parsePoint
    [ "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
    , "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    , "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661"
    , "020000000000000000000000000000000000000000000000000000000000000007"
    ]

-- | Public nonces from BIP-0327 test vectors.
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

-- | Messages from BIP-0327 test vectors.
testMessages :: [ByteString]
testMessages =
  [ decodeHex "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"
  , ""
  , decodeHex "2626262626262626262626262626262626262626262626262626262626262626262626262626"
  ]

validTestVectors :: [([Int], [Int], Int, Int, ByteString)]
validTestVectors =
  [ ([0, 1, 2], [0, 1, 2], 0, 0, decodeHex "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB")
  , ([1, 0, 2], [1, 0, 2], 0, 1, decodeHex "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52")
  , ([1, 2, 0], [1, 2, 0], 0, 2, decodeHex "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900")
  , ([0, 1, 2], [0, 1, 2], 1, 0, decodeHex "D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D")
  , ([0, 1, 2], [0, 1, 2], 2, 0, decodeHex "E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C")
  ]

invalidTestVectors :: [(ByteString, [Int], [Int], Int, Int, String)]
invalidTestVectors =
  [ (decodeHex "FED54434AD4CFE953FC527DC6A5E5BE8F6234907B7C187559557CE87A0541C46", [0, 1, 2], [0, 1, 2], 0, 0, "Wrong signature (negation of valid signature)")
  , (decodeHex "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB", [0, 1, 2], [0, 1, 2], 0, 1, "Wrong signer")
  ]

errorTestVectors :: [(ByteString, [Int], [Int], Int, Int, MuSig2Error)]
errorTestVectors =
  [ (decodeHex "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", [0, 1, 2], [0, 1, 2], 0, 0, PartialSignatureOutOfRange)
  ]

invalidSecNoncePub :: Pub
invalidSecNoncePub = fromMaybe (error "Failed to derive pubkey") $ derive_pub 1

makeValidTestCase :: Int -> ([Int], [Int], Int, Int, ByteString) -> TestTree
makeValidTestCase i (keyIndices, nonceIndices, msgIndex, signerIndex, expectedSig) =
  testCase ("BIP-0327 valid test vector " <> show (i + 1)) $ do
    let selectedKeys = map (inputPubkeys !!) keyIndices
        selectedNonces = map (inputPubNonces !!) nonceIndices
        msg = testMessages !! msgIndex
        signature = bytesToInteger expectedSig
    partialSigVerify signature selectedNonces selectedKeys [] msg signerIndex @?= Right True

makeInvalidTestCase :: Int -> (ByteString, [Int], [Int], Int, Int, String) -> TestTree
makeInvalidTestCase i (sigBytes, keyIndices, nonceIndices, msgIndex, signerIndex, comment) =
  testCase ("BIP-0327 invalid test vector " <> show (i + 1) <> ": " <> comment) $ do
    let selectedKeys = map (inputPubkeys !!) keyIndices
        selectedNonces = map (inputPubNonces !!) nonceIndices
        msg = testMessages !! msgIndex
        signature = bytesToInteger sigBytes
    partialSigVerify signature selectedNonces selectedKeys [] msg signerIndex @?= Right False

makeErrorTestCase :: Int -> (ByteString, [Int], [Int], Int, Int, MuSig2Error) -> TestTree
makeErrorTestCase i (sigBytes, keyIndices, nonceIndices, msgIndex, signerIndex, expectedError) =
  testCase ("BIP-0327 error test vector " <> show (i + 1)) $ do
    let selectedKeys = map (inputPubkeys !!) keyIndices
        selectedNonces = map (inputPubNonces !!) nonceIndices
        msg = testMessages !! msgIndex
        signature = bytesToInteger sigBytes
    partialSigVerify signature selectedNonces selectedKeys [] msg signerIndex @?= Left expectedError

testInvalidSecNonce :: TestTree
testInvalidSecNonce =
  testCase "mkSecNonce rejects zero scalars" $
    case mkSecNonce invalidSecNoncePub 1 0 of
      Left (SecretScalarZero "k2") -> pure ()
      Left err -> assertFailure $ "Expected SecretScalarZero \"k2\", got: Left " ++ show err
      Right _ -> assertFailure "Expected Left, got Right"

testContextRejectsInfinityPubkey :: TestTree
testContextRejectsInfinityPubkey =
  testCase "mkSessionContext rejects infinity public keys" $ do
    let aggNonce = unsafeRight $ aggNonces [firstPubNonce]
    case mkSessionContext aggNonce [_CURVE_ZERO] [] "msg" of
      Left PublicKeyAtInfinity -> pure ()
      _ -> assertFailure "Expected Left PublicKeyAtInfinity"
 where
  firstPubNonce = case inputPubNonces of
    nonce : _ -> nonce
    [] -> error "Expected at least one input public nonce"

testSignerKeyMismatch :: TestTree
testSignerKeyMismatch =
  testCase "sign rejects nonce/key mismatches" $ do
    let signerPub = fromMaybe (error "Failed to derive signer pubkey") $ derive_pub 2
        secNonce = unsafeMkSecNonce signerPub 5 7
        aggNonce = unsafeRight $ aggNonces [unsafeRight $ publicNonce secNonce]
        ctx = unsafeRight $ mkSessionContext aggNonce [signerPub] [] "msg"
    sign secNonce (SecKey 3) ctx @?= Left SecretKeyPublicKeyMismatch

testSignVerify :: TestTree
testSignVerify =
  testGroup "sign and verify" $
    zipWith makeValidTestCase [0 ..] validTestVectors
      <> zipWith makeInvalidTestCase [0 ..] invalidTestVectors
      <> zipWith makeErrorTestCase [0 ..] errorTestVectors
      <> [testInvalidSecNonce, testContextRejectsInfinityPubkey, testSignerKeyMismatch]
