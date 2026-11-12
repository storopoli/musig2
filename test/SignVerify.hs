{-# LANGUAGE OverloadedStrings #-}

{- | Input validation in 'mkSecNonce', 'mkSessionContext' and 'sign'.

The BIP-0327 @sign_verify_vectors.json@ cases run in "OfficialVectors".
-}
module SignVerify (testSignVerify) where

import Crypto.Curve.Secp256k1 (derive_pub, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2 (MuSig2Error (..), SecKey (..), aggNonces, mkSecNonce, mkSessionContext, publicNonce, sign)
import Data.Maybe (fromMaybe)
import Test.Tasty
import Test.Tasty.HUnit
import Util (parsePubNonce, unsafeMkSecNonce, unsafeRight)

testInvalidSecNonce :: TestTree
testInvalidSecNonce =
  testCase "mkSecNonce rejects zero scalars" $
    case mkSecNonce invalidSecNoncePub 1 0 of
      Left (SecretScalarZero "k2") -> pure ()
      Left err -> assertFailure $ "Expected SecretScalarZero \"k2\", got: Left " ++ show err
      Right _ -> assertFailure "Expected Left, got Right"
 where
  invalidSecNoncePub = fromMaybe (error "Failed to derive pubkey") $ derive_pub 1

testContextRejectsInfinityPubkey :: TestTree
testContextRejectsInfinityPubkey =
  testCase "mkSessionContext rejects infinity public keys" $ do
    let aggNonce = unsafeRight $ aggNonces [pubNonce]
    case mkSessionContext aggNonce [_CURVE_ZERO] [] "msg" of
      Left PublicKeyAtInfinity -> pure ()
      _ -> assertFailure "Expected Left PublicKeyAtInfinity"
 where
  -- First public nonce of BIP-0327 @sign_verify_vectors.json@.
  pubNonce = parsePubNonce "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"

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
  testGroup
    "sign and verify input validation"
    [testInvalidSecNonce, testContextRejectsInfinityPubkey, testSignerKeyMismatch]
