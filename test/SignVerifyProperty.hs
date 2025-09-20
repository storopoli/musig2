{-# LANGUAGE OverloadedStrings #-}

module SignVerifyProperty (propertySignVerify) where

import Crypto.Curve.Secp256k1 (derive_pub, _CURVE_Q)
import Crypto.Curve.Secp256k1.MuSig2 (SecKey (..), SecNonce (..), aggNonces, mkSessionContext, partialSigVerify, publicNonce, sign)
import Data.ByteString (ByteString)
import Data.Maybe (fromJust)
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Util ()

propertySignVerify :: TestTree
propertySignVerify =
  testGroup
    "sign and partialSigVerify Properties"
    [ testProperty "Valid Signature Range" prop_validSignatureRange
    , testProperty "Sign-Verify Roundtrip" prop_signVerifyRoundtrip
    , testProperty "Signature Determinism" prop_signatureDeterminism
    , testProperty "Invalid Signer Index Fails" prop_invalidSignerIndex
    ]

-- | Property: Generated signatures are in the valid range \([0, Q-1]\).
prop_validSignatureRange :: SecNonce -> SecKey -> ByteString -> Property
prop_validSignatureRange secNonce secKey@(SecKey sk) msg =
  let pubkey = derive_pub sk
      pubNonce = publicNonce secNonce
      pubNonces = [pubNonce]
      pubkeys = [pubkey]
      aggNonce = fromJust $ aggNonces pubNonces
      ctx = mkSessionContext aggNonce pubkeys [] msg
      sig = sign secNonce secKey ctx
   in (sig >= 0) .&&. (sig < _CURVE_Q)

-- | Property: A signature created with sign verifies with 'partialSigVerify'.
prop_signVerifyRoundtrip :: SecNonce -> SecKey -> ByteString -> Property
prop_signVerifyRoundtrip secNonce secKey@(SecKey sk) msg =
  let pubkey = derive_pub sk
      pubNonce = publicNonce secNonce
      pubNonces = [pubNonce]
      pubkeys = [pubkey]
      aggNonce = fromJust $ aggNonces pubNonces
      ctx = mkSessionContext aggNonce pubkeys [] msg
      sig = sign secNonce secKey ctx
      signerIndex = 0 -- We're always the first signer in this test
      result = partialSigVerify sig pubNonces pubkeys [] msg signerIndex
   in result === True

-- | Property: Signing the same message with the same parameters produces the same signature.
prop_signatureDeterminism :: SecNonce -> SecKey -> ByteString -> Property
prop_signatureDeterminism secNonce secKey@(SecKey sk) msg =
  let pubkey = derive_pub sk
      pubNonce = publicNonce secNonce
      pubNonces = [pubNonce]
      pubkeys = [pubkey]
      aggNonce = fromJust $ aggNonces pubNonces
      ctx = mkSessionContext aggNonce pubkeys [] msg
      sig1 = sign secNonce secKey ctx
      sig2 = sign secNonce secKey ctx
   in sig1 === sig2

-- | Property: Using an invalid signer index should fail verification.
prop_invalidSignerIndex :: SecNonce -> SecKey -> ByteString -> Property
prop_invalidSignerIndex secNonce secKey@(SecKey sk) msg =
  let pubkey = derive_pub sk
      pubNonce = publicNonce secNonce
      pubNonces = [pubNonce]
      pubkeys = [pubkey]
      aggNonce = fromJust $ aggNonces pubNonces
      ctx = mkSessionContext aggNonce pubkeys [] msg
      sig = sign secNonce secKey ctx
      invalidIndex = 1 -- Out of bounds index (only 1 signer at index 0)
      result = partialSigVerify sig pubNonces pubkeys [] msg invalidIndex
   in expectFailure (result === True)
