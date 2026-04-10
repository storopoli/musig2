{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module SignVerifyProperty (propertySignVerify) where

import Crypto.Curve.Secp256k1.MuSig2 (MuSig2Error (..), aggNonces, mkSessionContext, partialSigVerify, publicNonce, sign)
import Crypto.Curve.Secp256k1.MuSig2.Internal (curveOrder)
import Data.ByteString (ByteString)
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Util (SignerMaterial (..), unsafeRight)

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
prop_validSignatureRange :: SignerMaterial -> ByteString -> Property
prop_validSignatureRange signer msg =
  let pubNonce = unsafeRight $ publicNonce signer.signerSecNonce
      pubNonces = [pubNonce]
      pubkeys = [signer.signerPubKey]
      aggNonce = unsafeRight $ aggNonces pubNonces
      ctx = unsafeRight $ mkSessionContext aggNonce pubkeys [] msg
      sig = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx
   in (sig >= 0) .&&. (sig < curveOrder)

-- | Property: A signature created with sign verifies with 'partialSigVerify'.
prop_signVerifyRoundtrip :: SignerMaterial -> ByteString -> Property
prop_signVerifyRoundtrip signer msg =
  let pubNonce = unsafeRight $ publicNonce signer.signerSecNonce
      pubNonces = [pubNonce]
      pubkeys = [signer.signerPubKey]
      aggNonce = unsafeRight $ aggNonces pubNonces
      ctx = unsafeRight $ mkSessionContext aggNonce pubkeys [] msg
      sig = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx
      result = partialSigVerify sig pubNonces pubkeys [] msg 0
   in result === Right True

-- | Property: Signing the same message with the same parameters produces the same signature.
prop_signatureDeterminism :: SignerMaterial -> ByteString -> Property
prop_signatureDeterminism signer msg =
  let pubNonce = unsafeRight $ publicNonce signer.signerSecNonce
      pubNonces = [pubNonce]
      pubkeys = [signer.signerPubKey]
      aggNonce = unsafeRight $ aggNonces pubNonces
      ctx = unsafeRight $ mkSessionContext aggNonce pubkeys [] msg
      sig1 = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx
      sig2 = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx
   in sig1 === sig2

-- | Property: Using an invalid signer index should fail verification.
prop_invalidSignerIndex :: SignerMaterial -> ByteString -> Property
prop_invalidSignerIndex signer msg =
  let pubNonce = unsafeRight $ publicNonce signer.signerSecNonce
      pubNonces = [pubNonce]
      pubkeys = [signer.signerPubKey]
      aggNonce = unsafeRight $ aggNonces pubNonces
      ctx = unsafeRight $ mkSessionContext aggNonce pubkeys [] msg
      sig = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx
      result = partialSigVerify sig pubNonces pubkeys [] msg 1
   in result === Left (InvalidSignerIndex 1)
