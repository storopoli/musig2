{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module SignVerifyTweakProperty (propertySignVerifyTweak) where

import Crypto.Curve.Secp256k1 (Pub)
import Crypto.Curve.Secp256k1.MuSig2 (PubNonce, SessionContext, Tweak (..), aggNonces, mkSessionContext, partialSigVerify, publicNonce, sign)
import Crypto.Curve.Secp256k1.MuSig2.Internal (curveOrder)
import Data.ByteString (ByteString)
import Test.Tasty
import Test.Tasty.QuickCheck
import Util (SignerMaterial (..), unsafeRight)

propertySignVerifyTweak :: TestTree
propertySignVerifyTweak =
  testGroup
    "sign and partialSigVerify with Tweaks Properties"
    [ testProperty "Valid Signature Range with Tweaks" prop_validSignatureRangeWithTweaks
    , testProperty "Sign-Verify Roundtrip with Tweaks" prop_signVerifyRoundtripWithTweaks
    , testProperty "Signature Determinism with Tweaks" prop_signatureDeterminismWithTweaks
    , testProperty "Empty Tweaks Equals No Tweaks" prop_emptyTweaksEqualsNoTweaks
    , testProperty "Plain Tweaks Are Commutative" prop_plainTweaksCommutative
    ]

mkTweakedContext :: SignerMaterial -> [Tweak] -> ByteString -> ([PubNonce], [Pub], SessionContext)
mkTweakedContext signer tweaks msg =
  let pubNonce = publicNonce signer.signerSecNonce
      pubNonces = [pubNonce]
      pubkeys = [signer.signerPubKey]
      aggNonce = unsafeRight $ aggNonces pubNonces
      ctx = unsafeRight $ mkSessionContext aggNonce pubkeys tweaks msg
   in (pubNonces, pubkeys, ctx)

-- | Property: Generated signatures with tweaks are in the valid range \([0, Q-1]\).
prop_validSignatureRangeWithTweaks :: SignerMaterial -> Property
prop_validSignatureRangeWithTweaks signer =
  forAll (resize 5 $ listOf arbitrary :: Gen [Tweak]) $ \tweaks ->
    forAll (arbitrary :: Gen ByteString) $ \msg ->
      let (_, _, ctx) = mkTweakedContext signer tweaks msg
          sig = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx
       in (sig >= 0) .&&. (sig < curveOrder)

-- | Property: A signature created with tweaks verifies with 'partialSigVerify'.
prop_signVerifyRoundtripWithTweaks :: SignerMaterial -> Property
prop_signVerifyRoundtripWithTweaks signer =
  forAll (resize 5 $ listOf arbitrary :: Gen [Tweak]) $ \tweaks ->
    forAll (arbitrary :: Gen ByteString) $ \msg ->
      let (pubNonces, pubkeys, ctx) = mkTweakedContext signer tweaks msg
          sig = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx
          result = partialSigVerify sig pubNonces pubkeys tweaks msg 0
       in result === Right True

-- | Property: Signing the same message with the same tweaks produces the same signature.
prop_signatureDeterminismWithTweaks :: SignerMaterial -> Property
prop_signatureDeterminismWithTweaks signer =
  forAll (resize 5 $ listOf arbitrary :: Gen [Tweak]) $ \tweaks ->
    forAll (arbitrary :: Gen ByteString) $ \msg ->
      let (_, _, ctx) = mkTweakedContext signer tweaks msg
          sig1 = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx
          sig2 = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx
       in sig1 === sig2

-- | Property: Empty tweaks should produce the same result as no tweaks.
prop_emptyTweaksEqualsNoTweaks :: SignerMaterial -> ByteString -> Property
prop_emptyTweaksEqualsNoTweaks signer msg =
  let (_, _, ctxWithEmptyTweaks) = mkTweakedContext signer [] msg
      sigWithEmptyTweaks = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctxWithEmptyTweaks
      (_, _, ctxWithNoTweaks) = mkTweakedContext signer [] msg
      sigWithNoTweaks = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctxWithNoTweaks
   in sigWithEmptyTweaks === sigWithNoTweaks

-- | Property: Plain tweaks are commutative.
prop_plainTweaksCommutative :: SignerMaterial -> Integer -> Integer -> ByteString -> Property
prop_plainTweaksCommutative signer t1 t2 msg =
  t1 > 0
    && t1 < curveOrder
    && t2 > 0
    && t2 < curveOrder
    && t1 /= t2
    ==> let
          tweak1 = PlainTweak t1
          tweak2 = PlainTweak t2
          (_, _, ctx1) = mkTweakedContext signer [tweak1, tweak2] msg
          sig1 = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx1
          (_, _, ctx2) = mkTweakedContext signer [tweak2, tweak1] msg
          sig2 = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx2
         in
          sig1 === sig2
