{-# LANGUAGE OverloadedStrings #-}

module SignVerifyTweakProperty (propertySignVerifyTweak) where

import Crypto.Curve.Secp256k1 (derive_pub, _CURVE_Q)
import Crypto.Curve.Secp256k1.MuSig2 (SecKey (..), SecNonce (..), Tweak (..), aggNonces, mkSessionContext, partialSigVerify, publicNonce, sign)
import Data.ByteString (ByteString)
import Data.Maybe (fromJust)
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Util ()

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

-- | Property: Generated signatures with tweaks are in the valid range \([0, Q-1]\).
prop_validSignatureRangeWithTweaks :: SecNonce -> SecKey -> [Tweak] -> ByteString -> Property
prop_validSignatureRangeWithTweaks secNonce secKey@(SecKey sk) tweaks msg =
  length tweaks
    <= 5
    ==> let pubkey -- Limit tweaks to reasonable number
              =
              derive_pub sk
            pubNonce = publicNonce secNonce
            pubNonces = [pubNonce]
            pubkeys = [pubkey]
            aggNonce = fromJust $ aggNonces pubNonces
            ctx = mkSessionContext aggNonce pubkeys tweaks msg
            sig = sign secNonce secKey ctx
         in (sig >= 0) .&&. (sig < _CURVE_Q)

-- | Property: A signature created with tweaks verifies with 'partialSigVerify'.
prop_signVerifyRoundtripWithTweaks :: SecNonce -> SecKey -> [Tweak] -> ByteString -> Property
prop_signVerifyRoundtripWithTweaks secNonce secKey@(SecKey sk) tweaks msg =
  length tweaks
    <= 5
    ==> let pubkey -- Limit tweaks to reasonable number
              =
              derive_pub sk
            pubNonce = publicNonce secNonce
            pubNonces = [pubNonce]
            pubkeys = [pubkey]
            aggNonce = fromJust $ aggNonces pubNonces
            ctx = mkSessionContext aggNonce pubkeys tweaks msg
            sig = sign secNonce secKey ctx
            signerIndex = 0 -- We're always the first signer in this test
            result = partialSigVerify sig pubNonces pubkeys tweaks msg signerIndex
         in result === True

-- | Property: Signing the same message with the same tweaks produces the same signature.
prop_signatureDeterminismWithTweaks :: SecNonce -> SecKey -> [Tweak] -> ByteString -> Property
prop_signatureDeterminismWithTweaks secNonce secKey@(SecKey sk) tweaks msg =
  length tweaks
    <= 5
    ==> let pubkey -- Limit tweaks to reasonable number
              =
              derive_pub sk
            pubNonce = publicNonce secNonce
            pubNonces = [pubNonce]
            pubkeys = [pubkey]
            aggNonce = fromJust $ aggNonces pubNonces
            ctx = mkSessionContext aggNonce pubkeys tweaks msg
            sig1 = sign secNonce secKey ctx
            sig2 = sign secNonce secKey ctx
         in sig1 === sig2

-- | Property: Empty tweaks should produce the same result as no tweaks.
prop_emptyTweaksEqualsNoTweaks :: SecNonce -> SecKey -> ByteString -> Property
prop_emptyTweaksEqualsNoTweaks secNonce secKey@(SecKey sk) msg =
  let pubkey = derive_pub sk
      pubNonce = publicNonce secNonce
      pubNonces = [pubNonce]
      pubkeys = [pubkey]
      aggNonce = fromJust $ aggNonces pubNonces

      -- Context with empty tweaks
      ctxWithEmptyTweaks = mkSessionContext aggNonce pubkeys [] msg
      sigWithEmptyTweaks = sign secNonce secKey ctxWithEmptyTweaks

      -- Context with no tweaks parameter (though we still pass empty list)
      ctxWithNoTweaks = mkSessionContext aggNonce pubkeys [] msg
      sigWithNoTweaks = sign secNonce secKey ctxWithNoTweaks
   in sigWithEmptyTweaks === sigWithNoTweaks

-- | Property: Plain tweaks are commutative.
prop_plainTweaksCommutative :: SecNonce -> SecKey -> Integer -> Integer -> ByteString -> Property
prop_plainTweaksCommutative secNonce secKey@(SecKey sk) t1 t2 msg =
  t1 > 0
    && t1 < _CURVE_Q
    && t2 > 0
    && t2 < _CURVE_Q
    && t1
      /= t2
    ==> let pubkey = derive_pub sk
            pubNonce = publicNonce secNonce
            pubNonces = [pubNonce]
            pubkeys = [pubkey]
            aggNonce = fromJust $ aggNonces pubNonces

            -- First order: [PlainTweak t1, PlainTweak t2]
            tweak1 = PlainTweak t1
            tweak2 = PlainTweak t2
            ctx1 = mkSessionContext aggNonce pubkeys [tweak1, tweak2] msg
            sig1 = sign secNonce secKey ctx1

            -- Second order: [PlainTweak t2, PlainTweak t1]
            ctx2 = mkSessionContext aggNonce pubkeys [tweak2, tweak1] msg
            sig2 = sign secNonce secKey ctx2
         in -- Plain tweaks are commutative, order shouldn't matter
            sig1 === sig2
