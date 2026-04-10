{-# LANGUAGE OverloadedStrings #-}

module NonceGenProperty (propertyNonceGen) where

import Crypto.Curve.Secp256k1 (derive_pub, mul, _CURVE_G)
import Crypto.Curve.Secp256k1.MuSig2 (PubNonce (..), SecKey (..), SecNonceGenParams (..), publicNonce, secNonceGenWithRand)
import Crypto.Curve.Secp256k1.MuSig2.Internal (curveOrder, hashTag, integerToBytes32, secNonceScalars, xorByteStrings)
import Data.ByteString ()
import Data.Maybe (fromMaybe)
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Util (Rand32 (..), Scalar (..), unsafeRight)

propertyNonceGen :: TestTree
propertyNonceGen =
  testGroup
    "secNonceGenWithRand Properties"
    [ testProperty "Valid Nonce Range" prop_validRange
    , testProperty "Correct Public Nonce Computation" prop_correctPubNonce
    , testProperty "Secret Key XOR Consistency" prop_skConsistency
    ]

-- | Property: Generated k1 and k2 are in the valid range [1, Q-1]
prop_validRange :: Rand32 -> SecNonceGenParams -> Property
prop_validRange (Rand32 rand) params =
  let (k1, k2) = secNonceScalars (unsafeRight $ secNonceGenWithRand rand params)
   in (1 <= k1 && k1 < curveOrder) .&&. (1 <= k2 && k2 < curveOrder)

-- | Property: The public nonce points correspond to G multiplied by k1 and k2
prop_correctPubNonce :: Rand32 -> SecNonceGenParams -> Property
prop_correctPubNonce (Rand32 rand) params =
  let sn = unsafeRight $ secNonceGenWithRand rand params
      (k1, k2) = secNonceScalars sn
      PubNonce nonceR1 nonceR2 = unsafeRight $ publicNonce sn
   in nonceR1 === fromMaybe (error "Failed to multiply scalar by generator") (mul _CURVE_G (fromInteger k1))
        .&&. nonceR2
          === fromMaybe (error "Failed to multiply scalar by generator") (mul _CURVE_G (fromInteger k2))

-- | Property: Generating with sk provided is equivalent to XORing rand with the aux hash and generating without sk
prop_skConsistency :: Rand32 -> SecNonceGenParams -> Scalar -> Property
prop_skConsistency (Rand32 rand) params (Scalar sk) =
  let pkForSk = case derive_pub (fromInteger sk) of
        Just pub -> pub
        Nothing -> error "Failed to derive pubkey for property"
      paramsNoSk = params{_pk = pkForSk, _sk = Nothing}
      paramsWithSk = params{_pk = pkForSk, _sk = Just (SecKey sk)}
      auxHash = hashTag "MuSig/aux" rand
      skBytes = integerToBytes32 sk
      rand' = xorByteStrings skBytes auxHash
      (k1l, k2l) = secNonceScalars (unsafeRight $ secNonceGenWithRand rand paramsWithSk)
      (k1r, k2r) = secNonceScalars (unsafeRight $ secNonceGenWithRand rand' paramsNoSk)
   in k1l === k1r .&&. k2l === k2r
