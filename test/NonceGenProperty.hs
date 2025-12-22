{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module NonceGenProperty (propertyNonceGen) where

import Crypto.Curve.Secp256k1 (mul, _CURVE_G, _CURVE_Q)
import Crypto.Curve.Secp256k1.MuSig2 (PubNonce (..), SecKey (..), SecNonce (..), SecNonceGenParams (..), publicNonce, secNonceGenWithRand)
import Crypto.Curve.Secp256k1.MuSig2.Internal (hashTag, integerToBytes32, xorByteStrings)
import Data.ByteString ()
import Data.Maybe (fromMaybe)
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Util (Rand32 (..), Scalar (..))

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
  let SecNonce{..} = secNonceGenWithRand rand params
   in (1 <= k1 && k1 < _CURVE_Q) .&&. (1 <= k2 && k2 < _CURVE_Q)

-- | Property: The public nonce points correspond to G multiplied by k1 and k2
prop_correctPubNonce :: Rand32 -> SecNonceGenParams -> Property
prop_correctPubNonce (Rand32 rand) params =
  let sn@SecNonce{..} = secNonceGenWithRand rand params
      PubNonce r1 r2 = publicNonce sn
   in r1 === fromMaybe (error "Failed to multiply scalar by generator") (mul _CURVE_G k1) .&&. r2 === fromMaybe (error "Failed to multiply scalar by generator") (mul _CURVE_G k2)

-- | Property: Generating with sk provided is equivalent to XORing rand with the aux hash and generating without sk
prop_skConsistency :: Rand32 -> SecNonceGenParams -> Scalar -> Property
prop_skConsistency (Rand32 rand) params (Scalar sk) =
  let paramsNoSk = params{_sk = Nothing}
      paramsWithSk = params{_sk = Just (SecKey sk)}
      auxHash = hashTag "MuSig/aux" rand
      skBytes = integerToBytes32 sk
      rand' = xorByteStrings skBytes auxHash
      SecNonce k1l k2l = secNonceGenWithRand rand paramsWithSk
      SecNonce k1r k2r = secNonceGenWithRand rand' paramsNoSk
   in k1l === k1r .&&. k2l === k2r
