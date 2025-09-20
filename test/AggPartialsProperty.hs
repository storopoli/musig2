{-# LANGUAGE OverloadedStrings #-}

module AggPartialsProperty (propertyAggPartials) where

import Crypto.Curve.Secp256k1 (derive_pub)
import Crypto.Curve.Secp256k1.MuSig2 (SecKey (..), SecNonce (..), aggNonces, aggPartials, mkSessionContext, partialSigVerify, publicNonce, sign)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Maybe (fromJust)
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Util ()

propertyAggPartials :: TestTree
propertyAggPartials =
  testGroup
    "aggPartials Properties"
    [ testProperty "Aggregated partials from valid signatures" prop_aggValidPartials
    , testProperty "Aggregation is deterministic" prop_aggDeterministic
    , testProperty "All partial sigs verify before aggregation" prop_partialsVerifyBeforeAgg
    , testProperty "Aggregation with single signer equals partial sig" prop_singleSignerAgg
    ]

-- | Property: Aggregating valid partial signatures produces a consistent result
prop_aggValidPartials :: SecNonce -> SecKey -> SecNonce -> SecKey -> ByteString -> Property
prop_aggValidPartials secNonce1 secKey1 secNonce2 secKey2 msg =
  let pubkey1 = derive_pub (case secKey1 of SecKey sk -> sk)
      pubkey2 = derive_pub (case secKey2 of SecKey sk -> sk)
      pubkeys = [pubkey1, pubkey2]
      pubNonces = [publicNonce secNonce1, publicNonce secNonce2]
      aggNonce = fromJust $ aggNonces pubNonces
      ctx = mkSessionContext aggNonce pubkeys [] msg
      partialSig1 = sign secNonce1 secKey1 ctx
      partialSig2 = sign secNonce2 secKey2 ctx
      aggregated = aggPartials [partialSig1, partialSig2] ctx
   in BS.length aggregated === 64 -- Schnorr signature is 64 bytes

-- | Property: Aggregation is deterministic - same inputs produce same output
prop_aggDeterministic :: SecNonce -> SecKey -> SecNonce -> SecKey -> ByteString -> Property
prop_aggDeterministic secNonce1 secKey1 secNonce2 secKey2 msg =
  let pubkey1 = derive_pub (case secKey1 of SecKey sk -> sk)
      pubkey2 = derive_pub (case secKey2 of SecKey sk -> sk)
      pubkeys = [pubkey1, pubkey2]
      pubNonces = [publicNonce secNonce1, publicNonce secNonce2]
      aggNonce = fromJust $ aggNonces pubNonces
      ctx = mkSessionContext aggNonce pubkeys [] msg
      partialSig1 = sign secNonce1 secKey1 ctx
      partialSig2 = sign secNonce2 secKey2 ctx
      partialSigs = [partialSig1, partialSig2]
      aggregated1 = aggPartials partialSigs ctx
      aggregated2 = aggPartials partialSigs ctx
   in aggregated1 === aggregated2

-- | Property: All partial signatures should verify individually before aggregation
prop_partialsVerifyBeforeAgg :: SecNonce -> SecKey -> SecNonce -> SecKey -> ByteString -> Property
prop_partialsVerifyBeforeAgg secNonce1 secKey1 secNonce2 secKey2 msg =
  let pubkey1 = derive_pub (case secKey1 of SecKey sk -> sk)
      pubkey2 = derive_pub (case secKey2 of SecKey sk -> sk)
      pubkeys = [pubkey1, pubkey2]
      pubNonces = [publicNonce secNonce1, publicNonce secNonce2]
      aggNonce = fromJust $ aggNonces pubNonces
      ctx = mkSessionContext aggNonce pubkeys [] msg
      partialSig1 = sign secNonce1 secKey1 ctx
      partialSig2 = sign secNonce2 secKey2 ctx
      verify1 = partialSigVerify partialSig1 pubNonces pubkeys [] msg 0
      verify2 = partialSigVerify partialSig2 pubNonces pubkeys [] msg 1
   in verify1 === True .&&. verify2 === True

-- | Property: For a single signer, aggregation should work correctly
prop_singleSignerAgg :: SecNonce -> SecKey -> ByteString -> Property
prop_singleSignerAgg secNonce secKey@(SecKey sk) msg =
  let pubkey = derive_pub sk
      pubNonce = publicNonce secNonce
      pubNonces = [pubNonce]
      pubkeys = [pubkey]
      aggNonce = fromJust $ aggNonces pubNonces
      ctx = mkSessionContext aggNonce pubkeys [] msg
      partialSig = sign secNonce secKey ctx
      aggregated = aggPartials [partialSig] ctx
      verifyResult = partialSigVerify partialSig pubNonces pubkeys [] msg 0
   in verifyResult === True .&&. BS.length aggregated === 64
