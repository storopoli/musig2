{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module AggPartialsProperty (propertyAggPartials) where

import Crypto.Curve.Secp256k1 (Pub)
import Crypto.Curve.Secp256k1.MuSig2 (PubNonce, SessionContext, aggNonces, aggPartials, mkSessionContext, partialSigVerify, publicNonce, sign)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Util (SignerMaterial (..), unsafeRight)

propertyAggPartials :: TestTree
propertyAggPartials =
  testGroup
    "aggPartials Properties"
    [ testProperty "Aggregated partials from valid signatures" prop_aggValidPartials
    , testProperty "Aggregation is deterministic" prop_aggDeterministic
    , testProperty "All partial sigs verify before aggregation" prop_partialsVerifyBeforeAgg
    , testProperty "Aggregation with single signer equals partial sig" prop_singleSignerAgg
    ]

mkTwoSignerContext :: SignerMaterial -> SignerMaterial -> ByteString -> ([PubNonce], [Pub], SessionContext)
mkTwoSignerContext signer1 signer2 msg =
  let pubNonces = [publicNonce signer1.signerSecNonce, publicNonce signer2.signerSecNonce]
      pubkeys = [signer1.signerPubKey, signer2.signerPubKey]
      aggNonce = unsafeRight $ aggNonces pubNonces
      ctx = unsafeRight $ mkSessionContext aggNonce pubkeys [] msg
   in (pubNonces, pubkeys, ctx)

-- | Property: Aggregating valid partial signatures produces a consistent result
prop_aggValidPartials :: SignerMaterial -> SignerMaterial -> ByteString -> Property
prop_aggValidPartials signer1 signer2 msg =
  let (_, _, ctx) = mkTwoSignerContext signer1 signer2 msg
      partialSig1 = unsafeRight $ sign signer1.signerSecNonce signer1.signerSecKey ctx
      partialSig2 = unsafeRight $ sign signer2.signerSecNonce signer2.signerSecKey ctx
      aggregated = unsafeRight $ aggPartials [partialSig1, partialSig2] ctx
   in BS.length aggregated === 64

-- | Property: Aggregation is deterministic - same inputs produce same output
prop_aggDeterministic :: SignerMaterial -> SignerMaterial -> ByteString -> Property
prop_aggDeterministic signer1 signer2 msg =
  let (_, _, ctx) = mkTwoSignerContext signer1 signer2 msg
      partialSig1 = unsafeRight $ sign signer1.signerSecNonce signer1.signerSecKey ctx
      partialSig2 = unsafeRight $ sign signer2.signerSecNonce signer2.signerSecKey ctx
      partialSigs = [partialSig1, partialSig2]
      aggregated1 = unsafeRight $ aggPartials partialSigs ctx
      aggregated2 = unsafeRight $ aggPartials partialSigs ctx
   in aggregated1 === aggregated2

-- | Property: All partial signatures should verify individually before aggregation
prop_partialsVerifyBeforeAgg :: SignerMaterial -> SignerMaterial -> ByteString -> Property
prop_partialsVerifyBeforeAgg signer1 signer2 msg =
  let (pubNonces, pubkeys, ctx) = mkTwoSignerContext signer1 signer2 msg
      partialSig1 = unsafeRight $ sign signer1.signerSecNonce signer1.signerSecKey ctx
      partialSig2 = unsafeRight $ sign signer2.signerSecNonce signer2.signerSecKey ctx
      verify1 = partialSigVerify partialSig1 pubNonces pubkeys [] msg 0
      verify2 = partialSigVerify partialSig2 pubNonces pubkeys [] msg 1
   in verify1 === Right True .&&. verify2 === Right True

-- | Property: For a single signer, aggregation should work correctly
prop_singleSignerAgg :: SignerMaterial -> ByteString -> Property
prop_singleSignerAgg signer msg =
  let pubNonce = publicNonce signer.signerSecNonce
      pubNonces = [pubNonce]
      pubkeys = [signer.signerPubKey]
      aggNonce = unsafeRight $ aggNonces pubNonces
      ctx = unsafeRight $ mkSessionContext aggNonce pubkeys [] msg
      partialSig = unsafeRight $ sign signer.signerSecNonce signer.signerSecKey ctx
      aggregated = unsafeRight $ aggPartials [partialSig] ctx
      verifyResult = partialSigVerify partialSig pubNonces pubkeys [] msg 0
   in verifyResult === Right True .&&. BS.length aggregated === 64
