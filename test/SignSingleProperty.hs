{-# LANGUAGE OverloadedStrings #-}

module SignSingleProperty (propertySignSingle) where

import Crypto.Curve.Secp256k1 (derive_pub, verify_schnorr)
import Crypto.Curve.Secp256k1.MuSig2 (
  SecKey (..),
  SecNonceGenParams (..),
  Tweak (..),
  aggNonces,
  aggPartials,
  aggregatedPubkey,
  applyTweak,
  mkKeyAggContext,
  mkSessionContext,
  publicNonce,
  secNonceGenWithRand,
  sign,
  signSingle,
  sortPublicKeys,
 )
import Crypto.Curve.Secp256k1.MuSig2.Internal (
  hashTag,
  integerToBytes32,
  xorByteStrings,
 )
import Data.ByteString (ByteString)
import Data.Foldable (toList)
import Data.Maybe (fromJust, maybeToList)
import Test.Tasty
import Test.Tasty.QuickCheck
import Util ()

propertySignSingle :: TestTree
propertySignSingle =
  testGroup
    "signSingle Properties"
    [ testProperty "3-Signer MuSig2" propsignSingle
    ]

-- | Property: signSingle with a random tweak (sometimes None).
propsignSingle :: SecKey -> SecKey -> SecKey -> ByteString -> Property
propsignSingle secKey1 secKey2 secKey3 msg =
  forAll genTestParams $ \(maybeTweak, maybeExtra1, maybeExtra2, maybeExtra3) ->
    propsignSingleImpl secKey1 secKey2 secKey3 msg maybeTweak maybeExtra1 maybeExtra2 maybeExtra3

genTestParams :: Gen (Maybe Tweak, Maybe ByteString, Maybe ByteString, Maybe ByteString)
genTestParams = do
  maybeTweak <- frequency [(1, return Nothing), (3, Just <$> arbitrary)]
  maybeExtra1 <- frequency [(1, return Nothing), (3, Just <$> arbitrary)]
  maybeExtra2 <- frequency [(1, return Nothing), (3, Just <$> arbitrary)]
  maybeExtra3 <- frequency [(1, return Nothing), (3, Just <$> arbitrary)]
  return (maybeTweak, maybeExtra1, maybeExtra2, maybeExtra3)

propsignSingleImpl :: SecKey -> SecKey -> SecKey -> ByteString -> Maybe Tweak -> Maybe ByteString -> Maybe ByteString -> Maybe ByteString -> Property
propsignSingleImpl secKey1 secKey2 secKey3 msg maybeTweak maybeExtra1 maybeExtra2 maybeExtra3 =
  let
    -- Derive public keys
    pubKey1 = derive_pub (case secKey1 of SecKey sk -> sk)
    pubKey2 = derive_pub (case secKey2 of SecKey sk -> sk)
    pubKey3 = derive_pub (case secKey3 of SecKey sk -> sk)
    unsortedPubKeys = [pubKey1, pubKey2, pubKey3]
    pubKeys = toList $ sortPublicKeys unsortedPubKeys

    -- Create tweaks list
    tweaks = maybeToList maybeTweak

    -- Create key aggregation context to get aggregated public key (moved up for nonce params)
    keyAggCtx = if null tweaks then mkKeyAggContext pubKeys Nothing else foldl applyTweak (mkKeyAggContext pubKeys Nothing) tweaks
    aggPk = aggregatedPubkey keyAggCtx

    -- Generate nonces for all signers using full parameters
    fullParams1 =
      SecNonceGenParams
        { _pk = pubKey1
        , _sk = Just secKey1
        , _aggpk = Just aggPk
        , _msg = Just msg
        , _extraIn = Nothing
        }
    fullParams2 =
      SecNonceGenParams
        { _pk = pubKey2
        , _sk = Just secKey2
        , _aggpk = Just aggPk
        , _msg = Just msg
        , _extraIn = Nothing
        }
    fullParams3 =
      SecNonceGenParams
        { _pk = pubKey3
        , _sk = Just secKey3
        , _aggpk = Just aggPk
        , _msg = Just msg
        , _extraIn = Nothing
        }

    secNonce1 = case maybeExtra1 of
      Just extra -> secNonceGenWithRand extra fullParams1
      Nothing ->
        -- Generate randomness from secret key (BIP-0327 aux rand)
        let skInt = case secKey1 of SecKey sk -> sk
            skBytes = integerToBytes32 skInt
            auxHash = hashTag "MuSig/aux" skBytes
            rand = xorByteStrings skBytes auxHash
         in secNonceGenWithRand rand fullParams1
    secNonce2 = case maybeExtra2 of
      Just extra -> secNonceGenWithRand extra fullParams2
      Nothing ->
        -- Generate randomness from secret key (BIP-0327 aux rand)
        let skInt = case secKey2 of SecKey sk -> sk
            skBytes = integerToBytes32 skInt
            auxHash = hashTag "MuSig/aux" skBytes
            rand = xorByteStrings skBytes auxHash
         in secNonceGenWithRand rand fullParams2
    secNonce3 = case maybeExtra3 of
      Just extra -> secNonceGenWithRand extra fullParams3
      Nothing ->
        -- Generate randomness from secret key (BIP-0327 aux rand)
        let skInt = case secKey3 of SecKey sk -> sk
            skBytes = integerToBytes32 skInt
            auxHash = hashTag "MuSig/aux" skBytes
            rand = xorByteStrings skBytes auxHash
         in secNonceGenWithRand rand fullParams3

    pubNonce1 = publicNonce secNonce1
    pubNonce2 = publicNonce secNonce2
    pubNonce3 = publicNonce secNonce3

    -- Aggregate all three nonces for the full session context
    allPubNonces = [pubNonce1, pubNonce2, pubNonce3]
    finalAggNonce = fromJust $ aggNonces allPubNonces
    finalCtx = mkSessionContext finalAggNonce pubKeys tweaks msg

    -- All signers compute partial signatures using the full session context
    partialSig1 = sign secNonce1 secKey1 finalCtx
    partialSig2 = sign secNonce2 secKey2 finalCtx

    -- For signSingle, the third signer would receive aggOtherNonce = pubNonce1 <> pubNonce2
    aggOtherNonce = pubNonce1 <> pubNonce2
    partialSig3 = signSingle secKey3 aggOtherNonce pubKeys tweaks msg maybeExtra3

    -- Aggregate all partial signatures using the full context
    partials = [partialSig1, partialSig2, partialSig3]
    finalSig = aggPartials partials finalCtx
   in
    -- Verify the final signature against the full aggregated public key
    verify_schnorr msg aggPk finalSig === True
