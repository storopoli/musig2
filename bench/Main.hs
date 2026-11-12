{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import Crypto.Curve.Secp256k1.MuSig2
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (newSecNonce, pubNonceFromScalars)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (integerToBytes32)
import Crypto.Curve.Secp256k1.MuSig2.Unsafe (nonceGenWithRand, signWithoutVerification)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NE
import Data.Maybe (fromMaybe)

-- | Unwraps a 'Right' (benchmark setup only).
unsafeRight :: (Show e) => Either e a -> a
unsafeRight = either (error . show) id

secKeyN :: Integer -> SecKey
secKeyN = unsafeRight . secKeyFromBytes . integerToBytes32

-- | @n@ distinct public keys.
pubKeys :: Int -> NonEmpty PubKey
pubKeys n = NE.fromList [secKeyPubKey (secKeyN (fromIntegral i * 7919 + 3)) | i <- [1 .. n]]

msg :: ByteString
msg = "0123456789abcdef0123456789abcdef"

-- | Two signers with fixed nonce scalars and their public nonces.
signers :: NonEmpty (SecKey, (Integer, Integer), PubNonce)
signers =
  NE.fromList
    [ (sk, (100 + i, 200 + i), fromMaybe (error "zero nonce") (pubNonceFromScalars (100 + i) (200 + i)))
    | (sk, i) <- [(secKeyN 11, 1), (secKeyN 22, 2)]
    ]

-- | A fresh one-shot secret nonce for a signer (a nonce signs once, so every run needs one).
freshNonce :: (SecKey, (Integer, Integer), PubNonce) -> IO SecNonce
freshNonce (sk, (k1, k2), pn) = newSecNonce k1 k2 (secKeyPubKey sk) pn Nothing Nothing

signerKey :: (SecKey, (Integer, Integer), PubNonce) -> SecKey
signerKey (sk, _, _) = sk

keyAggCtx :: KeyAggContext
keyAggCtx = unsafeRight (keyAgg (fmap (secKeyPubKey . signerKey) signers))

pubNonces :: NonEmpty PubNonce
pubNonces = fmap (\(_, _, pn) -> pn) signers

session :: Session
session = newSession keyAggCtx (nonceAgg pubNonces) msg

-- | Signs with a fresh nonce.
signFresh :: Session -> (SecKey, (Integer, Integer), PubNonce) -> IO PartialSignature
signFresh ses s = freshNonce s >>= \sn -> unsafeRight <$> sign sn (signerKey s) ses

-- | Nonce aggregation, session, both partial signatures, their verification, aggregation and BIP-340 verification.
fullFlow :: ByteString -> IO Bool
fullFlow m = do
  let ses = newSession keyAggCtx (nonceAgg pubNonces) m
  ps <- traverse (signFresh ses) signers
  let ok = and (zipWith3 (partialSigVerify ses) (map (secKeyPubKey . signerKey) (NE.toList signers)) (NE.toList pubNonces) (NE.toList ps))
  pure (ok && verify (aggXOnlyPubKey keyAggCtx) m (partialSigAgg ses ps))

main :: IO ()
main = do
  psigs <- traverse (signFresh session) signers
  let aggOther = nonceAgg (NE.fromList (NE.tail pubNonces))
  defaultMain
    [ bgroup
        "key_aggregation"
        ( [env (pure (pubKeys n)) $ \pks -> bench ("keyAgg (n=" <> show n <> ")") $ nf keyAgg pks | n <- [2, 10, 50, 200]]
            <> [env (pure (pubKeys 50)) $ \pks -> bench "keySort (n=50)" $ nf keySort pks]
        )
    , bgroup
        "tweaks"
        [ bench "applyPlainTweak" $ nf (applyPlainTweak tweak) keyAggCtx
        , bench "applyXOnlyTweak" $ nf (applyXOnlyTweak tweak) keyAggCtx
        , bench "applyTaprootTweak" $ nf (applyTaprootTweak (Just (BS.replicate 32 0xAB))) keyAggCtx
        ]
    , bgroup
        "nonces"
        [ bench "nonceGen" $ nfIO (fmap (fmap snd) (nonceGen pk1 noNonceInputs))
        , bench "nonceGenWithRand (all inputs)" $ nfIO (fmap (fmap snd) (nonceGenWithRand (BS.replicate 32 0x42) pk1 allInputs))
        , env (pure (NE.fromList (concat (replicate 50 (NE.toList pubNonces))))) $ \pns -> bench "nonceAgg (n=100)" $ nf nonceAgg pns
        ]
    , bgroup
        "signing"
        [ bench "newSession (2 signers)" $ nf (newSession keyAggCtx (nonceAgg pubNonces)) msg
        , bench "sign (2 signers)" $ perRunEnv (freshNonce (NE.head signers)) $ \sn -> sign sn (signerKey (NE.head signers)) session
        , bench "signWithoutVerification (2 signers)" $ perRunEnv (freshNonce (NE.head signers)) $ \sn -> signWithoutVerification sn (signerKey (NE.head signers)) session
        , bench "deterministicSign (2 signers)" $ nf (deterministicSign (signerKey (NE.head signers)) aggOther keyAggCtx msg) Nothing
        , bench "partialSigVerify (2 signers)" $ nf (partialSigVerify session pk1 (NE.head pubNonces)) (NE.head psigs)
        , bench "partialSigAgg (2 signers)" $ nf (partialSigAgg session) psigs
        , bench "verify" $ nf (verify (aggXOnlyPubKey keyAggCtx) msg) (partialSigAgg session psigs)
        , bench "full 2-of-2 flow" $ nfIO (fullFlow msg)
        ]
    ]
 where
  pk1 = secKeyPubKey (signerKey (NE.head signers))
  tweak = unsafeRight (decode (integerToBytes32 0x1234567890ABCDEF))
  allInputs =
    NonceInputs
      { nonceSecKey = Just (signerKey (NE.head signers))
      , nonceAggPubKey = Just (aggXOnlyPubKey keyAggCtx)
      , nonceMessage = Just msg
      , nonceExtraInput = Just "extra"
      }
