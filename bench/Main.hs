{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import Crypto.Curve.Secp256k1.MuSig2
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (nonceGenWithRand, secNonceFromScalars, secNoncePubNonce)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (integerToBytes32)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NE

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

-- | Two signers with fixed nonces.
signers :: NonEmpty (SecKey, SecNonce)
signers = NE.fromList [(sk, unsafeRight (secNonceFromScalars (100 + i) (200 + i) (secKeyPubKey sk))) | (sk, i) <- [(secKeyN 11, 1), (secKeyN 22, 2)]]

keyAggCtx :: KeyAggContext
keyAggCtx = unsafeRight (keyAgg (fmap (secKeyPubKey . fst) signers))

pubNonces :: NonEmpty PubNonce
pubNonces = fmap (secNoncePubNonce . snd) signers

session :: Session
session = newSession keyAggCtx (nonceAgg pubNonces) msg

psigs :: NonEmpty PartialSignature
psigs = fmap (\(sk, sn) -> unsafeRight (sign sn sk session)) signers

-- | Nonce aggregation, session, both partial signatures, their verification, aggregation and BIP-340 verification.
fullFlow :: ByteString -> Bool
fullFlow m =
  let ses = newSession keyAggCtx (nonceAgg pubNonces) m
      ps = fmap (\(sk, sn) -> unsafeRight (sign sn sk ses)) signers
      ok = and (zipWith3 (partialSigVerify ses) (map (secKeyPubKey . fst) (NE.toList signers)) (NE.toList pubNonces) (NE.toList ps))
   in ok && verify (aggXOnlyPubKey keyAggCtx) m (partialSigAgg ses ps)

main :: IO ()
main =
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
        , bench "nonceGenWithRand (all inputs)" $ nf (fmap (fmap snd) . nonceGenWithRand (BS.replicate 32 0x42) pk1) allInputs
        , env (pure (NE.fromList (concat (replicate 50 (NE.toList pubNonces))))) $ \pns -> bench "nonceAgg (n=100)" $ nf nonceAgg pns
        ]
    , bgroup
        "signing"
        [ bench "newSession (2 signers)" $ nf (newSession keyAggCtx (nonceAgg pubNonces)) msg
        , bench "sign (2 signers)" $ nf (\(sk, sn) -> sign sn sk session) (NE.head signers)
        , bench "partialSigVerify (2 signers)" $ nf (partialSigVerify session pk1 (NE.head pubNonces)) (NE.head psigs)
        , bench "partialSigAgg (2 signers)" $ nf (partialSigAgg session) psigs
        , bench "verify" $ nf (verify (aggXOnlyPubKey keyAggCtx) msg) (partialSigAgg session psigs)
        , bench "full 2-of-2 flow" $ nf fullFlow msg
        ]
    ]
 where
  pk1 = secKeyPubKey (fst (NE.head signers))
  tweak = unsafeRight (decode (integerToBytes32 0x1234567890ABCDEF))
  allInputs =
    NonceInputs
      { nonceSecKey = Just (fst (NE.head signers))
      , nonceAggPubKey = Just (aggXOnlyPubKey keyAggCtx)
      , nonceMessage = Just msg
      , nonceExtraInput = Just "extra"
      }
