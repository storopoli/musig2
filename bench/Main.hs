{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}
{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Main where

import Control.DeepSeq
import Criterion.Main
import qualified Crypto.Curve.Secp256k1 as S
import Crypto.Curve.Secp256k1.MuSig2 (
  KeyAggContext,
  PubNonce (..),
  SecKey (..),
  SecNonce (..),
  SecNonceGenParams (..),
  SessionContext (..),
  Tweak (..),
 )
import qualified Crypto.Curve.Secp256k1.MuSig2 as M
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16

-- NFData instances for benchmarking
instance NFData S.Projective
instance NFData S.Affine
instance NFData S.ECDSA
instance NFData S.Context

instance NFData SecKey where
  rnf (SecKey i) = rnf i

instance NFData SecNonce where
  rnf (SecNonce k1 k2) = rnf k1 `seq` rnf k2

instance NFData PubNonce where
  rnf (PubNonce r1 r2) = rnf r1 `seq` rnf r2

instance NFData Tweak where
  rnf (XOnlyTweak i) = rnf i
  rnf (PlainTweak i) = rnf i

instance NFData KeyAggContext where
  rnf ctx = rnf (M.aggregatedPubkey ctx)

instance NFData SessionContext where
  rnf (SessionContext an ps ts m kc) =
    rnf an `seq` rnf ps `seq` rnf ts `seq` rnf m `seq` rnf kc

instance NFData SecNonceGenParams where
  rnf (SecNonceGenParams pk sk apk mg ei) =
    rnf pk `seq` rnf sk `seq` rnf apk `seq` rnf mg `seq` rnf ei

-- | Main benchmark function.
main :: IO ()
main =
  defaultMain
    [ keyAgg
    , tweakOps
    , nonceGen
    , nonceAgg
    , sessionOps
    , signing
    , verification
    ]

-- | A big scalar.
largeScalar :: Integer
largeScalar = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed

-- | Key aggregation.
keyAgg :: Benchmark
keyAgg =
  bgroup
    "key_aggregation"
    [ bench "mkKeyAggContext (2 keys)" $ nf (M.mkKeyAggContext [p, q]) Nothing
    , bench "mkKeyAggContext (3 keys)" $ nf (M.mkKeyAggContext [p, q, r]) Nothing
    , bench "mkKeyAggContext (5 keys)" $ nf (M.mkKeyAggContext [p, q, r, s, t]) Nothing
    , bench "sortPublicKeys (5 keys)" $ nf M.sortPublicKeys [p, q, r, s, t]
    , bench "aggregatedPubkey" $ nf M.aggregatedPubkey keyCtx2
    ]

-- | Tweak operations.
tweakOps :: Benchmark
tweakOps =
  bgroup
    "tweaks"
    [ bench "applyTweak (PlainTweak)" $ nf (M.applyTweak keyCtx2) plainTweak
    , bench "applyTweak (XOnlyTweak)" $ nf (M.applyTweak keyCtx2) xonlyTweak
    , bench "mkKeyAggContext with tweak" $ nf (M.mkKeyAggContext [p, q]) (Just plainTweak)
    ]

-- | Nonce generation.
nonceGen :: Benchmark
nonceGen = env setupNonce $ \ ~(params, rand) ->
  bgroup
    "nonce_generation"
    [ bench "mkSecNonce" $ nfIO M.mkSecNonce
    , bench "secNonceGen (minimal params)" $ nfIO (M.secNonceGen params)
    , bench "secNonceGenWithRand" $ nf (M.secNonceGenWithRand rand) params
    , bench "publicNonce" $ nf M.publicNonce secNonce1
    ]
 where
  setupNonce = do
    let params = M.defaultSecNonceGenParams p
    let rand = BS.replicate 32 0x42
    pure (params, rand)

-- | Nonce aggregation.
nonceAgg :: Benchmark
nonceAgg =
  bgroup
    "nonce_aggregation"
    [ bench "aggNonces (2 nonces)" $ nf M.aggNonces [pubNonce1, pubNonce2]
    , bench "aggNonces (3 nonces)" $ nf M.aggNonces [pubNonce1, pubNonce2, pubNonce3]
    , bench "aggNonces (5 nonces)" $ nf M.aggNonces [pubNonce1, pubNonce2, pubNonce3, pubNonce4, pubNonce5]
    ]

-- | Session operations.
sessionOps :: Benchmark
sessionOps = env setupSession $ \ ~(aggNonce, pks, tweaks) ->
  bgroup
    "session_context"
    [ bench "mkSessionContext (no tweaks)" $ nf (M.mkSessionContext aggNonce pks []) sMsg
    , bench "mkSessionContext (with tweaks)" $ nf (M.mkSessionContext aggNonce pks tweaks) sMsg
    ]
 where
  setupSession = do
    let !aggNonce = case M.aggNonces [pubNonce1, pubNonce2] of
          Nothing -> error "failed to aggregate nonces"
          Just n -> n
        !pks = [p, q]
        !tweaks = [plainTweak, xonlyTweak]
    pure (aggNonce, pks, tweaks)

-- | Signing benchmarks.
signing :: Benchmark
signing = env setupSigning $ \ ~(ctx, secNonce, sk) ->
  bgroup
    "signing"
    [ bench "sign (2 signers)" $ nf (M.sign secNonce sk) ctx
    ]
 where
  setupSigning = do
    let !aggNonce = case M.aggNonces [pubNonce1, pubNonce2] of
          Nothing -> error "failed to aggregate nonces"
          Just n -> n
        !ctx = M.mkSessionContext aggNonce [p, q] [] sMsg
        !secNonce = SecNonce sk1 sk2
        !sk = SecKey ssk
    pure (ctx, secNonce, sk)

-- | Verification.
verification :: Benchmark
verification = env setupVerification $ \ ~(partial, nonces, pks, ctx) ->
  bgroup
    "verification"
    [ bench "partialSigVerify" $ nf (\p -> M.partialSigVerify p nonces pks [] sMsg 0) partial
    , bench "aggPartials" $ nf (M.aggPartials [partial]) ctx
    ]
 where
  setupVerification = do
    let !aggNonce = case M.aggNonces [pubNonce1, pubNonce2] of
          Nothing -> error "failed to aggregate nonces"
          Just n -> n
        !ctx = M.mkSessionContext aggNonce [p, q] [] sMsg
        !secNonce = SecNonce sk1 sk2
        !sk = SecKey ssk
        !partial = M.sign secNonce sk ctx
        !nonces = [pubNonce1, pubNonce2]
        !pks = [p, q]
    pure (partial, nonces, pks, ctx)

-- Test data points.
pBS :: BS.ByteString
pBS =
  B16.decodeLenient
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

p :: S.Projective
p = case S.parse_point pBS of
  Nothing -> error "failed to parse point p"
  Just !pt -> pt

qBS :: BS.ByteString
qBS =
  B16.decodeLenient
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

q :: S.Projective
q = case S.parse_point qBS of
  Nothing -> error "failed to parse point q"
  Just !pt -> pt

rBS :: BS.ByteString
rBS =
  B16.decodeLenient
    "03a2113cf152585d96791a42cdd78782757fbfb5c6b2c11b59857eb4f7fda0b0e8"

r :: S.Projective
r = case S.parse_point rBS of
  Nothing -> error "failed to parse point r"
  Just !pt -> pt

sBS :: BS.ByteString
sBS =
  B16.decodeLenient
    "0306413898a49c93cccf3db6e9078c1b6a8e62568e4a4770e0d7d96792d1c580ad"

s :: S.Projective
s = case S.parse_point sBS of
  Nothing -> error "failed to parse point s"
  Just !pt -> pt

tBS :: BS.ByteString
tBS = B16.decodeLenient "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"

t :: S.Projective
t = case S.parse_point tBS of
  Nothing -> error "failed to parse point t"
  Just !pt -> pt

-- Test keys and nonces
ssk :: Integer
ssk = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF

sk1 :: Integer
sk1 = 0x508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61

sk2 :: Integer
sk2 = 0xFAA32323B08D52AE5ED0E85F09CEB3EB73B97FCA9D074924598B38DBBF966A9B

sMsg :: BS.ByteString
sMsg =
  B16.decodeLenient
    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"

-- Contexts and nonces for testing
keyCtx2 :: KeyAggContext
keyCtx2 = M.mkKeyAggContext [p, q] Nothing

plainTweak :: Tweak
plainTweak = PlainTweak 0x1234567890ABCDEF

xonlyTweak :: Tweak
xonlyTweak = XOnlyTweak 0xFEDCBA0987654321

secNonce1 :: SecNonce
secNonce1 = SecNonce sk1 sk2

pubNonce1 :: PubNonce
pubNonce1 = M.publicNonce secNonce1

secNonce2 :: SecNonce
secNonce2 = SecNonce (sk1 + 1) (sk2 + 1)

pubNonce2 :: PubNonce
pubNonce2 = M.publicNonce secNonce2

secNonce3 :: SecNonce
secNonce3 = SecNonce (sk1 + 2) (sk2 + 2)

pubNonce3 :: PubNonce
pubNonce3 = M.publicNonce secNonce3

secNonce4 :: SecNonce
secNonce4 = SecNonce (sk1 + 3) (sk2 + 3)

pubNonce4 :: PubNonce
pubNonce4 = M.publicNonce secNonce4

secNonce5 :: SecNonce
secNonce5 = SecNonce (sk1 + 4) (sk2 + 4)

pubNonce5 :: PubNonce
pubNonce5 = M.publicNonce secNonce5
