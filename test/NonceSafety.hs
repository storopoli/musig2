{-# LANGUAGE OverloadedStrings #-}

{- | One-shot secret nonces, session binding, the "Crypto.Curve.Secp256k1.MuSig2.Unsafe"
functions and 'deterministicSign' beyond the official vectors.
-}
module NonceSafety (testNonceSafety) where

import Control.Concurrent (forkIO, getNumCapabilities)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, readMVar, takeMVar)
import Control.Monad (forM_, replicateM, void)
import Crypto.Curve.Secp256k1.MuSig2
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (peekSecNonce, secNonceIsUsed, secNoncePubNonce)
import Crypto.Curve.Secp256k1.MuSig2.Unsafe
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Either (lefts, rights)
import Data.IORef (newIORef, readIORef)
import Data.List.NonEmpty (NonEmpty (..))
import Data.Maybe (isJust)
import Data.Word (Word64)
import Test.Tasty
import Test.Tasty.HUnit
import Util (failsWith, pubNonceFromInts, secKeyFromInt, unsafeRight)

testNonceSafety :: TestTree
testNonceSafety =
  testGroup
    "nonce safety"
    [ testGroup
        "one-shot secret nonces"
        [ testCase "a second sign with the same nonce returns SecNonceAlreadyUsed" secondSign
        , testCase "copies of the handle share the used state" copiesShareState
        , testCase "sign zero-fills the nonce's buffer" signWipes
        , testCase "concurrent signing with one nonce succeeds exactly once" concurrentSign
        , testCase "a failed sign (wrong key, signer not in session) consumes the nonce" failuresConsume
        ]
    , testGroup
        "session binding"
        [ testCase "a nonce bound to an aggregate key refuses other sessions" bindAggPubKey
        , testCase "a nonce bound to a message refuses other messages" bindMessage
        , testCase "a nonce bound to the session's key and message signs" bindMatches
        ]
    , testGroup
        "Unsafe"
        [ testCase "secNonceToBytes consumes the nonce" exportConsumes
        , testCase "secNonceFromBytes . secNonceToBytes signs like the original" exportImport
        , testCase "secNonceFromBytes validates its input" importValidates
        , testCase "nonceGenWithRand rejects random bytes that are not 32 long" randLength
        , testCase "nonceGenWithRand is deterministic and each result is a fresh nonce" withRandFresh
        , testCase "nonceGenCounter is NonceGen with bytes(8, counter) || 0^24 and the secret key" counterIsNonceGen
        , testCase "signWithoutVerification gives the same partial signature as sign" withoutVerification
        ]
    , testGroup
        "deterministicSign"
        [ testCase "the last signer signs deterministically in a 3-signer session" detSignSession
        , testCase "same inputs give the same output; rand, message and aggothernonce change it" detSignDeterministic
        , testCase "rejects auxiliary randomness that is not 32 bytes" detSignRandLength
        , testCase "rejects an aggothernonce with a half at infinity" detSignInfinity
        , testCase "rejects a signer outside the key list" detSignNotInSession
        ]
    ]

-- Fixtures ---------------------------------------------------------------------

sk1, sk2, sk3 :: SecKey
sk1 = secKeyFromInt 0x1111
sk2 = secKeyFromInt 0x2222
sk3 = secKeyFromInt 0x3333

pk1, pk2, pk3 :: PubKey
pk1 = secKeyPubKey sk1
pk2 = secKeyPubKey sk2
pk3 = secKeyPubKey sk3

ctx12 :: KeyAggContext
ctx12 = unsafeRight (keyAgg (pk1 :| [pk2]))

msgA, msgB :: ByteString
msgA = "message A"
msgB = "message B"

-- | A fresh nonce for a key, from a counter (deterministic test setup).
nonceFor :: SecKey -> NonceInputs -> Word64 -> IO (SecNonce, PubNonce)
nonceFor sk inputs n = unsafeRight <$> nonceGenCounter sk n inputs

-- | Another signer's public nonce (any valid points will do).
pubNonceFor :: Integer -> PubNonce
pubNonceFor n = pubNonceFromInts (1000 + n) (2000 + n)

-- | A session for signers 1 and 2 with the given nonces.
sessionWith :: KeyAggContext -> ByteString -> PubNonce -> PubNonce -> Session
sessionWith ctx m a b = newSession ctx (nonceAgg (a :| [b])) m

failure :: Either e a -> Maybe e
failure = either Just (const Nothing)

-- | Signer 1's nonce (with the given inputs), signer 2's nonce, and their session.
setup :: NonceInputs -> KeyAggContext -> ByteString -> IO (SecNonce, Session)
setup inputs ctx m = do
  (sn, pn) <- nonceFor sk1 inputs 1
  pure (sn, sessionWith ctx m pn (pubNonceFor 1))

-- One-shot ----------------------------------------------------------------------

secondSign :: Assertion
secondSign = do
  (sn, ses) <- setup noNonceInputs ctx12 msgA
  result <- sign sn sk1 ses
  assertBool "first sign succeeds" (isJust (either (const Nothing) Just result))
  failsWith SecNonceAlreadyUsed (sign sn sk1 ses)
  -- also with another session
  (_, sesB) <- setup noNonceInputs ctx12 msgB
  failsWith SecNonceAlreadyUsed (sign sn sk1 sesB)

copiesShareState :: Assertion
copiesShareState = do
  (sn, ses) <- setup noNonceInputs ctx12 msgA
  -- A copy kept elsewhere (in a mutable reference, in a list).
  ref <- newIORef sn
  let copies = [sn, sn]
  copy <- readIORef ref
  void (sign copy sk1 ses)
  forM_ copies $ \c -> failsWith SecNonceAlreadyUsed (sign c sk1 ses)
  secNonceIsUsed sn >>= assertBool "the original is marked used"

signWipes :: Assertion
signWipes = do
  (sn, ses) <- setup noNonceInputs ctx12 msgA
  fresh <- peekSecNonce sn
  assertBool "the buffer holds the scalars before use" (BS.any (/= 0) fresh)
  secNonceIsUsed sn >>= assertBool "fresh" . not
  void (sign sn sk1 ses)
  wiped <- peekSecNonce sn
  wiped @?= BS.replicate 64 0

concurrentSign :: Assertion
concurrentSign = do
  caps <- getNumCapabilities
  let threads = max 16 (4 * caps)
  -- Many rounds, each racing all threads on one fresh nonce.
  forM_ [1 .. 50 :: Word64] $ \round' -> do
    (sn, pn) <- nonceFor sk1 noNonceInputs round'
    let ses = sessionWith ctx12 msgA pn (pubNonceFor (toInteger round'))
    start <- newEmptyMVar
    dones <- replicateM threads newEmptyMVar
    forM_ dones $ \done -> forkIO $ do
      readMVar start
      sign sn sk1 ses >>= putMVar done
    putMVar start ()
    results <- traverse takeMVar dones
    let ok = rights results
        errs = lefts results
    length ok @?= 1
    errs @?= replicate (threads - 1) SecNonceAlreadyUsed
    assertBool "the signature verifies" (all (partialSigVerify ses pk1 pn) ok)

failuresConsume :: Assertion
failuresConsume = do
  -- SecNonceKeyMismatch
  (sn, ses) <- setup noNonceInputs ctx12 msgA
  failsWith SecNonceKeyMismatch (sign sn sk2 ses)
  failsWith SecNonceAlreadyUsed (sign sn sk1 ses)
  -- SignerNotInSession
  (sn3, pn3) <- nonceFor sk3 noNonceInputs 1
  let ses3 = sessionWith ctx12 msgA pn3 (pubNonceFor 1)
      ctx13 = unsafeRight (keyAgg (pk1 :| [pk3]))
  failsWith SignerNotInSession (sign sn3 sk3 ses3)
  failsWith SecNonceAlreadyUsed (sign sn3 sk3 (sessionWith ctx13 msgA pn3 pn3))
  peekSecNonce sn3 >>= (@?= BS.replicate 64 0)

-- Session binding ---------------------------------------------------------------

bindAggPubKey :: Assertion
bindAggPubKey = do
  let ctx13 = unsafeRight (keyAgg (pk1 :| [pk3]))
  (sn, ses) <- setup noNonceInputs{nonceAggPubKey = Just (aggXOnlyPubKey ctx13)} ctx12 msgA
  failsWith SecNonceSessionMismatch (sign sn sk1 ses)
  -- The failed attempt consumed it.
  (_, ses13) <- setup noNonceInputs ctx13 msgA
  failsWith SecNonceAlreadyUsed (sign sn sk1 ses13)
  -- The untweaked key does not match a tweaked session either.
  let tweaked = unsafeRight (applyTaprootTweak Nothing ctx12)
  (sn', ses') <- setup noNonceInputs{nonceAggPubKey = Just (aggXOnlyPubKey ctx12)} tweaked msgA
  failsWith SecNonceSessionMismatch (sign sn' sk1 ses')

bindMessage :: Assertion
bindMessage = do
  (sn, ses) <- setup noNonceInputs{nonceMessage = Just msgA} ctx12 msgB
  failsWith SecNonceSessionMismatch (sign sn sk1 ses)
  -- An empty message is a message too.
  (sn', ses') <- setup noNonceInputs{nonceMessage = Just ""} ctx12 msgA
  failsWith SecNonceSessionMismatch (sign sn' sk1 ses')

bindMatches :: Assertion
bindMatches = do
  let tweaked = unsafeRight (applyTaprootTweak Nothing ctx12)
      inputs = noNonceInputs{nonceAggPubKey = Just (aggXOnlyPubKey tweaked), nonceMessage = Just msgA}
  (sn, pn) <- nonceFor sk1 inputs 7
  let ses = sessionWith tweaked msgA pn (pubNonceFor 7)
  psig <- sign sn sk1 ses >>= either (assertFailure . show) pure
  assertBool "partialSigVerify" (partialSigVerify ses pk1 pn psig)

-- Unsafe --------------------------------------------------------------------------

exportConsumes :: Assertion
exportConsumes = do
  (sn, ses) <- setup noNonceInputs ctx12 msgA
  exported <- secNonceToBytes sn
  fmap BS.length exported @?= Just 97
  secNonceToBytes sn >>= (@?= Nothing)
  failsWith SecNonceAlreadyUsed (sign sn sk1 ses)
  peekSecNonce sn >>= (@?= BS.replicate 64 0)
  -- and a used nonce cannot be exported
  (sn', ses') <- setup noNonceInputs ctx12 msgB
  void (sign sn' sk1 ses')
  secNonceToBytes sn' >>= (@?= Nothing)

exportImport :: Assertion
exportImport = do
  (snA, ses) <- setup noNonceInputs ctx12 msgA
  (snB, _) <- setup noNonceInputs ctx12 msgA -- same scalars, separate handle
  bytes <- secNonceToBytes snA >>= maybe (assertFailure "export failed") pure
  BS.drop 64 bytes @?= encode pk1
  imported <- secNonceFromBytes bytes >>= either (assertFailure . show) pure
  secNoncePubNonce imported @?= secNoncePubNonce snB
  a <- sign imported sk1 ses
  b <- sign snB sk1 ses
  assertBool "both sign" (isJust (either (const Nothing) Just a))
  a @?= b

importValidates :: Assertion
importValidates = do
  (sn, _) <- setup noNonceInputs ctx12 msgA
  bytes <- secNonceToBytes sn >>= maybe (assertFailure "export failed") pure
  let err b = failure <$> secNonceFromBytes b
  err (BS.take 96 bytes) >>= (@?= Just (InvalidLength 97 96))
  err (BS.replicate 32 0 <> BS.drop 32 bytes) >>= (@?= Just ScalarZero)
  err (BS.take 32 bytes <> BS.replicate 32 0xFF <> BS.drop 64 bytes) >>= (@?= Just ScalarOutOfRange)
  err (BS.take 64 bytes <> BS.replicate 33 0) >>= (@?= Just PointAtInfinity)
  err (BS.take 64 bytes <> BS.cons 0x04 (BS.drop 65 bytes)) >>= (@?= Just InvalidPoint)

randLength :: Assertion
randLength = do
  failsWith (InvalidRandLength 31) (nonceGenWithRand (BS.replicate 31 1) pk1 noNonceInputs)
  failsWith (InvalidRandLength 33) (nonceGenWithRand (BS.replicate 33 1) pk1 noNonceInputs)

withRandFresh :: Assertion
withRandFresh = do
  let gen r inputs = unsafeRight <$> nonceGenWithRand (BS.replicate 32 r) pk1 inputs
  (sn, pn) <- gen 9 noNonceInputs
  (sn', pn') <- gen 9 noNonceInputs
  (_, other) <- gen 8 noNonceInputs
  (_, extra) <- gen 9 noNonceInputs{nonceExtraInput = Just ""}
  pn' @?= pn
  assertBool "other bytes give another nonce" (other /= pn)
  -- BIP-327: an absent extra input is the empty one.
  extra @?= pn
  -- Each call is its own handle: using one does not use the other.
  let ses = sessionWith ctx12 msgA pn (pubNonceFor 1)
  a <- sign sn sk1 ses
  failsWith SecNonceAlreadyUsed (sign sn sk1 ses)
  b <- sign sn' sk1 ses
  assertBool "signs" (isJust (either (const Nothing) Just a))
  a @?= b

counterIsNonceGen :: Assertion
counterIsNonceGen = do
  let counter = 0x0102030405060708 :: Word64
      rand = BS.pack [1 .. 8] <> BS.replicate 24 0
      inputs = noNonceInputs{nonceMessage = Just msgA, nonceAggPubKey = Just (aggXOnlyPubKey ctx12)}
  (snC, pnC) <- unsafeRight <$> nonceGenCounter sk1 counter inputs
  (snR, pnR) <- unsafeRight <$> nonceGenWithRand rand pk1 inputs{nonceSecKey = Just sk1}
  pnC @?= pnR
  bC <- secNonceToBytes snC
  bR <- secNonceToBytes snR
  bC @?= bR
  -- The nonceSecKey field is ignored; the counter matters.
  ignored <- nonceGenCounter sk1 counter inputs{nonceSecKey = Just sk2}
  fmap snd (either (const Nothing) Just ignored) @?= Just pnC
  next <- nonceGenCounter sk1 (counter + 1) inputs
  assertBool "another counter gives another nonce" (fmap snd (either (const Nothing) Just next) /= Just pnC)

withoutVerification :: Assertion
withoutVerification = do
  (snA, ses) <- setup noNonceInputs ctx12 msgA
  (snB, _) <- setup noNonceInputs ctx12 msgA
  a <- sign snA sk1 ses
  b <- signWithoutVerification snB sk1 ses
  assertBool "signs" (isJust (either (const Nothing) Just a))
  a @?= b
  failsWith SecNonceAlreadyUsed (signWithoutVerification snB sk1 ses)

-- deterministicSign ----------------------------------------------------------------

ctx123 :: KeyAggContext
ctx123 = unsafeRight (keyAgg (pk1 :| [pk2, pk3]) >>= applyTaprootTweak (Just (BS.replicate 32 0xAB)))

detSignSession :: Assertion
detSignSession = do
  let m = BS.replicate 32 0x42
  -- Signers 1 and 2 use nonceGen and send their public nonces first.
  let gen sk = nonceGen (secKeyPubKey sk) noNonceInputs{nonceSecKey = Just sk} >>= either (assertFailure . show) pure
  (sn1, pn1) <- gen sk1
  (sn2, pn2) <- gen sk2
  let aggOther = nonceAgg (pn1 :| [pn2])
  -- Signer 3 signs deterministically, last.
  (pn3, psig3) <- either (assertFailure . show) pure (deterministicSign sk3 aggOther ctx123 m Nothing)
  let ses = newSession ctx123 (nonceAgg (pn1 :| [pn2, pn3])) m
  psig1 <- sign sn1 sk1 ses >>= either (assertFailure . show) pure
  psig2 <- sign sn2 sk2 ses >>= either (assertFailure . show) pure
  assertBool "partialSigVerify of the deterministic signer" (partialSigVerify ses pk3 pn3 psig3)
  assertBool "the signature verifies" (verify (aggXOnlyPubKey ctx123) m (partialSigAgg ses (psig1 :| [psig2, psig3])))

detSignDeterministic :: Assertion
detSignDeterministic = do
  let aggOther = nonceAgg (pubNonceFor 3 :| [pubNonceFor 4])
      aggOther' = nonceAgg (pubNonceFor 3 :| [pubNonceFor 5])
      run a m r = unsafeRight (deterministicSign sk3 a ctx123 m r)
      base = run aggOther msgA Nothing
  run aggOther msgA Nothing @?= base
  run aggOther msgA (Just (BS.replicate 32 1)) @?= run aggOther msgA (Just (BS.replicate 32 1))
  let differs what x = assertBool what (fst x /= fst base && snd x /= snd base)
  differs "rand" (run aggOther msgA (Just (BS.replicate 32 0)))
  differs "message" (run aggOther msgB Nothing)
  differs "aggothernonce" (run aggOther' msgA Nothing)

detSignRandLength :: Assertion
detSignRandLength = do
  let aggOther = nonceAgg (pubNonceFor 3 :| [])
  failure (deterministicSign sk3 aggOther ctx123 msgA (Just (BS.replicate 31 0))) @?= Just (InvalidAuxRandLength 31)
  failure (deterministicSign sk3 aggOther ctx123 msgA (Just BS.empty)) @?= Just (InvalidAuxRandLength 0)

detSignInfinity :: Assertion
detSignInfinity = do
  let pn = pubNonceFor 3
      half = BS.take 33 (encode pn)
      agg b = unsafeRight (decode b) :: AggNonce
  failure (deterministicSign sk3 (agg (BS.replicate 33 0 <> half)) ctx123 msgA Nothing) @?= Just AggOtherNonceAtInfinity
  failure (deterministicSign sk3 (agg (half <> BS.replicate 33 0)) ctx123 msgA Nothing) @?= Just AggOtherNonceAtInfinity

detSignNotInSession :: Assertion
detSignNotInSession = do
  let aggOther = nonceAgg (pubNonceFor 3 :| [])
  failure (deterministicSign sk3 aggOther ctx12 msgA Nothing) @?= Just SignerNotInSession
