{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

{- | Tests of "Crypto.Curve.Secp256k1.MuSig2.Coordinator": honest rounds
produce a valid signature whatever the order contributions arrive in, and
every kind of misbehavior is blamed on exactly the signers responsible.
-}
module CoordinatorRounds (testCoordinator) where

import Control.Monad (foldM, forM)
import Crypto.Curve.Secp256k1.MuSig2
import Crypto.Curve.Secp256k1.MuSig2.Coordinator
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (curveOrder, integerToBytes32)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Types (PartialSignature (..))
import Crypto.Curve.Secp256k1.MuSig2.Unsafe (nonceGenWithRand)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Either (fromRight, isRight)
import Data.List (sortOn)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NE
import Generators (TweakOp, applyTweakOp, genMessage, genNonZeroScalar, genTweakOp)
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Util (secKeyFromInt, unsafeRight)

testCoordinator :: TestTree
testCoordinator =
  testGroup
    "Coordinator"
    [ testGroup
        "round one"
        [ testCase "honest signers: the aggregate nonce is nonceAgg of the nonces in signer order" nonceRoundHonest
        , testCase "an invalid encoding is blamed on its sender, with the decoding error" nonceRoundBadEncoding
        , testCase "an index outside the key list is an unknown signer" nonceRoundUnknown
        , testCase "a second, different nonce is a duplicate; the same bytes again are accepted" nonceRoundDuplicate
        , testCase "finishing blames every signer whose nonce is missing, in order" nonceRoundMissingBlame
        , testCase "a rejected contribution leaves the round unchanged, and the signer can send again" nonceRoundRetry
        ]
    , testGroup
        "round two"
        [ testCase "honest signers (two share a key): the signature verifies" sigRoundHonest
        , testCase "an invalid encoding is blamed on its sender, with the decoding error" sigRoundBadEncoding
        , testCase "a wrong partial signature is invalid" sigRoundCorrupt
        , testCase "another signer's partial signature is invalid, even for the same key" sigRoundOtherSigners
        , testCase "a second, different partial signature is a duplicate; the same bytes again are accepted" sigRoundDuplicate
        , testCase "an index outside the key list is an unknown signer" sigRoundUnknown
        , testCase "finishing blames every signer whose partial signature is missing" sigRoundMissingBlame
        , testCase "the coordinator can sign in sigRoundSession" sigRoundCoordinatorSigns
        ]
    , testGroup
        "properties"
        [ testProperty "honest contributions in any order give the same aggregate nonce and a valid signature" prop_orderIndependent
        , testProperty "round one blames exactly the misbehaving signers" prop_nonceRoundBlame
        , testProperty "round two blames exactly the misbehaving signers" prop_sigRoundBlame
        ]
    ]

-- Fixtures ---------------------------------------------------------------------

-- | A session: secret keys in signer order (duplicates allowed), the context and the message.
data Fixture = Fixture
  { fxSecKeys :: NonEmpty SecKey
  , fxCtx :: KeyAggContext
  , fxMsg :: ByteString
  }

-- | Three signers, the first and last sharing a key, under a Taproot tweak.
fixture :: Fixture
fixture = Fixture sks ctx "coordinator test"
 where
  sks = fmap secKeyFromInt (3 :| [5, 3])
  ctx = unsafeRight (keyAgg (fmap secKeyPubKey sks) >>= applyTaprootTweak Nothing)

signerCount :: Fixture -> Int
signerCount = length . fxSecKeys

-- | A nonce for every signer, deterministic in the signer index and a seed.
nonces :: Fixture -> Int -> IO [(SecNonce, PubNonce)]
nonces fx seed = forM (zip [0 ..] (NE.toList (fxSecKeys fx))) $ \(i, sk) ->
  unsafeRight <$> nonceGenWithRand (rand i) (secKeyPubKey sk) noNonceInputs
 where
  rand :: Int -> ByteString
  rand i = integerToBytes32 (toInteger seed * 1000 + toInteger i + 1)

-- | The encoded public nonce of a signer.
pubNonceOf :: [(SecNonce, PubNonce)] -> Int -> ByteString
pubNonceOf ns i = encode (snd (ns !! i))

-- | Receives every public nonce in signer order.
receiveAllNonces :: Fixture -> [PubNonce] -> NonceRound
receiveAllNonces fx pns = unsafeRight (foldM (\r (i, pn) -> receivePubNonce i (encode pn) r) (newNonceRound (fxCtx fx)) (zip [0 ..] pns))

-- | Round one done honestly, and every signer's partial signature for the resulting session.
honestRoundTwo :: Fixture -> IO (CollectedNonces, [PartialSignature])
honestRoundTwo fx = do
  ns <- nonces fx 1
  let collected = unsafeRight (finishNonceRound (receiveAllNonces fx (map snd ns)))
      ses = sigRoundSession (newSigRound collected (fxMsg fx))
  psigs <- forM (zip (NE.toList (fxSecKeys fx)) ns) $ \(sk, (sn, _)) -> unsafeRight <$> sign sn sk ses
  pure (collected, psigs)

receiveAllPsigs :: CollectedNonces -> ByteString -> [(Int, PartialSignature)] -> Either Blame SigRound
receiveAllPsigs collected msg = foldM (\r (i, psig) -> receivePartialSig i (encode psig) r) (newSigRound collected msg)

-- | Adds one to a partial signature.
corrupt :: PartialSignature -> PartialSignature
corrupt (PartialSignature s) = PartialSignature ((s + 1) `mod` curveOrder)

-- | The error of a 'Left'.
blameOf :: Either e a -> Maybe e
blameOf = either Just (const Nothing)

-- Round one --------------------------------------------------------------------

nonceRoundHonest :: Assertion
nonceRoundHonest = do
  ns <- nonces fixture 1
  let pns = map snd ns
      collected = unsafeRight (finishNonceRound (receiveAllNonces fixture pns))
  NE.toList (collectedPubNonces collected) @?= pns
  encode (collectedAggNonce collected) @?= encode (nonceAgg (NE.fromList pns))
  encode (aggXOnlyPubKey (collectedKeyAgg collected)) @?= encode (aggXOnlyPubKey (fxCtx fixture))

nonceRoundBadEncoding :: Assertion
nonceRoundBadEncoding = do
  ns <- nonces fixture 1
  let good = pubNonceOf ns 0
      r = newNonceRound (fxCtx fixture)
      receive bytes = blameOf (receivePubNonce 1 bytes r)
  receive (BS.take 65 good) @?= Just (Blame 1 (InvalidPubNonceEncoding (InvalidLength 66 65)))
  receive (BS.cons 0x04 (BS.drop 1 good)) @?= Just (Blame 1 (InvalidPubNonceEncoding InvalidPoint))
  receive (BS.take 33 good <> BS.replicate 33 0) @?= Just (Blame 1 (InvalidPubNonceEncoding PointAtInfinity))
  receive BS.empty @?= Just (Blame 1 (InvalidPubNonceEncoding (InvalidLength 66 0)))

nonceRoundUnknown :: Assertion
nonceRoundUnknown = do
  ns <- nonces fixture 1
  let good = pubNonceOf ns 0
      r = newNonceRound (fxCtx fixture)
  blameOf (receivePubNonce (-1) good r) @?= Just (Blame (-1) UnknownSigner)
  blameOf (receivePubNonce 3 good r) @?= Just (Blame 3 UnknownSigner)
  -- Checked before decoding: an unknown index is blamed whatever it sends.
  blameOf (receivePubNonce 7 "junk" r) @?= Just (Blame 7 UnknownSigner)

nonceRoundDuplicate :: Assertion
nonceRoundDuplicate = do
  ns <- nonces fixture 1
  other <- nonces fixture 2
  let r = unsafeRight (receivePubNonce 0 (pubNonceOf ns 0) (newNonceRound (fxCtx fixture)))
  blameOf (receivePubNonce 0 (pubNonceOf other 0) r) @?= Just (Blame 0 DuplicateContribution)
  -- An invalid second contribution is a duplicate too.
  blameOf (receivePubNonce 0 "junk" r) @?= Just (Blame 0 DuplicateContribution)
  -- A retry with the same bytes changes nothing.
  fmap nonceRoundMissing (receivePubNonce 0 (pubNonceOf ns 0) r) @?= Right [1, 2]

nonceRoundMissingBlame :: Assertion
nonceRoundMissingBlame = do
  ns <- nonces fixture 1
  let r = unsafeRight (receivePubNonce 1 (encode (snd (ns !! 1))) (newNonceRound (fxCtx fixture)))
  nonceRoundMissing (newNonceRound (fxCtx fixture)) @?= [0, 1, 2]
  nonceRoundMissing r @?= [0, 2]
  blameOf (finishNonceRound r) @?= Just (Blame 0 MissingContribution :| [Blame 2 MissingContribution])

nonceRoundRetry :: Assertion
nonceRoundRetry = do
  ns <- nonces fixture 1
  let r0 = newNonceRound (fxCtx fixture)
  blameOf (receivePubNonce 2 "junk" r0) @?= Just (Blame 2 (InvalidPubNonceEncoding (InvalidLength 66 4)))
  -- The caller keeps r0; the signer sends a valid nonce afterwards.
  let r = receiveAllNonces fixture (map snd ns)
  assertBool "finishes" (isRight (finishNonceRound r))
  nonceRoundMissing r0 @?= [0, 1, 2]

-- Round two --------------------------------------------------------------------

sigRoundHonest :: Assertion
sigRoundHonest = do
  (collected, psigs) <- honestRoundTwo fixture
  let sr = unsafeRight (receiveAllPsigs collected (fxMsg fixture) (zip [0 ..] psigs))
      ses = sigRoundSession sr
  sigRoundMissing sr @?= []
  sig <- either (assertFailure . show) pure (finishSigRound sr)
  sig @?= partialSigAgg ses (NE.fromList psigs)
  assertBool "verify" (verify (aggXOnlyPubKey (fxCtx fixture)) (fxMsg fixture) sig)

sigRoundBadEncoding :: Assertion
sigRoundBadEncoding = do
  (collected, psigs) <- honestRoundTwo fixture
  let sr = newSigRound collected (fxMsg fixture)
      receive bytes = blameOf (receivePartialSig 2 bytes sr)
  receive (BS.take 31 (encode (psigs !! 1))) @?= Just (Blame 2 (InvalidPartialSigEncoding (InvalidLength 32 31)))
  receive (integerToBytes32 curveOrder) @?= Just (Blame 2 (InvalidPartialSigEncoding ScalarOutOfRange))
  receive (BS.replicate 32 0xFF) @?= Just (Blame 2 (InvalidPartialSigEncoding ScalarOutOfRange))

sigRoundCorrupt :: Assertion
sigRoundCorrupt = do
  (collected, psigs) <- honestRoundTwo fixture
  let sr = newSigRound collected (fxMsg fixture)
  blameOf (receivePartialSig 1 (encode (corrupt (psigs !! 1))) sr) @?= Just (Blame 1 InvalidPartialSignature)
  blameOf (receivePartialSig 1 (BS.replicate 32 0) sr) @?= Just (Blame 1 InvalidPartialSignature)

sigRoundOtherSigners :: Assertion
sigRoundOtherSigners = do
  (collected, psigs) <- honestRoundTwo fixture
  let sr = newSigRound collected (fxMsg fixture)
      sends i j = blameOf (receivePartialSig i (encode (psigs !! j)) sr)
  sends 0 1 @?= Just (Blame 0 InvalidPartialSignature)
  -- Signers 0 and 2 share a key but not a nonce.
  sends 0 2 @?= Just (Blame 0 InvalidPartialSignature)
  sends 2 0 @?= Just (Blame 2 InvalidPartialSignature)

sigRoundDuplicate :: Assertion
sigRoundDuplicate = do
  (collected, psigs) <- honestRoundTwo fixture
  let sr = unsafeRight (receivePartialSig 1 (encode (psigs !! 1)) (newSigRound collected (fxMsg fixture)))
  blameOf (receivePartialSig 1 (encode (corrupt (psigs !! 1))) sr) @?= Just (Blame 1 DuplicateContribution)
  fmap sigRoundMissing (receivePartialSig 1 (encode (psigs !! 1)) sr) @?= Right [0, 2]

sigRoundUnknown :: Assertion
sigRoundUnknown = do
  (collected, psigs) <- honestRoundTwo fixture
  let sr = newSigRound collected (fxMsg fixture)
  blameOf (receivePartialSig 3 (encode (psigs !! 1)) sr) @?= Just (Blame 3 UnknownSigner)
  blameOf (receivePartialSig (-5) (encode (psigs !! 1)) sr) @?= Just (Blame (-5) UnknownSigner)

sigRoundMissingBlame :: Assertion
sigRoundMissingBlame = do
  (collected, psigs) <- honestRoundTwo fixture
  let sr = unsafeRight (receiveAllPsigs collected (fxMsg fixture) [(1, psigs !! 1)])
  sigRoundMissing sr @?= [0, 2]
  blameOf (finishSigRound sr) @?= Just (SigRoundBlame (Blame 0 MissingContribution :| [Blame 2 MissingContribution]))
  blameOf (finishSigRound (newSigRound collected (fxMsg fixture)))
    @?= Just (SigRoundBlame (Blame 0 MissingContribution :| [Blame 1 MissingContribution, Blame 2 MissingContribution]))

sigRoundCoordinatorSigns :: Assertion
sigRoundCoordinatorSigns = do
  -- Signer 1 coordinates: it signs in the round's own session.
  ns <- nonces fixture 3
  let collected = unsafeRight (finishNonceRound (receiveAllNonces fixture (map snd ns)))
      sr0 = newSigRound collected (fxMsg fixture)
  psigs <- forM (zip (NE.toList (fxSecKeys fixture)) ns) $ \(sk, (sn, _)) -> unsafeRight <$> sign sn sk (sigRoundSession sr0)
  sr <- either (assertFailure . show) pure (foldM (\r (i, psig) -> receivePartialSig i (encode psig) r) sr0 (zip [0 ..] psigs))
  assertBool "signature" (either (const False) (verify (aggXOnlyPubKey (fxCtx fixture)) (fxMsg fixture)) (finishSigRound sr))

-- Properties -------------------------------------------------------------------

-- | A random session: secret keys (with repeats), tweaks, a message, nonce randomness.
data Scenario = Scenario
  { scKeys :: [Integer]
  , scTweaks :: [TweakOp]
  , scMsg :: ByteString
  , scSeed :: Int
  }
  deriving (Show)

genScenario :: Gen Scenario
genScenario = do
  u <- choose (1, 6)
  pool <- vectorOf u genNonZeroScalar
  keys <- vectorOf u (elements pool)
  tweaks <- choose (0, 3) >>= (`vectorOf` genTweakOp)
  Scenario keys tweaks <$> genMessage <*> arbitrary

-- | The fixture of a scenario; tweaks that fail are skipped.
scenarioFixture :: Scenario -> Fixture
scenarioFixture sc = Fixture sks ctx (scMsg sc)
 where
  sks = NE.fromList (map secKeyFromInt (scKeys sc))
  ctx0 = unsafeRight (keyAgg (fmap secKeyPubKey sks))
  ctx = foldl (\c op -> fromRight c (applyTweakOp c op)) ctx0 (scTweaks sc)

-- | Runs both rounds honestly, receiving contributions in the given orders.
runHonest :: Fixture -> Int -> [Int] -> [Int] -> IO (Either String (AggNonce, Signature))
runHonest fx seed order1 order2 = do
  ns <- nonces fx seed
  let pns = map snd ns
  case showLeft (foldM (\r i -> receivePubNonce i (encode (pns !! i)) r) (newNonceRound (fxCtx fx)) order1) >>= showLeft . finishNonceRound of
    Left err -> pure (Left err)
    Right collected -> do
      let sr0 = newSigRound collected (fxMsg fx)
      psigs <- forM (zip (NE.toList (fxSecKeys fx)) ns) $ \(sk, (sn, _)) -> unsafeRight <$> sign sn sk (sigRoundSession sr0)
      pure $ do
        sr <- showLeft (foldM (\r i -> receivePartialSig i (encode (psigs !! i)) r) sr0 order2)
        sig <- showLeft (finishSigRound sr)
        Right (collectedAggNonce collected, sig)
 where
  showLeft :: (Show e) => Either e a -> Either String a
  showLeft = either (Left . show) Right

prop_orderIndependent :: Property
prop_orderIndependent = forAll genScenario $ \sc -> do
  let fx = scenarioFixture sc
      idx = [0 .. signerCount fx - 1]
  forAll ((,,,) <$> shuffle idx <*> shuffle idx <*> shuffle idx <*> shuffle idx) $ \(a1, a2, b1, b2) -> ioProperty $ do
    ra <- runHonest fx (scSeed sc) a1 a2
    rb <- runHonest fx (scSeed sc) b1 b2
    pure $ case (ra, rb) of
      (Right (aggA, sigA), Right (aggB, sigB)) ->
        counterexample "results differ" (aggA == aggB && sigA == sigB)
          .&&. counterexample "signature does not verify" (verify (aggXOnlyPubKey (fxCtx fx)) (fxMsg fx) sigA)
      _ -> counterexample (show (ra, rb)) False

-- | How a signer behaves in one round.
data Behavior
  = Honest
  | -- | Sends a truncated encoding.
    BadEncoding
  | -- | Sends nothing.
    Silent
  | -- | Sends its contribution, then a different one.
    Equivocates
  | -- | Round two: sends its partial signature plus one.
    Corrupts
  | -- | Round two: sends the next signer's partial signature.
    SendsOthers
  deriving (Eq, Show)

-- | A message from a signer index, and the blame it must cause (if any).
type Message = (Int, ByteString, Maybe BlameReason)

{- | Delivers the messages in order (the round is unchanged after a blame)
and returns the blames, then the blames of finishing.
-}
deliver :: (Int -> ByteString -> r -> Either Blame r) -> r -> [Message] -> (r, [Blame])
deliver receive r0 msgs = (final, received)
 where
  (final, received) = foldl step (r0, []) msgs
  step (r, bs) (i, bytes, _) = either (\b -> (r, bs <> [b])) (,bs) (receive i bytes r)

-- | Behaviors for every signer, and contributions from unknown indices.
genBehaviors :: [Behavior] -> Int -> Gen ([Behavior], [Int])
genBehaviors choices u = do
  bs <- vectorOf u (frequency [(4, pure Honest), (1, elements choices)])
  unknown <- sublistOf [-1, u, u + 3]
  pure (bs, unknown)

{- | Expected blames: those of the messages, plus 'MissingContribution' for
every signer that never got a contribution accepted.
-}
expectedBlames :: [Message] -> [Behavior] -> [Blame]
expectedBlames msgs bs = sortOn show ([Blame i why | (i, _, Just why) <- msgs] <> [Blame i MissingContribution | (i, b) <- zip [0 ..] bs, b `elem` [Silent, BadEncoding, Corrupts, SendsOthers]])

prop_nonceRoundBlame :: Property
prop_nonceRoundBlame = forAll genScenario $ \sc -> do
  let fx = scenarioFixture sc
  forAll (genBehaviors [BadEncoding, Silent, Equivocates] (signerCount fx)) $ \(bs, unknown) -> ioProperty $ do
    ns <- nonces fx (scSeed sc)
    others <- nonces fx (scSeed sc + 1)
    let pn i = encode (snd (ns !! i))
        firsts =
          [ (i, bytes, why)
          | (i, b) <- zip [0 ..] bs
          , (bytes, why) <- case b of
              Silent -> []
              BadEncoding -> [(BS.take 65 (pn i), Just (InvalidPubNonceEncoding (InvalidLength 66 65)))]
              _ -> [(pn i, Nothing)]
          ]
            <> [(i, pn 0, Just UnknownSigner) | i <- unknown]
        seconds = [(i, encode (snd (others !! i)), Just DuplicateContribution) | (i, Equivocates) <- zip [0 ..] bs]
    pure . forAll (shuffle firsts) $ \shuffled ->
      let msgs = shuffled <> seconds
          (final, received) = deliver receivePubNonce (newNonceRound (fxCtx fx)) msgs
          finishing = either NE.toList (const []) (finishNonceRound final)
       in counterexample (show (map (\(i, _, r) -> (i, r)) msgs)) $
            sortOn show (received <> finishing) === expectedBlames msgs bs

prop_sigRoundBlame :: Property
prop_sigRoundBlame = forAll genScenario $ \sc -> do
  let fx = scenarioFixture sc
      u = signerCount fx
      choices = [BadEncoding, Silent, Equivocates, Corrupts] <> [SendsOthers | u >= 2]
  forAll (genBehaviors choices u) $ \(bs, unknown) -> ioProperty $ do
    ns <- nonces fx (scSeed sc)
    let collected = unsafeRight (finishNonceRound (receiveAllNonces fx (map snd ns)))
        sr0 = newSigRound collected (fxMsg fx)
    psigs <- forM (zip (NE.toList (fxSecKeys fx)) ns) $ \(sk, (sn, _)) -> unsafeRight <$> sign sn sk (sigRoundSession sr0)
    let ps i = psigs !! i
        firsts =
          [ (i, bytes, why)
          | (i, b) <- zip [0 ..] bs
          , (bytes, why) <- case b of
              Silent -> []
              BadEncoding -> [(BS.take 31 (encode (ps i)), Just (InvalidPartialSigEncoding (InvalidLength 32 31)))]
              Corrupts -> [(encode (corrupt (ps i)), Just InvalidPartialSignature)]
              SendsOthers -> [(encode (ps ((i + 1) `mod` u)), Just InvalidPartialSignature)]
              _ -> [(encode (ps i), Nothing)]
          ]
            <> [(i, encode (ps 0), Just UnknownSigner) | i <- unknown]
        seconds = [(i, encode (corrupt (ps i)), Just DuplicateContribution) | (i, Equivocates) <- zip [0 ..] bs]
    pure . forAll (shuffle firsts) $ \shuffled ->
      let msgs = shuffled <> seconds
          (final, received) = deliver receivePartialSig sr0 msgs
       in counterexample (show (map (\(i, _, r) -> (i, r)) msgs)) $ case finishSigRound final of
            Right sig ->
              counterexample "a signature despite misbehavior" (all (`elem` [Honest, Equivocates]) bs)
                .&&. counterexample "the signature does not verify" (verify (aggXOnlyPubKey (fxCtx fx)) (fxMsg fx) sig)
                .&&. sortOn show received === expectedBlames msgs bs
            Left (SigRoundBlame missing) -> sortOn show (received <> NE.toList missing) === expectedBlames msgs bs
            Left FinalSignatureInvalid -> counterexample "FinalSignatureInvalid" False
