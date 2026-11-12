{-# LANGUAGE OverloadedStrings #-}

{- | Property tests of the whole protocol.

The central property runs complete sessions (1 to 6 signers, sometimes with
duplicate keys, random chains of plain, x-only and Taproot tweaks) and checks
the final signature with BIP-340 verification against 'aggXOnlyPubKey'. The
negative properties corrupt one input and check that verification fails.
-}
module Properties (testProtocol) where

import Control.Monad (foldM, void)
import Crypto.Curve.Secp256k1.MuSig2
import Crypto.Curve.Secp256k1.MuSig2.Internal.KeyAgg (KeyAggContext (..))
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (curveOrder, integerToBytes32)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Types (PartialSignature (..), Tweak (..))
import Crypto.Curve.Secp256k1.MuSig2.Unsafe (nonceGenWithRand)
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (elemIndex, sort)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NE
import Data.Maybe (fromMaybe)
import Generators
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Util (unsafeRight)

testProtocol :: TestTree
testProtocol =
  testGroup
    "Protocol properties"
    [ localOption (QuickCheckTests 200) $
        testProperty "end to end: every partial signature verifies and the signature verifies against aggXOnlyPubKey" prop_endToEnd
    , testProperty "a corrupted partial signature (s + 1) fails partialSigVerify and the final verify" prop_corruptedPartialSig
    , testProperty "a partial signature checked with another signer's nonce fails" prop_wrongNonce
    , testProperty "a partial signature checked in a session for another message fails" prop_wrongMessage
    , testProperty "signerIndex and partialSigVerify, for every signer index" prop_everySignerIndex
    , testProperty "sign rejects a nonce for another key and a key outside the session" prop_signRejects
    , testProperty "keySort is invariant under permutation and sorts by encoding" prop_keySort
    , testProperty "plain tweaks commute and add up" prop_plainTweaksAdd
    , testProperty "applyTaprootTweak is the BIP-341 TapTweak as an x-only tweak" prop_taprootIsXOnly
    , testCase "nonceGen draws fresh randomness on every call" nonceGenFresh
    , testCase "nonceGen rejects a secret key for another public key" nonceGenKeyMismatch
    ]

-- Scenarios --------------------------------------------------------------------

data Signer = Signer
  { signerSecKey :: SecKey
  , signerRand :: ByteString
  , signerBind :: (Bool, Bool, Bool, Maybe ByteString)
  -- ^ Bind the nonce to the secret key, the aggregate key, the message; extra input.
  }

data Scenario = Scenario
  { scSigners :: NonEmpty Signer
  , scSortKeys :: Bool
  , scTweaks :: [TweakOp]
  , scMessage :: ByteString
  }

instance Show Scenario where
  show sc =
    unlines $
      [ "signers (secret key, rand, binding):"
      ]
        <> [ "  " <> showSecKey (signerSecKey s) <> " " <> show (signerRand s) <> " " <> show (signerBind s)
           | s <- NE.toList (scSigners sc)
           ]
        <> [ "sorted: " <> show (scSortKeys sc)
           , "tweaks: " <> show (scTweaks sc)
           , "message: " <> show (scMessage sc)
           ]

genScenario :: Gen Scenario
genScenario = do
  n <- choose (1, 6)
  sks <- vectorOf n genSecKey
  -- Sometimes a signer reuses another signer's key (each with its own nonce).
  sks' <- case sks of
    sk0 : _ : _ -> frequency [(3, pure sks), (1, (\j -> take j sks <> [sk0] <> drop (j + 1) sks) <$> choose (1, n - 1))]
    _ -> pure sks
  signers <- traverse (\sk -> Signer sk <$> genRand <*> genBind) sks'
  Scenario (NE.fromList signers) <$> arbitrary <*> (choose (0, 4) >>= (`vectorOf` genTweakOp)) <*> genMessage
 where
  genBind = (,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> oneof [pure Nothing, Just <$> genMessage]

data Run = Run
  { runCtx :: KeyAggContext
  , runPubKeys :: NonEmpty PubKey
  -- ^ In signer order (not the aggregation order).
  , runPubNonces :: NonEmpty PubNonce
  , runSession :: Session
  , runPsigs :: NonEmpty PartialSignature
  , runSignature :: Signature
  }

runScenario :: Scenario -> IO (Either String Run)
runScenario sc = case setup of
  Left err -> pure (Left err)
  Right ctx -> do
    generated <- traverse (nonceFor ctx) signers
    case first show (sequence generated) of
      Left err -> pure (Left err)
      Right nonces -> do
        let session = newSession ctx (nonceAgg (fmap snd nonces)) msg
        signed <- traverse (\(s, (sn, _)) -> sign sn (signerSecKey s) session) (NE.zip signers nonces)
        pure $ do
          psigs <- first show (sequence signed)
          pure (Run ctx pks (fmap snd nonces) session psigs (partialSigAgg session psigs))
 where
  signers = scSigners sc
  pks = fmap (secKeyPubKey . signerSecKey) signers
  msg = scMessage sc
  setup = do
    ctx0 <- first show (keyAgg (if scSortKeys sc then keySort pks else pks))
    first show (foldM applyTweakOp ctx0 (scTweaks sc))
  nonceFor ctx s =
    let sk = signerSecKey s
        (bindSk, bindAgg, bindMsg, extra) = signerBind s
        inputs =
          NonceInputs
            { nonceSecKey = if bindSk then Just sk else Nothing
            , nonceAggPubKey = if bindAgg then Just (aggXOnlyPubKey ctx) else Nothing
            , nonceMessage = if bindMsg then Just msg else Nothing
            , nonceExtraInput = extra
            }
     in nonceGenWithRand (signerRand s) (secKeyPubKey sk) inputs

-- | Runs a scenario and a property on its result.
withRun :: (Testable p) => (Scenario -> Run -> p) -> Property
withRun k = forAll genScenario $ \sc -> ioProperty $ do
  result <- runScenario sc
  pure $ case result of
    Left err -> counterexample err False
    Right r ->
      tabulate "signers" [show (length (scSigners sc))]
        . classify (kacGaccNeg (runCtx r)) "gacc = n - 1"
        . classify (any isTaproot (scTweaks sc)) "Taproot tweak"
        . classify (hasDuplicates (runPubKeys r)) "duplicate keys"
        $ property (k sc r)
 where
  isTaproot (Taproot _) = True
  isTaproot _ = False
  hasDuplicates pks = length (NE.nub pks) /= length pks

-- | Picks a signer index.
withSigner :: (Testable p) => Run -> (Int -> p) -> Property
withSigner r = forAll (choose (0, length (runPubKeys r) - 1))

at :: NonEmpty a -> Int -> a
at xs i = NE.toList xs !! i

-- Properties --------------------------------------------------------------------

prop_endToEnd :: Property
prop_endToEnd = withRun $ \sc r ->
  let ctx = runCtx r
   in counterexample "partialSigVerify" (and (zipWith3 (partialSigVerify (runSession r)) (NE.toList (runPubKeys r)) (NE.toList (runPubNonces r)) (NE.toList (runPsigs r))))
        .&&. counterexample "verify" (verify (aggXOnlyPubKey ctx) (scMessage sc) (runSignature r))
        .&&. encode (aggXOnlyPubKey ctx) === BS.drop 1 (encode (aggPubKey ctx))

prop_corruptedPartialSig :: Property
prop_corruptedPartialSig = withRun $ \sc r -> withSigner r $ \j ->
  let PartialSignature s = at (runPsigs r) j
      bad = PartialSignature ((s + 1) `mod` curveOrder)
      psigs = NE.fromList [if i == j then bad else p | (i, p) <- zip [0 ..] (NE.toList (runPsigs r))]
   in not (partialSigVerify (runSession r) (at (runPubKeys r) j) (at (runPubNonces r) j) bad)
        .&&. not (verify (aggXOnlyPubKey (runCtx r)) (scMessage sc) (partialSigAgg (runSession r) psigs))

prop_wrongNonce :: Property
prop_wrongNonce = withRun $ \_ r ->
  let n = length (runPubKeys r)
   in n > 1 ==> withSigner r $ \j -> forAll ((\d -> (j + d) `mod` n) <$> choose (1, n - 1)) $ \k ->
        not (partialSigVerify (runSession r) (at (runPubKeys r) j) (at (runPubNonces r) k) (at (runPsigs r) j))

prop_wrongMessage :: Property
prop_wrongMessage = withRun $ \sc r -> withSigner r $ \j ->
  let msg' = BS.cons 0 (scMessage sc)
      session' = newSession (runCtx r) (nonceAgg (runPubNonces r)) msg'
   in not (partialSigVerify session' (at (runPubKeys r) j) (at (runPubNonces r) j) (at (runPsigs r) j))
        .&&. not (verify (aggXOnlyPubKey (runCtx r)) msg' (runSignature r))

{- | For every index i of the key list: signerIndex finds the first occurrence
of the key, and signer j's partial signature verifies exactly for its own key.
-}
prop_everySignerIndex :: Property
prop_everySignerIndex = withRun $ \_ r -> withSigner r $ \j ->
  let ctx = runCtx r
      keys = NE.toList (keyAggPubKeys ctx)
      pkJ = at (runPubKeys r) j
      check i pk =
        counterexample ("index " <> show i) $
          signerIndex ctx pk === elemIndex pk keys
            .&&. partialSigVerify (runSession r) pk (at (runPubNonces r) j) (at (runPsigs r) j) === (pk == pkJ)
   in conjoin (zipWith check [0 :: Int ..] keys)

prop_signRejects :: Property
prop_signRejects = withRun $ \_ r -> forAllShow genSecKey showSecKey $ \outsider -> withSigner r $ \j ->
  let session = runSession r
      outsiderPk = secKeyPubKey outsider
   in notElem outsiderPk (runPubKeys r) ==> ioProperty $ do
        (outsiderNonce, _) <- nonceGenWithRand (BS.replicate 32 7) outsiderPk noNonceInputs >>= either (fail . show) pure
        result <- sign outsiderNonce outsider session
        pure $
          void result === Left SignerNotInSession
            .&&. signerIndex (runCtx r) outsiderPk === Nothing
            .&&. not (partialSigVerify session outsiderPk (at (runPubNonces r) j) (at (runPsigs r) j))

prop_keySort :: Property
prop_keySort = forAll (choose (1, 8) >>= (`vectorOf` genPubKey)) $ \keys -> forAll (shuffle keys) $ \perm ->
  let sorted = keySort (NE.fromList keys)
   in sorted === keySort (NE.fromList perm)
        .&&. map encode (NE.toList sorted) === sort (map encode keys)
        .&&. fmap aggPubKey (keyAgg sorted) === fmap aggPubKey (keyAgg (keySort (NE.fromList perm)))

prop_plainTweaksAdd :: Property
prop_plainTweaksAdd = forAll ((,,) <$> genKeys <*> genTweak <*> genTweak) $ \(keys, t1, t2) ->
  let ctx = unsafeRight (keyAgg keys)
      apply ts = fmap aggPubKey (foldM (flip applyPlainTweak) ctx ts)
      Tweak a = t1
      Tweak b = t2
      sumT = Tweak ((a + b) `mod` curveOrder)
   in apply [t1, t2] === apply [t2, t1] .&&. apply [t1, t2] === apply [sumT]
 where
  genKeys = (:|) <$> genPubKey <*> (choose (0, 3) >>= (`vectorOf` genPubKey))

-- | Independent BIP-341 computation: t = hash_TapTweak(xbytes(Q) || root).
prop_taprootIsXOnly :: Property
prop_taprootIsXOnly = forAll ((,) <$> genPubKey <*> oneof [pure Nothing, Just <$> genBytes 32]) $ \(pk, root) ->
  let ctx = unsafeRight (keyAgg (pk :| []))
      tagHash = SHA256.hash "TapTweak"
      t = SHA256.hash (tagHash <> tagHash <> encode (aggXOnlyPubKey ctx) <> fromMaybe BS.empty root)
   in fmap aggPubKey (applyTaprootTweak root ctx) === fmap aggPubKey (applyXOnlyTweak (unsafeRight (decode t)) ctx)

nonceGenFresh :: Assertion
nonceGenFresh = do
  let pk = secKeyPubKey (unsafeRight (secKeyFromBytes (integerToBytes32 3)))
  a <- nonceGen pk noNonceInputs
  b <- nonceGen pk noNonceInputs
  assertBool "two calls give different public nonces" (fmap snd a /= fmap snd b)

nonceGenKeyMismatch :: Assertion
nonceGenKeyMismatch = do
  let sk n = unsafeRight (secKeyFromBytes (integerToBytes32 n))
  result <- nonceGen (secKeyPubKey (sk 3)) noNonceInputs{nonceSecKey = Just (sk 4)}
  either Just (const Nothing) result @?= Just NonceSecKeyMismatch
