{-# LANGUAGE OverloadedStrings #-}

{- | The differential corpus in @test\/vectors\/diff\/corpus.json@: NonceGen
cases and complete signing sessions whose expected values were computed by
the BIP-327 reference implementation (@scripts\/gen-diff-corpus.py@ documents
the format and how to regenerate it).

Every session is replayed through the public API (with
'nonceGenWithRand' and 'secNonceFromBytes' from
"Crypto.Curve.Secp256k1.MuSig2.Unsafe" for reproducible nonces) and through
"Crypto.Curve.Secp256k1.MuSig2.Coordinator", and every value is compared
byte for byte. The file is pinned by its SHA-256, and a coverage test checks
that it still contains every kind of case it is meant to.
-}
module DiffCorpus (diffCorpusTests) where

import Control.Monad (foldM, forM, forM_, unless, zipWithM_)
import Crypto.Curve.Secp256k1.MuSig2
import Crypto.Curve.Secp256k1.MuSig2.Coordinator (
  SigRoundError (..),
  collectedAggNonce,
  finishNonceRound,
  finishSigRound,
  newNonceRound,
  newSigRound,
  receivePartialSig,
  receivePubNonce,
 )
import Crypto.Curve.Secp256k1.MuSig2.Internal.KeyAgg (KeyAggContext (..))
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (secNoncePubNonce)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (bytesToInteger, curveOrder, integerToBytes32)
import Crypto.Curve.Secp256k1.MuSig2.Unsafe (nonceGenWithRand, secNonceFromBytes, secNonceToBytes)
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Aeson (FromJSON (..), Value, eitherDecodeFileStrict, withObject, (.:))
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Aeson.Types (Parser, parseEither)
import Data.Bits (testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import Data.Either (rights)
import Data.Foldable (for_)
import Data.List (nub)
import Data.List.NonEmpty (NonEmpty (..), nonEmpty)
import qualified Data.List.NonEmpty as NE
import Data.Maybe (fromMaybe, isJust)
import System.Environment (lookupEnv)
import Test.Tasty
import Test.Tasty.HUnit
import Util (Hex (..), hexOf, strictObject)

-- | Environment variable that overrides the corpus path.
corpusVar :: String
corpusVar = "MUSIG2_DIFF_CORPUS"

-- | SHA-256 of the corpus file, also recorded in @test\/vectors\/diff\/README.md@.
corpusSha256 :: String
corpusSha256 = "ee7da0d791afd3a1ffe423c2886e5ec6744069a3b7ba56371bedf48ef99247f3"

-- | Builds the corpus test tree; any loading problem becomes a failing test.
diffCorpusTests :: IO TestTree
diffCorpusTests = do
  path <- fromMaybe "test/vectors/diff/corpus.json" <$> lookupEnv corpusVar
  decoded <- eitherDecodeFileStrict path
  let loaded = decoded >>= parseEither parseCorpus
  pure . testGroup "Differential corpus (reference.py)" $
    testCase "corpus.json matches the pinned SHA-256" (integrity path) : case loaded of
      Left err -> [testCase "load corpus.json" (assertFailure (path <> ": " <> err <> " (set " <> corpusVar <> " to its path)"))]
      Right corpus ->
        [ testCase "the corpus covers every kind of case" (coverage corpus)
        , testGroup "NonceGen" (zipWith (\i c -> testCase ("#" <> show i) (nonceGenCase c)) [0 :: Int ..] (cNonceGen corpus))
        , testGroup "sessions" [testCase (sessionName s) (runSession s) | s <- cSessions corpus]
        ]

integrity :: FilePath -> Assertion
integrity path = do
  contents <- BS.readFile path
  assertEqual "sha256" corpusSha256 (BC.unpack (B16.encode (SHA256.hash contents)))

-- Corpus format -------------------------------------------------------------------

data Corpus = Corpus
  { cNonceGen :: [NonceGenCase]
  , cSessions :: [SessionCase]
  }

data NonceGenCase = NonceGenCase
  { ngRand :: ByteString
  , ngPk :: ByteString
  , ngSk :: Maybe ByteString
  , ngAggPk :: Maybe ByteString
  , ngMsg :: Maybe ByteString
  , ngExtraIn :: Maybe ByteString
  , ngSecNonce :: ByteString
  , ngPubNonce :: ByteString
  }

data TweakSpec = TweakPlain ByteString | TweakXOnly ByteString | TweakTaproot (Maybe ByteString)

data SessionCase = SessionCase
  { sId :: Int
  , sSecKeys :: [ByteString]
  , sKeySortInput :: Maybe [ByteString]
  , sQ :: Maybe ByteString
  , sTweaks :: [TweakSpec]
  , sOutcome :: Either String SessionResult
  -- ^ The error of the last tweak, or the session.
  }

data SessionResult = SessionResult
  { srAggPk :: ByteString
  , srGaccNeg :: Bool
  , srMsg :: ByteString
  , srSigners :: [SignerCase]
  , srAggNonce :: ByteString
  , srSig :: ByteString
  , srSigValid :: Bool
  , srBadVerify :: [BadVerify]
  }

data NonceSource
  = -- | NonceGen: random bytes, bindings (bit 0: secret key, 1: aggregate key, 2: message), extra input.
    FromNonceGen ByteString Int (Maybe ByteString)
  | Imported ByteString
  | Deterministic (Maybe ByteString)

data SignerCase = SignerCase
  { sgNonce :: NonceSource
  , sgPubNonce :: ByteString
  , sgPsig :: ByteString
  }

data BadVerify = BadVerify
  { bvKind :: String
  , bvSigner :: Int
  , bvOther :: Maybe Int
  , bvExpected :: Bool
  }

hex :: Value -> Parser ByteString
hex v = unHex <$> parseJSON v

parseCorpus :: Value -> Parser Corpus
parseCorpus = strictObject "corpus" ["bips_commit", "reference_sha256", "seed", "nonce_gen", "sessions"] $ \o -> do
  commit <- o .: "bips_commit"
  unless (commit == ("b34d9f751791d4feb22feff4f2ed00bcac83961b" :: String)) $ fail ("unexpected bips commit " <> commit)
  Corpus <$> (o .: "nonce_gen" >>= traverse parseNonceGen) <*> (o .: "sessions" >>= traverse parseSession)

parseNonceGen :: Value -> Parser NonceGenCase
parseNonceGen = strictObject "nonce_gen case" ["rand", "pk", "sk", "aggpk", "msg", "extra_in", "secnonce", "pubnonce"] $ \o ->
  NonceGenCase
    <$> (o .: "rand" >>= hex)
    <*> (o .: "pk" >>= hex)
    <*> (o .: "sk" >>= traverse hex)
    <*> (o .: "aggpk" >>= traverse hex)
    <*> (o .: "msg" >>= traverse hex)
    <*> (o .: "extra_in" >>= traverse hex)
    <*> (o .: "secnonce" >>= hex)
    <*> (o .: "pubnonce" >>= hex)

parseTweak :: Value -> Parser TweakSpec
parseTweak = withObject "tweak" $ \o -> case KeyMap.toList o of
  [("plain", v)] -> TweakPlain <$> hex v
  [("xonly", v)] -> TweakXOnly <$> hex v
  [("taproot", v)] -> TweakTaproot <$> (parseJSON v >>= traverse hex)
  _ -> fail "a tweak is {\"plain\" | \"xonly\": tweak} or {\"taproot\": merkle root}"

parseSession :: Value -> Parser SessionCase
parseSession v = do
  tweakError <- withObject "session" (.: "tweak_error") v
  let common = ["id", "sks", "key_sort_input", "q", "tweaks", "tweak_error"]
      session = ["aggpk", "gacc_neg", "msg", "signers", "aggnonce", "sig", "sig_valid", "bad_verify"]
  strictObject "session" (common <> maybe session (const []) (tweakError :: Maybe String)) (body tweakError) v
 where
  body tweakError o = do
    outcome <- case tweakError of
      Just err -> pure (Left err)
      Nothing ->
        fmap Right $
          SessionResult
            <$> (o .: "aggpk" >>= hex)
            <*> o .: "gacc_neg"
            <*> (o .: "msg" >>= hex)
            <*> (o .: "signers" >>= traverse parseSigner)
            <*> (o .: "aggnonce" >>= hex)
            <*> (o .: "sig" >>= hex)
            <*> o .: "sig_valid"
            <*> (o .: "bad_verify" >>= traverse parseBadVerify)
    SessionCase
      <$> o .: "id"
      <*> (o .: "sks" >>= traverse hex)
      <*> (o .: "key_sort_input" >>= traverse (traverse hex))
      <*> (o .: "q" >>= traverse hex)
      <*> (o .: "tweaks" >>= traverse parseTweak)
      <*> pure outcome

parseSigner :: Value -> Parser SignerCase
parseSigner = strictObject "signer" ["nonce", "pubnonce", "psig"] $ \o ->
  SignerCase <$> (o .: "nonce" >>= parseNonce) <*> (o .: "pubnonce" >>= hex) <*> (o .: "psig" >>= hex)
 where
  parseNonce = withObject "nonce" $ \o -> case KeyMap.keys o of
    ks
      | ks `sameAs` ["rand", "bind", "extra_in"] -> FromNonceGen <$> (o .: "rand" >>= hex) <*> o .: "bind" <*> (o .: "extra_in" >>= traverse hex)
      | ks `sameAs` ["secnonce"] -> Imported <$> (o .: "secnonce" >>= hex)
      | ks `sameAs` ["det_rand"] -> Deterministic <$> (o .: "det_rand" >>= traverse hex)
    _ -> fail "unknown nonce source"
  sameAs ks expected = length ks == length expected && all (`elem` expected) ks

parseBadVerify :: Value -> Parser BadVerify
parseBadVerify = strictObject "bad_verify" ["kind", "signer", "other", "expected"] $ \o ->
  BadVerify <$> o .: "kind" <*> o .: "signer" <*> o .: "other" <*> o .: "expected"

-- Coverage ------------------------------------------------------------------------

-- | Every kind of case the generator is meant to produce is in the corpus.
coverage :: Corpus -> Assertion
coverage corpus = do
  let sessions = cSessions corpus
      results = rights (map sOutcome sessions)
      signers = concatMap srSigners results
      nonceGenStates = [(isJust (ngSk c), isJust (ngAggPk c), presence (ngMsg c), presence (ngExtraIn c)) | c <- cNonceGen corpus]
      bindings = [(bind, presence extra) | FromNonceGen _ bind extra <- map sgNonce signers]
      tweakValues = [t | s <- sessions, spec <- sTweaks s, Just t <- [plainOrXOnly spec]]
      msgLengths = map (BS.length . srMsg) results
      aggNonceHalves = [(BS.take 33 (srAggNonce r) == zero33, BS.drop 33 (srAggNonce r) == zero33) | r <- results]
      zero33 = BS.replicate 33 0
      count what n = assertBool ("the corpus has no " <> what) (n > (0 :: Int))
  forM_ [1 .. 8] $ \u -> count (show u <> "-signer session") (length [s | s <- sessions, length (sSecKeys s) == u])
  count "session with duplicate keys" (length [s | s <- sessions, nub (sSecKeys s) /= sSecKeys s, length (nub (sSecKeys s)) > 1])
  count "session where every key is equal" (length [s | s <- sessions, length (sSecKeys s) > 1, length (nub (sSecKeys s)) == 1])
  count "KeySort case" (length [s | s <- sessions, isJust (sKeySortInput s)])
  count "plain tweak" (length [() | s <- sessions, TweakPlain _ <- sTweaks s])
  count "x-only tweak" (length [() | s <- sessions, TweakXOnly _ <- sTweaks s])
  count "Taproot tweak without merkle root" (length [() | s <- sessions, TweakTaproot Nothing <- sTweaks s])
  count "Taproot tweak with a merkle root" (length [() | s <- sessions, TweakTaproot (Just _) <- sTweaks s])
  count "tweak 0" (length (filter (== integerToBytes32 0) tweakValues))
  count "tweak n - 1" (length (filter (== integerToBytes32 (curveOrder - 1)) tweakValues))
  count "session with gacc = n - 1" (length (filter srGaccNeg results))
  count "tweak to infinity" (length [s | s <- sessions, either (== "TweakResultAtInfinity") (const False) (sOutcome s)])
  count "empty message" (length (filter (== 0) msgLengths))
  count "32-byte message" (length (filter (== 32) msgLengths))
  count "message over 255 bytes" (length (filter (> 255) msgLengths))
  forM_ [(sk, aggpk, m, e) | sk <- [False, True], aggpk <- [False, True], m <- states, e <- states] $ \st ->
    count ("NonceGen case with inputs " <> show st) (length (filter (== st) nonceGenStates))
  forM_ [(bind, e) | bind <- [0 .. 7], e <- states] $ \st ->
    count ("session nonce with bindings and extra input " <> show st) (length (filter (== st) bindings))
  count "imported nonce" (length [() | Imported _ <- map sgNonce signers])
  count "DeterministicSign without randomness" (length [() | Deterministic Nothing <- map sgNonce signers])
  count "DeterministicSign with randomness" (length [() | Deterministic (Just _) <- map sgNonce signers])
  forM_ [(True, False), (False, True), (True, True)] $ \halves ->
    count ("aggregate nonce with infinity halves " <> show halves) (length (filter (== halves) aggNonceHalves))
  count "invalid final signature" (length (filter (not . srSigValid) results))
  forM_ ["plus_one", "zero", "out_of_range", "wrong_msg", "wrong_signer", "swapped_nonces"] $ \kind ->
    count ("PartialSigVerify case " <> kind) (length [() | r <- results, b <- srBadVerify r, bvKind b == kind])
 where
  states = [Absent, Empty, NonEmpty]
  plainOrXOnly spec = case spec of
    TweakPlain t -> Just t
    TweakXOnly t -> Just t
    TweakTaproot _ -> Nothing

data Presence = Absent | Empty | NonEmpty deriving (Eq, Show)

presence :: Maybe ByteString -> Presence
presence = maybe Absent (\b -> if BS.null b then Empty else NonEmpty)

-- Running the cases ---------------------------------------------------------------

lib :: (Show e) => String -> Either e a -> IO a
lib what = either (\e -> assertFailure (what <> " failed: " <> show e)) pure

decodeAs :: (Encode a) => String -> ByteString -> IO a
decodeAs what = lib ("decode " <> what) . decode

nonEmptyIO :: String -> [a] -> IO (NonEmpty a)
nonEmptyIO what = maybe (assertFailure ("empty " <> what)) pure . nonEmpty

assertBytes :: String -> ByteString -> ByteString -> Assertion
assertBytes what expected actual = assertEqual what (hexOf expected) (hexOf actual)

nonceGenCase :: NonceGenCase -> Assertion
nonceGenCase c = do
  pk <- decodeAs "pk" (ngPk c)
  sk <- traverse (lib "secKeyFromBytes" . secKeyFromBytes) (ngSk c)
  aggpk <- traverse (decodeAs "aggpk") (ngAggPk c)
  let inputs = NonceInputs{nonceSecKey = sk, nonceAggPubKey = aggpk, nonceMessage = ngMsg c, nonceExtraInput = ngExtraIn c}
  (sn, pn) <- nonceGenWithRand (ngRand c) pk inputs >>= lib "NonceGen"
  assertBytes "pubnonce" (ngPubNonce c) (encode pn)
  exported <- secNonceToBytes sn >>= maybe (assertFailure "a fresh nonce cannot be exported") pure
  assertBytes "secnonce" (ngSecNonce c) exported

sessionName :: SessionCase -> String
sessionName s =
  "#" <> show (sId s) <> " (" <> show (length (sSecKeys s)) <> " signers, " <> show (length (sTweaks s)) <> " tweaks" <> extra <> ")"
 where
  extra = case sOutcome s of
    Left err -> ", " <> err
    Right r -> concat [", " <> what | (what, True) <- [("DeterministicSign", any isDet (srSigners r)), ("imported nonce", any isImported (srSigners r))]]
  isDet sg = case sgNonce sg of Deterministic _ -> True; _ -> False
  isImported sg = case sgNonce sg of Imported _ -> True; _ -> False

applyTweakSpec :: TweakSpec -> KeyAggContext -> IO (Either KeyAggError KeyAggContext)
applyTweakSpec spec ctx = case spec of
  TweakPlain t -> (`applyPlainTweak` ctx) <$> decodeAs "tweak" t
  TweakXOnly t -> (`applyXOnlyTweak` ctx) <$> decodeAs "tweak" t
  TweakTaproot root -> pure (applyTaprootTweak root ctx)

runSession :: SessionCase -> Assertion
runSession s = do
  sks <- traverse (lib "secKeyFromBytes" . secKeyFromBytes) (sSecKeys s)
  let pks = map secKeyPubKey sks
  pksNE <- nonEmptyIO "key list" pks
  for_ (sKeySortInput s) $ \input -> do
    keys <- traverse (decodeAs "pubkey") input >>= nonEmptyIO "KeySort input"
    keySort keys @?= pksNE
  ctx0 <- lib "KeyAgg" (keyAgg pksNE)
  for_ (sQ s) $ \q -> assertBytes "KeyAgg Q (before the tweaks)" q (encode (aggPubKey ctx0))
  case sOutcome s of
    Left err -> do
      assertEqual "expected error" "TweakResultAtInfinity" err
      (before, lastTweak) <- maybe (assertFailure "no tweak") pure (unsnoc (sTweaks s))
      ctx <- foldM (\c spec -> applyTweakSpec spec c >>= lib "ApplyTweak") ctx0 before
      result <- applyTweakSpec lastTweak ctx
      either Just (const Nothing) result @?= Just TweakResultAtInfinity
    Right r -> do
      ctx <- foldM (\c spec -> applyTweakSpec spec c >>= lib "ApplyTweak") ctx0 (sTweaks s)
      runSigning sks ctx r
 where
  unsnoc xs = (\ne -> (NE.init ne, NE.last ne)) <$> nonEmpty xs

-- | A signer's secret nonce, or its deterministic signing still to do.
data Pending = Signing SecNonce PubNonce | DetSigning (Maybe ByteString)

runSigning :: [SecKey] -> KeyAggContext -> SessionResult -> Assertion
runSigning sks ctx r = do
  assertBytes "aggpk (Q after the tweaks)" (srAggPk r) (encode (aggPubKey ctx))
  assertEqual "gacc = n - 1" (srGaccNeg r) (kacGaccNeg ctx)
  assertEqual "one signer per key" (length sks) (length (srSigners r))
  let msg = srMsg r
      aggpk = aggXOnlyPubKey ctx
      pks = map secKeyPubKey sks
  -- Round one.
  pending <- forM (zip sks (srSigners r)) $ \(sk, sg) -> case sgNonce sg of
    FromNonceGen rand bind extra -> do
      let inputs =
            NonceInputs
              { nonceSecKey = if testBit bind 0 then Just sk else Nothing
              , nonceAggPubKey = if testBit bind 1 then Just aggpk else Nothing
              , nonceMessage = if testBit bind 2 then Just msg else Nothing
              , nonceExtraInput = extra
              }
      (sn, pn) <- nonceGenWithRand rand (secKeyPubKey sk) inputs >>= lib "NonceGen"
      assertBytes "pubnonce (NonceGen)" (sgPubNonce sg) (encode pn)
      pure (Signing sn pn)
    Imported bytes -> do
      sn <- secNonceFromBytes bytes >>= lib "secNonceFromBytes"
      assertBytes "pubnonce (imported)" (sgPubNonce sg) (encode (secNoncePubNonce sn))
      pure (Signing sn (secNoncePubNonce sn))
    Deterministic rand -> pure (DetSigning rand)
  let others = [pn | Signing _ pn <- pending]
  detResults <- forM [(sk, rand) | (sk, DetSigning rand) <- zip sks pending] $ \(sk, rand) -> do
    aggOther <- nonceAgg <$> nonEmptyIO "other signers' nonces" others
    lib "DeterministicSign" (deterministicSign sk aggOther ctx msg rand)
  pubNonces <- nonEmptyIO "nonces" (others <> map fst detResults)
  let aggNonce = nonceAgg pubNonces
      ses = newSession ctx aggNonce msg
  assertBytes "aggnonce" (srAggNonce r) (encode aggNonce)
  -- Round two (DeterministicSign signers are last).
  signed <- forM [(sk, sn) | (sk, Signing sn _) <- zip sks pending] $ \(sk, sn) -> sign sn sk ses >>= lib "Sign"
  let psigs = signed <> map snd detResults
  zipWithM_ (\i (sg, psig) -> assertBytes ("psig " <> show i) (sgPsig sg) (encode psig)) [0 :: Int ..] (zip (srSigners r) psigs)
  zipWithM_ (\i (pk, (pn, psig)) -> assertBool ("partialSigVerify " <> show i) (partialSigVerify ses pk pn psig)) [0 :: Int ..] (zip pks (zip (NE.toList pubNonces) psigs))
  psigsNE <- nonEmptyIO "partial signatures" psigs
  let sig = partialSigAgg ses psigsNE
  assertBytes "sig" (srSig r) (encode sig)
  assertEqual "BIP-340 verification" (srSigValid r) (verify aggpk msg sig)
  forM_ (srBadVerify r) (badVerify ctx msg pks (NE.toList pubNonces) psigs)
  -- The same session through the coordinator.
  round1 <- lib "receivePubNonce" (foldM (\rd (i, sg) -> receivePubNonce i (sgPubNonce sg) rd) (newNonceRound ctx) (zip [0 ..] (srSigners r)))
  collected <- lib "finishNonceRound" (finishNonceRound round1)
  assertBytes "coordinator aggnonce" (srAggNonce r) (encode (collectedAggNonce collected))
  round2 <- lib "receivePartialSig" (foldM (\rd (i, sg) -> receivePartialSig i (sgPsig sg) rd) (newSigRound collected msg) (zip [0 ..] (srSigners r)))
  case finishSigRound round2 of
    Right coordSig -> assertBool "coordinator: valid signature" (srSigValid r) >> assertBytes "coordinator sig" (srSig r) (encode coordSig)
    Left FinalSignatureInvalid -> assertBool "coordinator: FinalSignatureInvalid for a valid signature" (not (srSigValid r))
    Left err -> assertFailure ("finishSigRound: " <> show err)

-- | A PartialSigVerify case that the reference implementation evaluated.
badVerify :: KeyAggContext -> ByteString -> [PubKey] -> [PubNonce] -> [PartialSignature] -> BadVerify -> Assertion
badVerify ctx msg pks pns psigs b = do
  let i = bvSigner b
      needsOther = bvKind b `elem` ["wrong_signer", "swapped_nonces"]
  assertEqual "other signer given exactly for wrong_signer and swapped_nonces" needsOther (isJust (bvOther b))
  let other = fromMaybe i (bvOther b)
      s = bytesToInteger (encode (psigs !! i))
      check ses checked nonces psigBytes = case decode psigBytes of
        Left _ -> False -- BIP-327 PartialSigVerify fails for s >= n
        Right psig -> partialSigVerify ses (pks !! checked) (nonces !! checked) psig
      session nonces = newSession ctx (nonceAgg (NE.fromList nonces))
      swapped = [if k == i then pns !! other else if k == other then pns !! i else pn | (k, pn) <- zip [0 ..] pns]
  result <- case bvKind b of
    "plus_one" -> pure (check (session pns msg) i pns (integerToBytes32 ((s + 1) `mod` curveOrder)))
    "zero" -> pure (check (session pns msg) i pns (integerToBytes32 0))
    "out_of_range" -> pure (check (session pns msg) i pns (integerToBytes32 curveOrder))
    "wrong_msg" -> pure (check (session pns (msg <> BS.singleton 0)) i pns (encode (psigs !! i)))
    "wrong_signer" -> pure (check (session pns msg) other pns (encode (psigs !! i)))
    "swapped_nonces" -> pure (check (session swapped msg) i swapped (encode (psigs !! i)))
    kind -> assertFailure ("unknown PartialSigVerify case " <> kind)
  assertEqual ("PartialSigVerify " <> bvKind b <> " (signer " <> show i <> ")") (bvExpected b) result
