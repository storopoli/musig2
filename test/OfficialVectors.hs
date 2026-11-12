{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

{- | Official BIP-0327 test vectors, read at test time from the JSON files
vendored in @test\/vectors\/bip327@ (see the @README.md@ there for the
upstream commit and checksums).

Every case runs with exact-output assertions. Invalid encodings are decoded
with 'decode', contribution by contribution in the order the reference
implementation parses them, and the first failure must be exactly the
contribution (and signer) the vector blames. The @NonceAgg@ and
@PartialSigAgg@ cases also run through
"Crypto.Curve.Secp256k1.MuSig2.Coordinator": it must produce the expected
aggregate nonce and signature, and blame exactly the vector's signer.

The parsers reject unknown fields, unknown error types and unknown error
messages, so an updated vector file cannot be silently half-run.
-}
module OfficialVectors (officialVectorTests) where

import Control.Monad (filterM, foldM, void, zipWithM, (>=>))
import Crypto.Curve.Secp256k1.MuSig2
import Crypto.Curve.Secp256k1.MuSig2.Coordinator (
  Blame (..),
  BlameReason (..),
  CollectedNonces,
  collectedAggNonce,
  finishNonceRound,
  finishSigRound,
  newNonceRound,
  newSigRound,
  receivePartialSig,
  receivePubNonce,
 )
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (secNoncePubNonce)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (bytesToInteger, curveOrder)
import Crypto.Curve.Secp256k1.MuSig2.Unsafe (nonceGenWithRand, secNonceFromBytes, secNonceToBytes)
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Aeson (FromJSON (..), Value, eitherDecodeFileStrict, withObject, (.:), (.:?))
import qualified Data.Aeson.Key as Key
import Data.Aeson.Types (Object, Parser, parseEither)
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import Data.Either (lefts)
import Data.List.NonEmpty (NonEmpty (..), nonEmpty)
import qualified Data.List.NonEmpty as NE
import Data.Maybe (fromMaybe)
import System.Directory (doesFileExist, getCurrentDirectory, makeAbsolute)
import System.Environment (lookupEnv)
import System.FilePath ((</>))
import Test.Tasty
import Test.Tasty.HUnit
import Util (Hex (..), hexOf, secKeyFromInt, strictObject)

-- Locating and loading the vector files ---------------------------------------

-- | Environment variable that overrides the vector directory.
vectorsDirVar :: String
vectorsDirVar = "MUSIG2_BIP327_VECTORS"

-- | Vector directory relative to the package root (the working directory of @cabal test@).
defaultVectorsDir :: FilePath
defaultVectorsDir = "test" </> "vectors" </> "bip327"

{- | The vendored files and their SHA-256 (also recorded in the README next to
them). Changing a vector file without updating this list fails the suite.
-}
pinnedFiles :: [(FilePath, String)]
pinnedFiles =
  [ ("key_sort_vectors.json", "2389fa0c146cfd7455c643ca240ec32835dcfc916f430f50dd94d0b49c9ea16c")
  , ("key_agg_vectors.json", "03c02a97e4ef3f2edfbc8e6013c127496dfcfd5889cfca60ddf009a4e9091cab")
  , ("nonce_gen_vectors.json", "2e823580fc072427f0db0f000212cc9124ad2b9dca2b58357eb65088aee4358d")
  , ("nonce_agg_vectors.json", "8409e87b81ea769759598ad3ce53b277a78afffb3a490a86ce02c4d69984524b")
  , ("sign_verify_vectors.json", "692eecc101f3e515c29137f05031935e1210d2a01bab91e674eb0234f095c15c")
  , ("tweak_vectors.json", "80ce6385ce062644ad1f4edcb9d4797f70ddb0b74769e4099f51b3c9e6ab4aff")
  , ("sig_agg_vectors.json", "15f14c034fb2a5739d7ce638be94c5b37ea675a2e01159092dd93b59d69c3439")
  , ("det_sign_vectors.json", "3d4fdb64b24e31762f20830036dc0c59d39fa896649131b54b87906ffdc6e9e8")
  ]

-- | Finds the vector directory, or explains where it looked.
locateVectorsDir :: IO (Either String FilePath)
locateVectorsDir = do
  override <- lookupEnv vectorsDirVar
  let dir = fromMaybe defaultVectorsDir override
  missing <- filterM (fmap not . doesFileExist) [dir </> f | (f, _) <- pinnedFiles]
  if null missing
    then pure (Right dir)
    else do
      cwd <- getCurrentDirectory
      absMissing <- traverse makeAbsolute missing
      pure . Left . unlines $
        ("BIP-0327 vector files not found:" : map ("  " <>) absMissing)
          <> [ "Working directory: " <> cwd
             , case override of
                 Just _ -> "The directory came from " <> vectorsDirVar <> "."
                 Nothing ->
                   "Run the suite from the package root (cabal test does this), or set "
                     <> vectorsDirVar
                     <> " to the directory holding the *_vectors.json files."
             ]

-- | Builds the official vector test tree; any loading problem becomes a failing test.
officialVectorTests :: IO TestTree
officialVectorTests = do
  located <- locateVectorsDir
  case located of
    Left err -> pure (testGroup groupName [loadFailure err])
    Right dir -> do
      loaded <- loadVectors dir
      pure . testGroup groupName $ case loaded of
        Left err -> [integrityTests dir, loadFailure err]
        Right vs -> integrityTests dir : vectorTests vs
 where
  groupName = "BIP-0327 official vectors (JSON)"
  loadFailure err = testCase "load vector files" (assertFailure err)

integrityTests :: FilePath -> TestTree
integrityTests dir =
  testGroup
    "vendored files match pinned SHA-256"
    [ testCase file $ do
        contents <- BS.readFile (dir </> file)
        assertEqual "sha256" digest (BC.unpack (B16.encode (SHA256.hash contents)))
    | (file, digest) <- pinnedFiles
    ]

data Vectors = Vectors
  { vKeySort :: KeySortVectors
  , vKeyAgg :: KeyAggVectors
  , vNonceGen :: [NonceGenCase]
  , vNonceAgg :: NonceAggVectors
  , vSignVerify :: SignVerifyVectors
  , vTweak :: TweakVectors
  , vSigAgg :: SigAggVectors
  , vDetSign :: DetSignVectors
  }

loadVectors :: FilePath -> IO (Either String Vectors)
loadVectors dir = do
  ks <- load "key_sort_vectors.json" parseKeySort
  ka <- load "key_agg_vectors.json" parseKeyAgg
  ng <- load "nonce_gen_vectors.json" parseNonceGen
  na <- load "nonce_agg_vectors.json" parseNonceAgg
  sv <- load "sign_verify_vectors.json" parseSignVerify
  tw <- load "tweak_vectors.json" parseTweak
  sa <- load "sig_agg_vectors.json" parseSigAgg
  ds <- load "det_sign_vectors.json" parseDetSign
  pure (Vectors <$> ks <*> ka <*> ng <*> na <*> sv <*> tw <*> sa <*> ds)
 where
  load :: FilePath -> (Value -> Parser a) -> IO (Either String a)
  load file p = do
    let path = dir </> file
    decoded <- eitherDecodeFileStrict path
    pure $ case decoded of
      Left err -> Left (path <> ": invalid JSON: " <> err)
      Right v -> either (\err -> Left (path <> ": " <> err)) Right (parseEither p v)

-- JSON parsing ---------------------------------------------------------------

hexField :: Object -> Key.Key -> Parser ByteString
hexField o k = unHex <$> o .: k

-- | A field that must be present but may be @null@.
nullableHexField :: Object -> Key.Key -> Parser (Maybe ByteString)
nullableHexField o k = fmap unHex <$> o .: k

hexList :: Object -> Key.Key -> Parser [ByteString]
hexList o k = map unHex <$> o .: k

-- | The @error@ object of an error test case.
data VectorError
  = -- | @invalid_contribution@: blamed signer (if any) and contribution kind.
    InvalidContribution (Maybe Int) String
  | -- | @value@: the reference implementation's @ValueError@ message.
    ValueError String
  deriving (Eq, Show)

instance FromJSON VectorError where
  parseJSON v = do
    ty <- withObject "error" (.: "type") v
    case ty :: String of
      "invalid_contribution" ->
        strictObject "invalid_contribution error" ["type", "signer", "contrib"] (\o -> InvalidContribution <$> o .: "signer" <*> o .: "contrib") v
      "value" ->
        strictObject "value error" ["type", "message"] (\o -> ValueError <$> o .: "message") v
      other -> fail ("unknown error type " <> show other)

data KeySortVectors = KeySortVectors [ByteString] [ByteString]

parseKeySort :: Value -> Parser KeySortVectors
parseKeySort = strictObject "key_sort" ["pubkeys", "sorted_pubkeys"] $ \o ->
  KeySortVectors <$> hexList o "pubkeys" <*> hexList o "sorted_pubkeys"

data KeyAggVectors = KeyAggVectors
  { kaPubkeys :: [ByteString]
  , kaTweaks :: [ByteString]
  , kaValid :: [([Int], ByteString)]
  , kaError :: [KeyAggErrorCase]
  }

data KeyAggErrorCase = KeyAggErrorCase
  { kaeKeys :: [Int]
  , kaeTweaks :: [Int]
  , kaeXOnly :: [Bool]
  , kaeError :: VectorError
  , kaeComment :: Maybe String
  }

parseKeyAgg :: Value -> Parser KeyAggVectors
parseKeyAgg = strictObject "key_agg" ["pubkeys", "tweaks", "valid_test_cases", "error_test_cases"] $ \o -> do
  pubkeys <- hexList o "pubkeys"
  tweaks <- hexList o "tweaks"
  valid <- o .: "valid_test_cases" >>= traverse (strictObject "key_agg valid case" ["key_indices", "expected"] (\c -> (,) <$> c .: "key_indices" <*> hexField c "expected"))
  errs <-
    o .: "error_test_cases"
      >>= traverse
        ( strictObject "key_agg error case" ["key_indices", "tweak_indices", "is_xonly", "error", "comment"] $ \c ->
            KeyAggErrorCase <$> c .: "key_indices" <*> c .: "tweak_indices" <*> c .: "is_xonly" <*> c .: "error" <*> c .:? "comment"
        )
  pure (KeyAggVectors pubkeys tweaks valid errs)

data NonceGenCase = NonceGenCase
  { ngRand :: ByteString
  , ngSk :: Maybe ByteString
  , ngPk :: ByteString
  , ngAggpk :: Maybe ByteString
  , ngMsg :: Maybe ByteString
  , ngExtraIn :: Maybe ByteString
  , ngSecnonce :: ByteString
  , ngPubnonce :: ByteString
  , ngComment :: Maybe String
  }

parseNonceGen :: Value -> Parser [NonceGenCase]
parseNonceGen = strictObject "nonce_gen" ["test_cases"] $ \o ->
  o .: "test_cases"
    >>= traverse
      ( strictObject "nonce_gen case" ["rand_", "sk", "pk", "aggpk", "msg", "extra_in", "expected_secnonce", "expected_pubnonce", "comment"] $ \c ->
          NonceGenCase
            <$> hexField c "rand_"
            <*> nullableHexField c "sk"
            <*> hexField c "pk"
            <*> nullableHexField c "aggpk"
            <*> nullableHexField c "msg"
            <*> nullableHexField c "extra_in"
            <*> hexField c "expected_secnonce"
            <*> hexField c "expected_pubnonce"
            <*> c .:? "comment"
      )

data NonceAggVectors = NonceAggVectors
  { naPnonces :: [ByteString]
  , naValid :: [([Int], ByteString, Maybe String)]
  , naError :: [([Int], VectorError, Maybe String)]
  }

parseNonceAgg :: Value -> Parser NonceAggVectors
parseNonceAgg = strictObject "nonce_agg" ["pnonces", "valid_test_cases", "error_test_cases"] $ \o -> do
  pnonces <- hexList o "pnonces"
  valid <-
    o .: "valid_test_cases"
      >>= traverse (strictObject "nonce_agg valid case" ["pnonce_indices", "expected", "comment"] (\c -> (,,) <$> c .: "pnonce_indices" <*> hexField c "expected" <*> c .:? "comment"))
  errs <-
    o .: "error_test_cases"
      >>= traverse (strictObject "nonce_agg error case" ["pnonce_indices", "error", "comment"] (\c -> (,,) <$> c .: "pnonce_indices" <*> c .: "error" <*> c .:? "comment"))
  pure (NonceAggVectors pnonces valid errs)

data SignVerifyVectors = SignVerifyVectors
  { svSk :: ByteString
  , svPubkeys :: [ByteString]
  , svSecnonces :: [ByteString]
  , svPnonces :: [ByteString]
  , svAggnonces :: [ByteString]
  , svMsgs :: [ByteString]
  , svValid :: [SvValid]
  , svSignError :: [SvSignError]
  , svVerifyFail :: [SvVerify]
  , svVerifyError :: [SvVerify]
  }

data SvValid = SvValid
  { svvKeys :: [Int]
  , svvNonces :: [Int]
  , svvAggnonce :: Int
  , svvMsg :: Int
  , svvSigner :: Int
  , svvExpected :: ByteString
  , svvComment :: Maybe String
  }

data SvSignError = SvSignError
  { sseKeys :: [Int]
  , sseAggnonce :: Int
  , sseMsg :: Int
  , sseSecnonce :: Int
  , sseError :: VectorError
  , sseComment :: Maybe String
  }

-- | A @verify_fail@ case (no error) or a @verify_error@ case.
data SvVerify = SvVerify
  { svfSig :: ByteString
  , svfKeys :: [Int]
  , svfNonces :: [Int]
  , svfMsg :: Int
  , svfSigner :: Int
  , svfError :: Maybe VectorError
  , svfComment :: Maybe String
  }

parseSignVerify :: Value -> Parser SignVerifyVectors
parseSignVerify =
  strictObject
    "sign_verify"
    ["sk", "pubkeys", "secnonces", "pnonces", "aggnonces", "msgs", "valid_test_cases", "sign_error_test_cases", "verify_fail_test_cases", "verify_error_test_cases"]
    $ \o ->
      SignVerifyVectors
        <$> hexField o "sk"
        <*> hexList o "pubkeys"
        <*> hexList o "secnonces"
        <*> hexList o "pnonces"
        <*> hexList o "aggnonces"
        <*> hexList o "msgs"
        <*> (o .: "valid_test_cases" >>= traverse validCase)
        <*> (o .: "sign_error_test_cases" >>= traverse signErrorCase)
        <*> (o .: "verify_fail_test_cases" >>= traverse (verifyCase False))
        <*> (o .: "verify_error_test_cases" >>= traverse (verifyCase True))
 where
  validCase = strictObject "sign_verify valid case" ["key_indices", "nonce_indices", "aggnonce_index", "msg_index", "signer_index", "expected", "comment"] $ \c ->
    SvValid <$> c .: "key_indices" <*> c .: "nonce_indices" <*> c .: "aggnonce_index" <*> c .: "msg_index" <*> c .: "signer_index" <*> hexField c "expected" <*> c .:? "comment"
  -- signer_index is informational here: Sign does not take it.
  signErrorCase = strictObject "sign_verify sign_error case" ["key_indices", "aggnonce_index", "msg_index", "secnonce_index", "signer_index", "error", "comment"] $ \c ->
    SvSignError <$> c .: "key_indices" <*> c .: "aggnonce_index" <*> c .: "msg_index" <*> c .: "secnonce_index" <*> c .: "error" <*> c .:? "comment"
  verifyCase hasError =
    strictObject "sign_verify verify case" (["sig", "key_indices", "nonce_indices", "msg_index", "signer_index", "comment"] <> ["error" | hasError]) $ \c ->
      SvVerify
        <$> hexField c "sig"
        <*> c .: "key_indices"
        <*> c .: "nonce_indices"
        <*> c .: "msg_index"
        <*> c .: "signer_index"
        <*> (if hasError then Just <$> c .: "error" else pure Nothing)
        <*> c .:? "comment"

data TweakVectors = TweakVectors
  { twSk :: ByteString
  , twPubkeys :: [ByteString]
  , twSecnonce :: ByteString
  , twPnonces :: [ByteString]
  , twAggnonce :: ByteString
  , twTweaks :: [ByteString]
  , twMsg :: ByteString
  , twValid :: [TweakCase]
  , twError :: [TweakCase]
  }

-- | A tweak case: valid cases carry @expected@, error cases carry @error@.
data TweakCase = TweakCase
  { tcKeys :: [Int]
  , tcNonces :: [Int]
  , tcTweaks :: [Int]
  , tcXOnly :: [Bool]
  , tcSigner :: Int
  , tcOutcome :: Either VectorError ByteString
  , tcComment :: Maybe String
  }

parseTweak :: Value -> Parser TweakVectors
parseTweak = strictObject "tweak" ["sk", "pubkeys", "secnonce", "pnonces", "aggnonce", "tweaks", "msg", "valid_test_cases", "error_test_cases"] $ \o ->
  TweakVectors
    <$> hexField o "sk"
    <*> hexList o "pubkeys"
    <*> hexField o "secnonce"
    <*> hexList o "pnonces"
    <*> hexField o "aggnonce"
    <*> hexList o "tweaks"
    <*> hexField o "msg"
    <*> (o .: "valid_test_cases" >>= traverse (tweakCase False))
    <*> (o .: "error_test_cases" >>= traverse (tweakCase True))
 where
  tweakCase isError =
    strictObject "tweak case" ["key_indices", "nonce_indices", "tweak_indices", "is_xonly", "signer_index", if isError then "error" else "expected", "comment"] $ \c ->
      TweakCase
        <$> c .: "key_indices"
        <*> c .: "nonce_indices"
        <*> c .: "tweak_indices"
        <*> c .: "is_xonly"
        <*> c .: "signer_index"
        <*> (if isError then Left <$> c .: "error" else Right <$> hexField c "expected")
        <*> c .:? "comment"

data SigAggVectors = SigAggVectors
  { saPubkeys :: [ByteString]
  , saPnonces :: [ByteString]
  , saTweaks :: [ByteString]
  , saPsigs :: [ByteString]
  , saMsg :: ByteString
  , saValid :: [SigAggCase]
  , saError :: [SigAggCase]
  }

-- | A sig_agg case: valid cases carry @expected@, error cases carry @error@.
data SigAggCase = SigAggCase
  { sacAggnonce :: ByteString
  , sacNonces :: [Int]
  , sacKeys :: [Int]
  , sacTweaks :: [Int]
  , sacXOnly :: [Bool]
  , sacPsigs :: [Int]
  , sacOutcome :: Either VectorError ByteString
  , sacComment :: Maybe String
  }

parseSigAgg :: Value -> Parser SigAggVectors
parseSigAgg = strictObject "sig_agg" ["pubkeys", "pnonces", "tweaks", "psigs", "msg", "valid_test_cases", "error_test_cases"] $ \o ->
  SigAggVectors
    <$> hexList o "pubkeys"
    <*> hexList o "pnonces"
    <*> hexList o "tweaks"
    <*> hexList o "psigs"
    <*> hexField o "msg"
    <*> (o .: "valid_test_cases" >>= traverse (sigAggCase False))
    <*> (o .: "error_test_cases" >>= traverse (sigAggCase True))
 where
  sigAggCase isError =
    strictObject "sig_agg case" ["aggnonce", "nonce_indices", "key_indices", "tweak_indices", "is_xonly", "psig_indices", if isError then "error" else "expected", "comment"] $ \c ->
      SigAggCase
        <$> hexField c "aggnonce"
        <*> c .: "nonce_indices"
        <*> c .: "key_indices"
        <*> c .: "tweak_indices"
        <*> c .: "is_xonly"
        <*> c .: "psig_indices"
        <*> (if isError then Left <$> c .: "error" else Right <$> hexField c "expected")
        <*> c .:? "comment"

data DetSignVectors = DetSignVectors
  { dsSk :: ByteString
  , dsPubkeys :: [ByteString]
  , dsMsgs :: [ByteString]
  , dsValid :: [DetSignCase]
  , dsError :: [DetSignCase]
  }

-- | A det_sign case: valid cases carry the expected (pubnonce, psig), error cases carry @error@.
data DetSignCase = DetSignCase
  { dscRand :: Maybe ByteString
  , dscAggOtherNonce :: ByteString
  , dscKeys :: [Int]
  , dscTweaks :: [ByteString]
  , dscXOnly :: [Bool]
  , dscMsg :: Int
  , dscSigner :: Int
  , dscOutcome :: Either VectorError (ByteString, ByteString)
  , dscComment :: Maybe String
  }

parseDetSign :: Value -> Parser DetSignVectors
parseDetSign = strictObject "det_sign" ["sk", "pubkeys", "msgs", "valid_test_cases", "error_test_cases"] $ \o ->
  DetSignVectors
    <$> hexField o "sk"
    <*> hexList o "pubkeys"
    <*> hexList o "msgs"
    <*> (o .: "valid_test_cases" >>= traverse (detSignCase False))
    <*> (o .: "error_test_cases" >>= traverse (detSignCase True))
 where
  detSignCase isError =
    strictObject "det_sign case" ["rand", "aggothernonce", "key_indices", "tweaks", "is_xonly", "msg_index", "signer_index", if isError then "error" else "expected", "comment"] $ \c ->
      DetSignCase
        <$> nullableHexField c "rand"
        <*> hexField c "aggothernonce"
        <*> c .: "key_indices"
        <*> hexList c "tweaks"
        <*> c .: "is_xonly"
        <*> c .: "msg_index"
        <*> c .: "signer_index"
        <*> (if isError then Left <$> c .: "error" else Right <$> (hexList c "expected" >>= pair))
        <*> c .:? "comment"
  pair [pn, psig] = pure (pn, psig)
  pair other = fail ("det_sign: expected [pubnonce, psig], got " <> show (length other) <> " values")

-- Library steps ------------------------------------------------------------------

-- | A failure of any library step (or a malformed vector).
data Failure
  = FDecode DecodeError
  | FKeyAgg KeyAggError
  | FSign SignError
  | FVector String
  deriving (Eq, Show)

decodeF :: (Encode a) => ByteString -> Either Failure a
decodeF = first FDecode . decode

nonEmptyF :: String -> [a] -> Either Failure (NonEmpty a)
nonEmptyF what = maybe (Left (FVector ("empty " <> what <> " list"))) Right . nonEmpty

-- | Decodes and applies tweaks (raw bytes, is_xonly) in order.
applyTweaks :: [(ByteString, Bool)] -> KeyAggContext -> Either Failure KeyAggContext
applyTweaks ts ctx0 = foldM step ctx0 ts
 where
  step ctx (b, xonly) = do
    t <- decodeF b
    first FKeyAgg ((if xonly then applyXOnlyTweak else applyPlainTweak) t ctx)

-- | KeyAgg of encoded keys, then the tweaks.
keyAggBytes :: [ByteString] -> [(ByteString, Bool)] -> Either Failure KeyAggContext
keyAggBytes keys ts = do
  pks <- traverse decodeF keys >>= nonEmptyF "pubkey"
  first FKeyAgg (keyAgg pks) >>= applyTweaks ts

-- | Opens a session from encoded inputs and signs with an encoded secret nonce.
signBytes :: SecKey -> ByteString -> [ByteString] -> [(ByteString, Bool)] -> ByteString -> ByteString -> IO (Either Failure PartialSignature)
signBytes sk secnonce keys ts aggnonce m = case (,) <$> keyAggBytes keys ts <*> decodeF aggnonce of
  Left err -> pure (Left err)
  Right (ctx, agg) -> do
    imported <- secNonceFromBytes secnonce
    case imported of
      Left err -> pure (Left (FDecode err))
      Right sn -> first FSign <$> sign sn sk (newSession ctx agg m)

{- | DeterministicSign from encoded inputs, in the order the reference
implementation parses them: public keys and tweaks, then aggothernonce.
-}
detSignBytes :: SecKey -> ByteString -> [ByteString] -> [(ByteString, Bool)] -> ByteString -> Maybe ByteString -> Either Failure (PubNonce, PartialSignature)
detSignBytes sk aggOther keys ts m rand = do
  ctx <- keyAggBytes keys ts
  agg <- decodeF aggOther
  first FSign (deterministicSign sk agg ctx m rand)

-- | PartialSigVerify as BIP-327 defines it: aggregates the given nonces itself.
verifyBytes :: [ByteString] -> [ByteString] -> [(ByteString, Bool)] -> ByteString -> Int -> PartialSignature -> Either Failure Bool
verifyBytes nonces keys ts m signer psig = do
  pns <- traverse decodeF nonces >>= nonEmptyF "pubnonce"
  ctx <- keyAggBytes keys ts
  pk <- first FVector (at "pubkey" (NE.toList (keyAggPubKeys ctx)) signer)
  pn <- first FVector (at "pubnonce" (NE.toList pns) signer)
  pure (partialSigVerify (newSession ctx (nonceAgg pns) m) pk pn psig)

-- Helpers --------------------------------------------------------------------

note :: String -> Maybe a -> Either String a
note err = maybe (Left err) Right

-- | Indexes into a vector table.
at :: String -> [a] -> Int -> Either String a
at what xs i = case drop i xs of
  x : _ | i >= 0 -> Right x
  _ -> Left (what <> " index " <> show i <> " is out of range")

-- | Selects entries of a vector table.
select :: String -> [ByteString] -> [Int] -> Either String [ByteString]
select what table = traverse (at what table)

tweakSpecs :: [ByteString] -> [Int] -> [Bool] -> Either String [(ByteString, Bool)]
tweakSpecs table idxs xonly
  | length idxs /= length xonly = Left "tweak_indices and is_xonly differ in length"
  | otherwise = zipWithM (\i x -> (,x) <$> at "tweak" table i) idxs xonly

{- | The library failure that corresponds to a reference-implementation
@ValueError@ message. Unknown messages fail, so new error cases need an
explicit mapping.
-}
expectedFailure :: [(ByteString, Bool)] -> Maybe ByteString -> String -> Either String Failure
expectedFailure tweaks secnonce message = case message of
  -- A tweak >= n cannot be decoded into a 'Tweak'.
  "The tweak must be less than n." ->
    if any ((>= curveOrder) . bytesToInteger . fst) tweaks
      then Right (FDecode ScalarOutOfRange)
      else Left "vector expects an out-of-range tweak but none is >= n"
  "The result of tweaking cannot be infinity." -> Right (FKeyAgg TweakResultAtInfinity)
  "The signer's pubkey must be included in the list of pubkeys." -> Right (FSign SignerNotInSession)
  -- An out-of-range secnonce scalar cannot be decoded into a 'SecNonce'.
  "first secnonce value is out of range." -> scalarFailure . BS.take 32 <$> note "no secnonce in case" secnonce
  "second secnonce value is out of range." -> scalarFailure . BS.take 32 . BS.drop 32 <$> note "no secnonce in case" secnonce
  other -> Left ("no library failure is mapped to the BIP-0327 error message " <> show other)
 where
  scalarFailure b = FDecode (if bytesToInteger b == 0 then ScalarZero else ScalarOutOfRange)

valueError :: VectorError -> Either String String
valueError (ValueError m) = Right m
valueError err = Left ("expected a value error, got " <> show err)

{- | A contribution in the order the reference implementation parses it:
kind, signer index (if any), and the result of decoding it.
-}
type Contribution = (String, Maybe Int, Either DecodeError ())

contributions :: String -> (ByteString -> Either DecodeError ()) -> [ByteString] -> [Int] -> Either String [Contribution]
contributions kind dec table = zipWithM (\signer i -> (\b -> (kind, Just signer, dec b)) <$> at kind table i) [0 ..]

asPubKey, asPubNonce, asAggNonce, asPsig :: ByteString -> Either DecodeError ()
asPubKey = void . (decode :: ByteString -> Either DecodeError PubKey)
asPubNonce = void . (decode :: ByteString -> Either DecodeError PubNonce)
asAggNonce = void . (decode :: ByteString -> Either DecodeError AggNonce)
asPsig = void . (decode :: ByteString -> Either DecodeError PartialSignature)

-- | The first contribution that does not decode.
firstInvalid :: [Contribution] -> Maybe (String, Maybe Int, DecodeError)
firstInvalid cs = case [(kind, signer, err) | (kind, signer, Left err) <- cs] of
  c : _ -> Just c
  [] -> Nothing

{- | An @invalid_contribution@ case: decoding must fail first at exactly the
blamed contribution, with an invalid point (or, for a partial signature, a
scalar out of range).
-}
encodingCase :: String -> VectorError -> Either String [Contribution] -> TestTree
encodingCase name err cs = testCase name $ do
  contribs <- expectRight "vector" cs
  case err of
    InvalidContribution signer kind ->
      firstInvalid contribs @?= Just (kind, signer, if kind == "psig" then ScalarOutOfRange else InvalidPoint)
    ValueError m -> assertFailure ("expected an invalid_contribution error, got value error " <> show m)

-- | Whether an error is an invalid encoding of a contribution.
isEncodingError :: VectorError -> Bool
isEncodingError (InvalidContribution _ kind) = kind `elem` ["pubkey", "pubnonce", "aggnonce", "psig"]
isEncodingError (ValueError _) = False

expectRight :: String -> Either String a -> IO a
expectRight ctx = either (\err -> assertFailure (ctx <> ": " <> err)) pure

expectLib :: (Show e) => String -> Either e a -> IO a
expectLib ctx = either (\err -> assertFailure (ctx <> " failed: " <> show err)) pure

expectFailure :: Failure -> Either Failure a -> Assertion
expectFailure expected result = case result of
  Left err -> err @?= expected
  Right _ -> assertFailure ("expected Left " <> show expected <> ", got Right")

assertBytes :: String -> ByteString -> ByteString -> Assertion
assertBytes what expected actual = assertEqual what (hexOf expected) (hexOf actual)

-- | Test name for a vector case: file section, index and the first sentence of its comment.
caseName :: String -> Int -> Maybe String -> String
caseName section i comment = section <> " #" <> show i <> maybe "" (\c -> " (" <> firstSentence c <> ")") comment
 where
  firstSentence s = case s of
    '.' : ' ' : _ -> ""
    "." -> ""
    ch : rest -> ch : firstSentence rest
    [] -> []

-- Tests ----------------------------------------------------------------------

vectorTests :: Vectors -> [TestTree]
vectorTests vs = [testGroup file run | (file, run) <- files]
 where
  files =
    [ ("key_sort_vectors.json", keySortTests (vKeySort vs))
    , ("key_agg_vectors.json", keyAggTests (vKeyAgg vs))
    , ("nonce_gen_vectors.json", nonceGenTests (vNonceGen vs))
    , ("nonce_agg_vectors.json", nonceAggTests (vNonceAgg vs))
    , ("sign_verify_vectors.json", signVerifyTests (vSignVerify vs))
    , ("tweak_vectors.json", tweakTests (vTweak vs))
    , ("sig_agg_vectors.json", sigAggTests (vSigAgg vs))
    , ("det_sign_vectors.json", detSignTests (vDetSign vs))
    ]

keySortTests :: KeySortVectors -> [TestTree]
keySortTests (KeySortVectors pubkeys sorted) =
  [ testCase "KeySort" $ do
      pks <- expectLib "decode" (traverse decodeF pubkeys >>= nonEmptyF "pubkey")
      map (hexOf . encode) (NE.toList (keySort (pks :: NonEmpty PubKey))) @?= map hexOf sorted
  ]

keyAggTests :: KeyAggVectors -> [TestTree]
keyAggTests v = zipWith validCase [0 ..] (kaValid v) <> zipWith errorCase [0 ..] (kaError v)
 where
  validCase i (keyIdxs, expected) = testCase (caseName "valid" i Nothing) $ do
    keys <- expectRight "vector" (select "pubkey" (kaPubkeys v) keyIdxs)
    ctx <- expectLib "KeyAgg" (keyAggBytes keys [])
    assertBytes "xbytes(Q)" expected (encode (aggXOnlyPubKey ctx))
  errorCase i c
    | isEncodingError (kaeError c) = encodingCase name (kaeError c) (contributions "pubkey" asPubKey (kaPubkeys v) (kaeKeys c))
    | otherwise = testCase name $ do
        keys <- expectRight "vector" (select "pubkey" (kaPubkeys v) (kaeKeys c))
        tweaks <- expectRight "vector" (tweakSpecs (kaTweaks v) (kaeTweaks c) (kaeXOnly c))
        expected <- expectRight "vector" (valueError (kaeError c) >>= expectedFailure tweaks Nothing)
        expectFailure expected (keyAggBytes keys tweaks)
   where
    name = caseName "error" (i :: Int) (kaeComment c)

nonceGenTests :: [NonceGenCase] -> [TestTree]
nonceGenTests = zipWith run [0 ..]
 where
  run :: Int -> NonceGenCase -> TestTree
  run i c = testCase (caseName "case" i (ngComment c)) $ do
    (pk, inputs) <- expectLib "decode" $ do
      pk <- decodeF (ngPk c)
      sk <- traverse (first FDecode . secKeyFromBytes) (ngSk c)
      aggpk <- traverse decodeF (ngAggpk c)
      pure (pk, NonceInputs{nonceSecKey = sk, nonceAggPubKey = aggpk, nonceMessage = ngMsg c, nonceExtraInput = ngExtraIn c})
    (sn, pn) <- nonceGenWithRand (ngRand c) pk inputs >>= expectLib "NonceGen"
    exported <- secNonceToBytes sn >>= maybe (assertFailure "a fresh nonce cannot be exported") pure
    assertBytes "secnonce" (ngSecnonce c) exported
    assertBytes "pubnonce" (ngPubnonce c) (encode pn)

nonceAggTests :: NonceAggVectors -> [TestTree]
nonceAggTests v = zipWith validCase [0 ..] (naValid v) <> zipWith errorCase [0 ..] (naError v)
 where
  validCase i (idxs, expected, comment) = testCase (caseName "valid" i comment) $ do
    nonces <- expectRight "vector" (select "pnonce" (naPnonces v) idxs)
    pns <- expectLib "decode" (traverse decodeF nonces >>= nonEmptyF "pubnonce")
    assertBytes "aggnonce (infinity as 33 zero bytes)" expected (encode (nonceAgg pns))
    ctx <- expectLib "KeyAgg" (placeholderKeyAgg (length nonces))
    collected <- expectLib "coordinator" (coordinateNonces ctx nonces)
    assertBytes "coordinator aggnonce" expected (encode (collectedAggNonce collected))
  errorCase i (idxs, err, comment) = case err of
    InvalidContribution (Just signer) "pubnonce" -> testGroup name [encodingCase "decode" err contribs, coordinatorCase signer]
    _ -> testCase name (assertFailure ("no library check for " <> show err))
   where
    name = caseName "error" (i :: Int) comment
    contribs = contributions "pubnonce" asPubNonce (naPnonces v) idxs
    -- Each nonce is received on its own: the coordinator blames exactly the vector's signer.
    coordinatorCase signer = testCase "the coordinator blames the signer" $ do
      nonces <- expectRight "vector" (select "pnonce" (naPnonces v) idxs)
      ctx <- expectLib "KeyAgg" (placeholderKeyAgg (length nonces))
      lefts [receivePubNonce j b (newNonceRound ctx) | (j, b) <- zip [0 ..] nonces]
        @?= [Blame signer (InvalidPubNonceEncoding InvalidPoint)]

{- | A key aggregation context for @u@ signers, for nonce aggregation vectors
(which have no keys: nonce aggregation does not depend on them).
-}
placeholderKeyAgg :: Int -> Either Failure KeyAggContext
placeholderKeyAgg u = nonEmptyF "pubkey" [secKeyPubKey (secKeyFromInt k) | k <- [1 .. toInteger u]] >>= first FKeyAgg . keyAgg

-- | Round one of the coordinator, receiving the encoded nonces in signer order.
coordinateNonces :: KeyAggContext -> [ByteString] -> Either String CollectedNonces
coordinateNonces ctx nonces = do
  r <- first show (foldM (\r (j, b) -> receivePubNonce j b r) (newNonceRound ctx) (zip [0 ..] nonces))
  first show (finishNonceRound r)

signVerifyTests :: SignVerifyVectors -> [TestTree]
signVerifyTests v =
  [ testCase "setup: sk derives pubkeys[0]" $ do
      pk0 <- expectRight "vector" (at "pubkey" (svPubkeys v) 0)
      sk <- secKey
      assertBytes "pubkey" pk0 (encode (secKeyPubKey sk))
  , testCase "setup: secnonces[0] has public nonce pnonces[0]" $ do
      sn <- expectRight "vector" (at "secnonce" (svSecnonces v) 0) >>= (secNonceFromBytes >=> expectLib "secnonce")
      pn0 <- expectRight "vector" (at "pnonce" (svPnonces v) 0)
      assertBytes "pubnonce" pn0 (encode (secNoncePubNonce sn))
  ]
    <> zipWith validCase [0 ..] (svValid v)
    <> zipWith signErrorCase [0 ..] (svSignError v)
    <> zipWith verifyFailCase [0 ..] (svVerifyFail v)
    <> zipWith verifyErrorCase [0 ..] (svVerifyError v)
 where
  secKey = expectLib "secKeyFromBytes" (secKeyFromBytes (svSk v))

  validCase i c =
    testGroup
      (caseName "valid" i (svvComment c))
      [ testCase "NonceAgg reproduces the aggnonce" $ do
          (_, nonces, agg, _) <- inputs
          pns <- expectLib "decode" (traverse decodeF nonces >>= nonEmptyF "pubnonce")
          assertBytes "aggnonce" agg (encode (nonceAgg pns))
      , testCase "Sign returns the expected partial signature" $ do
          (keys, _, agg, m) <- inputs
          sk <- secKey
          sn <- expectRight "vector" (at "secnonce" (svSecnonces v) 0)
          psig <- signBytes sk sn keys [] agg m >>= expectLib "Sign"
          assertBytes "psig" (svvExpected c) (encode psig)
      , testCase "PartialSigVerify accepts the expected partial signature" $ do
          (keys, nonces, _, m) <- inputs
          psig <- expectLib "decode psig" (decodeF (svvExpected c))
          verifyBytes nonces keys [] m (svvSigner c) psig @?= Right True
      ]
   where
    inputs = expectRight "vector" $ do
      keys <- select "pubkey" (svPubkeys v) (svvKeys c)
      nonces <- select "pnonce" (svPnonces v) (svvNonces c)
      agg <- at "aggnonce" (svAggnonces v) (svvAggnonce c)
      m <- at "msg" (svMsgs v) (svvMsg c)
      pure (keys, nonces, agg, m)

  signErrorCase i c
    | isEncodingError (sseError c) =
        encodingCase name (sseError c) $ do
          keys <- contributions "pubkey" asPubKey (svPubkeys v) (sseKeys c)
          agg <- at "aggnonce" (svAggnonces v) (sseAggnonce c)
          -- Sign parses the pubkeys (KeyAgg) before the aggregate nonce.
          pure (keys <> [("aggnonce", Nothing, asAggNonce agg)])
    | otherwise = testCase name $ do
        (keys, agg, m, sn) <- expectRight "vector" $ do
          keys <- select "pubkey" (svPubkeys v) (sseKeys c)
          agg <- at "aggnonce" (svAggnonces v) (sseAggnonce c)
          m <- at "msg" (svMsgs v) (sseMsg c)
          sn <- at "secnonce" (svSecnonces v) (sseSecnonce c)
          pure (keys, agg, m, sn)
        expected <- expectRight "vector" (valueError (sseError c) >>= expectedFailure [] (Just sn))
        sk <- secKey
        signBytes sk sn keys [] agg m >>= expectFailure expected
   where
    name = caseName "sign_error" (i :: Int) (sseComment c)

  verifyInputs c = expectRight "vector" $ do
    keys <- select "pubkey" (svPubkeys v) (svfKeys c)
    nonces <- select "pnonce" (svPnonces v) (svfNonces c)
    m <- at "msg" (svMsgs v) (svfMsg c)
    pure (keys, nonces, m)

  -- BIP-327 returns False for s >= n; such a partial signature does not decode.
  verifyFailCase i c = testCase (caseName "verify_fail" i (svfComment c)) $ do
    (keys, nonces, m) <- verifyInputs c
    if bytesToInteger (svfSig c) >= curveOrder
      then (decodeF (svfSig c) :: Either Failure PartialSignature) @?= Left (FDecode ScalarOutOfRange)
      else do
        psig <- expectLib "decode psig" (decodeF (svfSig c))
        verifyBytes nonces keys [] m (svfSigner c) psig @?= Right False

  verifyErrorCase i c = case svfError c of
    Just err
      | isEncodingError err ->
          encodingCase name err $ do
            -- PartialSigVerify aggregates (parses) the pubnonces before the pubkeys.
            nonces <- contributions "pubnonce" asPubNonce (svPnonces v) (svfNonces c)
            keys <- contributions "pubkey" asPubKey (svPubkeys v) (svfKeys c)
            pure (nonces <> keys)
    other -> testCase name (assertFailure ("no library check for " <> show other))
   where
    name = caseName "verify_error" (i :: Int) (svfComment c)

tweakTests :: TweakVectors -> [TestTree]
tweakTests v = zipWith (run "valid") [0 ..] (twValid v) <> zipWith (run "error") [0 ..] (twError v)
 where
  run :: String -> Int -> TweakCase -> TestTree
  run section i c = case tcOutcome c of
    Right expected ->
      testGroup
        name
        [ testCase "NonceAgg reproduces the aggnonce" $ do
            (_, nonces, _) <- inputs
            pns <- expectLib "decode" (traverse decodeF nonces >>= nonEmptyF "pubnonce")
            assertBytes "aggnonce" (twAggnonce v) (encode (nonceAgg pns))
        , testCase "Sign returns the expected partial signature" $ do
            (keys, _, tweaks) <- inputs
            sk <- secKey
            psig <- signBytes sk (twSecnonce v) keys tweaks (twAggnonce v) (twMsg v) >>= expectLib "Sign"
            assertBytes "psig" expected (encode psig)
        , testCase "PartialSigVerify accepts the expected partial signature" $ do
            (keys, nonces, tweaks) <- inputs
            psig <- expectLib "decode psig" (decodeF expected)
            verifyBytes nonces keys tweaks (twMsg v) (tcSigner c) psig @?= Right True
        ]
    Left err -> testCase name $ do
      (keys, _, tweaks) <- inputs
      sk <- secKey
      expected <- expectRight "vector" (valueError err >>= expectedFailure tweaks Nothing)
      signBytes sk (twSecnonce v) keys tweaks (twAggnonce v) (twMsg v) >>= expectFailure expected
   where
    name = caseName section i (tcComment c)
    inputs = expectRight "vector" $ do
      keys <- select "pubkey" (twPubkeys v) (tcKeys c)
      nonces <- select "pnonce" (twPnonces v) (tcNonces c)
      tweaks <- tweakSpecs (twTweaks v) (tcTweaks c) (tcXOnly c)
      pure (keys, nonces, tweaks)
  secKey = expectLib "secKeyFromBytes" (secKeyFromBytes (twSk v))

sigAggTests :: SigAggVectors -> [TestTree]
sigAggTests v = zipWith (run "valid") [0 ..] (saValid v) <> zipWith (run "error") [0 ..] (saError v)
 where
  run :: String -> Int -> SigAggCase -> TestTree
  run section i c = case sacOutcome c of
    Right expected ->
      testGroup
        name
        [ testCase "NonceAgg reproduces the aggnonce" $ do
            (_, nonces, _, _) <- inputs
            pns <- expectLib "decode" (traverse decodeF nonces >>= nonEmptyF "pubnonce")
            assertBytes "aggnonce" (sacAggnonce c) (encode (nonceAgg pns))
        , testCase "PartialSigAgg returns the expected signature" $ do
            (sig, _) <- aggregate
            assertBytes "sig" expected (encode sig)
        , testCase "the expected signature is a valid BIP-340 signature for aggXOnlyPubKey" $ do
            (_, ctx) <- aggregate
            sig <- expectLib "decode sig" (decodeF expected)
            assertBool "verify" (verify (aggXOnlyPubKey ctx) (saMsg v) sig)
        , testCase "the coordinator reproduces the aggnonce, accepts every partial signature and returns the signature" $ do
            (keys, nonces, tweaks, psigs) <- inputs
            ctx <- expectLib "KeyAgg" (keyAggBytes keys tweaks)
            collected <- expectLib "round one" (coordinateNonces ctx nonces)
            assertBytes "aggnonce" (sacAggnonce c) (encode (collectedAggNonce collected))
            r <- expectLib "round two" (foldM (\r (j, b) -> receivePartialSig j b r) (newSigRound collected (saMsg v)) (zip [0 ..] psigs))
            sig <- expectLib "finishSigRound" (finishSigRound r)
            assertBytes "sig" expected (encode sig)
        ]
    Left err@(InvalidContribution (Just signer) "psig") ->
      testGroup
        name
        [ encodingCase "decode" err (contributions "psig" asPsig (saPsigs v) (sacPsigs c))
        , -- PartialSigAgg only range-checks, so the other partial signatures
          -- of the vector need not verify in this session (and do not): only
          -- the vector's signer is checked.
          testCase "the coordinator blames the signer" $ do
            (keys, nonces, tweaks, psigs) <- inputs
            ctx <- expectLib "KeyAgg" (keyAggBytes keys tweaks)
            collected <- expectLib "round one" (coordinateNonces ctx nonces)
            psig <- expectRight "vector" (at "psig" psigs signer)
            lefts [receivePartialSig signer psig (newSigRound collected (saMsg v))]
              @?= [Blame signer (InvalidPartialSigEncoding ScalarOutOfRange)]
        ]
    Left err -> testCase name (assertFailure ("no library check for " <> show err))
   where
    name = caseName section i (sacComment c)
    inputs = expectRight "vector" $ do
      keys <- select "pubkey" (saPubkeys v) (sacKeys c)
      nonces <- select "pnonce" (saPnonces v) (sacNonces c)
      tweaks <- tweakSpecs (saTweaks v) (sacTweaks c) (sacXOnly c)
      psigs <- select "psig" (saPsigs v) (sacPsigs c)
      pure (keys, nonces, tweaks, psigs)
    aggregate = do
      (keys, _, tweaks, psigs) <- inputs
      expectLib "PartialSigAgg" $ do
        ctx <- keyAggBytes keys tweaks
        agg <- decodeF (sacAggnonce c)
        ps <- traverse decodeF psigs >>= nonEmptyF "psig"
        pure (partialSigAgg (newSession ctx agg (saMsg v)) ps, ctx)

detSignTests :: DetSignVectors -> [TestTree]
detSignTests v =
  testCase "setup: sk derives pubkeys[0]" (do pk0 <- expectRight "vector" (at "pubkey" (dsPubkeys v) 0); sk <- secKey; assertBytes "pubkey" pk0 (encode (secKeyPubKey sk)))
    : zipWith (run "valid") [0 ..] (dsValid v)
      <> zipWith (run "error") [0 ..] (dsError v)
 where
  secKey = expectLib "secKeyFromBytes" (secKeyFromBytes (dsSk v))
  run :: String -> Int -> DetSignCase -> TestTree
  run section i c = case dscOutcome c of
    Right (expectedNonce, expectedPsig) ->
      testGroup
        name
        [ testCase "DeterministicSign returns the expected public nonce and partial signature" $ do
            (pn, psig) <- detSign
            assertBytes "pubnonce" expectedNonce (encode pn)
            assertBytes "psig" expectedPsig (encode psig)
        , testCase "PartialSigVerify accepts it in the session of aggothernonce and the public nonce" $ do
            (keys, tweaks, m) <- inputs
            (pn, psig) <- detSign
            sk <- secKey
            -- NonceAgg((aggothernonce, pubnonce)): aggothernonce parses as a public nonce.
            other <- expectLib "decode aggothernonce" (decodeF (dscAggOtherNonce c))
            ctx <- expectLib "KeyAgg" (keyAggBytes keys tweaks)
            pk <- expectRight "vector" (at "pubkey" (NE.toList (keyAggPubKeys ctx)) (dscSigner c))
            pk @?= secKeyPubKey sk
            assertBool "partialSigVerify" (partialSigVerify (newSession ctx (nonceAgg (other :| [pn])) m) pk pn psig)
        ]
    Left err@(InvalidContribution (Just _) "pubkey") ->
      encodingCase name err $ do
        keys <- contributions "pubkey" asPubKey (dsPubkeys v) (dscKeys c)
        pure (keys <> [("aggothernonce", Nothing, asAggNonce (dscAggOtherNonce c))])
    -- BIP-327 blames the nonce aggregator both for an invalid encoding (which
    -- does not decode to an 'AggNonce') and for a half at infinity (which
    -- 'deterministicSign' rejects).
    Left (InvalidContribution Nothing "aggothernonce") -> testCase name $ do
      (keys, tweaks, m) <- inputs
      sk <- secKey
      ctx <- expectLib "KeyAgg" (keyAggBytes keys tweaks)
      case decode (dscAggOtherNonce c) of
        Left decodeErr -> decodeErr @?= InvalidPoint
        Right agg -> either Just (const Nothing) (deterministicSign sk agg ctx m (dscRand c)) @?= Just AggOtherNonceAtInfinity
    Left err -> testCase name $ do
      (keys, tweaks, m) <- inputs
      sk <- secKey
      expected <- expectRight "vector" (valueError err >>= expectedFailure tweaks Nothing)
      expectFailure expected (detSignBytes sk (dscAggOtherNonce c) keys tweaks m (dscRand c))
   where
    name = caseName section i (dscComment c)
    inputs = expectRight "vector" $ do
      keys <- select "pubkey" (dsPubkeys v) (dscKeys c)
      tweaks <- tweakSpecs (dscTweaks c) [0 .. length (dscTweaks c) - 1] (dscXOnly c)
      m <- at "msg" (dsMsgs v) (dscMsg c)
      pure (keys, tweaks, m)
    detSign = do
      (keys, tweaks, m) <- inputs
      sk <- secKey
      expectLib "DeterministicSign" (detSignBytes sk (dscAggOtherNonce c) keys tweaks m (dscRand c))
