{-# LANGUAGE OverloadedStrings #-}

{- | Official BIP-0327 test vectors, read at test time from the JSON files
vendored in @test\/vectors\/bip327@ (see the @README.md@ there for the
upstream commit and checksums).

Every case that the public API can express is run with exact-output
assertions. Cases that need something the library does not offer (parsing
invalid byte encodings and blaming the signer who sent them, or
DeterministicSign) are listed one by one in the
\"Not expressible through the public API\" group, so the coverage gap is
visible in the test output instead of being skipped silently. For invalid
encodings, that group still checks that @parse_point@ rejects exactly the
contribution the vector blames.

The parsers reject unknown fields, unknown error types and unknown error
messages, so an updated vector file cannot be silently half-run.
-}
module OfficialVectors (officialVectorTests) where

import Control.Monad (filterM, foldM, unless, zipWithM)
import Crypto.Curve.Secp256k1 (Pub, derive_pub, parse_point, serialize_point, verify_schnorr, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2 (
  MuSig2Error (..),
  PubNonce (..),
  SecKey (..),
  SecNonceGenParams (..),
  Tweak (..),
  aggNonces,
  aggPartials,
  aggregatedPubkey,
  applyTweak,
  mkKeyAggContext,
  mkSecNonce,
  mkSessionContext,
  partialSigVerify,
  publicNonce,
  secNonceGenWithRand,
  sign,
  sortPublicKeys,
 )
import Crypto.Curve.Secp256k1.MuSig2.Internal (
  SecNonce (..),
  bytesToInteger,
  cbytesExt,
  curveOrder,
  integerToBytes32,
  secNonceScalars,
  xBytes,
 )
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Aeson (FromJSON (..), Value, eitherDecodeFileStrict, withObject, (.:), (.:?))
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Aeson.Types (Object, Parser, parseEither)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import Data.Char (toUpper)
import Data.Either (lefts, rights)
import Data.Foldable (toList)
import Data.Maybe (fromMaybe, isJust)
import System.Directory (doesFileExist, getCurrentDirectory, makeAbsolute)
import System.Environment (lookupEnv)
import System.FilePath ((</>))
import Test.Tasty
import Test.Tasty.HUnit

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

-- | Hex-encoded bytes.
newtype Hex = Hex {unHex :: ByteString}

instance FromJSON Hex where
  parseJSON v = do
    s <- parseJSON v
    either (fail . (("invalid hex " <> show s <> ": ") <>)) (pure . Hex) (B16.decode (BC.pack s))

-- | Like 'withObject', but fails on fields outside the allowed list.
strictObject :: String -> [Key.Key] -> (Object -> Parser a) -> Value -> Parser a
strictObject what allowed k = withObject what $ \o -> do
  let unknown = filter (`notElem` allowed) (KeyMap.keys o)
  unless (null unknown) $ fail (what <> ": unexpected fields " <> show (map Key.toString unknown))
  k o

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
  , kaError :: [KeyAggError]
  }

data KeyAggError = KeyAggError
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
            KeyAggError <$> c .: "key_indices" <*> c .: "tweak_indices" <*> c .: "is_xonly" <*> c .: "error" <*> c .:? "comment"
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

-- | Only the case comments are read: DeterministicSign is not implemented.
data DetSignVectors = DetSignVectors [Maybe String] [Maybe String]

parseDetSign :: Value -> Parser DetSignVectors
parseDetSign = strictObject "det_sign" ["sk", "pubkeys", "msgs", "valid_test_cases", "error_test_cases"] $ \o ->
  DetSignVectors
    <$> (o .: "valid_test_cases" >>= traverse comment)
    <*> (o .: "error_test_cases" >>= traverse comment)
 where
  comment = withObject "det_sign case" (.:? "comment")

-- BIP-0327 encodings ------------------------------------------------------------

-- | @cpoint@: a 33-byte compressed point (@parse_point@ checks the 0x02/0x03 tag, @x < p@ and that @x@ is on the curve).
cpoint :: ByteString -> Maybe Pub
cpoint b
  | BS.length b == 33 = parse_point b
  | otherwise = Nothing

-- | @cpoint_ext@: like 'cpoint', but 33 zero bytes is the point at infinity.
cpointExt :: ByteString -> Maybe Pub
cpointExt b
  | b == BS.replicate 33 0 = Just _CURVE_ZERO
  | otherwise = cpoint b

-- | A 66-byte public nonce.
pubNonceFromBytes :: ByteString -> Maybe PubNonce
pubNonceFromBytes b
  | BS.length b == 66 = PubNonce <$> cpoint (BS.take 33 b) <*> cpoint (BS.drop 33 b)
  | otherwise = Nothing

-- | A 66-byte aggregate nonce (either half may be infinity).
aggNonceFromBytes :: ByteString -> Maybe PubNonce
aggNonceFromBytes b
  | BS.length b == 66 = PubNonce <$> cpointExt (BS.take 33 b) <*> cpointExt (BS.drop 33 b)
  | otherwise = Nothing

-- | Serializes an aggregate nonce with @cbytes_ext@.
aggNonceBytes :: PubNonce -> ByteString
aggNonceBytes (PubNonce a b) = cbytesExt a <> cbytesExt b

pubNonceBytes :: PubNonce -> ByteString
pubNonceBytes (PubNonce a b) = serialize_point a <> serialize_point b

-- | A 97-byte secret nonce: @k1 || k2 || pk@.
secNonceFromBytes :: ByteString -> Either String (Integer, Integer, Pub)
secNonceFromBytes b
  | BS.length b /= 97 = Left ("secnonce must be 97 bytes, got " <> show (BS.length b))
  | otherwise = do
      pk <- note "secnonce public key does not parse" (cpoint (BS.drop 64 b))
      Right (bytesToInteger (BS.take 32 b), bytesToInteger (BS.take 32 (BS.drop 32 b)), pk)

secNonceBytes :: SecNonce -> ByteString
secNonceBytes sn =
  let (k1, k2) = secNonceScalars sn
   in integerToBytes32 k1 <> integerToBytes32 k2 <> serialize_point (secNoncePubKeyInternal sn)

-- Helpers --------------------------------------------------------------------

note :: String -> Maybe a -> Either String a
note err = maybe (Left err) Right

-- | Indexes into a vector table.
at :: String -> [a] -> Int -> Either String a
at what xs i = case drop i xs of
  x : _ | i >= 0 -> Right x
  _ -> Left (what <> " index " <> show i <> " is out of range")

-- | Selects and decodes entries of a vector table.
select :: String -> (ByteString -> Maybe a) -> [ByteString] -> [Int] -> Either String [a]
select what decode table = traverse $ \i -> at what table i >>= note (what <> " #" <> show i <> " does not parse") . decode

mkTweaks :: [ByteString] -> [Int] -> [Bool] -> Either String [Tweak]
mkTweaks table idxs xonly
  | length idxs /= length xonly = Left "tweak_indices and is_xonly differ in length"
  | otherwise = zipWithM (\i x -> (if x then XOnlyTweak else PlainTweak) . bytesToInteger <$> at "tweak" table i) idxs xonly

tweakValue :: Tweak -> Integer
tweakValue (XOnlyTweak t) = t
tweakValue (PlainTweak t) = t

-- | Aggregate key after applying the tweaks in order (KeyAgg + ApplyTweak).
tweakedKeyAgg :: [Pub] -> [Tweak] -> Either MuSig2Error Pub
tweakedKeyAgg pks tweaks = aggregatedPubkey <$> (mkKeyAggContext pks Nothing >>= \ctx -> foldM applyTweak ctx tweaks)

{- | The library error that corresponds to a reference-implementation
@ValueError@ message. Unknown messages fail, so new error cases need an
explicit mapping.
-}
libraryErrorFor :: [Tweak] -> Maybe (Integer, Integer) -> String -> Either String MuSig2Error
libraryErrorFor tweaks secnonce message = case message of
  "The tweak must be less than n." -> case filter (>= curveOrder) (map tweakValue tweaks) of
    t : _ -> Right (TweakOutOfRange t)
    [] -> Left "vector expects an out-of-range tweak but none is >= n"
  "The result of tweaking cannot be infinity." -> Right TweakResultAtInfinity
  "The signer's pubkey must be included in the list of pubkeys." -> Right SecretKeyPublicKeyMismatch
  "first secnonce value is out of range." -> scalarError "k1" . fst <$> note "no secnonce in case" secnonce
  "second secnonce value is out of range." -> scalarError "k2" . snd <$> note "no secnonce in case" secnonce
  other -> Left ("no library error is mapped to the BIP-0327 error message " <> show other)
 where
  scalarError label k = if k == 0 then SecretScalarZero label else SecretScalarOutOfRange label

{- | A contribution as the reference implementation checks it: kind, signer
index (if any), and whether its encoding is valid.
-}
type Contribution = (String, Maybe Int, Bool)

contributions :: String -> (ByteString -> Bool) -> [ByteString] -> [Int] -> Either String [Contribution]
contributions kind valid table = zipWithM (\signer i -> (\b -> (kind, Just signer, valid b)) <$> at kind table i) [0 ..]

-- | The contribution the reference implementation would blame first.
firstInvalid :: [Contribution] -> Maybe (String, Maybe Int)
firstInvalid cs = case [(kind, signer) | (kind, signer, False) <- cs] of
  c : _ -> Just c
  [] -> Nothing

{- | For an @invalid_contribution@ that needs byte-level parsing: checks that
@parse_point@ rejects exactly the blamed contribution and nothing before it.
-}
encodingCase :: String -> VectorError -> Either String [Contribution] -> TestTree
encodingCase name err cs =
  testCase (name <> " [only the encoding is checked; the library has no byte-level parser that blames signers]") $ do
    contribs <- expectRight "vector" cs
    case err of
      InvalidContribution signer kind -> firstInvalid contribs @?= Just (kind, signer)
      ValueError m -> assertFailure ("expected an invalid_contribution error, got value error " <> show m)

-- | Whether an error is an invalid encoding of a point-based contribution.
isEncodingError :: VectorError -> Bool
isEncodingError (InvalidContribution _ kind) = kind `elem` ["pubkey", "pubnonce", "aggnonce", "aggothernonce"]
isEncodingError (ValueError _) = False

expectRight :: String -> Either String a -> IO a
expectRight ctx = either (\err -> assertFailure (ctx <> ": " <> err)) pure

expectLib :: (Show e) => String -> Either e a -> IO a
expectLib ctx = either (\err -> assertFailure (ctx <> " failed: " <> show err)) pure

expectLibError :: MuSig2Error -> Either MuSig2Error a -> Assertion
expectLibError expected result = case result of
  Left err -> err @?= expected
  Right _ -> assertFailure ("expected Left " <> show expected <> ", got Right")

hexOf :: ByteString -> String
hexOf = map toUpper . BC.unpack . B16.encode

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

-- | Tests run against the library, and cases listed as not expressible.
data FileTests = FileTests [TestTree] [TestTree]

vectorTests :: Vectors -> [TestTree]
vectorTests vs =
  [testGroup file run | (file, FileTests run _) <- files, not (null run)]
    <> [testGroup "Not expressible through the public API" [testGroup file skipped | (file, FileTests _ skipped) <- files, not (null skipped)]]
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

keySortTests :: KeySortVectors -> FileTests
keySortTests (KeySortVectors pubkeys sorted) =
  FileTests
    [ testCase "KeySort" $ do
        pks <- expectRight "pubkeys" (select "pubkey" cpoint pubkeys [0 .. length pubkeys - 1])
        map (hexOf . serialize_point) (toList (sortPublicKeys pks)) @?= map hexOf sorted
    ]
    []

keyAggTests :: KeyAggVectors -> FileTests
keyAggTests v =
  FileTests (zipWith validCase [0 ..] (kaValid v) <> rights errs) (lefts errs)
 where
  errs = zipWith errorCase [0 ..] (kaError v)
  validCase i (keyIdxs, expected) = testCase (caseName "valid" i Nothing) $ do
    pks <- expectRight "vector" (select "pubkey" cpoint (kaPubkeys v) keyIdxs)
    ctx <- expectLib "KeyAgg" (mkKeyAggContext pks Nothing)
    assertBytes "xbytes(Q)" expected (xBytes (aggregatedPubkey ctx))
  errorCase i c
    | isEncodingError (kaeError c) =
        Left $ encodingCase name (kaeError c) (contributions "pubkey" (isJust . cpoint) (kaPubkeys v) (kaeKeys c))
    | otherwise = Right . testCase name $ do
        pks <- expectRight "vector" (select "pubkey" cpoint (kaPubkeys v) (kaeKeys c))
        tweaks <- expectRight "vector" (mkTweaks (kaTweaks v) (kaeTweaks c) (kaeXOnly c))
        expected <- expectRight "vector" (valueError (kaeError c) >>= libraryErrorFor tweaks Nothing)
        expectLibError expected (tweakedKeyAgg pks tweaks)
   where
    name = caseName "error" i (kaeComment c)

valueError :: VectorError -> Either String String
valueError (ValueError m) = Right m
valueError err = Left ("expected a value error, got " <> show err)

nonceGenTests :: [NonceGenCase] -> FileTests
nonceGenTests cases = FileTests (zipWith run [0 ..] cases) []
 where
  run :: Int -> NonceGenCase -> TestTree
  run i c = testCase (caseName "case" i (ngComment c)) $ do
    pk <- expectRight "pk" (note "does not parse" (cpoint (ngPk c)))
    -- The library takes aggpk as a point; the vector gives 32-byte x-only bytes,
    -- so lift it (even y) and check that it serializes back to the same bytes.
    aggpk <- traverse (\b -> expectRight "aggpk" (note "is not a valid x-only key" (if BS.length b == 32 then parse_point b else Nothing))) (ngAggpk c)
    assertEqual "aggpk round-trips through the x-only lift" (fmap hexOf (ngAggpk c)) (fmap (hexOf . xBytes) aggpk)
    let params =
          SecNonceGenParams
            { _pk = pk
            , _sk = SecKey . bytesToInteger <$> ngSk c
            , _aggpk = aggpk
            , _msg = ngMsg c
            , _extraIn = ngExtraIn c
            }
    sn <- expectLib "NonceGen" (secNonceGenWithRand (ngRand c) params)
    assertBytes "secnonce" (ngSecnonce c) (secNonceBytes sn)
    pn <- expectLib "publicNonce" (publicNonce sn)
    assertBytes "pubnonce" (ngPubnonce c) (pubNonceBytes pn)

nonceAggTests :: NonceAggVectors -> FileTests
nonceAggTests v = FileTests (zipWith validCase [0 ..] (naValid v) <> rights errs) (lefts errs)
 where
  errs = zipWith errorCase [0 ..] (naError v)
  validCase i (idxs, expected, comment) = testCase (caseName "valid" i comment) $ do
    nonces <- expectRight "vector" (select "pnonce" pubNonceFromBytes (naPnonces v) idxs)
    agg <- expectLib "NonceAgg" (aggNonces nonces)
    assertBytes "aggnonce (infinity as 33 zero bytes)" expected (aggNonceBytes agg)
  errorCase i (idxs, err, comment)
    | isEncodingError err = Left (encodingCase name err (contributions "pubnonce" (isJust . pubNonceFromBytes) (naPnonces v) idxs))
    | otherwise = Right (testCase name (assertFailure ("no library check for " <> show err)))
   where
    name = caseName "error" i comment

signVerifyTests :: SignVerifyVectors -> FileTests
signVerifyTests v =
  FileTests
    ( [ testCase "setup: sk derives pubkeys[0]" $ do
          p <- expectRight "derive_pub" (note "failed" (derive_pub (fromInteger (bytesToInteger (svSk v)))))
          pk0 <- expectRight "vector" (at "pubkey" (svPubkeys v) 0)
          assertBytes "pubkey" pk0 (serialize_point p)
      , testCase "setup: secnonces[0] has public nonce pnonces[0]" $ do
          sn <- secnonce 0
          pn <- expectLib "publicNonce" (publicNonce sn)
          pn0 <- expectRight "vector" (at "pnonce" (svPnonces v) 0)
          assertBytes "pubnonce" pn0 (pubNonceBytes pn)
      ]
        <> zipWith validCase [0 ..] (svValid v)
        <> rights signErrs
        <> zipWith verifyFailCase [0 ..] (svVerifyFail v)
        <> rights verifyErrs
    )
    (lefts signErrs <> lefts verifyErrs)
 where
  sk = SecKey (bytesToInteger (svSk v))
  secnonce j = do
    (k1, k2, pk) <- expectRight "vector" (at "secnonce" (svSecnonces v) j >>= secNonceFromBytes)
    expectLib "mkSecNonce" (mkSecNonce pk k1 k2)
  signErrs = zipWith signErrorCase [0 ..] (svSignError v)
  verifyErrs = zipWith verifyErrorCase [0 ..] (svVerifyError v)

  validCase i c =
    testGroup
      (caseName "valid" i (svvComment c))
      [ testCase "NonceAgg reproduces the aggnonce" $ do
          (_, nonces, _, _) <- inputs
          expected <- expectRight "vector" (at "aggnonce" (svAggnonces v) (svvAggnonce c))
          agg <- expectLib "NonceAgg" (aggNonces nonces)
          assertBytes "aggnonce" expected (aggNonceBytes agg)
      , testCase "Sign returns the expected partial signature" $ do
          (pks, _, agg, m) <- inputs
          sn <- secnonce 0
          psig <- expectLib "Sign" (mkSessionContext agg pks [] m >>= sign sn sk)
          assertBytes "psig" (svvExpected c) (integerToBytes32 psig)
      , testCase "PartialSigVerify accepts the expected partial signature" $ do
          (pks, nonces, _, m) <- inputs
          partialSigVerify (bytesToInteger (svvExpected c)) nonces pks [] m (svvSigner c) @?= Right True
      ]
   where
    inputs = expectRight "vector" $ do
      pks <- select "pubkey" cpoint (svPubkeys v) (svvKeys c)
      nonces <- select "pnonce" pubNonceFromBytes (svPnonces v) (svvNonces c)
      agg <- at "aggnonce" (svAggnonces v) (svvAggnonce c) >>= note "aggnonce does not parse" . aggNonceFromBytes
      m <- at "msg" (svMsgs v) (svvMsg c)
      pure (pks, nonces, agg, m)

  signErrorCase i c
    | isEncodingError (sseError c) =
        Left . encodingCase name (sseError c) $ do
          keys <- contributions "pubkey" (isJust . cpoint) (svPubkeys v) (sseKeys c)
          agg <- at "aggnonce" (svAggnonces v) (sseAggnonce c)
          -- Sign parses the pubkeys (KeyAgg) before the aggregate nonce.
          pure (keys <> [("aggnonce", Nothing, isJust (aggNonceFromBytes agg))])
    | otherwise = Right . testCase name $ do
        (pks, agg, m, (k1, k2, snPk)) <- expectRight "vector" $ do
          pks <- select "pubkey" cpoint (svPubkeys v) (sseKeys c)
          agg <- at "aggnonce" (svAggnonces v) (sseAggnonce c) >>= note "aggnonce does not parse" . aggNonceFromBytes
          m <- at "msg" (svMsgs v) (sseMsg c)
          sn <- at "secnonce" (svSecnonces v) (sseSecnonce c) >>= secNonceFromBytes
          pure (pks, agg, m, sn)
        expected <- expectRight "vector" (valueError (sseError c) >>= libraryErrorFor [] (Just (k1, k2)))
        expectLibError expected $ do
          sn <- mkSecNonce snPk k1 k2
          mkSessionContext agg pks [] m >>= sign sn sk
   where
    name = caseName "sign_error" i (sseComment c)

  verifyInputs c = expectRight "vector" $ do
    pks <- select "pubkey" cpoint (svPubkeys v) (svfKeys c)
    nonces <- select "pnonce" pubNonceFromBytes (svPnonces v) (svfNonces c)
    m <- at "msg" (svMsgs v) (svfMsg c)
    pure (pks, nonces, m)

  verifyFailCase i c = testCase (caseName "verify_fail" i (svfComment c) <> outOfRangeNote) $ do
    (pks, nonces, m) <- verifyInputs c
    partialSigVerify s nonces pks [] m (svfSigner c) @?= expected
   where
    s = bytesToInteger (svfSig c)
    -- The reference implementation returns False for s >= n; the library
    -- reports that input as an error instead.
    (expected, outOfRangeNote)
      | s >= curveOrder = (Left PartialSignatureOutOfRange, " [library: Left PartialSignatureOutOfRange]")
      | otherwise = (Right False, "")

  verifyErrorCase i c = case svfError c of
    Just err
      | isEncodingError err ->
          Left . encodingCase name err $ do
            -- PartialSigVerify aggregates (parses) the pubnonces before the pubkeys.
            nonces <- contributions "pubnonce" (isJust . pubNonceFromBytes) (svPnonces v) (svfNonces c)
            keys <- contributions "pubkey" (isJust . cpoint) (svPubkeys v) (svfKeys c)
            pure (nonces <> keys)
    other -> Right (testCase name (assertFailure ("no library check for " <> show other)))
   where
    name = caseName "verify_error" i (svfComment c)

tweakTests :: TweakVectors -> FileTests
tweakTests v = FileTests (zipWith (run "valid") [0 ..] (twValid v) <> zipWith (run "error") [0 ..] (twError v)) []
 where
  sk = SecKey (bytesToInteger (twSk v))
  run section i c = case tcOutcome c of
    Right expected ->
      testGroup
        name
        [ testCase "NonceAgg reproduces the aggnonce" $ do
            (_, nonces, _, _) <- inputs
            agg <- expectLib "NonceAgg" (aggNonces nonces)
            assertBytes "aggnonce" (twAggnonce v) (aggNonceBytes agg)
        , testCase "Sign returns the expected partial signature" $ do
            (pks, _, tweaks, agg) <- inputs
            sn <- secnonce
            psig <- expectLib "Sign" (mkSessionContext agg pks tweaks (twMsg v) >>= sign sn sk)
            assertBytes "psig" expected (integerToBytes32 psig)
        , testCase "PartialSigVerify accepts the expected partial signature" $ do
            (pks, nonces, tweaks, _) <- inputs
            partialSigVerify (bytesToInteger expected) nonces pks tweaks (twMsg v) (tcSigner c) @?= Right True
        ]
    Left err -> testCase name $ do
      (pks, _, tweaks, agg) <- inputs
      sn <- secnonce
      libErr <- expectRight "vector" (valueError err >>= libraryErrorFor tweaks Nothing)
      expectLibError libErr (mkSessionContext agg pks tweaks (twMsg v) >>= sign sn sk)
   where
    name = caseName section i (tcComment c)
    inputs = expectRight "vector" $ do
      pks <- select "pubkey" cpoint (twPubkeys v) (tcKeys c)
      nonces <- select "pnonce" pubNonceFromBytes (twPnonces v) (tcNonces c)
      tweaks <- mkTweaks (twTweaks v) (tcTweaks c) (tcXOnly c)
      agg <- note "aggnonce does not parse" (aggNonceFromBytes (twAggnonce v))
      pure (pks, nonces, tweaks, agg)
  secnonce = do
    (k1, k2, pk) <- expectRight "vector" (secNonceFromBytes (twSecnonce v))
    expectLib "mkSecNonce" (mkSecNonce pk k1 k2)

sigAggTests :: SigAggVectors -> FileTests
sigAggTests v = FileTests (zipWith (run "valid") [0 ..] (saValid v) <> zipWith (run "error") [0 ..] (saError v)) []
 where
  run :: String -> Int -> SigAggCase -> TestTree
  run section i c = case sacOutcome c of
    Right expected ->
      testGroup
        name
        [ testCase "NonceAgg reproduces the aggnonce" $ do
            (_, nonces, _, _, _) <- inputs
            agg <- expectLib "NonceAgg" (aggNonces nonces)
            assertBytes "aggnonce" (sacAggnonce c) (aggNonceBytes agg)
        , testCase "PartialSigAgg returns the expected signature" $ do
            sig <- aggregate
            assertBytes "sig" expected sig
        , testCase "the expected signature is a valid BIP-340 signature for the tweaked key" $ do
            (pks, _, tweaks, _, _) <- inputs
            q <- expectLib "KeyAgg" (tweakedKeyAgg pks tweaks)
            assertBool "verify_schnorr" (verify_schnorr (saMsg v) q expected)
        ]
    Left (InvalidContribution (Just signer) "psig") -> testCase (name <> " [library cannot report the signer index]") $ do
      (pks, _, tweaks, agg, psigs) <- inputs
      blamed <- expectRight "vector" (at "psig" psigs signer)
      assertBool "the blamed psig is out of range" (blamed >= curveOrder)
      expectLibError PartialSignatureOutOfRange (mkSessionContext agg pks tweaks (saMsg v) >>= aggPartials psigs)
    Left err -> testCase name (assertFailure ("no library check for " <> show err))
   where
    name = caseName section i (sacComment c)
    inputs = expectRight "vector" $ do
      pks <- select "pubkey" cpoint (saPubkeys v) (sacKeys c)
      nonces <- select "pnonce" pubNonceFromBytes (saPnonces v) (sacNonces c)
      tweaks <- mkTweaks (saTweaks v) (sacTweaks c) (sacXOnly c)
      agg <- note "aggnonce does not parse" (aggNonceFromBytes (sacAggnonce c))
      psigs <- traverse (fmap bytesToInteger . at "psig" (saPsigs v)) (sacPsigs c)
      pure (pks, nonces, tweaks, agg, psigs)
    aggregate = do
      (pks, _, tweaks, agg, psigs) <- inputs
      expectLib "PartialSigAgg" (mkSessionContext agg pks tweaks (saMsg v) >>= aggPartials psigs)

detSignTests :: DetSignVectors -> FileTests
detSignTests (DetSignVectors valid errs) =
  FileTests [] (zipWith (skip "valid") [0 ..] valid <> zipWith (skip "error") [0 ..] errs)
 where
  skip section i comment = testCase (caseName section i comment <> " [SKIPPED: DeterministicSign is not implemented]") (pure ())
