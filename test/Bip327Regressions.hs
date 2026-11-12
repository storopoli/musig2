{-# LANGUAGE OverloadedStrings #-}

{- | Regression tests for BIP-0327 conformance bugs fixed in 0.2.1.

Expected values come from the official BIP-0327 test vectors or, for cases the
official vectors do not cover, from the BIP-0327 reference implementation
(@reference.py@).
-}
module Bip327Regressions (testBip327Regressions) where

import Control.Monad (zipWithM)
import Crypto.Curve.Secp256k1 (Pub, derive_pub, parse_point, serialize_point, verify_schnorr, _CURVE_G, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2 (
  MuSig2Error (..),
  PubNonce (..),
  SecKey (..),
  SecNonce,
  Tweak (..),
  aggNonces,
  aggPartials,
  aggregatedPubkey,
  applyTweak,
  mkKeyAggContext,
  mkSessionContext,
  partialSigVerify,
  publicNonce,
  sign,
 )
import Crypto.Curve.Secp256k1.MuSig2.Internal (integerToBytes32)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Foldable (foldlM)
import Data.Maybe (fromMaybe)
import Test.Tasty
import Test.Tasty.HUnit
import Util (decodeHex, parsePoint, parsePubNonce, parseScalar, unsafeMkSecNonce, unsafeRight)

testBip327Regressions :: TestTree
testBip327Regressions =
  testGroup
    "BIP-0327 regressions"
    [ testGroup "Aggregate nonce with point at infinity" (map infinityCase infinityCases)
    , testCase "Signer pubkey not in list of pubkeys (sign_verify sign_error #0)" signerNotInList
    , testGroup "PartialSigAgg with gacc = n - 1" (zipWith gaccCase [0 :: Int ..] gaccCases)
    , testGroup "ApplyTweak with t = 0" [zeroTweak False, zeroTweak True]
    , testCase "NonceAgg rejects a public nonce containing infinity" nonceAggRejectsInfinity
    , testCase "PartialSigVerify of a zero partial signature returns False" zeroPartialSig
    ]

-- Material from sign_verify_vectors.json ------------------------------------

svSecKey :: SecKey
svSecKey = SecKey (parseScalar "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671")

svPubkeys :: [Pub]
svPubkeys =
  map
    parsePoint
    [ "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
    , "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    , "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661"
    ]

-- | Public key of 'svSecKey' (first entry of 'svPubkeys').
svSignerPubkey :: Pub
svSignerPubkey = parsePoint "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"

svPubNonces :: [PubNonce]
svPubNonces =
  map
    parsePubNonce
    [ "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
    , "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    , "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046"
    , "0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
    ]

svMsg :: ByteString
svMsg = decodeHex "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"

svSecNonce :: SecNonce
svSecNonce =
  unsafeMkSecNonce
    svSignerPubkey
    (parseScalar "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61")
    (parseScalar "FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F7")

-- | Parses a 33-byte @cbytes_ext@ encoding (33 zero bytes is infinity).
pointExt :: ByteString -> Pub
pointExt h
  | bytes == BS.replicate 33 0 = _CURVE_ZERO
  | otherwise = fromMaybe (error "invalid point") (parse_point bytes)
 where
  bytes = decodeHex h

-- | Parses a 66-byte aggregate nonce encoded with @cbytes_ext@.
aggNonceExt :: ByteString -> PubNonce
aggNonceExt h = PubNonce (pointExt (BS.take 66 h)) (pointExt (BS.drop 66 h))

toHex32 :: Integer -> ByteString
toHex32 = integerToBytes32

-- Aggregate nonce with infinity ---------------------------------------------

-- | (label, keys, aggnonce, expected partial signature, expected xbytes(R))
infinityCases :: [(String, [Pub], ByteString, ByteString, ByteString)]
infinityCases =
  [ -- official sign_verify valid #3

    ( "R1 = R2 = infinity (official sign_verify valid #3)"
    , take 2 svPubkeys
    , "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    , "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531"
    , "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    )
  , -- reference.py

    ( "R1 = infinity, R2 = 3G"
    , svPubkeys
    , "00000000000000000000000000000000000000000000000000000000000000000002F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    , "A8F919D3C4291F0123AE9BC98F3F5A10FC1E82A0B40C7ECFE7F23F508F57D39A"
    , "3B7B5C67354E218951C0FF603D18261632638E9DA40615E6EF75C18CB3B60647"
    )
  ,
    ( "R1 = R2 = infinity, three signers"
    , svPubkeys
    , "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    , "4D1114440EBE1574F3BB2BF36B0C5BE8647E23C9405FCFDE473D82D5B4733E6D"
    , "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    )
  ,
    ( "R1 = 5G, R2 = infinity"
    , svPubkeys
    , "022F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4000000000000000000000000000000000000000000000000000000000000000000"
    , "7DB23FECD568EE90D6ABCB7915E46BD544B1804C412EDB936B44D7F3DC16A922"
    , "2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4"
    )
  ]

infinityCase :: (String, [Pub], ByteString, ByteString, ByteString) -> TestTree
infinityCase (label, keys, aggHex, expectedPsig, expectedRx) = testCase label $ do
  let ctx = unsafeRight $ mkSessionContext (aggNonceExt aggHex) keys [] svMsg
      psig = unsafeRight $ sign svSecNonce svSecKey ctx
      sig = unsafeRight $ aggPartials [0 :: Integer] ctx
  toHex32 psig @?= decodeHex expectedPsig
  BS.take 32 sig @?= decodeHex expectedRx

-- Signer not in list ----------------------------------------------------------

signerNotInList :: Assertion
signerNotInList = do
  let aggNonce = aggNonceExt "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"
      ctx = unsafeRight $ mkSessionContext aggNonce (drop 1 svPubkeys) [] svMsg
  sign svSecNonce svSecKey ctx @?= Left SecretKeyPublicKeyMismatch

-- gacc = n - 1 ------------------------------------------------------------------

-- | (secret keys, secret nonces, tweaks, expected partial sigs, expected signature)
gaccCases :: [([Integer], [(Integer, Integer)], [Tweak], [ByteString], ByteString)]
gaccCases =
  [
    ( [0x1118, 0x222F]
    , [(0xAAAB, 0xBBBC), (0xCCCD, 0xDDDE)]
    , [XOnlyTweak 0x1234567890ABCDEF]
    , ["036D45ADBF14F99296EA524AB2B6DF08B9C74E172B463671BBDC6EEB64F35659", "B3576E442485F4457A7D14F11643322900CECEB3C2086160866D93E3B0592D80"]
    , "5D56B500773C4BDB1D12E588DE0CD2420BB5C4740B54C59443CC02D32C820A2ABAF22138DE1A3B920468B3325C0C298FEFCCA7C37123034353C4A308C1D9B880"
    )
  ,
    ( [0x1118, 0x222F]
    , [(0xAAAB, 0xBBBC), (0xCCCD, 0xDDDE)]
    , [PlainTweak 0x1111, XOnlyTweak 0x2222]
    , ["AD330CCA8F1404AD4EF335592C22C3CBAFCD426E9010E9C7D26DE4E3BBCD1D12", "43CA5A1DD8CE93809555521478E46FED6DD826D1F78A96173BE310F229C5E813"]
    , "9B545290252036652491EA299A0FF359B1C8AD200406AE590A6CECF645D48B9E0F74CA8D4B552D7FDF7D3A0F03EB712DFEA36AA9C711CA191DD6B54EB63E4441"
    )
  ]

gaccCase :: Int -> ([Integer], [(Integer, Integer)], [Tweak], [ByteString], ByteString) -> TestTree
gaccCase i (sks, ks, tweaks, expectedPsigs, expectedSig) = testCase ("case " <> show i) $ do
  let msg = decodeHex "599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869"
      pubs = map (fromMaybe (error "derive_pub") . derive_pub . fromInteger) sks
      secNonces = zipWith (\p (k1, k2) -> unsafeMkSecNonce p k1 k2) pubs ks
      aggNonce = unsafeRight $ traverse publicNonce secNonces >>= aggNonces
      ctx = unsafeRight $ mkSessionContext aggNonce pubs tweaks msg
      psigs = unsafeRight $ zipWithM (\sn d -> sign sn (SecKey d) ctx) secNonces sks
      sig = unsafeRight $ aggPartials psigs ctx
      keyCtx = unsafeRight $ mkKeyAggContext pubs Nothing >>= \c -> foldlM applyTweak c tweaks
  map toHex32 psigs @?= map decodeHex expectedPsigs
  sig @?= decodeHex expectedSig
  assertBool "aggregated signature verifies" (verify_schnorr msg (aggregatedPubkey keyCtx) sig)

-- t = 0 -----------------------------------------------------------------------

zeroTweak :: Bool -> TestTree
zeroTweak isXOnly = testCase (if isXOnly then "x-only" else "plain") $ do
  let tweak = if isXOnly then XOnlyTweak 0 else PlainTweak 0
      expected =
        if isXOnly
          then "0254240C76B8F2999143301A99C7F721EE57EEE0BCE401DF3AFEAA9AE218C70F23"
          else "0354240C76B8F2999143301A99C7F721EE57EEE0BCE401DF3AFEAA9AE218C70F23"
      ctx = unsafeRight $ mkKeyAggContext (take 2 svPubkeys) (Just tweak)
  serialize_point (aggregatedPubkey ctx) @?= decodeHex expected

-- NonceAgg / PartialSigVerify ---------------------------------------------------

nonceAggRejectsInfinity :: Assertion
nonceAggRejectsInfinity = do
  let good = parsePubNonce "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
  aggNonces [good, PubNonce _CURVE_ZERO (r2 good)] @?= Left InvalidPointFormat
  aggNonces [good, PubNonce (r1 good) _CURVE_ZERO] @?= Left InvalidPointFormat
  partialSigVerify 1 (PubNonce _CURVE_ZERO _CURVE_G : drop 1 (take 3 svPubNonces)) svPubkeys [] svMsg 0 @?= Left InvalidPointFormat

zeroPartialSig :: Assertion
zeroPartialSig = partialSigVerify 0 (take 3 svPubNonces) svPubkeys [] svMsg 0 @?= Right False
