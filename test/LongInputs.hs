{-# LANGUAGE OverloadedStrings #-}

{- | Tagged hashes of long inputs, which are hashed chunk by chunk instead of
being joined first ('streamThreshold').

The official vectors and the differential corpus use short messages, so
these tests cover the chunked path: the tagged hash against plain SHA-256 on
both sides of the threshold, NonceGen against the BIP-327 formula computed
here with one strict hash, and signing sessions whose final signature is
checked by @ppad-secp256k1@'s BIP-340 verification, which hashes the message
itself.
-}
module LongInputs (testLongInputs) where

import Crypto.Curve.Secp256k1.MuSig2
import Crypto.Curve.Secp256k1.MuSig2.Internal.Hash (streamThreshold, taggedHash)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (bytesToInteger, integerToBytes32, modQ)
import Crypto.Curve.Secp256k1.MuSig2.Unsafe (nonceGenWithRand, secNonceToBytes)
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty (..))
import Data.Word (Word8)
import Test.Tasty
import Test.Tasty.HUnit
import Util (secKeyFromInt, unsafeRight)

testLongInputs :: TestTree
testLongInputs =
  testGroup
    "long inputs"
    [ testCase "taggedHash matches SHA-256 of the concatenation around the threshold" $
        mapM_ checkTagged [0, 1, 63, 64, streamThreshold - 1, streamThreshold, streamThreshold + 1, 3 * streamThreshold + 17]
    , testCase "NonceGen with a long message and extra input matches the BIP-327 formula" $ do
        let sk = secKeyFromInt 0x1234
            pk = secKeyPubKey sk
            rand = BS.replicate 32 0x5a
            msg = filler 0x11 (2 * streamThreshold + 5)
            extra = filler 0x22 (streamThreshold + 3)
            inputs = noNonceInputs{nonceMessage = Just msg, nonceExtraInput = Just extra}
        (sn, _) <- unsafeRight <$> nonceGenWithRand rand pk inputs
        bytes <- maybe (assertFailure "fresh nonce already used") pure =<< secNonceToBytes sn
        let expected i =
              integerToBytes32 . modQ . bytesToInteger . strictTagged "MuSig/nonce" $
                BS.concat
                  [ rand
                  , BS.singleton 33
                  , encode pk
                  , BS.singleton 0
                  , BS.singleton 1
                  , bigEndian 8 (BS.length msg)
                  , msg
                  , bigEndian 4 (BS.length extra)
                  , extra
                  , BS.singleton i
                  ]
        BS.take 64 bytes @?= expected 0 <> expected 1
    , testCase "a session with a long message signs and verifies" $ do
        let msg = filler 0x33 (3 * streamThreshold + 1)
            sks = secKeyFromInt 7 :| [secKeyFromInt 8]
            ctx = unsafeRight (keyAgg (fmap secKeyPubKey sks))
            nonceFor sk = unsafeRight <$> nonceGen (secKeyPubKey sk) noNonceInputs{nonceMessage = Just msg, nonceExtraInput = Just msg}
        nonces <- traverse nonceFor sks
        let session = newSession ctx (nonceAgg (fmap snd nonces)) msg
        psigs <- traverse (\(sk, (sn, _)) -> unsafeRight <$> sign sn sk session) (zipNE sks nonces)
        assertBool "partial signatures verify" $
          and (zipWith3 (partialSigVerify session) (toListNE (fmap secKeyPubKey sks)) (toListNE (fmap snd nonces)) (toListNE psigs))
        assertBool "final signature verifies" $
          verify (aggXOnlyPubKey ctx) msg (partialSigAgg session psigs)
    , testCase "deterministicSign with a long message verifies" $ do
        let msg = filler 0x44 (streamThreshold + 9)
            sk1 = secKeyFromInt 11
            sk2 = secKeyFromInt 12
            ctx = unsafeRight (keyAgg (secKeyPubKey sk1 :| [secKeyPubKey sk2]))
        (sn1, pn1) <- unsafeRight <$> nonceGen (secKeyPubKey sk1) noNonceInputs
        let (pn2, psig2) = unsafeRight (deterministicSign sk2 (nonceAgg (pn1 :| [])) ctx msg Nothing)
            session = newSession ctx (nonceAgg (pn1 :| [pn2])) msg
        psig1 <- unsafeRight <$> sign sn1 sk1 session
        assertBool "deterministic partial signature verifies" (partialSigVerify session (secKeyPubKey sk2) pn2 psig2)
        assertBool "final signature verifies" $
          verify (aggXOnlyPubKey ctx) msg (partialSigAgg session (psig1 :| [psig2]))
    ]
 where
  zipNE (a :| as) (b :| bs) = (a, b) :| zip as bs
  toListNE (a :| as) = a : as

-- | Checks 'taggedHash' on @n@ bytes split into uneven chunks, empty ones included.
checkTagged :: Int -> Assertion
checkTagged n = taggedHash tag (chunksOf' input) @?= strictTagged tag input
 where
  tag = "test/long"
  input = filler 0x77 n
  chunksOf' bs = BS.empty : go 1 bs
  go k bs
    | BS.null bs = [BS.empty]
    | otherwise = let (a, rest) = BS.splitAt (k * 1000 + 7) bs in a : go (k + 1) rest

-- | The BIP-340 tagged hash computed with one strict SHA-256 call.
strictTagged :: BS.ByteString -> BS.ByteString -> BS.ByteString
strictTagged tag x = SHA256.hash (th <> th <> x)
 where
  th = SHA256.hash tag

-- | @n@ bytes counting up from @start@.
filler :: Word8 -> Int -> BS.ByteString
filler start n = fst (BS.unfoldrN n (\w -> Just (w, w + 1)) start)

-- | @n@-byte big-endian encoding.
bigEndian :: Int -> Int -> BS.ByteString
bigEndian n x = BS.pack [fromIntegral (x `div` (256 ^ i)) | i <- [n - 1, n - 2 .. 0]]
