{-# LANGUAGE OverloadedStrings #-}

{- | The usage examples of the README and of the "Crypto.Curve.Secp256k1.MuSig2"
documentation, compiled and run by the test suite. Keep the three copies in
sync.
-}
module Example (testExample, example, taprootExample, coordinatorExample) where

import Control.Exception (Exception, throwIO)
import Control.Monad (foldM)
import qualified Crypto.Curve.Secp256k1.MuSig2 as MuSig2
import qualified Crypto.Curve.Secp256k1.MuSig2.Coordinator as Coordinator
import Data.Bifunctor (first)
import qualified Data.ByteString as BS
import Data.List (isInfixOf)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NE
import Test.Tasty
import Test.Tasty.HUnit

testExample :: TestTree
testExample =
  testGroup
    "documentation examples"
    [ testCase "2-of-2 signing" (example >>= assertBool "signature verifies")
    , testCase "Taproot key-path spend" (taprootExample >>= assertBool "signature verifies")
    , testCase "coordinator" (coordinatorExample >>= assertBool "signature verifies")
    , testCase "the README and the module documentation show this code verbatim" docsInSync
    ]

{- | The code between the markers below must appear verbatim in README.md and,
behind Haddock bird tracks, in the module header of
"Crypto.Curve.Secp256k1.MuSig2" (the first two examples) or
"Crypto.Curve.Secp256k1.MuSig2.Coordinator" (the coordinator example).
-}
docsInSync :: Assertion
docsInSync = do
  source <- readFile "test/Example.hs"
  readme <- readFile "README.md"
  let trim = dropWhile null . reverse . dropWhile null . reverse
      region from to = trim (takeWhile (/= to) (drop 1 (dropWhile (/= from) (lines source))))
      bird l = if null l then ">" else "> " <> l
      inHeader file b = do
        header <- readFile file
        assertBool (file <> " contains the example") (unlines (map bird b) `isInfixOf` header)
      blocks =
        [ (region "-- example start" "-- taproot start", "lib/Crypto/Curve/Secp256k1/MuSig2.hs")
        , (region "-- taproot start" "-- coordinator start", "lib/Crypto/Curve/Secp256k1/MuSig2.hs")
        , (region "-- coordinator start" "-- example end", "lib/Crypto/Curve/Secp256k1/MuSig2/Coordinator.hs")
        ]
  mapM_ (\(b, _) -> assertBool "README.md contains the example" (unlines b `isInfixOf` readme)) blocks
  mapM_ (\(b, file) -> inHeader file b) blocks

-- example start

-- | Throws the error of a 'Left'.
orThrow :: (Exception e) => Either e a -> IO a
orThrow = either throwIO pure

-- | Two signers sign a message; returns whether the signature verifies.
example :: IO Bool
example = do
  -- Each signer has a secret key and publishes its public key.
  -- (Fixed keys for the example only: never hard-code real keys.)
  sk1 <- orThrow (MuSig2.secKeyFromBytes (BS.replicate 32 0x11))
  sk2 <- orThrow (MuSig2.secKeyFromBytes (BS.replicate 32 0x22))
  let pk1 = MuSig2.secKeyPubKey sk1
      pk2 = MuSig2.secKeyPubKey sk2

  -- Everyone aggregates the same list of public keys, here sorted.
  keyAggCtx <- orThrow (MuSig2.keyAgg (MuSig2.keySort (pk1 :| [pk2])))
  let aggKey = MuSig2.aggXOnlyPubKey keyAggCtx
      msg = "i approve of this message"

  -- Each signer generates a fresh nonce and publishes the public part.
  (secNonce1, pubNonce1) <- MuSig2.nonceGen pk1 MuSig2.noNonceInputs >>= orThrow
  (secNonce2, pubNonce2) <- MuSig2.nonceGen pk2 MuSig2.noNonceInputs >>= orThrow

  -- Values travel as bytes; decoding validates them.
  received <- orThrow (MuSig2.decode (MuSig2.encode pubNonce2))

  -- Everyone aggregates the public nonces and opens the same session.
  let session = MuSig2.newSession keyAggCtx (MuSig2.nonceAgg (pubNonce1 :| [received])) msg

  -- Each signer signs once with its nonce and publishes its partial signature.
  -- 'sign' consumes the secret nonce: signing again with it fails.
  psig1 <- MuSig2.sign secNonce1 sk1 session >>= orThrow
  psig2 <- MuSig2.sign secNonce2 sk2 session >>= orThrow

  -- The aggregator checks each partial signature, then aggregates them.
  let valid =
        MuSig2.partialSigVerify session pk1 pubNonce1 psig1
          && MuSig2.partialSigVerify session pk2 pubNonce2 psig2
      signature = MuSig2.partialSigAgg session (psig1 :| [psig2])

  -- The result is an ordinary BIP-340 signature for the aggregate key.
  pure (valid && MuSig2.verify aggKey msg signature)

-- taproot start

-- | Three signers spend a Taproot output by key path.
taprootExample :: IO Bool
taprootExample = do
  sks <- traverse (orThrow . MuSig2.secKeyFromBytes . BS.replicate 32) (0x33 :| [0x44, 0x55])
  let pks = fmap MuSig2.secKeyPubKey sks

  -- The internal key is the aggregate key; the output key commits to the
  -- script tree's merkle root ('Nothing' for a key-path-only output, BIP-86).
  internal <- orThrow (MuSig2.keyAgg (MuSig2.keySort pks))
  output <- orThrow (MuSig2.applyTaprootTweak (Just (BS.replicate 32 0xAB)) internal)
  let outputKey = MuSig2.aggXOnlyPubKey output
      sighash = BS.replicate 32 0x01

  -- Binding the nonces to the key and message adds protection against bad randomness.
  let inputs sk =
        MuSig2.noNonceInputs
          { MuSig2.nonceSecKey = Just sk
          , MuSig2.nonceAggPubKey = Just outputKey
          , MuSig2.nonceMessage = Just sighash
          }
  nonces <- traverse (\sk -> MuSig2.nonceGen (MuSig2.secKeyPubKey sk) (inputs sk) >>= orThrow) sks

  -- Sessions are opened on the tweaked context: the tweak lives in the context only.
  let session = MuSig2.newSession output (MuSig2.nonceAgg (fmap snd nonces)) sighash
  psigs <- traverse (\(sk, (secNonce, _)) -> MuSig2.sign secNonce sk session >>= orThrow) (NE.zip sks nonces)
  let signature = MuSig2.partialSigAgg session psigs
  pure (MuSig2.verify outputKey sighash signature)

-- coordinator start

-- | A coordinator collects three signers' nonces and partial signatures as bytes.
coordinatorExample :: IO Bool
coordinatorExample = do
  sks <- traverse (orThrow . MuSig2.secKeyFromBytes . BS.replicate 32) (0x66 :| [0x77, 0x88])
  -- Signer i is the one with the i-th public key of the context.
  keyAggCtx <- orThrow (MuSig2.keyAgg (fmap MuSig2.secKeyPubKey sks))
  let msg = "pay Carol 1 BTC"

  -- Round one: each signer sends its encoded public nonce, in any order.
  nonces <- traverse (\sk -> MuSig2.nonceGen (MuSig2.secKeyPubKey sk) MuSig2.noNonceInputs >>= orThrow) (NE.toList sks)
  nonceRound <-
    orThrow $
      foldM
        (\r (i, (_, pubNonce)) -> Coordinator.receivePubNonce i (MuSig2.encode pubNonce) r)
        (Coordinator.newNonceRound keyAggCtx)
        (zip [0 ..] nonces)
  -- Fails if a nonce is missing (here reporting only the first such signer).
  collected <- orThrow (first NE.head (Coordinator.finishNonceRound nonceRound))

  -- The coordinator sends the aggregate nonce to every signer, who decodes it
  -- and opens the session.
  aggNonce <- orThrow (MuSig2.decode (MuSig2.encode (Coordinator.collectedAggNonce collected)))
  let session = MuSig2.newSession keyAggCtx aggNonce msg

  -- Round two: each signer sends its encoded partial signature. The
  -- coordinator verifies each one and blames the signer of an invalid one.
  psigs <- traverse (\(sk, (secNonce, _)) -> MuSig2.sign secNonce sk session >>= orThrow) (zip (NE.toList sks) nonces)
  sigRound <-
    orThrow $
      foldM
        (\r (i, psig) -> Coordinator.receivePartialSig i (MuSig2.encode psig) r)
        (Coordinator.newSigRound collected msg)
        (zip [0 ..] psigs)
  -- Aggregates the partial signatures and verifies the result.
  signature <- orThrow (Coordinator.finishSigRound sigRound)
  pure (MuSig2.verify (MuSig2.aggXOnlyPubKey keyAggCtx) msg signature)

-- example end
