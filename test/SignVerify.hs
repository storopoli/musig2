{-# LANGUAGE OverloadedStrings #-}

{- | Input validation in nonce generation, key aggregation and signing.

The BIP-327 @sign_verify_vectors.json@ cases run in "OfficialVectors".
-}
module SignVerify (testSignVerify) where

import Crypto.Curve.Secp256k1.MuSig2
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (secNonceFromScalars, secNoncePubNonce)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (curveOrder)
import qualified Data.ByteString as BS
import Data.ByteString.Internal (ByteString (BS))
import Data.List.NonEmpty (NonEmpty (..))
import Foreign.ForeignPtr (mallocForeignPtrBytes)
import Test.Tasty
import Test.Tasty.HUnit
import Util (secKeyFromInt, secNonceFromInts, unsafeRight)

testSignVerify :: TestTree
testSignVerify =
  testGroup
    "input validation"
    [ testCase "secret nonce scalars must be in [1, n)" $ do
        let pk = secKeyPubKey (secKeyFromInt 1)
            err k1 k2 = either Just (const Nothing) (secNonceFromScalars k1 k2 pk)
        err 0 1 @?= Just ScalarZero
        err 1 0 @?= Just ScalarZero
        err curveOrder 1 @?= Just ScalarOutOfRange
        err 1 (curveOrder - 1) @?= Nothing
    , testCase "sign rejects a nonce generated for another key" $ do
        let sk = secKeyFromInt 2
            other = secKeyPubKey (secKeyFromInt 3)
            sn = secNonceFromInts 5 7 other
            ctx = unsafeRight (keyAgg (secKeyPubKey sk :| [other]))
            session = newSession ctx (nonceAgg (pn 5 7 other :| [])) "msg"
        failure (sign sn sk session) @?= Just SecNonceKeyMismatch
    , testCase "sign rejects a signer outside the key list" $ do
        let sk = secKeyFromInt 2
            others = secKeyPubKey (secKeyFromInt 3) :| [secKeyPubKey (secKeyFromInt 4)]
            sn = secNonceFromInts 5 7 (secKeyPubKey sk)
            session = newSession (unsafeRight (keyAgg others)) (nonceAgg (pn 5 7 (secKeyPubKey sk) :| [])) "msg"
        failure (sign sn sk session) @?= Just SignerNotInSession
    , testCase "nonceGen rejects extra input longer than 2^32 - 1 bytes" $ do
        -- Only the length is read before the check fails, so a ByteString
        -- with a fake length over a 1-byte buffer is enough.
        fp <- mallocForeignPtrBytes 1
        let huge = BS fp (2 ^ (32 :: Int))
            pk = secKeyPubKey (secKeyFromInt 9)
        result <- nonceGen pk noNonceInputs{nonceExtraInput = Just huge}
        either Just (const Nothing) result @?= Just NonceExtraInputTooLong
        ok <- nonceGen pk noNonceInputs{nonceExtraInput = Just (BS.replicate 100 1)}
        either Just (const Nothing) ok @?= Nothing
    , testCase "applyTaprootTweak rejects a merkle root that is not 32 bytes" $ do
        let ctx = unsafeRight (keyAgg (secKeyPubKey (secKeyFromInt 9) :| []))
        failure (applyTaprootTweak (Just (BS.replicate 31 0)) ctx) @?= Just (InvalidMerkleRootLength 31)
    ]
 where
  failure :: Either e a -> Maybe e
  failure = either Just (const Nothing)
  pn k1 k2 pk = secNoncePubNonce (secNonceFromInts k1 k2 pk)
