{- | QuickCheck generators.

Plain 'Gen' values used with @forAll@/@forAllShow@, so the test suite defines
no orphan 'Arbitrary' instances for library types. Secrets have no 'Show'
instance; properties show them through 'secKeyToBytes'.

Scalars are drawn from the full range \([0, n)\) (not QuickCheck's small
integers), with extra weight on the edge cases \(0\), \(1\) and \(n - 1\).
-}
module Generators (
  genScalar,
  genNonZeroScalar,
  genSecKey,
  genPubKey,
  genTweak,
  TweakOp (..),
  genTweakOp,
  applyTweakOp,
  genBytes,
  genMessage,
  genRand,
  genPubNonce,
  genAggNonce,
  genPartialSignature,
  showSecKey,
) where

import Crypto.Curve.Secp256k1 (Projective, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2 (
  AggNonce,
  KeyAggContext,
  KeyAggError,
  PartialSignature,
  PubKey,
  PubNonce,
  SecKey,
  Tweak,
  applyPlainTweak,
  applyTaprootTweak,
  applyXOnlyTweak,
  secKeyPubKey,
  secKeyToBytes,
 )
import Crypto.Curve.Secp256k1.MuSig2.Internal.Point (mulGPublic)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (curveOrder)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Types (mkAggNonce, mkPubNonce)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Test.Tasty.QuickCheck (Gen, arbitrary, choose, frequency, oneof, vectorOf)
import Util (hexOf, psigFromInt, secKeyFromInt, tweakFromInt)

-- | A scalar in \([0, n)\), uniform with extra weight on the edges.
genScalar :: Gen Integer
genScalar = frequency [(1, pure 0), (1, pure 1), (1, pure (curveOrder - 1)), (7, choose (0, curveOrder - 1))]

-- | A scalar in \([1, n)\).
genNonZeroScalar :: Gen Integer
genNonZeroScalar = frequency [(1, pure 1), (1, pure (curveOrder - 1)), (8, choose (1, curveOrder - 1))]

genSecKey :: Gen SecKey
genSecKey = secKeyFromInt <$> genNonZeroScalar

genPubKey :: Gen PubKey
genPubKey = secKeyPubKey <$> genSecKey

genTweak :: Gen Tweak
genTweak = tweakFromInt <$> genScalar

-- | A tweak to apply to a key aggregation context.
data TweakOp
  = Plain Tweak
  | XOnly Tweak
  | -- | BIP-341 Taproot tweak with an optional 32-byte merkle root.
    Taproot (Maybe ByteString)
  deriving (Show)

genTweakOp :: Gen TweakOp
genTweakOp = oneof [Plain <$> genTweak, XOnly <$> genTweak, Taproot <$> oneof [pure Nothing, Just <$> genBytes 32]]

applyTweakOp :: KeyAggContext -> TweakOp -> Either KeyAggError KeyAggContext
applyTweakOp ctx op = case op of
  Plain t -> applyPlainTweak t ctx
  XOnly t -> applyXOnlyTweak t ctx
  Taproot root -> applyTaprootTweak root ctx

genBytes :: Int -> Gen ByteString
genBytes n = BS.pack <$> vectorOf n arbitrary

-- | Messages: empty, 32 bytes (the usual sighash), or any length up to 100.
genMessage :: Gen ByteString
genMessage = oneof [pure BS.empty, genBytes 32, choose (0, 100) >>= genBytes]

-- | 32 random bytes.
genRand :: Gen ByteString
genRand = genBytes 32

pointOf :: Integer -> Gen Projective
pointOf k = pure (mulGPublic k)

genPubNonce :: Gen PubNonce
genPubNonce = mkPubNonce <$> (genNonZeroScalar >>= pointOf) <*> (genNonZeroScalar >>= pointOf)

-- | An aggregate nonce; either half may be infinity.
genAggNonce :: Gen AggNonce
genAggNonce = mkAggNonce <$> half <*> half
 where
  half = frequency [(1, pure _CURVE_ZERO), (4, genNonZeroScalar >>= pointOf)]

genPartialSignature :: Gen PartialSignature
genPartialSignature = psigFromInt <$> genScalar

-- | Shows a secret key's bytes, for counterexamples.
showSecKey :: SecKey -> String
showSecKey = hexOf . secKeyToBytes
