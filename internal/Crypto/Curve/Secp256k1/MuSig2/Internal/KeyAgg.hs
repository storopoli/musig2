{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.KeyAgg
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

BIP-327 @KeySort@, @KeyAgg@ and @ApplyTweak@, plus the BIP-341 Taproot tweak.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.KeyAgg (
  KeyAggContext (..),
  keySort,
  keyAgg,
  applyPlainTweak,
  applyXOnlyTweak,
  applyTaprootTweak,
  aggPubKey,
  aggXOnlyPubKey,
  keyAggPubKeys,
  signerIndex,
  keyAggCoefficient,
) where

import Control.DeepSeq (NFData (..), force)
import Crypto.Curve.Secp256k1 (add, neg)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Error (KeyAggError (..))
import Crypto.Curve.Secp256k1.MuSig2.Internal.Hash (hashKeyAggCoef, hashKeyAggList, hashTapTweak)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Point (isInfinity, mulGPublic, mulPublic, sumPoints)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (bytesToInteger, curveOrder, hashToScalar, modQ)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Types (PubKey (..), Tweak (..), XOnlyPubKey (..), mkPubKey, pubKeyHasEvenY, pubKeyXOnly)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Foldable (toList)
import Data.List (find)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq

{- | The result of key aggregation, plus any tweaks applied since.

Holds the signers' keys in order, each signer's key aggregation coefficient,
the (possibly tweaked) aggregate key \(Q\), and the tweak accumulators
\(gacc\) and \(tacc\) of BIP-327.
-}
data KeyAggContext = KeyAggContext
  { kacPubKeys :: !(NonEmpty PubKey)
  -- ^ Signers' keys, in order.
  , kacCoefs :: !(Seq Integer)
  -- ^ Key aggregation coefficient \(a_i\) of signer \(i\).
  , kacIndex :: !(Map ByteString Int)
  -- ^ Encoded key to the first index it appears at.
  , kacQ :: !PubKey
  -- ^ Aggregate key \(Q\) after the tweaks so far.
  , kacGaccNeg :: !Bool
  -- ^ \(gacc = n - 1\) (otherwise \(1\)).
  , kacTacc :: !Integer
  -- ^ \(tacc\).
  }

instance NFData KeyAggContext where
  rnf (KeyAggContext pks coefs idx q g t) = rnf pks `seq` rnf coefs `seq` rnf idx `seq` rnf q `seq` rnf g `seq` rnf t

-- | BIP-327 @KeySort@: sorts keys by their 33-byte encoding.
keySort :: NonEmpty PubKey -> NonEmpty PubKey
keySort = NE.sort

{- | BIP-327 @KeyAgg@, in \(O(n)\): the key list is hashed once, the second
distinct key is found once, each coefficient takes one hash, and keys with
coefficient \(1\) are added without a multiplication.
-}
keyAgg :: NonEmpty PubKey -> Either KeyAggError KeyAggContext
keyAgg pks
  | toInteger (length pks) > 0xFFFFFFFF = Left TooManyPublicKeys
  | isInfinity q = Left AggPubKeyAtInfinity
  | otherwise =
      Right
        KeyAggContext
          { kacPubKeys = pks
          , kacCoefs = Seq.fromList (force coefs)
          , kacIndex = Map.fromListWith min (zip encs [0 ..])
          , kacQ = mkPubKey q
          , kacGaccNeg = False
          , kacTacc = 0
          }
 where
  encs = map pubKeyBytes (toList pks)
  l = hashKeyAggList (BS.concat encs)
  pk2 = find (/= NE.head (fmap pubKeyBytes pks)) encs
  coef enc
    | Just enc == pk2 = 1
    | otherwise = hashToScalar (hashKeyAggCoef (l <> enc))
  coefs = map coef encs
  q = sumPoints (zipWith term coefs (toList pks))
  term a pk
    | a == 1 = pubKeyPt pk
    | otherwise = mulPublic (pubKeyPt pk) a

-- | Adds \(t \cdot G\) to \(Q'\) and updates the accumulators.
tweakWith :: Bool -> Tweak -> KeyAggContext -> Either KeyAggError KeyAggContext
tweakWith negateQ (Tweak t) ctx
  | isInfinity q' = Left TweakResultAtInfinity
  | otherwise =
      Right
        ctx
          { kacQ = mkPubKey q'
          , kacGaccNeg = kacGaccNeg ctx /= negateQ
          , kacTacc = modQ (t + (if negateQ then curveOrder - kacTacc ctx else kacTacc ctx))
          }
 where
  q = pubKeyPt (kacQ ctx)
  q' = add (if negateQ then neg q else q) (mulGPublic t)

{- | BIP-327 @ApplyTweak@ with a plain tweak: \(Q' = Q + t \cdot G\). Use it
for BIP-32 derivation from the aggregate key.
-}
applyPlainTweak :: Tweak -> KeyAggContext -> Either KeyAggError KeyAggContext
applyPlainTweak = tweakWith False

{- | BIP-327 @ApplyTweak@ with an x-only tweak: \(Q' = g \cdot Q + t \cdot G\)
where \(g = -1\) if \(Q\) has odd \(y\).
-}
applyXOnlyTweak :: Tweak -> KeyAggContext -> Either KeyAggError KeyAggContext
applyXOnlyTweak tw ctx = tweakWith (not (pubKeyHasEvenY (kacQ ctx))) tw ctx

{- | The BIP-341 Taproot tweak: an x-only tweak by
\(t = hash_{TapTweak}(xbytes(Q) \| merkle\_root)\) (no merkle root for 'Nothing').
-}
applyTaprootTweak :: Maybe ByteString -> KeyAggContext -> Either KeyAggError KeyAggContext
applyTaprootTweak root ctx = case root of
  Just r | BS.length r /= 32 -> Left (InvalidMerkleRootLength (BS.length r))
  _
    | t >= curveOrder -> Left TaprootTweakOutOfRange
    | otherwise -> applyXOnlyTweak (Tweak t) ctx
 where
  t = bytesToInteger (hashTapTweak (xOnlyBytes (aggXOnlyPubKey ctx) <> fromMaybe BS.empty root))

-- | The aggregate key \(Q\), including the tweaks applied so far.
aggPubKey :: KeyAggContext -> PubKey
aggPubKey = kacQ

-- | The x-only aggregate key: the key the final signature verifies against.
aggXOnlyPubKey :: KeyAggContext -> XOnlyPubKey
aggXOnlyPubKey = pubKeyXOnly . kacQ

-- | The signers' public keys, in the order they were aggregated.
keyAggPubKeys :: KeyAggContext -> NonEmpty PubKey
keyAggPubKeys = kacPubKeys

-- | The index of a public key among the signers (its first position if it appears more than once).
signerIndex :: KeyAggContext -> PubKey -> Maybe Int
signerIndex ctx pk = Map.lookup (pubKeyBytes pk) (kacIndex ctx)

-- | The key aggregation coefficient of a signer's public key.
keyAggCoefficient :: KeyAggContext -> PubKey -> Maybe Integer
keyAggCoefficient ctx pk = signerIndex ctx pk >>= (`Seq.lookup` kacCoefs ctx)
