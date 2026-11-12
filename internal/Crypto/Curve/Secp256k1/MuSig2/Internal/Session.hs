{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Session
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

BIP-327 signing sessions: @GetSessionValues@, @Sign@, @PartialSigVerify@ and
@PartialSigAgg@, plus BIP-340 verification of the final signature.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Session (
  Session (..),
  newSession,
  sessionKeyAgg,
  sign,
  partialSigVerify,
  partialSigVerifyWith,
  partialSigAgg,
  verify,
) where

import Control.DeepSeq (NFData (..))
import Crypto.Curve.Secp256k1 (add, neg, serialize_point, verify_schnorr', _CURVE_G)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Error (SignError (..))
import Crypto.Curve.Secp256k1.MuSig2.Internal.Hash (hashChallenge, hashNonceCoef)
import Crypto.Curve.Secp256k1.MuSig2.Internal.KeyAgg (KeyAggContext (..), keyAggCoefficient)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (SecNonce, secNoncePubKey, secNoncePubNonce, secNonceScalars)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Point (gContext, hasEvenYBytes, isInfinity, mulGPublic, mulPublic)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Scalar (curveOrder, hashToScalar, integerToBytes32, modQ, signScalar)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Types (
  AggNonce (..),
  PartialSignature (..),
  PubKey (..),
  PubNonce (..),
  SecKey (..),
  Signature (..),
  XOnlyPubKey (..),
  pubKeyHasEvenY,
 )
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty)

{- | A signing session: a key aggregation context, an aggregate nonce and a
message, with the BIP-327 session values computed once.
-}
data Session = Session
  { sesKeyAgg :: !KeyAggContext
  -- ^ Key aggregation context (with tweaks).
  , sesAggNonce :: !AggNonce
  -- ^ Aggregate nonce.
  , sesMessage :: !ByteString
  -- ^ Message.
  , sesB :: !Integer
  -- ^ Nonce coefficient \(b\).
  , sesRx :: !ByteString
  -- ^ \(xbytes(R)\) of the final nonce \(R\).
  , sesREven :: !Bool
  -- ^ \(R\) has even \(y\).
  , sesE :: !Integer
  -- ^ Challenge \(e\).
  , sesQEven :: !Bool
  -- ^ \(Q\) has even \(y\) (\(g = 1\)).
  }

instance NFData Session where
  rnf (Session k a m b rx re e qe) = rnf k `seq` rnf a `seq` rnf m `seq` rnf b `seq` rnf rx `seq` rnf re `seq` rnf e `seq` rnf qe

{- | Starts a signing session (BIP-327 @GetSessionValues@): computes \(b\),
\(R = R_1 + b \cdot R_2\) (or \(G\) if that is infinity) and \(e\).
-}
newSession :: KeyAggContext -> AggNonce -> ByteString -> Session
newSession ctx aggNonce msg =
  Session
    { sesKeyAgg = ctx
    , sesAggNonce = aggNonce
    , sesMessage = msg
    , sesB = b
    , sesRx = BS.drop 1 rBytes
    , sesREven = hasEvenYBytes rBytes
    , sesE = hashToScalar (hashChallenge (BS.drop 1 rBytes <> qx <> msg))
    , sesQEven = pubKeyHasEvenY q
    }
 where
  q = kacQ ctx
  qx = BS.drop 1 (pubKeyBytes q)
  b = hashToScalar (hashNonceCoef (aggNonceBytes aggNonce <> qx <> msg))
  r' = add (aggNonceR1 aggNonce) (mulPublic (aggNonceR2 aggNonce) b)
  r = if isInfinity r' then _CURVE_G else r'
  rBytes = serialize_point r

-- | The key aggregation context of a session.
sessionKeyAgg :: Session -> KeyAggContext
sessionKeyAgg = sesKeyAgg

-- | \(g \cdot gacc = -1\): the secret key (and the signer's key in verification) is negated.
negatesKey :: Session -> Bool
negatesKey ses = not (sesQEven ses) /= kacGaccNeg (sesKeyAgg ses)

{- | BIP-327 @Sign@, followed by @PartialSigVerifyInternal@ on the result as
the BIP recommends.
-}
sign :: SecNonce -> SecKey -> Session -> Either SignError PartialSignature
sign sn sk ses
  | secNoncePubKey sn /= pk = Left SecNonceKeyMismatch
  | otherwise = case keyAggCoefficient (sesKeyAgg ses) pk of
      Nothing -> Left SignerNotInSession
      Just a ->
        let (k1, k2) = secNonceScalars sn
            s = signScalar k1 k2 (secKeyScalar sk) (not (sesREven ses)) (negatesKey ses) (sesB ses) (modQ (sesE ses * a))
            psig = PartialSignature s
         in if partialSigVerifyWith ses a pk (secNoncePubNonce sn) psig
              then Right psig
              else Left SelfVerificationFailed
 where
  pk = secKeyPub sk

{- | BIP-327 @PartialSigVerify@ for one signer of the session: 'False' if the
public key is not one of the session's keys.

Takes no hashing: the session caches \(b\), \(e\) and the coefficients.
-}
partialSigVerify :: Session -> PubKey -> PubNonce -> PartialSignature -> Bool
partialSigVerify ses pk pn psig = case keyAggCoefficient (sesKeyAgg ses) pk of
  Nothing -> False
  Just a -> partialSigVerifyWith ses a pk pn psig

{- | @PartialSigVerifyInternal@ with the signer's key aggregation coefficient:
\(s \cdot G = R_e + e \cdot a \cdot g' \cdot P\).
-}
partialSigVerifyWith :: Session -> Integer -> PubKey -> PubNonce -> PartialSignature -> Bool
partialSigVerifyWith ses a pk pn (PartialSignature s) = mulGPublic s == add re (mulPublic (pubKeyPt pk) factor)
 where
  re' = add (pubNonceR1 pn) (mulPublic (pubNonceR2 pn) (sesB ses))
  re = if sesREven ses then re' else neg re'
  ea = modQ (sesE ses * a)
  factor = if negatesKey ses then modQ (curveOrder - ea) else ea

{- | BIP-327 @PartialSigAgg@: \(s = \sum s_i + e \cdot g \cdot tacc\) with
\(g\) from the parity of \(Q\).

Does not check the partial signatures: verify each one with
'partialSigVerify' first, or the result may not be a valid signature.
-}
partialSigAgg :: Session -> NonEmpty PartialSignature -> Signature
partialSigAgg ses psigs = Signature (sesRx ses <> integerToBytes32 s)
 where
  total = foldl' (\acc (PartialSignature si) -> modQ (acc + si)) 0 psigs
  g = if sesQEven ses then 1 else curveOrder - 1
  s = modQ (total + sesE ses * g * kacTacc (sesKeyAgg ses))

-- | BIP-340 verification of a Schnorr signature.
verify :: XOnlyPubKey -> ByteString -> Signature -> Bool
verify pk msg (Signature sig) = verify_schnorr' gContext msg (xOnlyPoint pk) sig
