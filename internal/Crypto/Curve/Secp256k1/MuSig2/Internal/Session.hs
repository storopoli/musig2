{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Session
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

BIP-327 signing sessions: @GetSessionValues@, @Sign@, @DeterministicSign@,
@PartialSigVerify@ and @PartialSigAgg@, plus BIP-340 verification of the
final signature.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Session (
  Session (..),
  newSession,
  sessionKeyAgg,
  sign,
  signWithoutVerification,
  deterministicSign,
  partialSigVerify,
  partialSigVerifyWith,
  partialSigAgg,
  verify,
) where

import Control.DeepSeq (NFData (..), ($!!))
import Control.Monad (when)
import Crypto.Curve.Secp256k1 (add, neg, serialize_point, verify_schnorr', _CURVE_G)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Error (SignError (..))
import Crypto.Curve.Secp256k1.MuSig2.Internal.Hash (hashChallenge, hashNonceCoef)
import Crypto.Curve.Secp256k1.MuSig2.Internal.KeyAgg (KeyAggContext (..), aggXOnlyPubKey, keyAggCoefficient)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (
  SecNonce,
  claimSecNonce,
  deterministicNonceScalars,
  pubNonceFromScalars,
  secNonceAggPubKey,
  secNonceMessage,
  secNoncePubKey,
  secNoncePubNonce,
 )
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
  mkAggNonce,
  pubKeyHasEvenY,
 )
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Foldable (for_)
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

Consumes the secret nonce first, as BIP-327 and libsecp256k1 do: the nonce
is atomically marked used and its buffer zero-filled before any check, so
every call after the first, through any copy of the t'SecNonce' and from any
thread, returns 'SecNonceAlreadyUsed', and a failed call uses the nonce up
too. Then, in order: 'SecNonceKeyMismatch', 'SecNonceSessionMismatch' (if
the nonce was generated with an aggregate key or a message, they must be the
session's), 'SignerNotInSession', and 'SelfVerificationFailed'.
-}
sign :: SecNonce -> SecKey -> Session -> IO (Either SignError PartialSignature)
sign = signNonce True

{- | 'sign' without the verification of the result: a fault during signing
(e.g. a bit flip) may then go unnoticed, and a faulty partial signature can
leak the secret key.
-}
signWithoutVerification :: SecNonce -> SecKey -> Session -> IO (Either SignError PartialSignature)
signWithoutVerification = signNonce False

-- | Consumes the nonce, checks its binding and signs.
signNonce :: Bool -> SecNonce -> SecKey -> Session -> IO (Either SignError PartialSignature)
signNonce verifyResult sn sk ses = do
  claimed <- claimSecNonce sn
  pure $!! case claimed of
    Nothing -> Left SecNonceAlreadyUsed
    Just (k1, k2) -> do
      when (secNoncePubKey sn /= secKeyPub sk) (Left SecNonceKeyMismatch)
      when (any (/= aggXOnlyPubKey (sesKeyAgg ses)) (secNonceAggPubKey sn) || any (/= sesMessage ses) (secNonceMessage sn)) $
        Left SecNonceSessionMismatch
      signScalars verifyResult k1 k2 (secNoncePubNonce sn) sk ses

{- | BIP-327 @Sign@ with the nonce scalars \(k_1, k_2\) (in \([1, n)\)) and
the matching public nonce, for a nonce bound to the secret key's public key.
-}
signScalars :: Bool -> Integer -> Integer -> PubNonce -> SecKey -> Session -> Either SignError PartialSignature
signScalars verifyResult k1 k2 pn sk ses = case keyAggCoefficient (sesKeyAgg ses) pk of
  Nothing -> Left SignerNotInSession
  Just a
    | not verifyResult || partialSigVerifyWith ses a pk pn psig -> Right psig
    | otherwise -> Left SelfVerificationFailed
   where
    s = signScalar k1 k2 (secKeyScalar sk) (not (sesREven ses)) (negatesKey ses) (sesB ses) (modQ (sesE ses * a))
    psig = PartialSignature s
 where
  pk = secKeyPub sk

{- | BIP-327 @DeterministicSign@: signing without a random nonce, for the
signer who contributes its nonce last.

Derives the nonce from the secret key, the other signers' aggregate nonce
@aggothernonce@ (the 'Crypto.Curve.Secp256k1.MuSig2.nonceAgg' of all other
signers' public nonces), the (tweaked) aggregate key of the context and the
message, and optionally 32 bytes of auxiliary randomness. Returns this
signer's public nonce, to send with the partial signature, and the partial
signature for the session whose aggregate nonce combines the two.

Safe without randomness only if every other signer's public nonce is fixed
before this one is revealed: call it only after receiving all other public
nonces, never before. The secret nonce never leaves this function, and the
same inputs always give the same output.

Fails with 'InvalidAuxRandLength', 'DeterministicNonceIsZero' (negligible
probability), 'AggOtherNonceAtInfinity', 'SignerNotInSession' or
'SelfVerificationFailed'.
-}
deterministicSign ::
  -- | The signer's secret key.
  SecKey ->
  -- | @aggothernonce@: the aggregate of the other signers' public nonces.
  AggNonce ->
  -- | The key aggregation context, with all tweaks applied.
  KeyAggContext ->
  -- | The message.
  ByteString ->
  -- | Optional auxiliary randomness: 32 bytes.
  Maybe ByteString ->
  Either SignError (PubNonce, PartialSignature)
deterministicSign sk aggOther ctx msg rand = do
  for_ rand $ \r -> when (BS.length r /= 32) (Left (InvalidAuxRandLength (BS.length r)))
  let (k1, k2) = deterministicNonceScalars sk aggOther (aggXOnlyPubKey ctx) msg rand
  pn <- maybe (Left DeterministicNonceIsZero) Right (pubNonceFromScalars k1 k2)
  -- NonceAgg((pubnonce, aggothernonce)) parses aggothernonce as a public nonce.
  when (isInfinity (aggNonceR1 aggOther) || isInfinity (aggNonceR2 aggOther)) (Left AggOtherNonceAtInfinity)
  let aggNonce = mkAggNonce (add (pubNonceR1 pn) (aggNonceR1 aggOther)) (add (pubNonceR2 pn) (aggNonceR2 aggOther))
  psig <- signScalars True k1 k2 pn sk (newSession ctx aggNonce msg)
  Right (pn, psig)

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
