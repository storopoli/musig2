{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-orphans #-}
{-# OPTIONS_GHC -Wno-x-partial #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

Pure [BIP0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
[MuSig2](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
(partial)signatures with tweak support on the elliptic curve secp256k1.

== Usage

A sample GHCi session:

@
> -- pragmas and b16 import for illustration only; not required
> :set -XOverloadedStrings
> :set -XBangPatterns
> import qualified Data.ByteString.Base16 as B16
>
> -- import qualified
> import qualified Crypto.Curve.Secp256k1.MuSig2 as MuSig2
> import qualified Crypto.Curve.Secp256k1 as Secp256k1
>
> -- secret keys for a 2-of-2 multisig
> let sec1 = MuSig2.SecKey 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
> let sec2 = MuSig2.SecKey 0x68E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
>
> -- derive public keys
> let Just pub1 = Secp256k1.derive_pub 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
> let Just pub2 = Secp256k1.derive_pub 0x68E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
> let pubkeys = [pub1, pub2]
>
> -- create key aggregation context
> let Right keyagg_ctx = MuSig2.mkKeyAggContext pubkeys Nothing
> let agg_pk = MuSig2.aggregatedPubkey keyagg_ctx
>
> -- message to sign
> let msg = "i approve of this message"
>
> -- generate nonces for each signer
> let params1 = MuSig2.defaultSecNonceGenParams pub1
> let params2 = MuSig2.defaultSecNonceGenParams pub2
> Right secnonce1 <- MuSig2.secNonceGen params1
> Right secnonce2 <- MuSig2.secNonceGen params2
> let pubnonce1 = MuSig2.publicNonce secnonce1
> let pubnonce2 = MuSig2.publicNonce secnonce2
> let pubnonces = [pubnonce1, pubnonce2]
>
> -- aggregate nonces and create session context
> let Right aggnonce = MuSig2.aggNonces pubnonces
> let Right session_ctx = MuSig2.mkSessionContext aggnonce pubkeys [] msg
>
> -- each signer creates a partial signature
> let Right psig1 = MuSig2.sign secnonce1 sec1 session_ctx
> let Right psig2 = MuSig2.sign secnonce2 sec2 session_ctx
> let psigs = [psig1, psig2]
>
> -- aggregate partial signatures into final signature
> let Right final_sig = MuSig2.aggPartials psigs session_ctx
>
> -- verify the aggregated signature
> Secp256k1.verify_schnorr msg agg_pk final_sig
> True
@
-}
module Crypto.Curve.Secp256k1.MuSig2 (
  -- Main types and functions
  MuSig2Error (..),
  sign,
  SecKey (..),
  PartialSignature,
  partialSigVerify,
  aggPartials,
  -- MuSig2 Session
  SessionContext (..),
  mkSessionContext,
  -- Key aggregation
  KeyAggContext,
  mkKeyAggContext,
  aggregatedPubkey,
  -- tweak functions
  applyTweak,
  Tweak (..),
  sortPublicKeys,
  -- nonces
  SecNonce,
  mkSecNonce,
  secNonceScalars,
  SecNonceGenParams (..),
  defaultSecNonceGenParams,
  secNonceGen,
  secNonceGenWithRand,
  PubNonce (..),
  publicNonce,
  aggNonces,
) where

import Control.Monad (foldM)
import Crypto.Curve.Secp256k1 (Projective, Pub, add, derive_pub, mul, neg, serialize_point, _CURVE_G, _CURVE_ZERO)
import Crypto.Curve.Secp256k1.MuSig2.Internal
import Data.Binary.Put (
  putWord32be,
  putWord64be,
  runPut,
 )
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

{- HLINT ignore "Use fewer imports" -}
#if !MIN_VERSION_base(4,20,0)
import Data.Foldable (foldl')
#endif
import Data.Foldable (toList, traverse_)
import Data.Maybe (fromMaybe)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Traversable ()
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)
import System.Entropy (getEntropy)

data MuSig2Error
  = EmptyPartialSignatureCollection
  | EmptyNonceCollection
  | EmptyPublicKeyCollection
  | TooManyPublicKeys
  | TooManyTweaks
  | PublicKeyAtInfinity
  | SignerCountMismatch Int Int
  | InvalidSignerIndex Int
  | NegativeTweak Integer
  | TweakOutOfRange Integer
  | AggregatedPublicKeyAtInfinity
  | TweakResultAtInfinity
  | SecretScalarZero String
  | SecretScalarOutOfRange String Integer
  | SecretKeyPublicKeyMismatch
  | PartialSignatureOutOfRange Integer
  | InvalidRandomBytesLength Int
  | PublicNonceGenerationFailed String
  | KeyDerivationFailed
  | ScalarMultiplicationFailed String
  | ZeroNonceGenerated
  deriving (Eq, Show)

liftMaybe :: e -> Maybe a -> Either e a
liftMaybe err = maybe (Left err) Right

validateSecretScalar :: String -> Integer -> Either MuSig2Error Integer
validateSecretScalar label scalar
  | scalar == 0 = Left (SecretScalarZero label)
  | scalar < 0 || scalar >= curveOrder = Left (SecretScalarOutOfRange label scalar)
  | otherwise = Right scalar

validateTweakValue :: Integer -> Either MuSig2Error Integer
validateTweakValue tweak
  | tweak < 0 = Left (NegativeTweak tweak)
  | tweak >= curveOrder = Left (TweakOutOfRange tweak)
  | otherwise = Right tweak

validatePublicKey :: Pub -> Either MuSig2Error Pub
validatePublicKey pub
  | pub == _CURVE_ZERO = Left PublicKeyAtInfinity
  | otherwise = Right pub

-- | Aggregates 'PartialSignature's into a 64-byte Schnorr signature.
aggPartials ::
  (Traversable t) =>
  -- | Partial signatures.
  t PartialSignature ->
  -- | Session context.
  SessionContext ->
  -- | 64-byte Schnorr signature.
  Either MuSig2Error ByteString
aggPartials partials ctx =
  if Seq.null partialsSeq
    then Left EmptyPartialSignatureCollection
    else case traverse validatePartialSignature partialsSeq of
      Left err -> Left err
      Right validPartials ->
        let
          nonce = getSigningNonce ctx
          e = bytesToInteger $ getSigningHash ctx
          keyCtx = cachedKeyAggCtx ctx
          aggPk = q keyCtx
          taccVal = maybe 0 getTweak $ tacc keyCtx
          gaccVal = gacc keyCtx
          -- BIP 327: Let g = 1 if has_even_y(Q), otherwise let g = -1 mod n
          g = if isEvenPub aggPk then 1 else curveOrder - 1
          -- Apply accumulated parity factor
          g' = modQ (g * gaccVal)
          sSum = modQ $ sum validPartials
          -- BIP 327: Let s = s₁ + ... + sᵤ + e⋅g'⋅tacc mod n
          s = modQ (sSum + e * g' * taccVal)
          left = xBytes nonce
          right = integerToBytes32 s
         in
          Right (left <> right)
 where
  partialsSeq = Seq.fromList (toList partials)
  validatePartialSignature partial
    | partial < 0 || partial >= curveOrder = Left (PartialSignatureOutOfRange partial)
    | otherwise = Right partial

{- | Compute a partial signature on a message.

The partial signature returned from this function is a potentially-zero
scalar value which can then be passed to other signers for verification
and aggregation.
-}
sign ::
  -- | Secret nonce.
  SecNonce ->
  -- | Secret key.
  SecKey ->
  -- | Session context.
  SessionContext ->
  -- | Partial signature.
  Either MuSig2Error PartialSignature
sign secnonce sk ctx =
  do
    let publicKeys = pks ctx
        nonce = getSigningNonce ctx
        e = bytesToInteger $ getSigningHash ctx
        keyCtx = cachedKeyAggCtx ctx
        aggPk = q keyCtx
        oddAggPk = not $ isEvenPub aggPk
        gaccVal = gacc keyCtx
        SecNonce k1 k2 boundPk = secnonce
    _ <- validateSecretScalar "k1" k1
    _ <- validateSecretScalar "k2" k2
    d' <- validateSecretScalar "secret key" (unSecKey sk)
    p <- liftMaybe KeyDerivationFailed $ derive_pub (fromInteger d')
    if p /= boundPk
      then Left SecretKeyPublicKeyMismatch
      else do
        let
          -- `d` is negated if exactly one of the parity accumulator OR the aggregated pubkey has odd parity.
          -- gaccVal == 1 means no negation, gaccVal == n-1 means negation
          parityFromGacc = gaccVal /= 1
          d = if parityFromGacc /= oddAggPk then curveOrder - d' else d'
          a = computeKeyAggCoef p publicKeys
          -- if has_even_Y(R):
          --   k = k1 + b*k2
          -- else:
          --   k = (n-k1) + b(n-k2)
          --     = n - (k1 + b*k2)
          b = getSigningNonceCoeff ctx
          k = if isEvenPub nonce then k1 + b * k2 else curveOrder - (k1 + b * k2)
          s = modQ (k + e * a * d)
        verified <- partialSigVerifyInternal s (publicNonce secnonce) p ctx
        if verified
          then Right s
          else Left (PublicNonceGenerationFailed "partial signature self-verification failed")

{- | A partial signature which is a scalar in the range \(0 \leq x < n\) where
\(n\) is the curve order.
-}
type PartialSignature = Integer

-- | Verifies a 'PartialSignature'.
partialSigVerify ::
  (Traversable t) =>
  -- | Partial signature to verify.
  PartialSignature ->
  -- | 'PubNonce's
  t PubNonce ->
  -- | 'Pub'lic keys.
  t Pub ->
  -- | 'Tweak's
  t Tweak ->
  -- | Message.
  ByteString ->
  -- | Index of the signer.
  Int ->
  -- | If the partial signature is valid.
  Either MuSig2Error Bool
partialSigVerify partial nonces pks tweaks msg idx =
  do
    aggNonce <- aggNonces nonces
    ctx <- mkSessionContext aggNonce pks tweaks msg
    let noncesSeq = Seq.fromList (toList nonces)
        pksSeq = Seq.fromList (toList pks)
    if Seq.length noncesSeq /= Seq.length pksSeq
      then Left (SignerCountMismatch (Seq.length pksSeq) (Seq.length noncesSeq))
      else do
        pk <- maybe (Left (InvalidSignerIndex idx)) Right (Seq.lookup idx pksSeq)
        pubnonce <- maybe (Left (InvalidSignerIndex idx)) Right (Seq.lookup idx noncesSeq)
        partialSigVerifyInternal partial pubnonce pk ctx

{- | Verifies a 'PartialSignature'.

== WARNING

Internal function you should probably be using 'partialSigVerify' instead.
-}
partialSigVerifyInternal ::
  -- | Partial signature to verify.
  PartialSignature ->
  -- | Public nonce.
  PubNonce ->
  -- | 'Pub'lic key.
  Pub ->
  -- | MuSig2 session context.
  SessionContext ->
  -- | If the partial signature is valid.
  Either MuSig2Error Bool
partialSigVerifyInternal partial pubnonce pk ctx =
  do
    s <- validatePartialSignature partial
    let
      publicKeys = pks ctx
      keyCtx = cachedKeyAggCtx ctx
      aggPk = q keyCtx
      oddAggPk = not $ isEvenPub aggPk
      gaccVal = gacc keyCtx
      e = bytesToInteger $ getSigningHash ctx
      r1' = pubnonce.r1
      r2' = pubnonce.r2
      b = getSigningNonceCoeff ctx
      finalNonce = getSigningNonce ctx
      a = computeKeyAggCoef pk publicKeys
      -- Calculate g factor: 1 if aggregate pubkey has even Y, n-1 if odd
      g = if oddAggPk then curveOrder - 1 else 1
      -- Apply parity accumulator: gacc is accumulated parity factor
      g' = modQ (g * gaccVal)
    r2b <- liftMaybe (ScalarMultiplicationFailed "r2 * b") $ mul r2' (fromInteger b)
    sG <- liftMaybe (ScalarMultiplicationFailed "s * G") $ mul _CURVE_G (fromInteger s)
    pkMul <- liftMaybe (ScalarMultiplicationFailed "pk multiplication") $ mul pk (fromInteger (modQ (e * a * g')))
    let
      re' = add r1' r2b
      -- Negate individual nonce if final aggregate nonce has odd Y
      re = if isEvenPub finalNonce then re' else neg re'
      sG' = re `add` pkMul
    Right (sG == sG')
 where
  validatePartialSignature s
    | s < 0 || s >= curveOrder = Left (PartialSignatureOutOfRange s)
    | otherwise = Right s

-- | Secret key.
newtype SecKey = SecKey Integer
  deriving (Read, Eq, Ord, Num, Generic)

-- | Gets the secret 'Integer' from a 'SecKey'.
unSecKey :: SecKey -> Integer
unSecKey (SecKey int) = int

-- | Key aggregation context that holds the aggregated public key and a tweak, if applicable.
data KeyAggContext = KeyAggContext
  { q :: Projective
  -- ^ Point representing the potentially tweaked aggregate public key: an elliptic curve point.
  , tacc :: Maybe Tweak
  -- ^ accumulated tweak: an integer with \(0 \leq tacc < n\) where \(n\) is the curve order. 'Nothing' means \(0\).
  , gacc :: !Integer
  -- ^ parity accumulator: 1 means \(g = 1\), \(n-1\) means \(g = n-1\) where \(n\) is the curve order.
  }

{- | Creates a 'KeyAggContext'.

The order in which the 'Pub'keys are presented will be preserved.
A specific ordering of 'Pub'keys will uniquely determine the aggregated 'Pub'key.

If the same keys are provided again in a different sorting order, a different
aggregated 'Pub'key will result. It is recommended to sort keys ahead of time
using 'sortPublicKeys' before creating a 'KeyAggContext'.

== NOTE

Internally it validates if all keys and the resulting aggregated key are not
points at infinity, if the optional tweak is within the curve order, and if
the length of the collection of keys is not bigger than 32 bits.
-}
mkKeyAggContext ::
  (Traversable t) =>
  -- | 'Pub'keys.
  t Pub ->
  -- | Optional 'Tweak' value.
  Maybe Tweak ->
  -- | Resulting 'KeyAggContext'.
  Either MuSig2Error KeyAggContext
mkKeyAggContext pks mTweak
  | Seq.null pks' = Left EmptyPublicKeyCollection
  | Seq.length pks' > fromIntegral (maxBound :: Word32) = Left TooManyPublicKeys
  | otherwise = do
      traverse_ validatePublicKey pks'
      aggPk <- liftMaybe AggregatedPublicKeyAtInfinity $ aggPublicKeys pks'
      if aggPk == _CURVE_ZERO
        then Left AggregatedPublicKeyAtInfinity
        else do
          let baseCtx = KeyAggContext aggPk Nothing 1
          case mTweak of
            Nothing -> Right baseCtx
            Just tweak -> applyTweak baseCtx tweak
 where
  pks' = Seq.fromList (toList pks)

-- | Session aggregation context that holds the relevant context for a MuSig2 signing session.
data SessionContext = SessionContext
  { aggNonce :: !PubNonce
  -- ^ Aggregated 'PubNonce'.
  , pks :: !(Seq Pub)
  -- ^ Ordered 'Seq' of 'Pub'keys.
  , tweaks :: !(Seq Tweak)
  -- ^ 'Seq' of 'Tweak's.
  , msg :: !ByteString
  -- ^ Message to be signed.
  , cachedKeyAggCtx :: !KeyAggContext
  -- ^ Cached 'KeyAggContext' to avoid recomputation.
  }

{- | Creates a 'SessionContext'.

The order in which the 'Pub'keys are presented will be preserved.
A specific ordering of 'Pub'keys will uniquely determine the aggregated 'Pub'key.

If the same keys are provided again in a different sorting order, a different
aggregated 'Pub'key will result. It is recommended to sort keys ahead of time
using 'sortPublicKeys' before creating a 'SessionContext'.

== NOTE

Internally it validates if all keys, the resulting aggregated key, and the
aggregated public nonce are not points at infinity, if the tweaks are within the
curve order, and if the length of the collection of keys is not bigger than 32 bits.
-}
mkSessionContext ::
  (Traversable t) =>
  -- | Aggregated 'PubNonce'.
  PubNonce ->
  -- | 'Pub'keys.
  t Pub ->
  -- | 'Tweak's.
  t Tweak ->
  -- | Message to be signed.
  ByteString ->
  -- | Resulting 'SessionContext'.
  Either MuSig2Error SessionContext
mkSessionContext aggNonce pks tweaks msg
  | Seq.null pks' = Left EmptyPublicKeyCollection
  | Seq.length pks' > fromIntegral (maxBound :: Word32) = Left TooManyPublicKeys
  | Seq.length tweaks' > fromIntegral (maxBound :: Word32) = Left TooManyTweaks
  | otherwise = do
      traverse_ validatePublicKey pks'
      traverse_ (validateTweakValue . getTweak) tweaks'
      keyCtx <- if Seq.null tweaks' then mkKeyAggContext pks' Nothing else mkKeyAggContext pks' Nothing >>= \baseCtx -> foldM applyTweak baseCtx tweaks'
      Right (SessionContext aggNonce pks' tweaks' msg keyCtx)
 where
  pks' = Seq.fromList (toList pks)
  tweaks' = Seq.fromList (toList tweaks)

{- | Gets the signing nonce as a 'Projective' following
[BIP-0327 algorithm and recommendations](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#dealing-with-infinity-in-nonce-aggregation).
-}
getSigningNonce :: SessionContext -> Projective
getSigningNonce ctx =
  let
    b = getSigningNonceCoeff ctx
    aggNonce = ctx.aggNonce
    aggNonce' = if aggNonce.r1 == _CURVE_ZERO then PubNonce _CURVE_G aggNonce.r2 else aggNonce
    r2b = fromMaybe (error "musig2 (getSigningNonce): failed to compute r2 * b") $ mul aggNonce'.r2 (fromInteger b)
    finalNonce = add aggNonce'.r1 r2b
   in
    if finalNonce == _CURVE_ZERO then _CURVE_G else finalNonce

{- | Gets the signing nonce coefficient following
[BIP-0327 algorithm and recommendations](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#dealing-with-infinity-in-nonce-aggregation).
-}
getSigningNonceCoeff :: SessionContext -> Integer
getSigningNonceCoeff ctx =
  let
    aggNonce = ctx.aggNonce
    aggNonce' = if aggNonce.r1 == _CURVE_ZERO then PubNonce _CURVE_G aggNonce.r2 else aggNonce
    aggPubKey = q (cachedKeyAggCtx ctx)
    msg = ctx.msg
    nonceBytes = serialize_point aggNonce'.r1 <> serialize_point aggNonce'.r2
    qBytes = xBytes aggPubKey
    preimage = nonceBytes <> qBytes <> msg
   in
    bytesToInteger $ hashTagModQ "MuSig/noncecoef" preimage

{- | Gets the signing challenge hash as a 'ByteString' following
[BIP-0327 algorithm](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).

Note that the signing challenge hash is the naming convention from the
[MuSig2 paper, page 6](https://eprint.iacr.org/2020/1261).
In the BIP-0327 it is referred as @e@.
-}
getSigningHash :: SessionContext -> ByteString
getSigningHash ctx =
  let
    aggPubKey = q (cachedKeyAggCtx ctx)
    qBytes = xBytes aggPubKey
    msg = ctx.msg
    nonce = getSigningNonce ctx
    r = xBytes nonce
    preimage = r <> qBytes <> msg
   in
    hashTagModQ "BIP0340/challenge" preimage

-- | Tweak that can be added to an aggregated 'Pub'key.
data Tweak
  = {- | X-only tweak required by Taproot tweaking to add script paths to a Taproot output.
    See [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).
    -}
    XOnlyTweak !Integer
  | {- | Plain tweak that can be used to derive child aggregated 'Pub'keys per
    [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
    -}
    PlainTweak !Integer
  deriving (Read, Show, Eq, Ord, Generic)

-- | Retrieves the 'Integer' from 'Tweak'.
getTweak :: Tweak -> Integer
getTweak (XOnlyTweak int) = int
getTweak (PlainTweak int) = int

applyTweak :: KeyAggContext -> Tweak -> Either MuSig2Error KeyAggContext
applyTweak ctx newTweak = do
  let pubkey = q ctx
      mAccTweak = tacc ctx
      gaccIn = gacc ctx
      accTweakVal = maybe 0 getTweak mAccTweak
  t <- validateTweakValue (getTweak newTweak)
  case newTweak of
    PlainTweak _ -> do
      let g = 1
      pubkeyMul <- liftMaybe (ScalarMultiplicationFailed "pubkey * g") $ mul pubkey (fromInteger g)
      tG <- liftMaybe (ScalarMultiplicationFailed "t * G") $ mul _CURVE_G (fromInteger t)
      let tweakedPk = add pubkeyMul tG
          newAccTweak = modQ (t + (g * accTweakVal))
          newGacc = modQ (g * gaccIn)
      if tweakedPk == _CURVE_ZERO
        then Left TweakResultAtInfinity
        else Right ctx{q = tweakedPk, tacc = Just (PlainTweak newAccTweak), gacc = newGacc}
    XOnlyTweak _ -> do
      let g = if isEvenPub pubkey then 1 else curveOrder - 1
      pubkeyMul <- liftMaybe (ScalarMultiplicationFailed "pubkey * g") $ mul pubkey (fromInteger g)
      tG <- liftMaybe (ScalarMultiplicationFailed "t * G") $ mul _CURVE_G (fromInteger t)
      let tweakedPk = add pubkeyMul tG
          newAccTweak = modQ (t + (g * accTweakVal))
          newGacc = modQ (g * gaccIn)
      if tweakedPk == _CURVE_ZERO
        then Left TweakResultAtInfinity
        else Right ctx{q = tweakedPk, tacc = Just (XOnlyTweak newAccTweak), gacc = newGacc}

-- | Manual 'Ord' implementation of 'Projective' for lexicography sorting.
instance Ord Projective where
  compare x y = compare (serialize_point x) (serialize_point y)

-- | 'Data.Semigroup' implementation of 'Projective' for algebraic sound combination of points.
instance Semigroup Projective where
  (<>) :: Projective -> Projective -> Projective
  (<>) = add

-- | 'Data.Monoid' implementation of 'Projective' for algebraic sound combination of points.
instance Monoid Projective where
  mempty :: Projective
  mempty = _CURVE_ZERO

-- | Lexicographically 'Data.Sequence.sort's a 'Traversable' of 'Pub'keys.
sortPublicKeys :: (Traversable t) => t Pub -> Seq Pub
sortPublicKeys = Seq.sort . Seq.fromList . toList

-- | Gets the aggregated public key from a 'KeyAggContext'.
aggregatedPubkey :: KeyAggContext -> Pub
aggregatedPubkey = q

{- | Secret nonce.

The secret nonce provides randomness, blinding a signer's private key when
signing. It is imperative that the same 'SecNonce' is not used to sign more
than one message with the same key, as this would allow an observer to
compute the private key used to create both signatures.

If you want to follow
[BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
suggestions, then use 'secNonceGen' otherwise use 'mkSecNonce'.
-}
data SecNonce = SecNonce
  { secNonceK1Internal :: !Integer
  -- ^ First secret scalar.
  , secNonceK2Internal :: !Integer
  -- ^ Second secret scalar.
  , secNoncePubKeyInternal :: !Pub
  -- ^ Public key this nonce is bound to.
  }
  deriving (Eq, Ord, Generic)

-- | Returns the two secret scalars contained in a 'SecNonce'.
secNonceScalars :: SecNonce -> (Integer, Integer)
secNonceScalars secNonce = (secNonceK1Internal secNonce, secNonceK2Internal secNonce)

mkSecNonce ::
  -- | Public key this nonce is bound to.
  Pub ->
  -- | First secret scalar.
  Integer ->
  -- | Second secret scalar.
  Integer ->
  Either MuSig2Error SecNonce
mkSecNonce pub k1 k2 = do
  _ <- validatePublicKey pub
  k1' <- validateSecretScalar "k1" k1
  k2' <- validateSecretScalar "k2" k2
  Right SecNonce{secNonceK1Internal = k1', secNonceK2Internal = k2', secNoncePubKeyInternal = pub}

-- | Required and Optional data to generate a 'SecNonce'.
data SecNonceGenParams = SecNonceGenParams
  { _pk :: Pub
  -- ^ 'Pub'lic key: mandatory.
  , _sk :: Maybe SecKey
  -- ^ Secret key: optional.
  , _aggpk :: Maybe Pub
  -- ^ Aggregated 'Pub'lic key: optional.
  , _msg :: Maybe ByteString
  -- ^ Message: optional.
  , _extraIn :: Maybe ByteString
  -- Auxiliary input: optional.
  }
  deriving (Eq, Ord, Generic)

-- | Default approach to generate 'SecNonce's with the only required 'Pub'lic key.
defaultSecNonceGenParams :: Pub -> SecNonceGenParams
defaultSecNonceGenParams pk =
  SecNonceGenParams
    { _pk = pk
    , _sk = Nothing
    , _aggpk = Nothing
    , _msg = Nothing
    , _extraIn = Nothing
    }

{- | Generates a 'SecNonce' using the inputs and algorithms from
[BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).

Tries to get the entropy from the system's underlying Cryptographic Secure
Pseudorandom Number Generator (CSPRNG) using the
[@entropy@](https://hackage.haskell.org/package/entropy) package.

== WARNING

Make sure that you have access to a good CSPRNG in your system before calling
this function.
-}
secNonceGen :: SecNonceGenParams -> IO (Either MuSig2Error SecNonce)
secNonceGen params = loop
 where
  loop = do
    rand <- getEntropy 32
    case secNonceGenWithRand rand params of
      Left ZeroNonceGenerated -> loop
      other -> pure other

{- | Generates a 'SecNonce' using a given random 'ByteString' and the inputs and
algorithms from
[BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).

== WARNING

You should probably use 'secNonceGen'.
Use this function if you really have a randomly-generated 'ByteString'.
-}
secNonceGenWithRand :: ByteString -> SecNonceGenParams -> Either MuSig2Error SecNonce
secNonceGenWithRand rand _params@(SecNonceGenParams{_pk = pkPoint, ..}) = do
  if BS.length rand /= 32
    then Left (InvalidRandomBytesLength (BS.length rand))
    else Right ()
  _ <- validatePublicKey pkPoint
  traverse_ validatePublicKey _aggpk
  case _sk of
    Nothing -> Right ()
    Just (SecKey skScalar) -> do
      skScalar' <- validateSecretScalar "secret key" skScalar
      expectedPk <- liftMaybe KeyDerivationFailed $ derive_pub (fromInteger skScalar')
      if expectedPk == pkPoint
        then Right ()
        else Left SecretKeyPublicKeyMismatch
  let
    -- Step 2: Optional sk XOR (with tagged hash for safety)
    rand' = case _sk of
      Just (SecKey skScalar) ->
        let skBytes = integerToBytes32 skScalar
            auxHash = hashTag "MuSig/aux" rand
         in xorByteStrings skBytes auxHash
      Nothing -> rand

    -- Steps 3-5: Defaults for optionals
    pkBytes = serialize_point pkPoint
    aggpkBytes = maybe "" (BS.drop 1 . serialize_point) _aggpk
    msgPrefixed = case _msg of
      Nothing -> BS.singleton 0
      Just m ->
        let len = fromIntegral (BS.length m) :: Word64
            lenBytes = LBS.toStrict . runPut $ putWord64be len
         in BS.singleton 1 `BS.append` lenBytes `BS.append` m
    extraInBytes = fromMaybe "" _extraIn

    -- Steps 6-8: Hash for k1/k2
    mkInput :: Word8 -> ByteString
    mkInput i =
      rand'
        `BS.append` (BS.singleton . fromIntegral $ BS.length pkBytes)
        `BS.append` pkBytes
        `BS.append` (BS.singleton . fromIntegral $ BS.length aggpkBytes)
        `BS.append` aggpkBytes
        `BS.append` msgPrefixed
        `BS.append` (LBS.toStrict . runPut . putWord32be . fromIntegral $ BS.length extraInBytes)
        `BS.append` extraInBytes
        `BS.append` BS.singleton i

    k1' = modQ . bytesToInteger $ hashTag "MuSig/nonce" (mkInput 0)
    k2' = modQ . bytesToInteger $ hashTag "MuSig/nonce" (mkInput 1)
  if k1' == 0 || k2' == 0
    then Left ZeroNonceGenerated
    else mkSecNonce pkPoint k1' k2'

{- | Public nonce.

Represents a public nonce derived from a secret nonce. It is composed
of two public points, 'r1' and 'r2', derived by base-point multiplying
the two scalars in a 'SecNonce'.

A 'PubNonce' can be derived from a 'SecNonce' using 'publicNonce'.
-}
data PubNonce = PubNonce
  { r1 :: Pub
  -- ^ First public point.
  , r2 :: Pub
  -- ^ Second public point.
  }
  deriving (Eq, Ord, Show)

-- | Generates a 'PubNonce' from a 'SecNonce'.
publicNonce :: SecNonce -> PubNonce
publicNonce secNonce =
  let (k1, k2) = secNonceScalars secNonce
      r1' = fromMaybe (error "musig2 (publicNonce): failed to compute r1") $ mul _CURVE_G (fromInteger k1)
      r2' = fromMaybe (error "musig2 (publicNonce): failed to compute r2") $ mul _CURVE_G (fromInteger k2)
   in PubNonce r1' r2'

-- | 'Data.Semigroup' implementation of 'PubNonce' for algebraic sound combination of public nonces.
instance Semigroup PubNonce where
  (<>) :: PubNonce -> PubNonce -> PubNonce
  a <> b = PubNonce{r1 = r1Agg, r2 = r2Agg}
   where
    r1Agg = add a.r1 b.r1
    r2Agg = add a.r2 b.r2

-- | 'Data.Monoid' implementation of 'PubNonce' for algebraic sound combination of public nonces.
instance Monoid PubNonce where
  mempty :: PubNonce
  mempty = PubNonce _CURVE_ZERO _CURVE_ZERO

{- | Aggregates a 'Traversable' of 'PubNonce's using the
[Nonce Aggregation algorithm in BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
-}
aggNonces :: (Traversable t) => t PubNonce -> Either MuSig2Error PubNonce
aggNonces nonces
  | Seq.null noncesSeq = Left EmptyNonceCollection
  | otherwise = case Seq.viewl noncesSeq of
      Seq.EmptyL -> Left EmptyNonceCollection
      x Seq.:< xs -> Right $! foldl' (<>) x xs
 where
  noncesSeq = Seq.fromList (toList nonces)
