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
> let keyagg_ctx = MuSig2.mkKeyAggContext pubkeys Nothing
> let agg_pk = MuSig2.aggregatedPubkey keyagg_ctx
>
> -- message to sign
> let msg = "i approve of this message"
>
> -- generate nonces for each signer
> let params1 = MuSig2.defaultSecNonceGenParams pub1
> let params2 = MuSig2.defaultSecNonceGenParams pub2
> secnonce1 <- MuSig2.secNonceGen params1
> secnonce2 <- MuSig2.secNonceGen params2
> let pubnonce1 = MuSig2.publicNonce secnonce1
> let pubnonce2 = MuSig2.publicNonce secnonce2
> let pubnonces = [pubnonce1, pubnonce2]
>
> -- aggregate nonces and create session context
> let Just aggnonce = MuSig2.aggNonces pubnonces
> let session_ctx = MuSig2.mkSessionContext aggnonce pubkeys [] msg
>
> -- each signer creates a partial signature
> let psig1 = MuSig2.sign secnonce1 sec1 session_ctx
> let psig2 = MuSig2.sign secnonce2 sec2 session_ctx
> let psigs = [psig1, psig2]
>
> -- aggregate partial signatures into final signature
> let final_sig = MuSig2.aggPartials psigs session_ctx
>
> -- verify the aggregated signature
> Secp256k1.verify_schnorr msg agg_pk final_sig
> True
@
-}
module Crypto.Curve.Secp256k1.MuSig2 (
  -- Main types and functions
  sign,
  SecKey (..),
  PartialSignature,
  partialSigVerify,
  aggPartials,
  -- MuSig2 Session
  SessionContext,
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
  SecNonce (..),
  mkSecNonce,
  SecNonceGenParams (..),
  defaultSecNonceGenParams,
  secNonceGen,
  secNonceGenWithRand,
  PubNonce (..),
  publicNonce,
  aggNonces,
) where

import Control.Exception (ErrorCall (..), evaluate, throwIO, try)
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
import Data.Foldable (toList)
import Data.List (isPrefixOf)
import Data.Maybe (fromJust, fromMaybe)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Traversable ()
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)
import System.Entropy (getEntropy)

-- | Aggregates 'PartialSignature's into a 64-byte Schnorr signature.
aggPartials ::
  (Traversable t) =>
  -- | Partial signatures.
  t PartialSignature ->
  -- | Session context.
  SessionContext ->
  -- | 64-byte Schnorr signature.
  ByteString
aggPartials partials ctx =
  let
    publicKeys = pks ctx
    tweaks' = tweaks ctx
    nonce = getSigningNonce ctx
    e = bytesToInteger $ getSigningHash ctx
    keyCtx = if Seq.null tweaks' then mkKeyAggContext publicKeys Nothing else foldl applyTweak (mkKeyAggContext publicKeys Nothing) tweaks'
    aggPk = q keyCtx
    taccVal = maybe 0 getTweak $ tacc keyCtx
    gaccVal = gacc keyCtx
    -- BIP 327: Let g = 1 if has_even_y(Q), otherwise let g = -1 mod n
    g = if isEvenPub aggPk then 1 else curveOrder - 1
    -- Apply accumulated parity factor
    g' = modQ (g * gaccVal)
    sSum = modQ $ sum partials
    -- BIP 327: Let s = s₁ + ... + sᵤ + e⋅g'⋅tacc mod n
    s = modQ (sSum + e * g' * taccVal)
    left = xBytes nonce
    right = integerToBytes32 s
   in
    left <> right

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
  PartialSignature
sign secnonce sk ctx =
  let
    publicKeys = pks ctx
    tweaks' = tweaks ctx
    nonce = getSigningNonce ctx
    e = bytesToInteger $ getSigningHash ctx
    keyCtx = if Seq.null tweaks' then mkKeyAggContext publicKeys Nothing else foldl applyTweak (mkKeyAggContext publicKeys Nothing) tweaks'
    aggPk = q keyCtx
    oddAggPk = not $ isEvenPub aggPk
    gaccVal = gacc keyCtx
    k1 = if secnonce.k1 == 0 then error "musig2 (sign): first secret scalar k1 is zero" else secnonce.k1
    k2 = if secnonce.k2 == 0 then error "musig2 (sign): first secret scalar k2 is zero" else secnonce.k2
    d' = if unSecKey sk == 0 then error "musig2 (sign): secret key is zero" else unSecKey sk
    -- `d` is negated if exactly one of the parity accumulator OR the aggregated pubkey has odd parity.
    -- gaccVal == 1 means no negation, gaccVal == n-1 means negation
    parityFromGacc = gaccVal /= 1
    d = if parityFromGacc /= oddAggPk then curveOrder - d' else d'
    p = fromMaybe (error "musig2 (sign): failed to derive public key") $ derive_pub (fromInteger d') -- Use original secret key for public key derivation
    a = computeKeyAggCoef p publicKeys
    -- if has_even_Y(R):
    --   k = k1 + b*k2
    -- else:
    --   k = (n-k1) + b(n-k2)
    --     = n - (k1 + b*k2)
    b = getSigningNonceCoeff ctx
    k = if isEvenPub nonce then k1 + b * k2 else curveOrder - (k1 + b * k2)
    s = modQ (k + e * a * d)
    r1' = fromMaybe (error "musig2 (sign): failed to compute r1") $ mul _CURVE_G (fromInteger secnonce.k1)
    r2' = fromMaybe (error "musig2 (sign): failed to compute r2") $ mul _CURVE_G (fromInteger secnonce.k2)
    pubNonce' = PubNonce r1' r2'
   in
    if partialSigVerifyInternal s pubNonce' p ctx then s else error "musig2 (sign): could not verify partial signature against public nonce, public key and session context"

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
  Bool
partialSigVerify partial nonces pks tweaks msg idx =
  let aggNonce = fromJust $ aggNonces nonces
      ctx = mkSessionContext aggNonce pks tweaks msg
      noncesList = toList nonces
      pk = if idx < length pks then toList pks !! idx else error "musig2 (partialSigVerify): signer index out of range of the list of public keys"
      pubnonce = if idx < length noncesList then noncesList !! idx else error "musig2 (partialSigVerify): signer index out of range of the list of public nonces"
   in partialSigVerifyInternal partial pubnonce pk ctx

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
  Bool
partialSigVerifyInternal partial pubnonce pk ctx =
  let
    publicKeys = pks ctx
    tweaks' = tweaks ctx
    keyCtx = if Seq.null tweaks' then mkKeyAggContext publicKeys Nothing else foldl applyTweak (mkKeyAggContext publicKeys Nothing) tweaks'
    aggPk = q keyCtx
    oddAggPk = not $ isEvenPub aggPk
    gaccVal = gacc keyCtx
    e = bytesToInteger $ getSigningHash ctx
    r1' = pubnonce.r1
    r2' = pubnonce.r2
    b = getSigningNonceCoeff ctx
    finalNonce = getSigningNonce ctx -- This is the final aggregate nonce used for evenness check
    s = if partial < 0 || partial >= curveOrder then error "musig2 (partialSigVerifyInternal): partial signature must be within curve order." else partial
    -- Reconstruct the individual's effective nonce: R_s1 + b * R_s2
    r2b = fromMaybe (error "musig2 (partialSigVerifyInternal): failed to compute r2 * b") $ mul r2' (fromInteger b)
    re' = add r1' r2b
    -- Negate individual nonce if final aggregate nonce has odd Y
    re = if isEvenPub finalNonce then re' else neg re'
    a = computeKeyAggCoef pk publicKeys
    -- Calculate g factor: 1 if aggregate pubkey has even Y, n-1 if odd
    g = if oddAggPk then curveOrder - 1 else 1
    -- Apply parity accumulator: gacc is accumulated parity factor
    g' = modQ (g * gaccVal)
    sG = fromMaybe (error "musig2 (partialSigVerifyInternal): failed to compute s * G") $ mul _CURVE_G (fromInteger s)
    pkMul = fromMaybe (error "musig2 (partialSigVerifyInternal): failed to compute pk multiplication") $ mul pk (fromInteger (modQ (e * a * g')))
    sG' = re `add` pkMul
   in
    sG == sG'

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
  KeyAggContext
mkKeyAggContext pks mTweak
  | Seq.null pks' = error "musig2 (mkKeyAggContext): empty public key collection"
  | Seq.length pks' > fromIntegral (maxBound :: Word32) = error "musig2 (mkKeyAggContext): too many public keys (max 2^32 - 1)"
  | _CURVE_ZERO `elem` pks' = error "musig2 (mkKeyAggContext): public key at point of infinity"
  | maybe False ((< 0) . getTweak) mTweak = error "musig2 (mkKeyAggContext): tweak must be non-negative"
  | maybe False ((>= curveOrder) . getTweak) mTweak = error "musig2 (mkKeyAggContext): tweak must be less than curve order"
  | otherwise = case aggPublicKeys pks' of
      Nothing -> error "musig2 (mkKeyAggContext): failed to aggregate public keys"
      Just aggPk
        | aggPk == _CURVE_ZERO -> error "musig2 (mkKeyAggContext): aggregated public key is point at infinity"
        | otherwise ->
            let baseCtx = KeyAggContext aggPk Nothing 1
             in case mTweak of
                  Nothing -> baseCtx
                  Just tweak -> applyTweak baseCtx tweak
 where
  pks' = Seq.fromList (toList pks)

-- | Session aggregation context that holds the relevant context for a MuSig2 signing session.
data SessionContext = SessionContext
  { aggNonce :: PubNonce
  -- ^ Aggregated 'PubNonce'.
  , pks :: Seq Pub
  -- ^ Ordered 'Seq' of 'Pub'keys.
  , tweaks :: Seq Tweak
  -- ^ 'Seq' of 'Tweak's.
  , msg :: ByteString
  -- ^ Message to be signed.
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
  SessionContext
mkSessionContext aggNonce pks tweaks msg
  | Seq.null pks' = error "musig2 (mkSessionContext): empty public key collection"
  | Seq.length pks' > fromIntegral (maxBound :: Word32) = error "musig2 (mkSessionContext): too many public keys (max 2^32 - 1)"
  | _CURVE_ZERO `elem` pks' = error "musig2 (mkSessionContext): public key at point of infinity"
  | Seq.length tweaks' > fromIntegral (maxBound :: Word32) = error "musig2 (mkSessionContext): too many tweaks (max 2^32 - 1)"
  | any checkNeg tweaks' = error "musig2 (mkSessionContext): tweaks must be non-negative"
  | any checkOrder tweaks' = error "musig2 (mkSessionContext): tweaks must be less than curve order"
  | otherwise = case aggPublicKeys pks' of
      Nothing -> error "musig2 (mkSessionContext): failed to aggregate public keys"
      Just aggPk
        | aggPk == _CURVE_ZERO -> error "musig2 (mkSessionContext): aggregated public key is point at infinity"
        | otherwise -> SessionContext aggNonce pks' tweaks' msg
 where
  pks' = Seq.fromList (toList pks)
  tweaks' = Seq.fromList (toList tweaks)
  checkNeg = (< 0) . getTweak
  checkOrder = (>= curveOrder) . getTweak

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
    -- Apply tweaks to get the correct aggregate public key
    keyCtx =
      if Seq.null (tweaks ctx)
        then mkKeyAggContext (pks ctx) Nothing
        else foldl applyTweak (mkKeyAggContext (pks ctx) Nothing) (tweaks ctx)
    aggPubKey = q keyCtx
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
    -- Apply tweaks to get the correct aggregate public key
    keyCtx =
      if Seq.null (tweaks ctx)
        then mkKeyAggContext (pks ctx) Nothing
        else foldl applyTweak (mkKeyAggContext (pks ctx) Nothing) (tweaks ctx)
    aggPubKey = q keyCtx
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

-- | Applies a tweak to a KeyAggContext and returns a new KeyAggContext following [BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
applyTweak :: KeyAggContext -> Tweak -> KeyAggContext
applyTweak ctx newTweak =
  let pubkey = q ctx
      mAccTweak = tacc ctx
      gaccIn = gacc ctx
      accTweakVal = maybe 0 getTweak mAccTweak
   in case newTweak of
        PlainTweak t ->
          -- Plain tweak: g = 1, Q' = g*Q + t*G, tacc' = t + g*tacc, gacc' = g*gacc
          let g = 1
              pubkeyMul = fromMaybe (error "musig2 (applyTweak): failed to compute pubkey * g") $ mul pubkey (fromInteger g)
              tG = fromMaybe (error "musig2 (applyTweak): failed to compute t * G") $ mul _CURVE_G (fromInteger t)
              tweakedPk = add pubkeyMul tG
              newAccTweak = modQ (t + (g * accTweakVal))
              newGacc = modQ (g * gaccIn)
           in if tweakedPk == _CURVE_ZERO
                then error "musig2 (applyTweak): result of tweaking cannot be infinity"
                else ctx{q = tweakedPk, tacc = Just (PlainTweak newAccTweak), gacc = newGacc}
        XOnlyTweak t ->
          -- X-only tweak: g = 1 if even Y, g = n-1 if odd Y, tacc' = t + g*tacc
          let g = if isEvenPub pubkey then 1 else curveOrder - 1
              pubkeyMul = fromMaybe (error "musig2 (applyTweak): failed to compute pubkey * g") $ mul pubkey (fromInteger g)
              tG = fromMaybe (error "musig2 (applyTweak): failed to compute t * G") $ mul _CURVE_G (fromInteger t)
              tweakedPk = add pubkeyMul tG
              newAccTweak = modQ (t + (g * accTweakVal))
              newGacc = modQ (g * gaccIn)
           in if tweakedPk == _CURVE_ZERO
                then error "musig2 (applyTweak): result of tweaking cannot be infinity"
                else ctx{q = tweakedPk, tacc = Just (XOnlyTweak newAccTweak), gacc = newGacc}

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
  { k1 :: !Integer
  -- ^ First secret scalar.
  , k2 :: !Integer
  -- ^ Second secret scalar.
  }
  deriving (Read, Eq, Ord, Generic)

{- | Generates a 'SecNonce' using only the system's underlying Cryptographic Secure
Pseudorandom Number Generator (CSPRNG) using the
[@entropy@](https://hackage.haskell.org/package/entropy) package.

== WARNING

Make sure that you have access to a good CSPRNG in your system before calling
this function.

Note that this does not follow the
[BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
algorithm.
-}
mkSecNonce :: IO SecNonce
mkSecNonce = do
  bytes <- getEntropy 64 -- 64 bytes = 512 bits for two 256-bit scalars
  let k1' = bytesToInteger (BS.take 32 bytes)
      k2' = bytesToInteger (BS.drop 32 bytes)
  pure SecNonce{k1 = k1', k2 = k2'}

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
secNonceGen :: SecNonceGenParams -> IO SecNonce
secNonceGen params = loop
 where
  loop = do
    rand <- getEntropy 32
    eres <- try (evaluate (secNonceGenWithRand rand params))
    case eres of
      Right sn -> pure sn
      Left (ErrorCall msg) | "musig2 (nonceGen): zero nonce generated" `isPrefixOf` msg -> loop
      Left e -> throwIO e

{- | Generates a 'SecNonce' using a given random 'ByteString' and the inputs and
algorithms from
[BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).

== WARNING

You should probably use 'secNonceGen'.
Use this function if you really have a randomly-generated 'ByteString'.
-}
secNonceGenWithRand :: ByteString -> SecNonceGenParams -> SecNonce
secNonceGenWithRand rand _params@(SecNonceGenParams{_pk = pkPoint, ..}) =
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
   in
    -- Step 9: check for zero nonce and retry if so
    if k1' == 0 || k2' == 0
      then error "musig2 (nonceGen): zero nonce generated (retry)"
      else SecNonce{k1 = k1', k2 = k2'}

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
  let r1' = fromMaybe (error "musig2 (publicNonce): failed to compute r1") $ mul _CURVE_G (fromInteger (k1 secNonce))
      r2' = fromMaybe (error "musig2 (publicNonce): failed to compute r2") $ mul _CURVE_G (fromInteger (k2 secNonce))
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
aggNonces :: (Traversable t) => t PubNonce -> Maybe PubNonce
aggNonces nonces
  | Seq.null noncesSeq = Nothing
  | otherwise = Just $ foldl1 (<>) noncesSeq
 where
  noncesSeq = Seq.fromList (toList nonces)
