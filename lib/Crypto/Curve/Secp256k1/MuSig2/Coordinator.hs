{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Coordinator
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

A coordinator for BIP-327 signing sessions: it collects the signers'
contributions as bytes from the network, decodes and verifies each one as it
arrives, and blames the signer responsible for anything wrong.

The coordinator can be one of the signers or a separate party. It runs two
rounds:

1. __Public nonces.__ 'newNonceRound' on the session's key aggregation
   context (with all tweaks applied), 'receivePubNonce' for each signer's
   encoded t'PubNonce', then 'finishNonceRound', which gives the aggregate
   nonce to send back to every signer.
2. __Partial signatures.__ 'newSigRound' on the collected nonces and the
   message, 'receivePartialSig' for each signer's encoded
   t'PartialSignature' (each one is checked with 'partialSigVerify'), then
   'finishSigRound', which aggregates them and checks the final BIP-340
   signature.

Signers are identified by their index in 'keyAggPubKeys', from \(0\). A
public key that appears more than once in the key list belongs to as many
signers, each with its own index, nonce and partial signature.

Every function is pure and every value is immutable, so the rounds are safe
to share between threads. To receive from several threads, keep the round in
an @IORef@ (updated with @atomicModifyIORef'@), an @MVar@ or a @TVar@.

== Blame

'receivePubNonce' and 'receivePartialSig' return a t'Blame' naming the
signer and the reason, and leave the round unchanged: the caller decides
whether to abort the session or wait for the signer to send a valid
contribution. A signer may send the same bytes again (a network retry is not
an error), but a different contribution from a signer whose contribution was
accepted is a 'DuplicateContribution'. The finishing functions blame every
signer whose contribution is still missing. Blames carry no secrets.

The signer index passed to 'receivePubNonce' and 'receivePartialSig' is
trusted: take it from the authenticated connection the bytes arrived on (for
example, a roster that maps each signer's authenticated identity to its
index), never from the message itself. A participant that can choose the
index can send a valid nonce in an honest signer's slot first: the honest
signer's own nonce is then blamed as a 'DuplicateContribution', and its
partial signature, checked against the wrong nonce, as invalid. It cannot
make the coordinator accept an invalid signature, but it can make the
session fail with an honest signer blamed.

== Trust

The coordinator learns nothing secret and cannot forge signatures, so the
signers need not trust it: BIP-327 treats the nonce aggregator as untrusted,
and a coordinator that sends a wrong aggregate nonce can only make the
session fail. Its blame, however, is only as reliable as the coordinator
itself: a signer that wants to check the other signers must receive their
public nonces and partial signatures and run 'nonceAgg' and
'partialSigVerify' itself.

Signers who receive the aggregate nonce from a coordinator 'decode' it as an
t'AggNonce', open the session with 'newSession' on the same key aggregation
context and message, and 'Crypto.Curve.Secp256k1.MuSig2.sign'.

The coordinator does not support
'Crypto.Curve.Secp256k1.MuSig2.deterministicSign', whose signer sends its
public nonce together with its partial signature, after the other signers'
nonces are aggregated.

== Example

A coordinator collects the contributions of three signers. This example is
compiled and run by the test suite; it needs the @OverloadedStrings@
language extension and uses @orThrow@ from the example in
"Crypto.Curve.Secp256k1.MuSig2".

> import Control.Monad (foldM)
> import qualified Crypto.Curve.Secp256k1.MuSig2 as MuSig2
> import qualified Crypto.Curve.Secp256k1.MuSig2.Coordinator as Coordinator
> import Data.Bifunctor (first)
> import qualified Data.ByteString as BS
> import Data.List.NonEmpty (NonEmpty (..))
> import qualified Data.List.NonEmpty as NE

> -- | A coordinator collects three signers' nonces and partial signatures as bytes.
> coordinatorExample :: IO Bool
> coordinatorExample = do
>   sks <- traverse (orThrow . MuSig2.secKeyFromBytes . BS.replicate 32) (0x66 :| [0x77, 0x88])
>   -- Signer i is the one with the i-th public key of the context.
>   keyAggCtx <- orThrow (MuSig2.keyAgg (fmap MuSig2.secKeyPubKey sks))
>   let msg = "pay Carol 1 BTC"
>
>   -- Round one: each signer sends its encoded public nonce, in any order.
>   nonces <- traverse (\sk -> MuSig2.nonceGen (MuSig2.secKeyPubKey sk) MuSig2.noNonceInputs >>= orThrow) (NE.toList sks)
>   nonceRound <-
>     orThrow $
>       foldM
>         (\r (i, (_, pubNonce)) -> Coordinator.receivePubNonce i (MuSig2.encode pubNonce) r)
>         (Coordinator.newNonceRound keyAggCtx)
>         (zip [0 ..] nonces)
>   -- Fails if a nonce is missing (here reporting only the first such signer).
>   collected <- orThrow (first NE.head (Coordinator.finishNonceRound nonceRound))
>
>   -- The coordinator sends the aggregate nonce to every signer, who decodes it
>   -- and opens the session.
>   aggNonce <- orThrow (MuSig2.decode (MuSig2.encode (Coordinator.collectedAggNonce collected)))
>   let session = MuSig2.newSession keyAggCtx aggNonce msg
>
>   -- Round two: each signer sends its encoded partial signature. The
>   -- coordinator verifies each one and blames the signer of an invalid one.
>   psigs <- traverse (\(sk, (secNonce, _)) -> MuSig2.sign secNonce sk session >>= orThrow) (zip (NE.toList sks) nonces)
>   sigRound <-
>     orThrow $
>       foldM
>         (\r (i, psig) -> Coordinator.receivePartialSig i (MuSig2.encode psig) r)
>         (Coordinator.newSigRound collected msg)
>         (zip [0 ..] psigs)
>   -- Aggregates the partial signatures and verifies the result.
>   signature <- orThrow (Coordinator.finishSigRound sigRound)
>   pure (MuSig2.verify (MuSig2.aggXOnlyPubKey keyAggCtx) msg signature)
-}
module Crypto.Curve.Secp256k1.MuSig2.Coordinator (
  -- * Blame
  Blame (..),
  BlameReason (..),

  -- * Round one: public nonces
  NonceRound,
  newNonceRound,
  receivePubNonce,
  nonceRoundMissing,
  finishNonceRound,
  CollectedNonces,
  collectedKeyAgg,
  collectedPubNonces,
  collectedAggNonce,

  -- * Round two: partial signatures
  SigRound,
  newSigRound,
  sigRoundSession,
  receivePartialSig,
  sigRoundMissing,
  finishSigRound,
  SigRoundError (..),
) where

import Control.DeepSeq (NFData (..), rwhnf)
import Control.Exception (Exception)
import Crypto.Curve.Secp256k1.MuSig2 (
  AggNonce,
  DecodeError,
  Encode (..),
  KeyAggContext,
  PartialSignature,
  PubKey,
  PubNonce,
  Session,
  Signature,
  aggXOnlyPubKey,
  keyAggPubKeys,
  newSession,
  nonceAgg,
  partialSigAgg,
  partialSigVerify,
  sessionKeyAgg,
  verify,
 )
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.Foldable (toList)
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IntMap
import Data.List.NonEmpty (NonEmpty (..), nonEmpty)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq

-- Blame ----------------------------------------------------------------------

-- | A signer who misbehaved, and how.
data Blame = Blame
  { blameSigner :: !Int
  -- ^ The signer's index in 'keyAggPubKeys' (for 'UnknownSigner', the index it claimed).
  , blameReason :: !BlameReason
  -- ^ What the signer did wrong.
  }
  deriving (Eq, Show)

instance Exception Blame

instance NFData Blame where
  rnf = rwhnf

-- | Why a signer is blamed.
data BlameReason
  = -- | The signer's public nonce does not decode (wrong length, invalid or infinite point).
    InvalidPubNonceEncoding !DecodeError
  | -- | The signer's partial signature does not decode (wrong length, not below \(n\)).
    InvalidPartialSigEncoding !DecodeError
  | {- | The signer's partial signature fails 'partialSigVerify' for its
    public key and public nonce: it is wrong, or it is another signer's.
    -}
    InvalidPartialSignature
  | -- | The signer already sent a different, accepted contribution in this round.
    DuplicateContribution
  | -- | The index is not a signer of the session (negative, or not below the number of keys).
    UnknownSigner
  | -- | The round was finished without the signer's contribution.
    MissingContribution
  deriving (Eq, Show)

instance NFData BlameReason where
  rnf = rwhnf

-- | Contributions by signer index: all of them, or the blame of every missing one.
collect :: Int -> IntMap a -> Either (NonEmpty Blame) (NonEmpty a)
collect size received = case nonEmpty [Blame i MissingContribution | Left i <- toList entries] of
  Just missing -> Left missing
  Nothing -> traverse (first (\i -> Blame i MissingContribution :| [])) entries
 where
  entries = fmap (\i -> maybe (Left i) Right (IntMap.lookup i received)) (0 :| [1 .. size - 1])

-- | The indices in \([0, size)\) without a contribution.
missingFrom :: Int -> IntMap a -> [Int]
missingFrom size received = filter (`IntMap.notMember` received) [0 .. size - 1]

-- Round one ---------------------------------------------------------------------

{- | Round one in progress: the public nonces received so far, by signer
index.
-}
data NonceRound = NonceRound
  { nrKeyAgg :: !KeyAggContext
  , nrSize :: !Int
  , nrNonces :: !(IntMap PubNonce)
  }

instance NFData NonceRound where
  rnf (NonceRound ctx size nonces) = rnf ctx `seq` rnf size `seq` rnf nonces

{- | Starts round one for the signers of a key aggregation context, with no
nonce received yet.

Pass the context the session will use, with all tweaks applied:
'newSigRound' opens the session on it.
-}
newNonceRound :: KeyAggContext -> NonceRound
newNonceRound ctx = NonceRound ctx (length (keyAggPubKeys ctx)) IntMap.empty

{- | Receives a signer's encoded public nonce (66 bytes).

Blames the signer with 'UnknownSigner', 'DuplicateContribution' (a
different nonce was already accepted from it; the same bytes again are
accepted and change nothing) or 'InvalidPubNonceEncoding'. On 'Left' the
round is unchanged.
-}
receivePubNonce ::
  -- | Signer index, from the authenticated connection the bytes arrived on.
  Int ->
  -- | The encoded public nonce.
  ByteString ->
  NonceRound ->
  Either Blame NonceRound
receivePubNonce i bytes nr
  | i < 0 || i >= nrSize nr = blame UnknownSigner
  | Just prev <- IntMap.lookup i (nrNonces nr) =
      if encode prev == bytes then Right nr else blame DuplicateContribution
  | otherwise = case decode bytes of
      Left err -> blame (InvalidPubNonceEncoding err)
      Right pn -> Right nr{nrNonces = IntMap.insert i pn (nrNonces nr)}
 where
  blame = Left . Blame i

-- | The signers whose public nonce has not been received yet, in increasing order.
nonceRoundMissing :: NonceRound -> [Int]
nonceRoundMissing nr = missingFrom (nrSize nr) (nrNonces nr)

{- | Ends round one: aggregates the public nonces (BIP-327 @NonceAgg@).
Blames every signer whose nonce is missing with 'MissingContribution', in
increasing index order.
-}
finishNonceRound :: NonceRound -> Either (NonEmpty Blame) CollectedNonces
finishNonceRound nr = do
  pns <- collect (nrSize nr) (nrNonces nr)
  Right (CollectedNonces (nrKeyAgg nr) pns (nonceAgg pns))

{- | The result of round one: every signer's public nonce and their
aggregate.
-}
data CollectedNonces = CollectedNonces
  { cnKeyAgg :: !KeyAggContext
  , cnPubNonces :: !(NonEmpty PubNonce)
  , cnAggNonce :: !AggNonce
  }

instance NFData CollectedNonces where
  rnf (CollectedNonces ctx pns agg) = rnf ctx `seq` rnf pns `seq` rnf agg

-- | The key aggregation context the round was started with.
collectedKeyAgg :: CollectedNonces -> KeyAggContext
collectedKeyAgg = cnKeyAgg

-- | Every signer's public nonce, in signer order.
collectedPubNonces :: CollectedNonces -> NonEmpty PubNonce
collectedPubNonces = cnPubNonces

-- | The aggregate nonce, to send to every signer ('encode' it).
collectedAggNonce :: CollectedNonces -> AggNonce
collectedAggNonce = cnAggNonce

-- Round two --------------------------------------------------------------------

{- | Round two in progress: the session, and the verified partial signatures
received so far, by signer index.
-}
data SigRound = SigRound
  { srSession :: !Session
  , srMessage :: !ByteString
  , srSigners :: !(Seq (PubKey, PubNonce))
  , srPsigs :: !(IntMap PartialSignature)
  }

instance NFData SigRound where
  rnf (SigRound ses msg signers psigs) = rnf ses `seq` rnf msg `seq` rnf signers `seq` rnf psigs

{- | Starts round two: opens the session ('newSession') on the key
aggregation context and aggregate nonce of round one, for the message.
-}
newSigRound :: CollectedNonces -> ByteString -> SigRound
newSigRound cn msg =
  SigRound
    { srSession = newSession (cnKeyAgg cn) (cnAggNonce cn) msg
    , srMessage = msg
    , srSigners = Seq.fromList (zip (toList (keyAggPubKeys (cnKeyAgg cn))) (toList (cnPubNonces cn)))
    , srPsigs = IntMap.empty
    }

-- | The session the partial signatures are verified in (the coordinator can sign in it too).
sigRoundSession :: SigRound -> Session
sigRoundSession = srSession

{- | Receives a signer's encoded partial signature (32 bytes) and verifies it
with 'partialSigVerify' against the signer's public key and public nonce.

Blames the signer with 'UnknownSigner', 'DuplicateContribution' (a
different partial signature was already accepted from it; the same bytes
again are accepted and change nothing), 'InvalidPartialSigEncoding' or
'InvalidPartialSignature'. On 'Left' the round is unchanged.
-}
receivePartialSig ::
  -- | Signer index, from the authenticated connection the bytes arrived on.
  Int ->
  -- | The encoded partial signature.
  ByteString ->
  SigRound ->
  Either Blame SigRound
receivePartialSig i bytes sr = case Seq.lookup i (srSigners sr) of
  Nothing -> blame UnknownSigner
  Just (pk, pn) -> case IntMap.lookup i (srPsigs sr) of
    Just prev -> if encode prev == bytes then Right sr else blame DuplicateContribution
    Nothing -> case decode bytes of
      Left err -> blame (InvalidPartialSigEncoding err)
      Right psig
        | partialSigVerify (srSession sr) pk pn psig -> Right sr{srPsigs = IntMap.insert i psig (srPsigs sr)}
        | otherwise -> blame InvalidPartialSignature
 where
  blame = Left . Blame i

-- | The signers whose partial signature has not been accepted yet, in increasing order.
sigRoundMissing :: SigRound -> [Int]
sigRoundMissing sr = missingFrom (Seq.length (srSigners sr)) (srPsigs sr)

-- | Why round two cannot produce a signature.
data SigRoundError
  = -- | Partial signatures are missing: blames each of those signers with 'MissingContribution'.
    SigRoundBlame !(NonEmpty Blame)
  | {- | Every partial signature verified, but their aggregate is not a valid
    BIP-340 signature. This happens if the final nonce is the point at
    infinity, for which BIP-327 substitutes the generator: the signers'
    nonces cancel out, which takes every signer colluding (an honest signer's
    nonce is unpredictable) or negligible luck. Otherwise the coordinator
    itself is faulty (a bug or, e.g., a bit flip). No single signer can be
    blamed.
    -}
    FinalSignatureInvalid
  deriving (Eq, Show)

instance Exception SigRoundError

instance NFData SigRoundError where
  rnf = rwhnf

{- | Ends round two: aggregates the partial signatures (BIP-327
@PartialSigAgg@) and checks the result with 'verify' against the session's
'aggXOnlyPubKey' before returning it.
-}
finishSigRound :: SigRound -> Either SigRoundError Signature
finishSigRound sr = do
  psigs <- first SigRoundBlame (collect (Seq.length (srSigners sr)) (srPsigs sr))
  let ses = srSession sr
      sig = partialSigAgg ses psigs
  if verify (aggXOnlyPubKey (sessionKeyAgg ses)) (srMessage sr) sig then Right sig else Left FinalSignatureInvalid
