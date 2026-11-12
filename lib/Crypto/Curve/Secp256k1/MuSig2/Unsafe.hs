{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Unsafe
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

Escape hatches from the guarantees of "Crypto.Curve.Secp256k1.MuSig2".

__Do not use this module unless you know exactly why you need it.__ Every
function here can make you reuse a nonce, and signing twice with the same
nonce, in any two sessions, lets the other signers compute your secret key.

* 'nonceGenWithRand' and 'nonceGenCounter' generate nonces
  deterministically from their inputs: if the random bytes (or the counter)
  ever repeat, so does the nonce. Use them for test vectors, or with a
  counter you can prove never repeats; otherwise use
  'Crypto.Curve.Secp256k1.MuSig2.nonceGen'.

* 'secNonceToBytes' and 'secNonceFromBytes' move a secret nonce out of the
  process and back, e.g. to keep it on disk between the two rounds of a
  session. The library can only prevent reuse within one process: storing
  the bytes and importing them twice (or restoring a backup, or a snapshot
  of a virtual machine) reuses the nonce. Delete the bytes before signing
  with the imported nonce, and never keep a copy.

* 'signWithoutVerification' skips the check of the partial signature that
  'Crypto.Curve.Secp256k1.MuSig2.sign' does, so a fault during signing goes
  unnoticed. Use it only if you verify the partial signature yourself or
  cannot afford the time.

For a signer who cannot rely on randomness at all, prefer
'Crypto.Curve.Secp256k1.MuSig2.deterministicSign', which is safe when the
signer sends its nonce last.
-}
module Crypto.Curve.Secp256k1.MuSig2.Unsafe (
  -- * Deterministic nonce generation
  nonceGenWithRand,
  nonceGenCounter,

  -- * Secret nonce import and export
  secNonceToBytes,
  secNonceFromBytes,

  -- * Signing
  signWithoutVerification,
) where

import Crypto.Curve.Secp256k1.MuSig2.Internal.Error (DecodeError, NonceGenError, SignError)
import Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce (NonceInputs, SecNonce)
import qualified Crypto.Curve.Secp256k1.MuSig2.Internal.Nonce as Nonce
import Crypto.Curve.Secp256k1.MuSig2.Internal.Session (Session)
import qualified Crypto.Curve.Secp256k1.MuSig2.Internal.Session as Session
import Crypto.Curve.Secp256k1.MuSig2.Internal.Types (PartialSignature, PubKey, PubNonce, SecKey)
import Data.ByteString (ByteString)
import Data.Word (Word64)

{- | BIP-327 @NonceGen@ with caller-supplied randomness instead of the
operating system's.

__Deterministic: the same random bytes and inputs give the same nonce.__
Reusing the bytes for two sessions reuses the nonce and leaks the secret
key. The bytes must be 32 bytes of fresh, uniformly random data used for
nothing else; this function exists for test vectors and for callers with
their own vetted random number generator.

Each call returns a fresh one-shot t'SecNonce', so two calls with the same
bytes give two nonces with the same secret scalars, which
'Crypto.Curve.Secp256k1.MuSig2.sign' cannot tell apart. (It is in 'IO',
although deterministic, so that one call creates exactly one t'SecNonce':
GHC may evaluate a pure thunk twice when two threads force it at once.)

Fails with 'Crypto.Curve.Secp256k1.MuSig2.InvalidRandLength' if the bytes
are not 32 long, with 'Crypto.Curve.Secp256k1.MuSig2.NonceIsZero' with
negligible probability, and otherwise as
'Crypto.Curve.Secp256k1.MuSig2.nonceGen'.
-}
nonceGenWithRand ::
  -- | 32 random bytes, never reused.
  ByteString ->
  -- | The signer's public key.
  PubKey ->
  NonceInputs ->
  IO (Either NonceGenError (SecNonce, PubNonce))
nonceGenWithRand = Nonce.nonceGenWithRand

{- | Counter-based nonce generation (BIP-327 @CounterNonceGen@), compatible
with libsecp256k1's @secp256k1_musig_nonce_gen_counter@: @NonceGen@ with the
secret key always hashed in (the 'Crypto.Curve.Secp256k1.MuSig2.nonceSecKey'
of the inputs is ignored) and the random bytes
@bytes(8, counter) || bytes(24, 0)@.

__The counter must never repeat for the same secret key__, across restarts,
backups and every device holding the key: a repeated counter with the same
inputs repeats the nonce and leaks the secret key. Use it only where a
reliable non-repeating counter is easier to get than randomness. Each call
returns a fresh one-shot t'SecNonce', like 'nonceGenWithRand'.

Fails with 'Crypto.Curve.Secp256k1.MuSig2.NonceIsZero' with negligible
probability, and otherwise as 'Crypto.Curve.Secp256k1.MuSig2.nonceGen'.
-}
nonceGenCounter ::
  -- | The signer's secret key.
  SecKey ->
  -- | A counter value never used before with this key.
  Word64 ->
  NonceInputs ->
  IO (Either NonceGenError (SecNonce, PubNonce))
nonceGenCounter = Nonce.nonceGenCounter

{- | Exports a secret nonce in the 97-byte BIP-327 encoding
@bytes(32, k1) || bytes(32, k2) || pk@, __consuming it__: the t'SecNonce'
(and every copy of it) can no longer sign. 'Nothing' if it was already used
or exported.

The encoding does not carry the aggregate key or message the nonce may have
been generated with, so a nonce imported back with 'secNonceFromBytes' is no
longer bound to them.

The bytes are as secret as the secret key, and importing them more than once
reuses the nonce: see the module documentation.
-}
secNonceToBytes :: SecNonce -> IO (Maybe ByteString)
secNonceToBytes = Nonce.secNonceToBytes

{- | Imports a secret nonce from its 97-byte BIP-327 encoding, as a fresh
one-shot t'SecNonce'. Checks that both scalars are in \([1, n)\) (a nonce
zeroed by another BIP-327 implementation after use is rejected with
'Crypto.Curve.Secp256k1.MuSig2.ScalarZero') and that the public key is a
valid encoding.

__Each encoding must be imported at most once__: the library cannot know
that two imports are the same nonce. See the module documentation.
-}
secNonceFromBytes :: ByteString -> IO (Either DecodeError SecNonce)
secNonceFromBytes = Nonce.secNonceFromBytes

{- | 'Crypto.Curve.Secp256k1.MuSig2.sign' without the verification of the
partial signature before it is returned.

Consumes the nonce exactly like 'Crypto.Curve.Secp256k1.MuSig2.sign' and
makes the same checks, except that it never returns
'Crypto.Curve.Secp256k1.MuSig2.SelfVerificationFailed': a fault during
signing (a bug, a bit flip, a fault attack) then goes unnoticed and the
faulty partial signature is released, which can leak the secret key. It
saves the elliptic curve multiplications of the check, which are nearly all
the work of signing once the 'Session' exists.
-}
signWithoutVerification :: SecNonce -> SecKey -> Session -> IO (Either SignError PartialSignature)
signWithoutVerification = Session.signWithoutVerification
