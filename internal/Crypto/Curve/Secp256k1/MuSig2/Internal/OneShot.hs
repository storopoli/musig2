{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.OneShot
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

A secret that can be read at most once: a pinned mutable byte array holding
the secret bytes plus a state word. 'claimOneShot' flips the state from fresh
to claimed with an atomic compare-and-swap, copies the secret out and
zero-fills it in the buffer. Every later claim, through any copy of the
handle and from any thread, gets 'Nothing'.

The buffer is pinned, so the garbage collector never moves (and so never
copies) it. Zero-filling it is best-effort hygiene, not a guarantee: the
bytes the secret was built from, the copy 'claimOneShot' returns and
anything computed from it are ordinary heap values that are not wiped. A
buffer that is never claimed is not wiped either before its memory is
reused.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.OneShot (
  OneShot,
  newOneShot,
  claimOneShot,
  isClaimed,
  peekOneShot,
) where

import Control.Exception (mask_, onException)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import GHC.Exts (
  Int (..),
  MutableByteArray#,
  Ptr (..),
  RealWorld,
  casIntArray#,
  copyAddrToByteArray#,
  copyMutableByteArrayToAddr#,
  isTrue#,
  newAlignedPinnedByteArray#,
  readIntArray#,
  setByteArray#,
  touch#,
  writeIntArray#,
  (+#),
  (==#),
 )
import GHC.IO (IO (..))

{- | A handle to a pinned buffer. Copies of the handle share the buffer and
its state.

Layout: one machine word of state (@0@ fresh, @1@ claimed) at byte offset
@0@, then the secret bytes from byte offset 'secretOffset'.
-}
data OneShot = OneShot !Int (MutableByteArray# RealWorld)

-- | Byte offset of the secret in the buffer (after the state word).
secretOffset :: Int
secretOffset = 8

-- | Copies the bytes into a new pinned buffer, in the fresh state.
newOneShot :: ByteString -> IO OneShot
newOneShot bytes = do
  let !(I# n) = BS.length bytes
      !(I# off) = secretOffset
  os <- IO $ \s0 -> case newAlignedPinnedByteArray# (off +# n) off s0 of
    (# s1, mba #) -> case writeIntArray# mba 0# 0# s1 of
      s2 -> (# s2, OneShot (I# n) mba #)
  BU.unsafeUseAsCString bytes $ \(Ptr addr) -> withBuffer os $ \mba ->
    IO $ \s -> (# copyAddrToByteArray# addr mba off n s, () #)
  pure os

{- | Claims the secret: atomically marks the buffer claimed, returns a copy of
the secret and zero-fills it in the buffer. 'Nothing' if it was claimed
before.

Asynchronous exceptions are masked, so a claim either does not happen or
both marks the buffer and wipes it.
-}
claimOneShot :: OneShot -> IO (Maybe ByteString)
claimOneShot os@(OneShot len mba) = mask_ $ do
  won <- IO $ \s0 -> case casIntArray# mba 0# 0# 1# s0 of
    (# s1, old #) -> (# s1, isTrue# (old ==# 0#) #)
  if not won
    then pure Nothing
    else do
      secret <- copyOut os `onException` wipe
      wipe
      pure (Just secret)
 where
  !(I# n) = len
  !(I# off) = secretOffset
  wipe = IO $ \s -> (# setByteArray# mba off n 0# s, () #)

-- | Whether the buffer has been claimed.
isClaimed :: OneShot -> IO Bool
isClaimed (OneShot _ mba) = IO $ \s0 -> case readIntArray# mba 0# s0 of
  (# s1, st #) -> (# s1, isTrue# (st ==# 1#) #)

{- | The current contents of the secret area, without claiming it (all zero
after a claim). For tests only: it defeats the point of the buffer.
-}
peekOneShot :: OneShot -> IO ByteString
peekOneShot = copyOut

-- | A copy of the secret area.
copyOut :: OneShot -> IO ByteString
copyOut os@(OneShot len _) =
  BI.create len $ \(Ptr addr) -> withBuffer os $ \mba ->
    IO $ \s -> (# copyMutableByteArrayToAddr# mba off addr n s, () #)
 where
  !(I# n) = len
  !(I# off) = secretOffset

-- | Runs an action on the buffer, keeping it alive until the action ends.
withBuffer :: OneShot -> (MutableByteArray# RealWorld -> IO a) -> IO a
withBuffer (OneShot _ mba) k = do
  r <- k mba
  IO $ \s -> (# touch# mba s, () #)
  pure r
