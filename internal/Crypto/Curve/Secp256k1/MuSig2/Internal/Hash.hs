{-# LANGUAGE OverloadedStrings #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Hash
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

The BIP-340 tagged hashes used by BIP-327 and BIP-341, with the tag prefix
\(SHA256(tag) \| SHA256(tag)\) computed once per tag.

Each hash takes its input as a list of chunks, hashed as their
concatenation. Inputs shorter than 'streamThreshold' bytes are joined and
hashed with the hardware-accelerated @hash@ of @ppad-sha256@; longer ones
(long messages or extra inputs) are hashed chunk by chunk with @hash_lazy@,
so the library never copies a long message to hash it.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Hash (
  taggedHash,
  streamThreshold,
  hashKeyAggList,
  hashKeyAggCoef,
  hashNonceCoef,
  hashChallenge,
  hashAux,
  hashNonce,
  hashDetNonce,
  hashTapTweak,
) where

import Crypto.Hash.SHA256 (hash, hash_lazy)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL

{- | @hash_tag(x) = SHA256(SHA256(tag) || SHA256(tag) || x)@, where \(x\) is
the concatenation of the chunks.

Partially apply it to a tag to share the prefix between calls.
-}
taggedHash :: ByteString -> [ByteString] -> ByteString
taggedHash tag = \xs ->
  let chunks = prefix : xs
   in if sum (map BS.length xs) < streamThreshold
        then hash (BS.concat chunks)
        else hash_lazy (BL.fromChunks chunks)
 where
  th = hash tag
  prefix = th <> th

{- | Inputs of at least this many bytes (64 KiB) are hashed chunk by chunk
instead of being joined first.

Below it, joining costs less than the slower chunked hash; above it, the
copy would dominate memory use.
-}
streamThreshold :: Int
streamThreshold = 65536

-- | @hash_KeyAgg list@.
hashKeyAggList :: [ByteString] -> ByteString
hashKeyAggList = taggedHash "KeyAgg list"
{-# NOINLINE hashKeyAggList #-}

-- | @hash_KeyAgg coefficient@.
hashKeyAggCoef :: [ByteString] -> ByteString
hashKeyAggCoef = taggedHash "KeyAgg coefficient"
{-# NOINLINE hashKeyAggCoef #-}

-- | @hash_MuSig/noncecoef@.
hashNonceCoef :: [ByteString] -> ByteString
hashNonceCoef = taggedHash "MuSig/noncecoef"
{-# NOINLINE hashNonceCoef #-}

-- | @hash_BIP0340/challenge@.
hashChallenge :: [ByteString] -> ByteString
hashChallenge = taggedHash "BIP0340/challenge"
{-# NOINLINE hashChallenge #-}

-- | @hash_MuSig/aux@.
hashAux :: [ByteString] -> ByteString
hashAux = taggedHash "MuSig/aux"
{-# NOINLINE hashAux #-}

-- | @hash_MuSig/nonce@.
hashNonce :: [ByteString] -> ByteString
hashNonce = taggedHash "MuSig/nonce"
{-# NOINLINE hashNonce #-}

-- | @hash_MuSig/deterministic/nonce@.
hashDetNonce :: [ByteString] -> ByteString
hashDetNonce = taggedHash "MuSig/deterministic/nonce"
{-# NOINLINE hashDetNonce #-}

-- | @hash_TapTweak@ (BIP-341).
hashTapTweak :: [ByteString] -> ByteString
hashTapTweak = taggedHash "TapTweak"
{-# NOINLINE hashTapTweak #-}
