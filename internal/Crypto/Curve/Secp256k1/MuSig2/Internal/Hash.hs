{-# LANGUAGE OverloadedStrings #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2.Internal.Hash
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

The BIP-340 tagged hashes used by BIP-327 and BIP-341, with the tag prefix
\(SHA256(tag) \| SHA256(tag)\) computed once per tag.

Not part of the public API.
-}
module Crypto.Curve.Secp256k1.MuSig2.Internal.Hash (
  taggedHash,
  hashKeyAggList,
  hashKeyAggCoef,
  hashNonceCoef,
  hashChallenge,
  hashAux,
  hashNonce,
  hashTapTweak,
) where

import Crypto.Hash.SHA256 (hash)
import Data.ByteString (ByteString)

{- | @hash_tag(x) = SHA256(SHA256(tag) || SHA256(tag) || x)@.

Partially apply it to a tag to share the prefix between calls.
-}
taggedHash :: ByteString -> ByteString -> ByteString
taggedHash tag = let prefix = th <> th in \x -> hash (prefix <> x)
 where
  th = hash tag

-- | @hash_KeyAgg list@.
hashKeyAggList :: ByteString -> ByteString
hashKeyAggList = taggedHash "KeyAgg list"
{-# NOINLINE hashKeyAggList #-}

-- | @hash_KeyAgg coefficient@.
hashKeyAggCoef :: ByteString -> ByteString
hashKeyAggCoef = taggedHash "KeyAgg coefficient"
{-# NOINLINE hashKeyAggCoef #-}

-- | @hash_MuSig/noncecoef@.
hashNonceCoef :: ByteString -> ByteString
hashNonceCoef = taggedHash "MuSig/noncecoef"
{-# NOINLINE hashNonceCoef #-}

-- | @hash_BIP0340/challenge@.
hashChallenge :: ByteString -> ByteString
hashChallenge = taggedHash "BIP0340/challenge"
{-# NOINLINE hashChallenge #-}

-- | @hash_MuSig/aux@.
hashAux :: ByteString -> ByteString
hashAux = taggedHash "MuSig/aux"
{-# NOINLINE hashAux #-}

-- | @hash_MuSig/nonce@.
hashNonce :: ByteString -> ByteString
hashNonce = taggedHash "MuSig/nonce"
{-# NOINLINE hashNonce #-}

-- | @hash_TapTweak@ (BIP-341).
hashTapTweak :: ByteString -> ByteString
hashTapTweak = taggedHash "TapTweak"
{-# NOINLINE hashTapTweak #-}
