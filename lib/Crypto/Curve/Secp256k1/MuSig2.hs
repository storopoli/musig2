{-# LANGUAGE FlexibleInstances #-}
{-# OPTIONS_GHC -Wno-orphans #-}
{-# OPTIONS_HADDOCK prune #-}

{- |
Module: Crypto.Curve.Secp256k1.MuSig2
Copyright: (c) 2025 Jose Storopoli
License: MIT
Maintainer: Jose Storopoli <jose@storopoli.com>

MuSig2 signing Haskell library.
TODO: add description
-}
module Crypto.Curve.Secp256k1.MuSig2 (sortPubkeys) where

import Crypto.Curve.Secp256k1 (Pub, serialize_point)
import Data.List (sort)

-- | Manual 'Ord' implementation of 'Projective' for lexicography sorting.
instance Ord Projective where
  compare x y = compare (serialize_point x) (serialize_point y)

-- | Lexicographically 'sort's a 'List' of 'Pub'keys.
sortPubkeys :: [Pub] -> [Pub]
sortPubkeys = sort
