{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE InstanceSigs #-}
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
module Crypto.Curve.Secp256k1.MuSig2 (sortPubkeys, Monoid, Semigroup) where

import Crypto.Curve.Secp256k1 (Projective, Pub, add, serialize_point, _CURVE_ZERO)
import Data.List (sort)

-- | Manual 'Ord' implementation of 'Projective' for lexicography sorting.
instance Ord Projective where
  compare x y = compare (serialize_point x) (serialize_point y)

-- | 'Semigroup' implementation of 'Projective' for algebraic sound combination of points.
instance Semigroup Projective where
  (<>) :: Projective -> Projective -> Projective
  (<>) = add

-- | 'Monoid' implementation of 'Projective' for algebraic sound combination of points.
instance Monoid Projective where
  mempty :: Projective
  mempty = _CURVE_ZERO

-- | Lexicographically 'sort's a 'List' of 'Pub'keys.
sortPubkeys :: [Pub] -> [Pub]
sortPubkeys = sort
