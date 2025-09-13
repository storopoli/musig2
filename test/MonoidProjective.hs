{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Monoid law, right identity" #-}
{-# HLINT ignore "Monoid law, left identity" #-}

module MonoidProjective (propertyMonoidProjective) where

import Crypto.Curve.Secp256k1 (Projective (..))
import Crypto.Curve.Secp256k1.MuSig2 ()
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Util ()

propertyMonoidProjective :: TestTree
propertyMonoidProjective =
  testGroup
    "Monoid Laws for Projective"
    [ testProperty "Left Identity" prop_leftIdentity
    , testProperty "Right Identity" prop_rightIdentity
    , testProperty "Associativity" prop_associativity
    ]

-- | Left identity 'Monoid' law.
prop_leftIdentity :: Projective -> Property
prop_leftIdentity x = mempty <> x === x

-- | Right identity 'Monoid' law.
prop_rightIdentity :: Projective -> Property
prop_rightIdentity x = x <> mempty === x

-- | Associativity 'Monoid' law.
prop_associativity :: Projective -> Projective -> Projective -> Property
prop_associativity x y z = (x <> y) <> z === x <> (y <> z)
