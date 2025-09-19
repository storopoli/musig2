{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Monoid law, right identity" #-}
{-# HLINT ignore "Monoid law, left identity" #-}

module MonoidPubNonce (propertyMonoidPubNonce) where

import Crypto.Curve.Secp256k1.MuSig2 (PubNonce)
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Util ()

propertyMonoidPubNonce :: TestTree
propertyMonoidPubNonce =
  testGroup
    "Monoid Laws for PubNonce"
    [ testProperty "Left Identity" prop_leftIdentity
    , testProperty "Right Identity" prop_rightIdentity
    , testProperty "Associativity" prop_associativity
    ]

-- | Left identity 'Monoid' law.
prop_leftIdentity :: PubNonce -> Property
prop_leftIdentity x = mempty <> x === x

-- | Right identity 'Monoid' law.
prop_rightIdentity :: PubNonce -> Property
prop_rightIdentity x = x <> mempty === x

-- | Associativity 'Monoid' law.
prop_associativity :: PubNonce -> PubNonce -> PubNonce -> Property
prop_associativity x y z = (x <> y) <> z === x <> (y <> z)
