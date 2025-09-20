module Main where

import AggNonces (testAggNonces)
import AggPubkeys (testAggPubkeys)
import ApplyTweaks (testApplyTweaks)
import MonoidProjective (propertyMonoidProjective)
import MonoidPubNonce (propertyMonoidPubNonce)
import NonceGen (testNonceGen)
import NonceGenProperty (propertyNonceGen)
import ParityPub (testParityPub)
import SignVerify (testSignVerify)
import SortPubkeys (testSortPubkeys)
import Test.Tasty

-- | Unit tests.
unitTests :: TestTree
unitTests = testGroup "Unit Tests" [testSortPubkeys, testAggPubkeys, testParityPub, testApplyTweaks, testNonceGen, testAggNonces, testSignVerify]

-- | Property tests.
propertyTests :: TestTree
propertyTests = testGroup "Property Tests" [propertyMonoidProjective, propertyNonceGen, propertyMonoidPubNonce]

-- | Tests.
tests :: TestTree
tests = testGroup "All Tests" [unitTests, propertyTests]

-- | Run all tests.
main :: IO ()
main = defaultMain tests
