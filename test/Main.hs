module Main where

import AggPubkeys (testAggPubkeys)
import MonoidProjective (propertyMonoidProjective)
import ParityPub (testParityPub)
import SortPubkeys (testSortPubkeys)
import Test.Tasty

-- | Unit tests.
unitTests :: TestTree
unitTests = testGroup "Unit Tests" [testSortPubkeys, testAggPubkeys, testParityPub]

-- | Property tests.
propertyTests :: TestTree
propertyTests = testGroup "Property Tests" [propertyMonoidProjective]

-- | Tests.
tests :: TestTree
tests = testGroup "All Tests" [unitTests, propertyTests]

-- | Run all tests.
main :: IO ()
main = defaultMain tests
