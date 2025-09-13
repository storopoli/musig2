module Main where

import MonoidProjective (propertyMonoidProjective)
import SortPubkeys (testSortPubkey)
import Test.Tasty

-- | Unit tests.
unitTests :: TestTree
unitTests = testGroup "Unit Tests" [testSortPubkey]

-- | Property tests.
propertyTests :: TestTree
propertyTests = testGroup "Property Tests" [propertyMonoidProjective]

-- | Tests.
tests :: TestTree
tests = testGroup "All Tests" [unitTests, propertyTests]

-- | Run all tests.
main :: IO ()
main = defaultMain tests
