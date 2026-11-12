module Main where

import ApplyTweaks (testApplyTweaks)
import Bip327Regressions (testBip327Regressions)
import Encoding (testEncoding)
import Example (testExample)
import NonceSafety (testNonceSafety)
import OfficialVectors (officialVectorTests)
import Properties (testProtocol)
import SignVerify (testSignVerify)
import Test.Tasty

-- | Unit tests.
unitTests :: TestTree
unitTests = testGroup "Unit Tests" [testExample, testSignVerify, testNonceSafety, testApplyTweaks, testBip327Regressions]

-- | Property tests.
propertyTests :: TestTree
propertyTests = testGroup "Property Tests" [testEncoding, testProtocol]

-- | Run all tests.
main :: IO ()
main = do
  officialVectors <- officialVectorTests
  defaultMain (testGroup "All Tests" [officialVectors, unitTests, propertyTests])
