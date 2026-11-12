module Main where

import ApplyTweaks (testApplyTweaks)
import Bip327Regressions (testBip327Regressions)
import OfficialVectors (officialVectorTests)
import SignVerify (testSignVerify)
import Test.Tasty

-- | Unit tests.
unitTests :: TestTree
unitTests = testGroup "Unit Tests" [testSignVerify, testApplyTweaks, testBip327Regressions]

-- | Run all tests.
main :: IO ()
main = do
  officialVectors <- officialVectorTests
  defaultMain (testGroup "All Tests" [officialVectors, unitTests])
