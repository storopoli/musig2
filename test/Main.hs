module Main where

import ApplyTweaks (testApplyTweaks)
import Bip327Regressions (testBip327Regressions)
import CoordinatorRounds (testCoordinator)
import DiffCorpus (diffCorpusTests)
import Encoding (testEncoding)
import Example (testExample)
import LongInputs (testLongInputs)
import NonceSafety (testNonceSafety)
import OfficialVectors (officialVectorTests)
import Properties (testProtocol)
import Scalars (testScalars)
import SignVerify (testSignVerify)
import Test.Tasty

-- | Unit tests.
unitTests :: TestTree
unitTests = testGroup "Unit Tests" [testExample, testSignVerify, testNonceSafety, testApplyTweaks, testBip327Regressions, testCoordinator, testLongInputs]

-- | Property tests.
propertyTests :: TestTree
propertyTests = testGroup "Property Tests" [testEncoding, testScalars, testProtocol]

-- | Run all tests.
main :: IO ()
main = do
  officialVectors <- officialVectorTests
  diffCorpus <- diffCorpusTests
  defaultMain (testGroup "All Tests" [officialVectors, diffCorpus, unitTests, propertyTests])
