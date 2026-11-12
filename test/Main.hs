module Main where

import AggPartialsProperty (propertyAggPartials)
import ApplyTweaks (testApplyTweaks)
import Bip327Regressions (testBip327Regressions)
import MonoidProjective (propertyMonoidProjective)
import MonoidPubNonce (propertyMonoidPubNonce)
import NonceGenProperty (propertyNonceGen)
import OfficialVectors (officialVectorTests)
import ParityPub (testParityPub)
import SignVerify (testSignVerify)
import SignVerifyProperty (propertySignVerify)
import SignVerifyTweakProperty (propertySignVerifyTweak)
import Test.Tasty

-- | Unit tests.
unitTests :: TestTree
unitTests = testGroup "Unit Tests" [testParityPub, testApplyTweaks, testSignVerify, testBip327Regressions]

-- | Property tests.
propertyTests :: TestTree
propertyTests = testGroup "Property Tests" [propertyMonoidProjective, propertyNonceGen, propertyMonoidPubNonce, propertySignVerify, propertySignVerifyTweak, propertyAggPartials]

-- | Tests.
tests :: TestTree -> TestTree
tests officialVectors = testGroup "All Tests" [officialVectors, unitTests, propertyTests]

-- | Run all tests.
main :: IO ()
main = officialVectorTests >>= defaultMain . tests
