{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module NonceGen (testNonceGen) where

import Crypto.Curve.Secp256k1 (Pub)
import Crypto.Curve.Secp256k1.MuSig2 (PubNonce (..), SecKey (..), SecNonce (..), SecNonceGenParams (..), publicNonce, secNonceGenWithRand)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit
import Util (decodeHex, parsePoint, parseScalar)

-- | Test vector structure.
data NonceGenTestVector = NonceGenTestVector
  { rand_ :: BS.ByteString
  , sk :: Maybe Integer
  , pk :: Pub
  , aggpk :: Maybe Pub
  , msg :: Maybe ByteString
  , extra_in :: Maybe ByteString
  , expected_k1 :: Integer
  , expected_k2 :: Integer
  , expected_r1 :: Pub
  , expected_r2 :: Pub
  }

-- | Hardcoded test vectors from bip-0327/vectors/nonce_gen_vectors.json.
testVectors :: [NonceGenTestVector]
testVectors =
  [ NonceGenTestVector
      { rand_ = decodeHex "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
      , sk = Just 0x0202020202020202020202020202020202020202020202020202020202020202
      , pk = parsePoint "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766"
      , aggpk = Just $ parsePoint "0707070707070707070707070707070707070707070707070707070707070707"
      , msg = Just $ decodeHex "0101010101010101010101010101010101010101010101010101010101010101"
      , extra_in = Just $ decodeHex "0808080808080808080808080808080808080808080808080808080808080808"
      , expected_k1 = parseScalar "B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB64"
      , expected_k2 = parseScalar "95B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2"
      , expected_r1 = parsePoint "02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF"
      , expected_r2 = parsePoint "02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A"
      }
  , NonceGenTestVector
      { rand_ = decodeHex "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
      , sk = Just 0x0202020202020202020202020202020202020202020202020202020202020202
      , pk = parsePoint "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766"
      , aggpk = Just $ parsePoint "0707070707070707070707070707070707070707070707070707070707070707"
      , msg = Just $ decodeHex ""
      , extra_in = Just $ decodeHex "0808080808080808080808080808080808080808080808080808080808080808"
      , expected_k1 = parseScalar "E862B068500320088138468D47E0E6F147E01B6024244AE45EAC40ACE5929B9F"
      , expected_k2 = parseScalar "0789E051170B9E705D0B9EB49049A323BBBBB206D8E05C19F46C6228742AA7A9"
      , expected_r1 = parsePoint "023034FA5E2679F01EE66E12225882A7A48CC66719B1B9D3B6C4DBD743EFEDA2C5"
      , expected_r2 = parsePoint "03F3FD6F01EB3A8E9CB315D73F1F3D287CAFBB44AB321153C6287F407600205109"
      }
  , NonceGenTestVector
      { rand_ = decodeHex "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
      , sk = Just 0x0202020202020202020202020202020202020202020202020202020202020202
      , pk = parsePoint "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766"
      , aggpk = Just $ parsePoint "0707070707070707070707070707070707070707070707070707070707070707"
      , msg = Just $ decodeHex "2626262626262626262626262626262626262626262626262626262626262626262626262626"
      , extra_in = Just $ decodeHex "0808080808080808080808080808080808080808080808080808080808080808"
      , expected_k1 = parseScalar "3221975ACBDEA6820EABF02A02B7F27D3A8EF68EE42787B88CBEFD9AA06AF363"
      , expected_k2 = parseScalar "2EE85B1A61D8EF31126D4663A00DD96E9D1D4959E72D70FE5EBB6E7696EBA66F"
      , expected_r1 = parsePoint "02E5BBC21C69270F59BD634FCBFA281BE9D76601295345112C58954625BF23793A"
      , expected_r2 = parsePoint "021307511C79F95D38ACACFF1B4DA98228B77E65AA216AD075E9673286EFB4EAF3"
      }
  , NonceGenTestVector
      { rand_ = decodeHex "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
      , sk = Nothing
      , pk = parsePoint "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
      , aggpk = Nothing
      , msg = Nothing
      , extra_in = Nothing
      , expected_k1 = parseScalar "89BDD787D0284E5E4D5FC572E49E316BAB7E21E3B1830DE37DFE80156FA41A6D"
      , expected_k2 = parseScalar "0B17AE8D024C53679699A6FD7944D9C4A366B514BAF43088E0708B1023DD2897"
      , expected_r1 = parsePoint "02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C00"
      , expected_r2 = parsePoint "0299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786"
      }
  ]

-- | Creates a test case from a test vector.
makeNonceGenTestCase :: Int -> NonceGenTestVector -> TestTree
makeNonceGenTestCase i NonceGenTestVector{..} =
  testCase ("BIP327 NonceGen Vector " ++ show (i + 1)) $ do
    let params =
          SecNonceGenParams
            { _pk = pk
            , _sk = fmap SecKey sk
            , _aggpk = aggpk
            , _msg = msg
            , _extraIn = extra_in
            }
    let sec = secNonceGenWithRand rand_ params
    let pub = publicNonce sec
    assertEqual "k1 mismatch" expected_k1 sec.k1
    assertEqual "k2 mismatch" expected_k2 sec.k2
    assertEqual "r1 mismatch" expected_r1 pub.r1
    assertEqual "r2 mismatch" expected_r2 pub.r2

-- | Main test group for NonceGen.
testNonceGen :: TestTree
testNonceGen =
  testGroup "BIP327 NonceGen Vectors" $
    zipWith makeNonceGenTestCase [0 ..] testVectors
