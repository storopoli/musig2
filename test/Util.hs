module Util (parsePoint) where

import Crypto.Curve.Secp256k1 (Pub, parse_point)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as B16
import Data.Maybe (fromJust)

{- | Parses a 'ByteString' into a 'Pub'key.

This is a test YOLO function that blows up on your face if you don't
supply proper string representations.
-}
parsePoint :: ByteString -> Pub
parsePoint s = case B16.decode s of
  Left _ -> error "cannot decode point"
  Right p -> (fromJust . parse_point) p
