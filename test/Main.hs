module Main where

import SortPubkeys (testSortPubkey)
import Test.Tasty

main :: IO ()
main = defaultMain testSortPubkey
