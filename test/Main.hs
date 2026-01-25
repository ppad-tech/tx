{-# LANGUAGE OverloadedStrings #-}

module Main where

import Test.Tasty
import qualified Test.Tasty.HUnit as H

-- main ------------------------------------------------------------------------

main :: IO ()
main = defaultMain $
  testGroup "ppad-tx" [
      testGroup "serialisation" [
          testGroup "round-trip" [
            ]
        , testGroup "known vectors" [
            ]
        ]
    , testGroup "txid" [
        ]
    , testGroup "sighash" [
          testGroup "legacy" [
            ]
        , testGroup "BIP143 segwit" [
            ]
        ]
    ]
