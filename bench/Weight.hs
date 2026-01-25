{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StandaloneDeriving #-}

module Main where

import Control.DeepSeq
import GHC.Generics
import qualified Weigh as W

import Bitcoin.Prim.Tx
import Bitcoin.Prim.Tx.Sighash

-- NFData instances ------------------------------------------------------------

deriving stock instance Generic TxId
instance NFData TxId

deriving stock instance Generic OutPoint
instance NFData OutPoint

deriving stock instance Generic TxIn
instance NFData TxIn

deriving stock instance Generic TxOut
instance NFData TxOut

deriving stock instance Generic Witness
instance NFData Witness

deriving stock instance Generic Tx
instance NFData Tx

deriving stock instance Generic SighashType
instance NFData SighashType

-- allocation benchmarks -------------------------------------------------------

main :: IO ()
main = W.mainWith $ do
    -- add allocation benchmarks here
    pure ()
