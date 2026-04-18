{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns #-}

module Main where

import Control.DeepSeq
import Criterion.Main
import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty(..))

import Bitcoin.Prim.Tx
import Bitcoin.Prim.Tx.Sighash

-- NFData instances ------------------------------------------------------------

instance NFData SighashType

-- sample data -----------------------------------------------------------------

-- | Sample outpoint (references a dummy txid).
sampleOutPoint :: OutPoint
sampleOutPoint = OutPoint (TxId (BS.replicate 32 0xab)) 0

-- | Sample input with typical P2PKH signature (~107 bytes).
sampleInput :: TxIn
sampleInput = TxIn
  { txin_prevout    = sampleOutPoint
  , txin_script_sig = BS.replicate 107 0x00  -- typical P2PKH sig
  , txin_sequence   = 0xffffffff
  }

-- | Sample input for segwit (empty scriptSig).
sampleSegwitInput :: TxIn
sampleSegwitInput = TxIn
  { txin_prevout    = sampleOutPoint
  , txin_script_sig = BS.empty
  , txin_sequence   = 0xffffffff
  }

-- | Sample output with typical P2PKH script (25 bytes).
sampleOutput :: TxOut
sampleOutput = TxOut
  { txout_value         = 50000000
  , txout_script_pubkey = BS.replicate 25 0x00  -- typical P2PKH script
  }

-- | Sample witness stack (signature + pubkey for P2WPKH).
sampleWitness :: Witness
sampleWitness = Witness
  [ BS.replicate 72 0x00  -- DER signature
  , BS.replicate 33 0x00  -- compressed pubkey
  ]

-- | Create a legacy transaction with n inputs and m outputs.
--   Requires n >= 1 and m >= 1.
mkLegacyTx :: Int -> Int -> Tx
mkLegacyTx !numInputs !numOutputs = Tx
  { tx_version   = 1
  , tx_inputs    = sampleInput :| replicate (numInputs - 1) sampleInput
  , tx_outputs   = sampleOutput :| replicate (numOutputs - 1) sampleOutput
  , tx_witnesses = []
  , tx_locktime  = 0
  }

-- | Create a segwit transaction with n inputs and m outputs.
--   Requires n >= 1 and m >= 1.
mkSegwitTx :: Int -> Int -> Tx
mkSegwitTx !numInputs !numOutputs = Tx
  { tx_version   = 2
  , tx_inputs    = sampleSegwitInput :| replicate (numInputs - 1) sampleSegwitInput
  , tx_outputs   = sampleOutput :| replicate (numOutputs - 1) sampleOutput
  , tx_witnesses = replicate numInputs sampleWitness
  , tx_locktime  = 0
  }

-- sample transactions ---------------------------------------------------------

smallLegacyTx, mediumLegacyTx, largeLegacyTx :: Tx
smallLegacyTx  = mkLegacyTx 1 1
mediumLegacyTx = mkLegacyTx 5 5
largeLegacyTx  = mkLegacyTx 20 20

smallSegwitTx, mediumSegwitTx, largeSegwitTx :: Tx
smallSegwitTx  = mkSegwitTx 1 1
mediumSegwitTx = mkSegwitTx 5 5
largeSegwitTx  = mkSegwitTx 20 20

-- serialised bytes ------------------------------------------------------------

smallLegacyBytes, mediumLegacyBytes, largeLegacyBytes :: BS.ByteString
smallLegacyBytes  = to_bytes smallLegacyTx
mediumLegacyBytes = to_bytes mediumLegacyTx
largeLegacyBytes  = to_bytes largeLegacyTx

smallSegwitBytes, mediumSegwitBytes, largeSegwitBytes :: BS.ByteString
smallSegwitBytes  = to_bytes smallSegwitTx
mediumSegwitBytes = to_bytes mediumSegwitTx
largeSegwitBytes  = to_bytes largeSegwitTx

-- benchmarks ------------------------------------------------------------------

main :: IO ()
main = defaultMain
    [ bgroup "serialisation"
        [ bgroup "to_bytes"
            [ bench "small-legacy"  $ nf to_bytes smallLegacyTx
            , bench "small-segwit"  $ nf to_bytes smallSegwitTx
            , bench "medium-legacy" $ nf to_bytes mediumLegacyTx
            , bench "medium-segwit" $ nf to_bytes mediumSegwitTx
            , bench "large-legacy"  $ nf to_bytes largeLegacyTx
            , bench "large-segwit"  $ nf to_bytes largeSegwitTx
            ]
        , bgroup "from_bytes"
            [ bench "small-legacy"  $ nf from_bytes smallLegacyBytes
            , bench "small-segwit"  $ nf from_bytes smallSegwitBytes
            , bench "medium-legacy" $ nf from_bytes mediumLegacyBytes
            , bench "medium-segwit" $ nf from_bytes mediumSegwitBytes
            , bench "large-legacy"  $ nf from_bytes largeLegacyBytes
            , bench "large-segwit"  $ nf from_bytes largeSegwitBytes
            ]
        , bgroup "to_bytes_legacy"
            [ bench "small-legacy"  $ nf to_bytes_legacy smallLegacyTx
            , bench "small-segwit"  $ nf to_bytes_legacy smallSegwitTx
            , bench "medium-legacy" $ nf to_bytes_legacy mediumLegacyTx
            , bench "medium-segwit" $ nf to_bytes_legacy mediumSegwitTx
            , bench "large-legacy"  $ nf to_bytes_legacy largeLegacyTx
            , bench "large-segwit"  $ nf to_bytes_legacy largeSegwitTx
            ]
        ]
    , bgroup "txid"
        [ bench "small-legacy"  $ nf txid smallLegacyTx
        , bench "small-segwit"  $ nf txid smallSegwitTx
        , bench "medium-legacy" $ nf txid mediumLegacyTx
        , bench "medium-segwit" $ nf txid mediumSegwitTx
        , bench "large-legacy"  $ nf txid largeLegacyTx
        , bench "large-segwit"  $ nf txid largeSegwitTx
        ]
    ]
