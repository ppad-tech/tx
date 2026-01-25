{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns #-}

module Main where

import Control.DeepSeq
import qualified Data.ByteString as BS
import qualified Weigh as W

import Bitcoin.Prim.Tx
import Bitcoin.Prim.Tx.Sighash

-- NFData instances ------------------------------------------------------------

instance NFData TxId
instance NFData OutPoint
instance NFData TxIn
instance NFData TxOut
instance NFData Witness
instance NFData Tx
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
mkLegacyTx :: Int -> Int -> Tx
mkLegacyTx !numInputs !numOutputs = Tx
  { tx_version   = 1
  , tx_inputs    = replicate numInputs sampleInput
  , tx_outputs   = replicate numOutputs sampleOutput
  , tx_witnesses = []
  , tx_locktime  = 0
  }

-- | Create a segwit transaction with n inputs and m outputs.
mkSegwitTx :: Int -> Int -> Tx
mkSegwitTx !numInputs !numOutputs = Tx
  { tx_version   = 2
  , tx_inputs    = replicate numInputs sampleSegwitInput
  , tx_outputs   = replicate numOutputs sampleOutput
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

-- allocation benchmarks -------------------------------------------------------

main :: IO ()
main = W.mainWith $ do
    -- to_bytes
    W.func "to_bytes/small-legacy"  to_bytes smallLegacyTx
    W.func "to_bytes/small-segwit"  to_bytes smallSegwitTx
    W.func "to_bytes/medium-legacy" to_bytes mediumLegacyTx
    W.func "to_bytes/medium-segwit" to_bytes mediumSegwitTx
    W.func "to_bytes/large-legacy"  to_bytes largeLegacyTx
    W.func "to_bytes/large-segwit"  to_bytes largeSegwitTx

    -- from_bytes
    W.func "from_bytes/small-legacy"  from_bytes smallLegacyBytes
    W.func "from_bytes/small-segwit"  from_bytes smallSegwitBytes
    W.func "from_bytes/medium-legacy" from_bytes mediumLegacyBytes
    W.func "from_bytes/medium-segwit" from_bytes mediumSegwitBytes
    W.func "from_bytes/large-legacy"  from_bytes largeLegacyBytes
    W.func "from_bytes/large-segwit"  from_bytes largeSegwitBytes

    -- to_bytes_legacy
    W.func "to_bytes_legacy/small-legacy"  to_bytes_legacy smallLegacyTx
    W.func "to_bytes_legacy/small-segwit"  to_bytes_legacy smallSegwitTx
    W.func "to_bytes_legacy/medium-legacy" to_bytes_legacy mediumLegacyTx
    W.func "to_bytes_legacy/medium-segwit" to_bytes_legacy mediumSegwitTx
    W.func "to_bytes_legacy/large-legacy"  to_bytes_legacy largeLegacyTx
    W.func "to_bytes_legacy/large-segwit"  to_bytes_legacy largeSegwitTx

    -- txid
    W.func "txid/small-legacy"  txid smallLegacyTx
    W.func "txid/small-segwit"  txid smallSegwitTx
    W.func "txid/medium-legacy" txid mediumLegacyTx
    W.func "txid/medium-segwit" txid mediumSegwitTx
    W.func "txid/large-legacy"  txid largeLegacyTx
    W.func "txid/large-segwit"  txid largeSegwitTx
