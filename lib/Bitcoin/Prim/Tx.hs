{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- |
-- Module: Bitcoin.Prim.Tx
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Minimal Bitcoin transaction primitives, including raw transaction
-- types, serialisation to/from bytes, and txid computation.

module Bitcoin.Prim.Tx (
    -- * Transaction Types
    Tx(..)
  , TxIn(..)
  , TxOut(..)
  , OutPoint(..)
  , Witness(..)
  , TxId(..)

    -- * Serialisation
  , to_bytes
  , from_bytes
  , to_bytes_legacy
  , to_base16
  , from_base16

    -- * TxId
  , txid
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Lazy as BL
import Data.Word (Word32, Word64)
import GHC.Generics (Generic)

-- | Transaction ID (32 bytes, little-endian double-SHA256).
newtype TxId = TxId BS.ByteString
  deriving (Eq, Show, Generic)

-- | Transaction outpoint (txid + output index).
data OutPoint = OutPoint
  { op_txid  :: {-# UNPACK #-} !TxId
  , op_vout  :: {-# UNPACK #-} !Word32
  } deriving (Eq, Show, Generic)

-- | Transaction input.
data TxIn = TxIn
  { txin_prevout    :: {-# UNPACK #-} !OutPoint
  , txin_script_sig :: !BS.ByteString
  , txin_sequence   :: {-# UNPACK #-} !Word32
  } deriving (Eq, Show, Generic)

-- | Transaction output.
data TxOut = TxOut
  { txout_value         :: {-# UNPACK #-} !Word64  -- ^ satoshis
  , txout_script_pubkey :: !BS.ByteString
  } deriving (Eq, Show, Generic)

-- | Witness stack for a single input.
newtype Witness = Witness [BS.ByteString]
  deriving (Eq, Show, Generic)

-- | Complete transaction.
data Tx = Tx
  { tx_version   :: {-# UNPACK #-} !Word32
  , tx_inputs    :: ![TxIn]
  , tx_outputs   :: ![TxOut]
  , tx_witnesses :: ![Witness]  -- ^ empty list for legacy tx
  , tx_locktime  :: {-# UNPACK #-} !Word32
  } deriving (Eq, Show, Generic)

-- serialisation ---------------------------------------------------------------

-- | Serialise a transaction to bytes.
--
--   Uses segwit format if witnesses are present, legacy otherwise.
to_bytes :: Tx -> BS.ByteString
to_bytes tx@Tx {..}
    | null tx_witnesses = to_bytes_legacy tx
    | otherwise         = to_strict $
           put_word32_le tx_version
        <> BSB.word8 0x00  -- marker
        <> BSB.word8 0x01  -- flag
        <> put_compact (fromIntegral (length tx_inputs))
        <> foldMap put_txin tx_inputs
        <> put_compact (fromIntegral (length tx_outputs))
        <> foldMap put_txout tx_outputs
        <> foldMap put_witness tx_witnesses
        <> put_word32_le tx_locktime

-- | Parse a transaction from bytes.
from_bytes :: BS.ByteString -> Maybe Tx
from_bytes = error "Bitcoin.Prim.Tx.from_bytes: not yet implemented"

-- | Serialise a transaction to legacy format (no witness data).
--
--   Used for txid computation.
to_bytes_legacy :: Tx -> BS.ByteString
to_bytes_legacy Tx {..} = to_strict $
       put_word32_le tx_version
    <> put_compact (fromIntegral (length tx_inputs))
    <> foldMap put_txin tx_inputs
    <> put_compact (fromIntegral (length tx_outputs))
    <> foldMap put_txout tx_outputs
    <> put_word32_le tx_locktime

-- | Serialise a transaction to base16.
to_base16 :: Tx -> BS.ByteString
to_base16 tx = B16.encode (to_bytes tx)

-- | Parse a transaction from base16.
from_base16 :: BS.ByteString -> Maybe Tx
from_base16 b16 = do
  bs <- B16.decode b16
  from_bytes bs

-- internal: builders ----------------------------------------------------------

-- | Convert a Builder to a strict ByteString.
to_strict :: BSB.Builder -> BS.ByteString
to_strict = BL.toStrict . BSB.toLazyByteString
{-# INLINE to_strict #-}

-- | Encode a Word32 as little-endian bytes.
put_word32_le :: Word32 -> BSB.Builder
put_word32_le = BSB.word32LE
{-# INLINE put_word32_le #-}

-- | Encode a Word64 as little-endian bytes.
put_word64_le :: Word64 -> BSB.Builder
put_word64_le = BSB.word64LE
{-# INLINE put_word64_le #-}

-- | Encode a Word64 as Bitcoin compactSize (varint).
--
--   Encoding:
--   - 0x00-0xfc: 1 byte (value itself)
--   - 0xfd-0xffff: 0xfd ++ 2 bytes LE
--   - 0x10000-0xffffffff: 0xfe ++ 4 bytes LE
--   - larger: 0xff ++ 8 bytes LE
put_compact :: Word64 -> BSB.Builder
put_compact !n
    | n <= 0xfc       = BSB.word8 (fromIntegral n)
    | n <= 0xffff     = BSB.word8 0xfd <> BSB.word16LE (fromIntegral n)
    | n <= 0xffffffff = BSB.word8 0xfe <> BSB.word32LE (fromIntegral n)
    | otherwise       = BSB.word8 0xff <> BSB.word64LE n
{-# INLINE put_compact #-}

-- | Encode an OutPoint (txid + vout).
put_outpoint :: OutPoint -> BSB.Builder
put_outpoint OutPoint {..} =
    let !(TxId !txid_bs) = op_txid
    in  BSB.byteString txid_bs <> put_word32_le op_vout
{-# INLINE put_outpoint #-}

-- | Encode a TxIn.
put_txin :: TxIn -> BSB.Builder
put_txin TxIn {..} =
       put_outpoint txin_prevout
    <> put_compact (fromIntegral (BS.length txin_script_sig))
    <> BSB.byteString txin_script_sig
    <> put_word32_le txin_sequence
{-# INLINE put_txin #-}

-- | Encode a TxOut.
put_txout :: TxOut -> BSB.Builder
put_txout TxOut {..} =
       put_word64_le txout_value
    <> put_compact (fromIntegral (BS.length txout_script_pubkey))
    <> BSB.byteString txout_script_pubkey
{-# INLINE put_txout #-}

-- | Encode a Witness stack.
put_witness :: Witness -> BSB.Builder
put_witness (Witness items) =
       put_compact (fromIntegral (length items))
    <> foldMap put_witness_item items
  where
    put_witness_item :: BS.ByteString -> BSB.Builder
    put_witness_item !item =
           put_compact (fromIntegral (BS.length item))
        <> BSB.byteString item
{-# INLINE put_witness #-}

-- txid ------------------------------------------------------------------------

-- | Compute the transaction ID (double SHA256 of legacy serialisation).
txid :: Tx -> TxId
txid = error "Bitcoin.Prim.Tx.txid: not yet implemented"
