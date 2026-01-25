{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

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
to_bytes = error "Bitcoin.Prim.Tx.to_bytes: not yet implemented"

-- | Parse a transaction from bytes.
from_bytes :: BS.ByteString -> Maybe Tx
from_bytes = error "Bitcoin.Prim.Tx.from_bytes: not yet implemented"

-- | Serialise a transaction to legacy format (no witness data).
--
--   Used for txid computation.
to_bytes_legacy :: Tx -> BS.ByteString
to_bytes_legacy = error "Bitcoin.Prim.Tx.to_bytes_legacy: not yet implemented"

-- | Serialise a transaction to base16.
to_base16 :: Tx -> BS.ByteString
to_base16 tx = B16.encode (to_bytes tx)

-- | Parse a transaction from base16.
from_base16 :: BS.ByteString -> Maybe Tx
from_base16 b16 = do
  bs <- B16.decode b16
  from_bytes bs

-- txid ------------------------------------------------------------------------

-- | Compute the transaction ID (double SHA256 of legacy serialisation).
txid :: Tx -> TxId
txid = error "Bitcoin.Prim.Tx.txid: not yet implemented"
