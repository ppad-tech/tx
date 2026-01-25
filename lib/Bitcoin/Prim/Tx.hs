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

import Data.Bits ((.|.), shiftL)
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

-- decoding --------------------------------------------------------------------

-- | Parse a transaction from bytes.
--
--   Automatically detects segwit vs legacy format by checking for
--   marker byte 0x00 followed by flag 0x01 after the version field.
from_bytes :: BS.ByteString -> Maybe Tx
from_bytes !bs = do
  -- need at least 4 bytes for version
  guard (BS.length bs >= 4)
  let !version = get_word32_le bs 0
      !off0 = 4
  -- check for segwit marker (0x00) and flag (0x01)
  if   BS.length bs > off0 + 1
    && BS.index bs off0 == 0x00
    && BS.index bs (off0 + 1) == 0x01
  then parse_segwit bs version (off0 + 2)
  else parse_legacy bs version off0

-- Parse legacy transaction (no witness data)
parse_legacy :: BS.ByteString -> Word32 -> Int -> Maybe Tx
parse_legacy !bs !version !off0 = do
  -- input count
  (input_count, off1) <- get_compact bs off0
  -- inputs
  (inputs, off2) <- get_many get_txin bs off1 (fromIntegral input_count)
  -- output count
  (output_count, off3) <- get_compact bs off2
  -- outputs
  (outputs, off4) <- get_many get_txout bs off3 (fromIntegral output_count)
  -- locktime (4 bytes)
  guard (BS.length bs >= off4 + 4)
  let !locktime = get_word32_le bs off4
      !off5 = off4 + 4
  -- should have consumed all bytes
  guard (off5 == BS.length bs)
  pure $! Tx version inputs outputs [] locktime

-- Parse segwit transaction (with witness data)
parse_segwit :: BS.ByteString -> Word32 -> Int -> Maybe Tx
parse_segwit !bs !version !off0 = do
  -- input count
  (input_count, off1) <- get_compact bs off0
  -- inputs
  (inputs, off2) <- get_many get_txin bs off1 (fromIntegral input_count)
  -- output count
  (output_count, off3) <- get_compact bs off2
  -- outputs
  (outputs, off4) <- get_many get_txout bs off3 (fromIntegral output_count)
  -- witnesses (one per input)
  (witnesses, off5) <- get_many get_witness bs off4 (fromIntegral input_count)
  -- locktime (4 bytes)
  guard (BS.length bs >= off5 + 4)
  let !locktime = get_word32_le bs off5
      !off6 = off5 + 4
  -- should have consumed all bytes
  guard (off6 == BS.length bs)
  pure $! Tx version inputs outputs witnesses locktime

-- internal helpers ------------------------------------------------------------

-- | Guard for Maybe monad.
guard :: Bool -> Maybe ()
guard True  = Just ()
guard False = Nothing
{-# INLINE guard #-}

-- | Decode a 32-bit little-endian word at the given offset.
--   Does not bounds-check; caller must ensure sufficient bytes.
get_word32_le :: BS.ByteString -> Int -> Word32
get_word32_le !bs !off =
  let !b0 = fromIntegral (BS.index bs off) :: Word32
      !b1 = fromIntegral (BS.index bs (off + 1)) :: Word32
      !b2 = fromIntegral (BS.index bs (off + 2)) :: Word32
      !b3 = fromIntegral (BS.index bs (off + 3)) :: Word32
  in  b0 .|. (b1 `shiftL` 8) .|. (b2 `shiftL` 16) .|. (b3 `shiftL` 24)
{-# INLINE get_word32_le #-}

-- | Decode a 64-bit little-endian word at the given offset.
--   Does not bounds-check; caller must ensure sufficient bytes.
get_word64_le :: BS.ByteString -> Int -> Word64
get_word64_le !bs !off =
  let !b0 = fromIntegral (BS.index bs off) :: Word64
      !b1 = fromIntegral (BS.index bs (off + 1)) :: Word64
      !b2 = fromIntegral (BS.index bs (off + 2)) :: Word64
      !b3 = fromIntegral (BS.index bs (off + 3)) :: Word64
      !b4 = fromIntegral (BS.index bs (off + 4)) :: Word64
      !b5 = fromIntegral (BS.index bs (off + 5)) :: Word64
      !b6 = fromIntegral (BS.index bs (off + 6)) :: Word64
      !b7 = fromIntegral (BS.index bs (off + 7)) :: Word64
  in  b0 .|. (b1 `shiftL` 8) .|. (b2 `shiftL` 16) .|. (b3 `shiftL` 24)
          .|. (b4 `shiftL` 32) .|. (b5 `shiftL` 40)
          .|. (b6 `shiftL` 48) .|. (b7 `shiftL` 56)
{-# INLINE get_word64_le #-}

-- | Decode a 16-bit little-endian word at the given offset.
--   Does not bounds-check; caller must ensure sufficient bytes.
get_word16_le :: BS.ByteString -> Int -> Word64
get_word16_le !bs !off =
  let !b0 = fromIntegral (BS.index bs off) :: Word64
      !b1 = fromIntegral (BS.index bs (off + 1)) :: Word64
  in  b0 .|. (b1 `shiftL` 8)
{-# INLINE get_word16_le #-}

-- | Decode compactSize (Bitcoin's variable-length integer).
--   Returns (value, new_offset).
--   Enforces minimal encoding: rejects non-minimal representations.
get_compact :: BS.ByteString -> Int -> Maybe (Word64, Int)
get_compact !bs !off
  | off >= BS.length bs = Nothing
  | otherwise = case BS.index bs off of
      tag | tag <= 0xfc ->
        -- Single byte: value is the tag itself
        Just (fromIntegral tag, off + 1)

      0xfd ->
        -- 2-byte value follows
        if BS.length bs < off + 3
        then Nothing
        else
          let !val = get_word16_le bs (off + 1)
          in  if val < 0xfd
              then Nothing  -- non-minimal encoding
              else Just (val, off + 3)

      0xfe ->
        -- 4-byte value follows
        if BS.length bs < off + 5
        then Nothing
        else
          let !val = fromIntegral (get_word32_le bs (off + 1)) :: Word64
          in  if val <= 0xffff
              then Nothing  -- non-minimal encoding
              else Just (val, off + 5)

      _ -> -- 0xff
        -- 8-byte value follows
        if BS.length bs < off + 9
        then Nothing
        else
          let !val = get_word64_le bs (off + 1)
          in  if val <= 0xffffffff
              then Nothing  -- non-minimal encoding
              else Just (val, off + 9)
{-# INLINE get_compact #-}

-- | Decode an outpoint (txid + vout).
--   Returns (OutPoint, new_offset).
get_outpoint :: BS.ByteString -> Int -> Maybe (OutPoint, Int)
get_outpoint !bs !off
  | BS.length bs < off + 36 = Nothing
  | otherwise =
      let !txid_bytes = BS.take 32 (BS.drop off bs)
          !vout = get_word32_le bs (off + 32)
      in  Just (OutPoint (TxId txid_bytes) vout, off + 36)
{-# INLINE get_outpoint #-}

-- | Decode a transaction input.
--   Returns (TxIn, new_offset).
get_txin :: BS.ByteString -> Int -> Maybe (TxIn, Int)
get_txin !bs !off0 = do
  -- outpoint: 36 bytes
  (outpoint, off1) <- get_outpoint bs off0
  -- scriptSig length + bytes
  (script_len, off2) <- get_compact bs off1
  let !slen = fromIntegral script_len
  guard (BS.length bs >= off2 + slen)
  let !script_sig = BS.take slen (BS.drop off2 bs)
      !off3 = off2 + slen
  -- sequence: 4 bytes
  guard (BS.length bs >= off3 + 4)
  let !seqn = get_word32_le bs off3
      !off4 = off3 + 4
  pure (TxIn outpoint script_sig seqn, off4)

-- | Decode a transaction output.
--   Returns (TxOut, new_offset).
get_txout :: BS.ByteString -> Int -> Maybe (TxOut, Int)
get_txout !bs !off0 = do
  -- value: 8 bytes
  guard (BS.length bs >= off0 + 8)
  let !value = get_word64_le bs off0
      !off1 = off0 + 8
  -- scriptPubKey length + bytes
  (script_len, off2) <- get_compact bs off1
  let !slen = fromIntegral script_len
  guard (BS.length bs >= off2 + slen)
  let !script_pk = BS.take slen (BS.drop off2 bs)
      !off3 = off2 + slen
  pure (TxOut value script_pk, off3)

-- | Decode a witness stack for one input.
--   Returns (Witness, new_offset).
get_witness :: BS.ByteString -> Int -> Maybe (Witness, Int)
get_witness !bs !off0 = do
  -- stack item count
  (item_count, off1) <- get_compact bs off0
  -- each item: length + bytes
  (items, off2) <- get_many get_witness_item bs off1 (fromIntegral item_count)
  pure (Witness items, off2)

-- | Decode a single witness stack item (length-prefixed bytes).
get_witness_item :: BS.ByteString -> Int -> Maybe (BS.ByteString, Int)
get_witness_item !bs !off0 = do
  (item_len, off1) <- get_compact bs off0
  let !ilen = fromIntegral item_len
  guard (BS.length bs >= off1 + ilen)
  let !item = BS.take ilen (BS.drop off1 bs)
  pure (item, off1 + ilen)

-- | Decode multiple items using a decoder function.
--   Returns (list of items, new_offset).
get_many :: (BS.ByteString -> Int -> Maybe (a, Int))
         -> BS.ByteString -> Int -> Int -> Maybe ([a], Int)
get_many getter !bs = go []
  where
    go !acc !off !n
      | n <= 0    = Just (reverse acc, off)
      | otherwise = do
          (item, off') <- getter bs off
          go (item : acc) off' (n - 1)
{-# INLINE get_many #-}

-- txid ------------------------------------------------------------------------

-- | Compute the transaction ID (double SHA256 of legacy serialisation).
txid :: Tx -> TxId
txid = error "Bitcoin.Prim.Tx.txid: not yet implemented"
