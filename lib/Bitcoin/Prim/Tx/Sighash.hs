{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}

-- |
-- Module: Bitcoin.Prim.Tx.Sighash
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Sighash computation for legacy and BIP143 segwit transactions.

module Bitcoin.Prim.Tx.Sighash (
    -- * Sighash Types
    SighashType(..)

    -- * Legacy Sighash
  , sighash_legacy

    -- * BIP143 Segwit Sighash
  , sighash_segwit
  ) where

import Bitcoin.Prim.Tx
    ( Tx(..)
    , TxIn(..)
    , TxOut(..)
    , put_word32_le
    , put_word64_le
    , put_compact
    , put_outpoint
    , put_txout
    , to_strict
    )
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import Data.Word (Word8, Word64)
import GHC.Generics (Generic)

-- | Sighash type flags.
data SighashType
  = SIGHASH_ALL
  | SIGHASH_NONE
  | SIGHASH_SINGLE
  | SIGHASH_ALL_ANYONECANPAY
  | SIGHASH_NONE_ANYONECANPAY
  | SIGHASH_SINGLE_ANYONECANPAY
  deriving (Eq, Show, Generic)

-- | Encode sighash type to byte value.
sighash_byte :: SighashType -> Word8
sighash_byte !st = case st of
  SIGHASH_ALL                -> 0x01
  SIGHASH_NONE               -> 0x02
  SIGHASH_SINGLE             -> 0x03
  SIGHASH_ALL_ANYONECANPAY    -> 0x81
  SIGHASH_NONE_ANYONECANPAY   -> 0x82
  SIGHASH_SINGLE_ANYONECANPAY -> 0x83
{-# INLINE sighash_byte #-}

-- | Check if ANYONECANPAY flag is set.
is_anyonecanpay :: SighashType -> Bool
is_anyonecanpay !st = case st of
  SIGHASH_ALL_ANYONECANPAY    -> True
  SIGHASH_NONE_ANYONECANPAY   -> True
  SIGHASH_SINGLE_ANYONECANPAY -> True
  _                           -> False
{-# INLINE is_anyonecanpay #-}

-- | Get base sighash type (without ANYONECANPAY).
base_type :: SighashType -> SighashType
base_type !st = case st of
  SIGHASH_ALL_ANYONECANPAY    -> SIGHASH_ALL
  SIGHASH_NONE_ANYONECANPAY   -> SIGHASH_NONE
  SIGHASH_SINGLE_ANYONECANPAY -> SIGHASH_SINGLE
  other                       -> other
{-# INLINE base_type #-}

-- | 32 zero bytes.
zero32 :: BS.ByteString
zero32 = BS.replicate 32 0x00
{-# NOINLINE zero32 #-}

-- | Hash of 0x01 followed by 31 zero bytes (SIGHASH_SINGLE edge case).
sighash_single_bug :: BS.ByteString
sighash_single_bug = BS.cons 0x01 (BS.replicate 31 0x00)
{-# NOINLINE sighash_single_bug #-}

-- | Double SHA256.
hash256 :: BS.ByteString -> BS.ByteString
hash256 = SHA256.hash . SHA256.hash
{-# INLINE hash256 #-}

-- legacy sighash -------------------------------------------------------------

-- | Compute legacy sighash for P2PKH/P2SH inputs.
--
--   Modifies a copy of the transaction based on sighash flags, appends
--   the sighash type as 4-byte little-endian, and double SHA256s.
--
--   @
--   -- sign input 0 with SIGHASH_ALL
--   let hash = sighash_legacy tx 0 scriptPubKey SIGHASH_ALL
--   -- use hash with ECDSA signing
--   @
--
--   For SIGHASH_SINGLE with input index >= output count, returns the
--   special \"sighash single bug\" value (0x01 followed by 31 zero bytes).
sighash_legacy
  :: Tx
  -> Int              -- ^ input index
  -> BS.ByteString    -- ^ scriptPubKey being spent
  -> SighashType
  -> BS.ByteString    -- ^ 32-byte hash
sighash_legacy !tx !idx !script_pubkey !sighash_type
  -- SIGHASH_SINGLE edge case: index >= number of outputs
  | base == SIGHASH_SINGLE && idx >= length (tx_outputs tx) =
      sighash_single_bug
  | otherwise =
      let !modified = modify_tx_legacy tx idx script_pubkey sighash_type
          !serialized = serialize_legacy_for_sighash modified sighash_type
      in  hash256 serialized
  where
    !base = base_type sighash_type

-- | Modify transaction for legacy sighash computation.
modify_tx_legacy
  :: Tx
  -> Int
  -> BS.ByteString
  -> SighashType
  -> Tx
modify_tx_legacy Tx{..} !idx !script_pubkey !sighash_type =
  let !base = base_type sighash_type
      !anyonecanpay = is_anyonecanpay sighash_type

      -- Clear all scriptSigs, set signing input's script to scriptPubKey
      clear_scripts :: Int -> [TxIn] -> [TxIn]
      clear_scripts !_ [] = []
      clear_scripts !i (inp : rest)
        | i == idx  = inp { txin_script_sig = script_pubkey } : clear_rest
        | otherwise = inp { txin_script_sig = BS.empty } : clear_rest
        where
          !clear_rest = clear_scripts (i + 1) rest

      -- For NONE/SINGLE: zero out sequence numbers for other inputs
      zero_other_sequences :: Int -> [TxIn] -> [TxIn]
      zero_other_sequences !_ [] = []
      zero_other_sequences !i (inp : rest)
        | i == idx  = inp : zero_other_sequences (i + 1) rest
        | otherwise =
            inp { txin_sequence = 0 } : zero_other_sequences (i + 1) rest

      -- Process inputs based on sighash type
      !inputs_cleared = clear_scripts 0 tx_inputs

      !inputs_processed = case base of
        SIGHASH_NONE   -> zero_other_sequences 0 inputs_cleared
        SIGHASH_SINGLE -> zero_other_sequences 0 inputs_cleared
        _              -> inputs_cleared

      -- ANYONECANPAY: keep only signing input
      !final_inputs
        | anyonecanpay = case safe_index inputs_processed idx of
            Just inp -> [inp]
            Nothing  -> []  -- shouldn't happen if idx is valid
        | otherwise = inputs_processed

      -- Process outputs based on sighash type
      !final_outputs = case base of
        SIGHASH_NONE   -> []
        SIGHASH_SINGLE -> build_single_outputs tx_outputs idx
        _              -> tx_outputs

  in  Tx tx_version final_inputs final_outputs [] tx_locktime

-- | Build outputs for SIGHASH_SINGLE: keep only output at idx,
--   replace earlier outputs with empty/zero outputs.
build_single_outputs :: [TxOut] -> Int -> [TxOut]
build_single_outputs !outs !target_idx = go 0 outs
  where
    go :: Int -> [TxOut] -> [TxOut]
    go !_ [] = []
    go !i (o : rest)
      | i == target_idx = [o]  -- keep this one and stop
      | i < target_idx  = empty_output : go (i + 1) rest
      | otherwise       = []   -- shouldn't reach here

    -- Empty output: -1 (0xffffffffffffffff) value, empty script
    empty_output :: TxOut
    empty_output = TxOut 0xffffffffffffffff BS.empty

-- | Safe list indexing.
safe_index :: [a] -> Int -> Maybe a
safe_index [] _ = Nothing
safe_index (x : xs) !n
  | n < 0     = Nothing
  | n == 0    = Just x
  | otherwise = safe_index xs (n - 1)
{-# INLINE safe_index #-}

-- | Serialize modified transaction for legacy sighash, appending sighash type.
serialize_legacy_for_sighash :: Tx -> SighashType -> BS.ByteString
serialize_legacy_for_sighash Tx{..} !sighash_type = to_strict $
       put_word32_le tx_version
    <> put_compact (fromIntegral (length tx_inputs))
    <> foldMap put_txin_legacy tx_inputs
    <> put_compact (fromIntegral (length tx_outputs))
    <> foldMap put_txout tx_outputs
    <> put_word32_le tx_locktime
    <> put_word32_le (fromIntegral (sighash_byte sighash_type))

-- | Encode TxIn for legacy sighash (same as normal encoding).
put_txin_legacy :: TxIn -> BSB.Builder
put_txin_legacy TxIn{..} =
       put_outpoint txin_prevout
    <> put_compact (fromIntegral (BS.length txin_script_sig))
    <> BSB.byteString txin_script_sig
    <> put_word32_le txin_sequence
{-# INLINE put_txin_legacy #-}

-- BIP143 segwit sighash -------------------------------------------------------

-- | Compute BIP143 segwit sighash.
--
--   Required for signing segwit inputs (P2WPKH, P2WSH). Unlike legacy
--   sighash, this commits to the value being spent, preventing fee
--   manipulation attacks.
--
--   @
--   -- sign P2WPKH input 0
--   let scriptCode = ...  -- P2WPKH scriptCode
--   let hash = sighash_segwit tx 0 scriptCode inputValue SIGHASH_ALL
--   -- use hash with ECDSA signing
--   @
sighash_segwit
  :: Tx
  -> Int              -- ^ input index
  -> BS.ByteString    -- ^ scriptCode
  -> Word64           -- ^ value being spent (satoshis)
  -> SighashType
  -> BS.ByteString    -- ^ 32-byte hash
sighash_segwit !tx !idx !script_code !value !sighash_type =
  let !preimage = build_bip143_preimage tx idx script_code value sighash_type
  in  hash256 preimage

-- | Build BIP143 preimage for signing.
build_bip143_preimage
  :: Tx
  -> Int
  -> BS.ByteString
  -> Word64
  -> SighashType
  -> BS.ByteString
build_bip143_preimage Tx{..} !idx !script_code !value !sighash_type =
  let !base = base_type sighash_type
      !anyonecanpay = is_anyonecanpay sighash_type

      -- hashPrevouts: double SHA256 of all outpoints, or zero if ANYONECANPAY
      !hash_prevouts
        | anyonecanpay = zero32
        | otherwise    = hash256 $ to_strict $
            foldMap (put_outpoint . txin_prevout) tx_inputs

      -- hashSequence: double SHA256 of all sequences, or zero if
      -- ANYONECANPAY or NONE or SINGLE
      !hash_sequence
        | anyonecanpay = zero32
        | base == SIGHASH_SINGLE = zero32
        | base == SIGHASH_NONE   = zero32
        | otherwise = hash256 $ to_strict $
            foldMap (put_word32_le . txin_sequence) tx_inputs

      -- hashOutputs: depends on sighash type
      !hash_outputs = case base of
        SIGHASH_NONE -> zero32
        SIGHASH_SINGLE ->
          case safe_index tx_outputs idx of
            Nothing  -> zero32  -- index out of range
            Just out -> hash256 $ to_strict $ put_txout out
        _ -> hash256 $ to_strict $ foldMap put_txout tx_outputs

      -- Get the input being signed
      !signing_input = case safe_index tx_inputs idx of
        Just inp -> inp
        Nothing  -> error "sighash_segwit: invalid input index"

      !outpoint = txin_prevout signing_input
      !sequence_n = txin_sequence signing_input

  in  to_strict $
         put_word32_le tx_version
      <> BSB.byteString hash_prevouts
      <> BSB.byteString hash_sequence
      <> put_outpoint outpoint
      <> put_compact (fromIntegral (BS.length script_code))
      <> BSB.byteString script_code
      <> put_word64_le value
      <> put_word32_le sequence_n
      <> BSB.byteString hash_outputs
      <> put_word32_le tx_locktime
      <> put_word32_le (fromIntegral (sighash_byte sighash_type))
