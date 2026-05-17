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
  , encode_sighash

    -- * Legacy Sighash
  , sighash_legacy

    -- * BIP143 Segwit Sighash
  , sighash_segwit

    -- * Internal
  , strip_codeseparators
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
import Data.Bits ((.&.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.List.NonEmpty as NE
import Data.Word (Word8, Word32, Word64)
import GHC.Generics (Generic)

-- | Canonical sighash type flags.
--
--   The Bitcoin consensus rules commit the full 32-bit @hashType@ to
--   the signature preimage and only use its low byte for behavioral
--   dispatch (low 5 bits select base type; bit 0x80 selects
--   ANYONECANPAY). 'SighashType' enumerates the six canonical
--   single-byte hashTypes; pass arbitrary 32-bit values directly when
--   reproducing non-canonical hashes.
data SighashType
  = SIGHASH_ALL
  | SIGHASH_NONE
  | SIGHASH_SINGLE
  | SIGHASH_ALL_ANYONECANPAY
  | SIGHASH_NONE_ANYONECANPAY
  | SIGHASH_SINGLE_ANYONECANPAY
  deriving (Eq, Show, Generic)

-- | Encode a canonical 'SighashType' to its 32-bit hashType value.
--
--   @
--   encode_sighash SIGHASH_ALL                 == 0x01
--   encode_sighash SIGHASH_SINGLE_ANYONECANPAY == 0x83
--   @
encode_sighash :: SighashType -> Word32
encode_sighash !st = case st of
  SIGHASH_ALL                 -> 0x01
  SIGHASH_NONE                -> 0x02
  SIGHASH_SINGLE              -> 0x03
  SIGHASH_ALL_ANYONECANPAY    -> 0x81
  SIGHASH_NONE_ANYONECANPAY   -> 0x82
  SIGHASH_SINGLE_ANYONECANPAY -> 0x83
{-# INLINE encode_sighash #-}

-- | Internal base sighash classification derived from a 32-bit hashType.
data BaseType = BaseAll | BaseNone | BaseSingle
  deriving Eq

-- | Behavioral base type: @hashType & 0x1f@. 2 → NONE, 3 → SINGLE,
--   anything else → ALL.
base_type :: Word32 -> BaseType
base_type !ht = case ht .&. 0x1f of
  2 -> BaseNone
  3 -> BaseSingle
  _ -> BaseAll
{-# INLINE base_type #-}

-- | Check ANYONECANPAY flag: @hashType & 0x80@.
is_anyonecanpay :: Word32 -> Bool
is_anyonecanpay !ht = (ht .&. 0x80) /= 0
{-# INLINE is_anyonecanpay #-}

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

-- | Strip @OP_CODESEPARATOR@ (0xab) opcodes from a script, skipping
--   push-data sections so that data bytes equal to 0xab are preserved.
--
--   This is consensus-required preprocessing for the legacy sighash
--   scriptCode (see Bitcoin Core's @CTransactionSignatureSerializer@).
--   BIP143 segwit sighash does /not/ perform this stripping; for
--   segwit, the caller is responsible for trimming the scriptCode to
--   the portion after the last executed @OP_CODESEPARATOR@.
--
--   On a malformed script (truncated push data), the malformed tail is
--   copied verbatim without further codeseparator processing.
strip_codeseparators :: BS.ByteString -> BS.ByteString
strip_codeseparators = BS.pack . go . BS.unpack
  where
    go :: [Word8] -> [Word8]
    go [] = []
    go (b : rest)
      | b == 0xab              = go rest
      | b >= 0x01 && b <= 0x4b = push (fromIntegral b) [b] rest
      | b == 0x4c              = case rest of
          (n : rest') -> push (fromIntegral n) [b, n] rest'
          []          -> [b]
      | b == 0x4d              = case rest of
          (n0 : n1 : rest') ->
            let !len = fromIntegral n0
                     + fromIntegral n1 * 0x100
            in  push len [b, n0, n1] rest'
          _ -> b : rest
      | b == 0x4e              = case rest of
          (n0 : n1 : n2 : n3 : rest') ->
            let !len = fromIntegral n0
                     + fromIntegral n1 * 0x100
                     + fromIntegral n2 * 0x10000
                     + fromIntegral n3 * 0x1000000
            in  push len [b, n0, n1, n2, n3] rest'
          _ -> b : rest
      | otherwise              = b : go rest

    -- | Copy a push header and N data bytes verbatim. If the script is
    --   truncated, copy whatever's available and stop processing.
    push :: Int -> [Word8] -> [Word8] -> [Word8]
    push !len !header !rest =
      let (chunk, rest') = splitAt len rest
      in  header ++ chunk ++
            if length chunk == len then go rest' else []

-- legacy sighash -------------------------------------------------------------

-- | Compute legacy sighash for P2PKH/P2SH inputs.
--
--   Modifies a copy of the transaction based on hashType flags, appends
--   the 4-byte little-endian hashType, and double SHA256s. The
--   @hashType@ is committed to the preimage verbatim; only its low byte
--   determines behavior (see 'base_type', 'is_anyonecanpay').
--
--   @
--   -- sign input 0 with SIGHASH_ALL
--   let hash = sighash_legacy tx 0 scriptPubKey (encode_sighash SIGHASH_ALL)
--   -- non-canonical hashType (consensus-valid, committed raw)
--   let hash = sighash_legacy tx 0 scriptPubKey 0x6f29291f
--   @
--
--   For base SIGHASH_SINGLE with input index >= output count, returns
--   the special \"sighash single bug\" value (0x01 followed by 31 zero
--   bytes).
sighash_legacy
  :: Tx
  -> Int              -- ^ input index
  -> BS.ByteString    -- ^ scriptPubKey being spent
  -> Word32           -- ^ hashType
  -> BS.ByteString    -- ^ 32-byte hash
sighash_legacy !tx !idx !script_pubkey !ht
  -- SIGHASH_SINGLE edge case: index >= number of outputs
  | base == BaseSingle && idx >= NE.length (tx_outputs tx) =
      sighash_single_bug
  | otherwise =
      let !serialized = serialize_legacy_sighash tx idx script_pubkey ht
      in  hash256 serialized
  where
    !base = base_type ht

-- | Serialize transaction for legacy sighash computation.
--   Handles all sighash flags directly without constructing intermediate Tx.
serialize_legacy_sighash
  :: Tx
  -> Int
  -> BS.ByteString
  -> Word32
  -> BS.ByteString
serialize_legacy_sighash Tx{..} !idx !script_pubkey !ht =
  let !script' = strip_codeseparators script_pubkey
      !base = base_type ht
      !anyonecanpay = is_anyonecanpay ht
      !inputs_list = NE.toList tx_inputs
      !outputs_list = NE.toList tx_outputs

      -- Clear all scriptSigs, set signing input's script to scriptPubKey
      clear_scripts :: Int -> [TxIn] -> [TxIn]
      clear_scripts !_ [] = []
      clear_scripts !i (inp : rest)
        | i == idx  = inp { txin_script_sig = script' } : clear_rest
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
      !inputs_cleared = clear_scripts 0 inputs_list

      !inputs_processed = case base of
        BaseNone   -> zero_other_sequences 0 inputs_cleared
        BaseSingle -> zero_other_sequences 0 inputs_cleared
        _          -> inputs_cleared

      -- ANYONECANPAY: keep only signing input
      !final_inputs
        | anyonecanpay = case safe_index inputs_processed idx of
            Just inp -> [inp]
            Nothing  -> []  -- shouldn't happen if idx is valid
        | otherwise = inputs_processed

      -- Process outputs based on sighash type
      !final_outputs = case base of
        BaseNone   -> []
        BaseSingle -> build_single_outputs outputs_list idx
        _          -> outputs_list

  in  to_strict $
         put_word32_le tx_version
      <> put_compact (fromIntegral (length final_inputs))
      <> foldMap put_txin_legacy final_inputs
      <> put_compact (fromIntegral (length final_outputs))
      <> foldMap put_txout final_outputs
      <> put_word32_le tx_locktime
      <> put_word32_le ht

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
--   manipulation attacks. The @hashType@ is committed to the preimage
--   verbatim; only its low byte determines behavior.
--
--   Returns 'Nothing' if the input index is out of range.
--
--   @
--   -- sign P2WPKH input 0
--   let scriptCode = ...  -- P2WPKH scriptCode
--   let hash = sighash_segwit tx 0 scriptCode inputValue
--                  (encode_sighash SIGHASH_ALL)
--   -- use hash with ECDSA signing (after checking Just)
--   @
sighash_segwit
  :: Tx
  -> Int              -- ^ input index
  -> BS.ByteString    -- ^ scriptCode
  -> Word64           -- ^ value being spent (satoshis)
  -> Word32           -- ^ hashType
  -> Maybe BS.ByteString    -- ^ 32-byte hash, or Nothing if index invalid
sighash_segwit !tx !idx !script_code !value !ht = do
  preimage <- build_bip143_preimage tx idx script_code value ht
  pure $! hash256 preimage

-- | Build BIP143 preimage for signing.
--   Returns Nothing if the input index is out of range.
build_bip143_preimage
  :: Tx
  -> Int
  -> BS.ByteString
  -> Word64
  -> Word32
  -> Maybe BS.ByteString
build_bip143_preimage Tx{..} !idx !script_code !value !ht = do
  -- Get the input being signed; fail if index out of range
  let !inputs_list = NE.toList tx_inputs
      !outputs_list = NE.toList tx_outputs
  signing_input <- safe_index inputs_list idx

  let !base = base_type ht
      !anyonecanpay = is_anyonecanpay ht

      -- hashPrevouts: double SHA256 of all outpoints, or zero if ANYONECANPAY
      !hash_prevouts
        | anyonecanpay = zero32
        | otherwise    = hash256 $ to_strict $
            foldMap (put_outpoint . txin_prevout) tx_inputs

      -- hashSequence: double SHA256 of all sequences, or zero if
      -- ANYONECANPAY or NONE or SINGLE
      !hash_sequence
        | anyonecanpay        = zero32
        | base == BaseSingle  = zero32
        | base == BaseNone    = zero32
        | otherwise = hash256 $ to_strict $
            foldMap (put_word32_le . txin_sequence) tx_inputs

      -- hashOutputs: depends on sighash type
      !hash_outputs = case base of
        BaseNone   -> zero32
        BaseSingle ->
          case safe_index outputs_list idx of
            Nothing  -> zero32  -- index out of range
            Just out -> hash256 $ to_strict $ put_txout out
        _ -> hash256 $ to_strict $ foldMap put_txout tx_outputs

      !outpoint = txin_prevout signing_input
      !sequence_n = txin_sequence signing_input

  pure $! to_strict $
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
    <> put_word32_le ht
