{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}

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

import Bitcoin.Prim.Tx (Tx)
import qualified Data.ByteString as BS
import Data.Word (Word64)
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

-- | Compute legacy sighash.
--
--   Modifies a copy of the transaction based on sighash flags, appends
--   the sighash type as 4-byte little-endian, and double SHA256s.
sighash_legacy
  :: Tx
  -> Int              -- ^ input index
  -> BS.ByteString    -- ^ scriptPubKey being spent
  -> SighashType
  -> BS.ByteString    -- ^ 32-byte hash
sighash_legacy = error "Bitcoin.Prim.Tx.Sighash.sighash_legacy: not yet implemented"

-- | Compute BIP143 segwit sighash.
--
--   Required for signing segwit inputs.
sighash_segwit
  :: Tx
  -> Int              -- ^ input index
  -> BS.ByteString    -- ^ scriptCode
  -> Word64           -- ^ value being spent (satoshis)
  -> SighashType
  -> BS.ByteString    -- ^ 32-byte hash
sighash_segwit = error "Bitcoin.Prim.Tx.Sighash.sighash_segwit: not yet implemented"
