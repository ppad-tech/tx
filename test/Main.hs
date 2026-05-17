{-# LANGUAGE OverloadedStrings #-}

module Main where

import Bitcoin.Prim.Tx
import Bitcoin.Prim.Tx.Sighash
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Int (Int32)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NE
import Data.Word (Word32, Word64)
import Test.Tasty
import qualified Test.Tasty.HUnit as H
import Test.Tasty.QuickCheck as QC hiding (Witness)
import Test.QuickCheck
  ( Gen, Arbitrary(..), elements, oneof, chooseInt, forAll, (==>) )

-- main ------------------------------------------------------------------------

main :: IO ()
main = defaultMain $
  testGroup "ppad-tx" [
      testGroup "serialisation" [
          testGroup "round-trip" [
              roundtrip_legacy_simple
            , roundtrip_segwit
            , roundtrip_multi_io
            ]
        , testGroup "known vectors" [
              parse_satoshi_hal
            , parse_first_segwit
            ]
        , testGroup "compactSize" [
              test_compact_non_minimal_fd
            , test_compact_non_minimal_fe
            , test_compact_non_minimal_ff
            ]
        ]
    , testGroup "txid" [
          txid_satoshi_hal
        , txid_first_segwit
        ]
    , testGroup "edge cases" [
          edge_empty_scriptsig
        , edge_max_sequence
        , edge_zero_locktime
        , edge_multi_witness
        ]
    , testGroup "validation" [
          test_mkTxId_valid
        , test_mkTxId_short
        , test_mkTxId_long
        , test_mkTxId_empty
        , test_from_bytes_truncated
        , test_from_bytes_trailing
        , test_from_bytes_garbage
        , test_from_base16_invalid_hex
        , test_sighash_segwit_oob
        ]
    , testGroup "sighash" [
          testGroup "legacy" [
              sighash_legacy_minimal
            , testGroup "codeseparators" [
                  codesep_no_op
                , codesep_strip_simple
                , codesep_inside_push
                , codesep_inside_pushdata1
                ]
            , testGroup "Bitcoin Core sighash.json" [
                  bc_sighash_1
                , bc_sighash_2
                , bc_sighash_4
                , bc_sighash_9
                , bc_sighash_14
                , bc_sighash_20
                ]
            ]
        , testGroup "BIP143 segwit" [
              bip143_native_p2wpkh
            , bip143_p2sh_p2wpkh
            , testGroup "P2SH-P2WSH multi-sighash" [
                  bip143_p2sh_p2wsh_all
                , bip143_p2sh_p2wsh_none
                , bip143_p2sh_p2wsh_single
                , bip143_p2sh_p2wsh_all_acp
                , bip143_p2sh_p2wsh_none_acp
                , bip143_p2sh_p2wsh_single_acp
                ]
            ]
        ]
    , testGroup "properties" [
          testGroup "round-trip" [
              prop_roundtrip_bytes
            , prop_roundtrip_base16
            ]
        , testGroup "serialisation" [
              prop_legacy_no_witnesses
            , prop_segwit_longer
            ]
        , testGroup "txid" [
              prop_txid_32_bytes
            , prop_txid_ignores_witnesses
            ]
        , testGroup "sighash" [
              prop_sighash_legacy_32_bytes
            , prop_sighash_segwit_32_bytes
            , prop_sighash_single_bug
            , prop_sighash_segwit_oob
            , prop_sighash_legacy_acp_invariant
            , prop_sighash_legacy_none_invariant
            , prop_sighash_legacy_none_acp_invariant
            , prop_strip_codesep_idempotent
            , prop_strip_codesep_no_0xab_unchanged
            ]
        ]
    ]

-- helpers ---------------------------------------------------------------------

-- | Decode hex, failing the test on invalid input.
hex :: BS.ByteString -> BS.ByteString
hex h = case B16.decode h of
  Just bs -> bs
  Nothing -> error "test error: invalid hex literal"

-- | Assert round-trip: from_bytes (to_bytes tx) == Just tx
assertRoundtrip :: Tx -> H.Assertion
assertRoundtrip tx =
  let bs = to_bytes tx
  in  case from_bytes bs of
        Nothing  -> H.assertFailure "from_bytes returned Nothing"
        Just tx' -> H.assertEqual "round-trip mismatch" tx tx'

-- | Assert parsing from hex succeeds.
assertParses :: BS.ByteString -> H.Assertion
assertParses rawHex =
  case from_base16 rawHex of
    Nothing -> H.assertFailure "from_base16 returned Nothing"
    Just _  -> pure ()

-- round-trip tests ------------------------------------------------------------

-- Simple legacy tx: 1 input, 1 output, no witnesses
roundtrip_legacy_simple :: TestTree
roundtrip_legacy_simple = H.testCase "simple legacy tx" $
  assertRoundtrip legacyTx
  where
    legacyTx = Tx
      { tx_version   = 1
      , tx_inputs    = txin :| []
      , tx_outputs   = txout :| []
      , tx_witnesses = []
      , tx_locktime  = 0
      }
    txin = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0xab)
          , op_vout = 0
          }
      , txin_script_sig = hex "483045022100abcd"
      , txin_sequence   = 0xffffffff
      }
    txout = TxOut
      { txout_value = 50000
      , txout_script_pubkey = hex "76a91489abcdef"
      }

-- Segwit tx with witnesses
roundtrip_segwit :: TestTree
roundtrip_segwit = H.testCase "segwit tx with witnesses" $
  assertRoundtrip segwitTx
  where
    segwitTx = Tx
      { tx_version   = 2
      , tx_inputs    = txin :| []
      , tx_outputs   = txout :| []
      , tx_witnesses = [witness]
      , tx_locktime  = 500000
      }
    txin = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0x12)
          , op_vout = 1
          }
      , txin_script_sig = BS.empty  -- segwit: empty scriptSig
      , txin_sequence   = 0xfffffffe
      }
    txout = TxOut
      { txout_value = 100000000
      , txout_script_pubkey = hex "0014abcdef1234567890"
      }
    witness = Witness
      [ hex "304402201234"
      , hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      ]

-- Multiple inputs and outputs
roundtrip_multi_io :: TestTree
roundtrip_multi_io = H.testCase "multiple inputs/outputs" $
  assertRoundtrip multiTx
  where
    multiTx = Tx
      { tx_version   = 1
      , tx_inputs    = txin1 :| [txin2, txin3]
      , tx_outputs   = txout1 :| [txout2]
      , tx_witnesses = []
      , tx_locktime  = 123456
      }
    txin1 = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0x11)
          , op_vout = 0
          }
      , txin_script_sig = hex "4730440220"
      , txin_sequence   = 0xffffffff
      }
    txin2 = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0x22)
          , op_vout = 2
          }
      , txin_script_sig = hex "483045022100"
      , txin_sequence   = 0xffffffff
      }
    txin3 = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0x33)
          , op_vout = 5
          }
      , txin_script_sig = hex "00"
      , txin_sequence   = 0xfffffffe
      }
    txout1 = TxOut
      { txout_value = 10000000
      , txout_script_pubkey = hex "76a914"
      }
    txout2 = TxOut
      { txout_value = 5000000
      , txout_script_pubkey = hex "a914"
      }

-- known vector tests ----------------------------------------------------------

-- First Bitcoin transaction ever (block 170, Satoshi to Hal Finney)
-- TxId: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
satoshiHalRaw :: BS.ByteString
satoshiHalRaw =
  "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37\
  \04000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c6\
  \1548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac46220822\
  \21a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f0\
  \6b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303\
  \b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a01\
  \6b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f8\
  \2e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"

satoshiHalTxId :: BS.ByteString
satoshiHalTxId = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"

parse_satoshi_hal :: TestTree
parse_satoshi_hal = H.testCase "parse Satoshi->Hal tx (block 170)" $
  assertParses satoshiHalRaw

txid_satoshi_hal :: TestTree
txid_satoshi_hal = H.testCase "txid of Satoshi->Hal tx" $ do
  case from_base16 satoshiHalRaw of
    Nothing -> H.assertFailure "failed to parse tx"
    Just tx -> do
      let TxId computed = txid tx
          -- txid is displayed big-endian, but stored little-endian
          expected = BS.reverse (hex satoshiHalTxId)
      H.assertEqual "txid mismatch" expected computed

-- First segwit tx on mainnet (block 481824)
firstSegwitRaw :: BS.ByteString
firstSegwitRaw =
  "0200000000010140d43a99926d43eb0e619bf0b3d83b4a31f60c176beecfb9d35bf45e54\
  \d0f7420100000017160014a4b4ca48de0b3fffc15404a1acdc8dbaae226955ffffffff01\
  \00e1f5050000000017a9144a1154d50b03292b3024370901711946cb7cccc38702483045\
  \0221008604ef8f6d8afa892dee0f31259b6ce02dd70c545cfcfed8148179971f48d59202\
  \20770b9e1e5cf7f8c5d28c48abe49a3a25f1cf9e8a5b0d8f1c8f2f1c2dde88aa370121\
  \03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210500000000"

parse_first_segwit :: TestTree
parse_first_segwit = H.testCase "parse first segwit tx (block 481824)" $
  assertParses firstSegwitRaw

-- edge case tests -------------------------------------------------------------

-- Empty scriptSig (common in segwit)
edge_empty_scriptsig :: TestTree
edge_empty_scriptsig = H.testCase "empty scriptSig" $
  assertRoundtrip tx
  where
    tx = Tx
      { tx_version   = 2
      , tx_inputs    = txin :| []
      , tx_outputs   = txout :| []
      , tx_witnesses = [witness]
      , tx_locktime  = 0
      }
    txin = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0xff)
          , op_vout = 0
          }
      , txin_script_sig = BS.empty
      , txin_sequence   = 0xffffffff
      }
    txout = TxOut
      { txout_value = 1000
      , txout_script_pubkey = hex "0014abcdef"
      }
    witness = Witness [hex "3044", hex "02"]

-- Maximum sequence number (0xffffffff)
edge_max_sequence :: TestTree
edge_max_sequence = H.testCase "maximum sequence (0xffffffff)" $
  assertRoundtrip tx
  where
    tx = Tx
      { tx_version   = 1
      , tx_inputs    = txin :| []
      , tx_outputs   = txout :| []
      , tx_witnesses = []
      , tx_locktime  = 0
      }
    txin = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0x00)
          , op_vout = 0xffffffff  -- max vout too
          }
      , txin_script_sig = hex "00"
      , txin_sequence   = 0xffffffff
      }
    txout = TxOut
      { txout_value = 0
      , txout_script_pubkey = hex "6a"  -- OP_RETURN
      }

-- Zero locktime
edge_zero_locktime :: TestTree
edge_zero_locktime = H.testCase "zero locktime" $
  assertRoundtrip tx
  where
    tx = Tx
      { tx_version   = 1
      , tx_inputs    = txin :| []
      , tx_outputs   = txout :| []
      , tx_witnesses = []
      , tx_locktime  = 0
      }
    txin = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0xaa)
          , op_vout = 0
          }
      , txin_script_sig = hex "51"  -- OP_1
      , txin_sequence   = 0
      }
    txout = TxOut
      { txout_value = 100
      , txout_script_pubkey = hex "51"
      }

-- Multiple witness items per input
edge_multi_witness :: TestTree
edge_multi_witness = H.testCase "multiple witness items" $
  assertRoundtrip tx
  where
    tx = Tx
      { tx_version   = 2
      , tx_inputs    = txin1 :| [txin2]
      , tx_outputs   = txout :| []
      , tx_witnesses = [witness1, witness2]
      , tx_locktime  = 0
      }
    txin1 = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0x01)
          , op_vout = 0
          }
      , txin_script_sig = BS.empty
      , txin_sequence   = 0xffffffff
      }
    txin2 = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0x02)
          , op_vout = 1
          }
      , txin_script_sig = BS.empty
      , txin_sequence   = 0xffffffff
      }
    txout = TxOut
      { txout_value = 50000
      , txout_script_pubkey = hex "0014"
      }
    -- 5 witness items for input 1
    witness1 = Witness
      [ BS.empty  -- empty item (common in multisig)
      , hex "304402201234"
      , hex "3045022100abcd"
      , hex "522102"
      , hex "ae"
      ]
    -- 2 witness items for input 2
    witness2 = Witness
      [ hex "3044"
      , hex "03"
      ]

-- validation tests -----------------------------------------------------------

-- mkTxId: valid 32-byte input accepted
test_mkTxId_valid :: TestTree
test_mkTxId_valid = H.testCase "mkTxId accepts 32 bytes" $
  case mkTxId (BS.replicate 32 0x00) of
    Nothing -> H.assertFailure "mkTxId returned Nothing"
    Just _  -> pure ()

-- mkTxId: 31 bytes rejected
test_mkTxId_short :: TestTree
test_mkTxId_short = H.testCase "mkTxId rejects 31 bytes" $
  H.assertEqual "should be Nothing"
    Nothing (mkTxId (BS.replicate 31 0x00))

-- mkTxId: 33 bytes rejected
test_mkTxId_long :: TestTree
test_mkTxId_long = H.testCase "mkTxId rejects 33 bytes" $
  H.assertEqual "should be Nothing"
    Nothing (mkTxId (BS.replicate 33 0x00))

-- mkTxId: empty input rejected
test_mkTxId_empty :: TestTree
test_mkTxId_empty = H.testCase "mkTxId rejects empty" $
  H.assertEqual "should be Nothing"
    Nothing (mkTxId BS.empty)

-- from_bytes: truncated input rejected
test_from_bytes_truncated :: TestTree
test_from_bytes_truncated =
  H.testCase "from_bytes rejects truncated input" $ do
    let full = to_bytes legacyTx1
        truncated = BS.take (BS.length full - 1) full
    H.assertEqual "should be Nothing"
      Nothing (from_bytes truncated)

-- from_bytes: trailing bytes rejected
test_from_bytes_trailing :: TestTree
test_from_bytes_trailing =
  H.testCase "from_bytes rejects trailing bytes" $ do
    let full = to_bytes legacyTx1
        padded = full <> BS.singleton 0x00
    H.assertEqual "should be Nothing"
      Nothing (from_bytes padded)

-- from_bytes: garbage rejected
test_from_bytes_garbage :: TestTree
test_from_bytes_garbage =
  H.testCase "from_bytes rejects garbage" $
    H.assertEqual "should be Nothing"
      Nothing (from_bytes (BS.pack [0xde, 0xad]))

-- from_base16: invalid hex rejected
test_from_base16_invalid_hex :: TestTree
test_from_base16_invalid_hex =
  H.testCase "from_base16 rejects invalid hex" $
    H.assertEqual "should be Nothing"
      Nothing (from_base16 "not valid hex!!!")

-- sighash_segwit: out-of-range index returns Nothing
test_sighash_segwit_oob :: TestTree
test_sighash_segwit_oob =
  H.testCase "sighash_segwit rejects out-of-range index" $ do
    let rawTx = hex $ mconcat
          [ "0100000002fff7f7881a8099afa6940d42d1e7f6362bec"
          , "38171ea3edf433541db4e4ad969f0000000000eeffffff"
          , "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287"
          , "d9b2b55d57b90ec68a0100000000ffffffff02202cb206"
          , "000000001976a9148280b37df378db99f66f85c95a783a"
          , "76ac7a6d5988ac9093510d000000001976a9143bde42db"
          , "ee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
          ]
    case from_bytes rawTx of
      Nothing -> H.assertFailure "failed to parse tx"
      Just tx ->
        H.assertEqual "should be Nothing"
          Nothing
          (sighash_segwit tx 99 "script" 0 (encode_sighash SIGHASH_ALL))

-- | A minimal legacy tx used by validation tests.
legacyTx1 :: Tx
legacyTx1 = Tx
  { tx_version   = 1
  , tx_inputs    = txin :| []
  , tx_outputs   = txout :| []
  , tx_witnesses = []
  , tx_locktime  = 0
  }
  where
    txin = TxIn
      { txin_prevout = OutPoint
          { op_txid = TxId (BS.replicate 32 0x00)
          , op_vout = 0
          }
      , txin_script_sig = hex "00"
      , txin_sequence   = 0xffffffff
      }
    txout = TxOut
      { txout_value = 0
      , txout_script_pubkey = hex "6a"
      }

-- legacy sighash vectors ----------------------------------------------------

-- Minimal tx: 1-in/1-out, signing input 0, SIGHASH_ALL,
-- scriptPubKey = OP_1 (0x51)
sighash_legacy_minimal :: TestTree
sighash_legacy_minimal =
  H.testCase "minimal tx SIGHASH_ALL" $ do
    let tx = Tx
          { tx_version   = 1
          , tx_inputs    = txin :| []
          , tx_outputs   = txout :| []
          , tx_witnesses = []
          , tx_locktime  = 0
          }
        txin = TxIn
          { txin_prevout = OutPoint
              { op_txid = TxId (BS.replicate 32 0x00)
              , op_vout = 0
              }
          , txin_script_sig = hex "00"
          , txin_sequence   = 0xffffffff
          }
        txout = TxOut
          { txout_value = 0
          , txout_script_pubkey = hex "6a"
          }
        script_pubkey = hex "51"
        expected = hex
          "049b7618cbda49a0190c5eea6f97320b\
          \930aa32b64be6e71ed20041067685c45"
        result = sighash_legacy tx 0 script_pubkey
                   (encode_sighash SIGHASH_ALL)
    H.assertEqual "sighash mismatch" expected result

-- BIP143 sighash vectors -----------------------------------------------------

-- Native P2WPKH (BIP143 example)
-- https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
bip143_native_p2wpkh :: TestTree
bip143_native_p2wpkh = H.testCase "native P2WPKH" $ do
  let rawTx = hex $ mconcat
        [ "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf43354"
        , "1db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e"
        , "815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb20600"
        , "0000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093"
        , "510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988"
        , "ac11000000"
        ]
  case from_bytes rawTx of
    Nothing -> H.assertFailure "failed to parse BIP143 tx"
    Just tx -> do
      let inputIdx = 1
          -- scriptCode for P2WPKH (without length prefix)
          scriptCode = hex
            "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
          value = 600000000 :: Word64
          expected = hex
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
      case sighash_segwit tx inputIdx scriptCode value
             (encode_sighash SIGHASH_ALL) of
        Nothing -> H.assertFailure "sighash_segwit returned Nothing"
        Just result -> H.assertEqual "sighash mismatch" expected result

-- P2SH-P2WPKH (BIP143 example)
bip143_p2sh_p2wpkh :: TestTree
bip143_p2sh_p2wpkh = H.testCase "P2SH-P2WPKH" $ do
  let rawTx = hex $ mconcat
        [ "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac"
        , "4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b6"
        , "84d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914"
        , "fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
        ]
  case from_bytes rawTx of
    Nothing -> H.assertFailure "failed to parse BIP143 tx"
    Just tx -> do
      let inputIdx = 0
          -- scriptCode without length prefix
          scriptCode = hex
            "76a91479091972186c449eb1ded22b78e40d009bdf008988ac"
          value = 1000000000 :: Word64
          expected = hex
            "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
      case sighash_segwit tx inputIdx scriptCode value
             (encode_sighash SIGHASH_ALL) of
        Nothing -> H.assertFailure "sighash_segwit returned Nothing"
        Just result -> H.assertEqual "sighash mismatch" expected result

-- Arbitrary instances --------------------------------------------------------

instance Arbitrary TxId where
  arbitrary = TxId . BS.pack <$> vectorOf 32 arbitrary

instance Arbitrary OutPoint where
  arbitrary = OutPoint <$> arbitrary <*> arbitrary

instance Arbitrary TxIn where
  arbitrary = TxIn
    <$> arbitrary
    <*> arbitraryScript
    <*> arbitrary

instance Arbitrary TxOut where
  arbitrary = TxOut
    <$> arbitrary
    <*> arbitraryScript

instance Arbitrary Witness where
  arbitrary = Witness <$> listOf arbitraryScript

instance Arbitrary SighashType where
  arbitrary = elements
    [ SIGHASH_ALL
    , SIGHASH_NONE
    , SIGHASH_SINGLE
    , SIGHASH_ALL_ANYONECANPAY
    , SIGHASH_NONE_ANYONECANPAY
    , SIGHASH_SINGLE_ANYONECANPAY
    ]

-- | Generate arbitrary script-like bytestrings (0-200 bytes).
arbitraryScript :: Gen BS.ByteString
arbitraryScript = do
  len <- chooseInt (0, 200)
  BS.pack <$> vectorOf len arbitrary

-- | Generate a NonEmpty list of 1-5 items.
arbitraryNonEmpty :: Arbitrary a => Gen (NonEmpty a)
arbitraryNonEmpty = do
  x <- arbitrary
  xs <- listOf1to4
  pure (x :| xs)
  where
    listOf1to4 = do
      n <- chooseInt (0, 4)
      vectorOf n arbitrary

-- | Generate a valid legacy transaction (no witnesses).
genLegacyTx :: Gen Tx
genLegacyTx = do
  ver <- arbitrary
  ins <- arbitraryNonEmpty
  outs <- arbitraryNonEmpty
  lt <- arbitrary
  pure $ Tx ver ins outs [] lt

-- | Generate a valid segwit transaction (with witnesses).
genSegwitTx :: Gen Tx
genSegwitTx = do
  ver <- arbitrary
  ins <- arbitraryNonEmpty
  outs <- arbitraryNonEmpty
  -- One witness per input
  let numInputs = NE.length ins
  wits <- vectorOf numInputs arbitrary
  lt <- arbitrary
  pure $ Tx ver ins outs wits lt

-- | Generate any valid transaction.
instance Arbitrary Tx where
  arbitrary = oneof [genLegacyTx, genSegwitTx]

-- property tests -------------------------------------------------------------

-- Round-trip: from_bytes (to_bytes tx) == Just tx
prop_roundtrip_bytes :: TestTree
prop_roundtrip_bytes = QC.testProperty "from_bytes . to_bytes == Just" $
  \tx -> from_bytes (to_bytes tx) === Just (tx :: Tx)

-- Round-trip: from_base16 (to_base16 tx) == Just tx
prop_roundtrip_base16 :: TestTree
prop_roundtrip_base16 = QC.testProperty "from_base16 . to_base16 == Just" $
  \tx -> from_base16 (to_base16 tx) === Just (tx :: Tx)

-- Legacy tx (no witnesses): to_bytes == to_bytes_legacy
prop_legacy_no_witnesses :: TestTree
prop_legacy_no_witnesses =
  QC.testProperty "legacy tx: to_bytes == to_bytes_legacy" $
    forAll genLegacyTx $ \tx ->
      to_bytes tx === to_bytes_legacy tx

-- Segwit tx: to_bytes is longer than to_bytes_legacy (when witnesses present)
prop_segwit_longer :: TestTree
prop_segwit_longer =
  QC.testProperty "segwit tx: to_bytes longer than to_bytes_legacy" $
    forAll genSegwitTx $ \tx ->
      not (null (tx_witnesses tx)) ==>
        BS.length (to_bytes tx) > BS.length (to_bytes_legacy tx)

-- TxId is always 32 bytes
prop_txid_32_bytes :: TestTree
prop_txid_32_bytes = QC.testProperty "txid is always 32 bytes" $
  \tx -> let TxId bs = txid tx in BS.length bs === 32

-- TxId ignores witnesses (same txid with or without witnesses)
prop_txid_ignores_witnesses :: TestTree
prop_txid_ignores_witnesses =
  QC.testProperty "txid ignores witnesses" $
    forAll genSegwitTx $ \tx ->
      let txNoWit = tx { tx_witnesses = [] }
      in  txid tx === txid txNoWit

-- sighash_legacy always returns 32 bytes
prop_sighash_legacy_32_bytes :: TestTree
prop_sighash_legacy_32_bytes =
  QC.testProperty "sighash_legacy is always 32 bytes" $
    forAll genLegacyTx $ \tx ->
      forAll arbitraryScript $ \spk ->
        forAll arbitrary $ \st ->
          BS.length (sighash_legacy tx 0 spk (encode_sighash st)) === 32

-- sighash_segwit returns Just 32 bytes for any valid index
prop_sighash_segwit_32_bytes :: TestTree
prop_sighash_segwit_32_bytes =
  QC.testProperty "sighash_segwit is 32 bytes for valid index" $
    forAll genSegwitTx $ \tx ->
      let nIns = NE.length (tx_inputs tx)
      in  forAll (chooseInt (0, nIns - 1)) $ \idx ->
            forAll arbitraryScript $ \sc ->
              forAll (arbitrary :: Gen Word64) $ \val ->
                forAll arbitrary $ \st ->
                  case sighash_segwit tx idx sc val (encode_sighash st) of
                    Nothing -> False  -- should succeed for valid index
                    Just bs -> BS.length bs == 32

-- SIGHASH_SINGLE bug: returns 0x01 ++ 0x00*31 when index >= outputs
prop_sighash_single_bug :: TestTree
prop_sighash_single_bug =
  QC.testProperty "SIGHASH_SINGLE bug when index >= outputs" $
    forAll genLegacyTx $ \tx ->
      let numOutputs = NE.length (tx_outputs tx)
          bugValue = BS.cons 0x01 (BS.replicate 31 0x00)
      in  forAll arbitraryScript $ \spk ->
            sighash_legacy tx numOutputs spk
              (encode_sighash SIGHASH_SINGLE) === bugValue

-- sighash_segwit: out-of-range index always returns Nothing
prop_sighash_segwit_oob :: TestTree
prop_sighash_segwit_oob =
  QC.testProperty "sighash_segwit returns Nothing for oob index" $
    forAll genSegwitTx $ \tx ->
      let nIns = NE.length (tx_inputs tx)
      in  forAll (chooseInt (nIns, nIns + 10)) $ \idx ->
            forAll arbitraryScript $ \sc ->
              forAll (arbitrary :: Gen Word64) $ \val ->
                forAll arbitrary $ \st ->
                  sighash_segwit tx idx sc val (encode_sighash st)
                    === Nothing

-- ANYONECANPAY commits to only the signing input. Appending extra
-- inputs to the tx (without displacing index 0) must not change the
-- hash.
prop_sighash_legacy_acp_invariant :: TestTree
prop_sighash_legacy_acp_invariant =
  QC.testProperty "SIGHASH_ALL|ANYONECANPAY ignores appended inputs" $
    forAll genLegacyTx $ \tx ->
      forAll (QC.listOf1 (arbitrary :: Gen TxIn)) $ \extras ->
        forAll arbitraryScript $ \spk ->
          let tx' = tx { tx_inputs = appendInputs (tx_inputs tx) extras }
              ht  = encode_sighash SIGHASH_ALL_ANYONECANPAY
              h1  = sighash_legacy tx  0 spk ht
              h2  = sighash_legacy tx' 0 spk ht
          in  h1 === h2

-- SIGHASH_NONE strips outputs from the preimage. Appending extra
-- outputs must not change the hash.
prop_sighash_legacy_none_invariant :: TestTree
prop_sighash_legacy_none_invariant =
  QC.testProperty "SIGHASH_NONE ignores appended outputs" $
    forAll genLegacyTx $ \tx ->
      forAll (QC.listOf1 (arbitrary :: Gen TxOut)) $ \extras ->
        forAll arbitraryScript $ \spk ->
          let tx' = tx { tx_outputs = appendOutputs (tx_outputs tx) extras }
              ht  = encode_sighash SIGHASH_NONE
              h1  = sighash_legacy tx  0 spk ht
              h2  = sighash_legacy tx' 0 spk ht
          in  h1 === h2

-- SIGHASH_NONE|ANYONECANPAY ignores both other inputs and all outputs.
prop_sighash_legacy_none_acp_invariant :: TestTree
prop_sighash_legacy_none_acp_invariant =
  QC.testProperty
    "SIGHASH_NONE|ANYONECANPAY ignores appended inputs and outputs" $
    forAll genLegacyTx $ \tx ->
      forAll (QC.listOf1 (arbitrary :: Gen TxIn)) $ \extraIns ->
        forAll (QC.listOf1 (arbitrary :: Gen TxOut)) $ \extraOuts ->
          forAll arbitraryScript $ \spk ->
            let tx' = tx
                  { tx_inputs  = appendInputs  (tx_inputs tx)  extraIns
                  , tx_outputs = appendOutputs (tx_outputs tx) extraOuts
                  }
                ht = encode_sighash SIGHASH_NONE_ANYONECANPAY
                h1 = sighash_legacy tx  0 spk ht
                h2 = sighash_legacy tx' 0 spk ht
            in  h1 === h2

-- | Append items to a NonEmpty list.
appendInputs :: NonEmpty TxIn -> [TxIn] -> NonEmpty TxIn
appendInputs (x :| xs) extras = x :| (xs ++ extras)

appendOutputs :: NonEmpty TxOut -> [TxOut] -> NonEmpty TxOut
appendOutputs (x :| xs) extras = x :| (xs ++ extras)

-- compactSize non-minimal rejection -----------------------------------------

-- Build a legacy tx whose input scriptSig length is encoded with a
-- non-minimal compactSize tag. We construct the bytes directly.
--
-- Layout (legacy):
--   version(4) | n_inputs(compact) | outpoint(36) | scriptSig_len(compact)
--   | scriptSig | sequence(4) | n_outputs(compact) | outputs... | locktime(4)
--
-- We use a 0-byte scriptSig but encode its length with a non-minimal tag.
nonMinimalLegacyTx :: BS.ByteString -> BS.ByteString
nonMinimalLegacyTx badLen = BS.concat
  [ BS.pack [0x01, 0x00, 0x00, 0x00]      -- version 1
  , BS.pack [0x01]                        -- 1 input
  , BS.replicate 32 0x00                  -- outpoint txid
  , BS.pack [0x00, 0x00, 0x00, 0x00]      -- outpoint vout
  , badLen                                -- non-minimal compactSize
  , BS.pack [0xff, 0xff, 0xff, 0xff]      -- sequence
  , BS.pack [0x01]                        -- 1 output
  , BS.replicate 8 0x00                   -- value
  , BS.pack [0x00]                        -- empty scriptPubKey
  , BS.pack [0x00, 0x00, 0x00, 0x00]      -- locktime
  ]

test_compact_non_minimal_fd :: TestTree
test_compact_non_minimal_fd =
  H.testCase "rejects 0xfd encoding of value < 0xfd" $
    H.assertEqual "should be Nothing"
      Nothing
      (from_bytes (nonMinimalLegacyTx (BS.pack [0xfd, 0x00, 0x00])))

test_compact_non_minimal_fe :: TestTree
test_compact_non_minimal_fe =
  H.testCase "rejects 0xfe encoding of value <= 0xffff" $
    H.assertEqual "should be Nothing"
      Nothing
      (from_bytes
         (nonMinimalLegacyTx (BS.pack [0xfe, 0x00, 0x00, 0x00, 0x00])))

test_compact_non_minimal_ff :: TestTree
test_compact_non_minimal_ff =
  H.testCase "rejects 0xff encoding of value <= 0xffffffff" $
    H.assertEqual "should be Nothing"
      Nothing
      (from_bytes (nonMinimalLegacyTx
         (BS.pack [0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])))

-- segwit txid known vector --------------------------------------------------

-- Regression vector: txid of firstSegwitRaw, displayed big-endian.
firstSegwitTxId :: BS.ByteString
firstSegwitTxId =
  "c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a"

txid_first_segwit :: TestTree
txid_first_segwit = H.testCase "txid of first-segwit fixture" $
  case from_base16 firstSegwitRaw of
    Nothing -> H.assertFailure "failed to parse tx"
    Just tx -> do
      let TxId computed = txid tx
          expected      = BS.reverse (hex firstSegwitTxId)
      H.assertEqual "txid mismatch" expected computed

-- BIP143 P2SH-P2WSH multi-sighash vectors -----------------------------------

-- Shared fixture: unsigned tx, scriptCode, input index, value.
-- Source: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
p2shP2wshTx :: Tx
p2shP2wshTx =
  let raw = mconcat
        [ "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c"
        , "1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffc"
        , "e9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a914"
        , "7480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"
        ]
  in  case from_base16 raw of
        Just t  -> t
        Nothing -> error "BIP143 P2SH-P2WSH fixture failed to parse"

p2shP2wshScriptCode :: BS.ByteString
p2shP2wshScriptCode = hex $ mconcat
  [ "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c"
  , "3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43ee"
  , "a8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f5"
  , "0376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de746831239"
  , "87e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c"
  , "07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c1"
  , "9617681024306b56ae"
  ]

p2shP2wshValue :: Word64
p2shP2wshValue = 987654321  -- 9.87654321 BTC

assertP2shP2wshSighash :: SighashType -> BS.ByteString -> H.Assertion
assertP2shP2wshSighash st expectedHex =
  case sighash_segwit p2shP2wshTx 0 p2shP2wshScriptCode p2shP2wshValue
         (encode_sighash st) of
    Nothing  -> H.assertFailure "sighash_segwit returned Nothing"
    Just res -> H.assertEqual "sighash mismatch" (hex expectedHex) res

bip143_p2sh_p2wsh_all :: TestTree
bip143_p2sh_p2wsh_all = H.testCase "SIGHASH_ALL" $
  assertP2shP2wshSighash SIGHASH_ALL
    "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c"

bip143_p2sh_p2wsh_none :: TestTree
bip143_p2sh_p2wsh_none = H.testCase "SIGHASH_NONE" $
  assertP2shP2wshSighash SIGHASH_NONE
    "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36"

bip143_p2sh_p2wsh_single :: TestTree
bip143_p2sh_p2wsh_single = H.testCase "SIGHASH_SINGLE" $
  assertP2shP2wshSighash SIGHASH_SINGLE
    "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea"

bip143_p2sh_p2wsh_all_acp :: TestTree
bip143_p2sh_p2wsh_all_acp = H.testCase "SIGHASH_ALL|ANYONECANPAY" $
  assertP2shP2wshSighash SIGHASH_ALL_ANYONECANPAY
    "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e"

bip143_p2sh_p2wsh_none_acp :: TestTree
bip143_p2sh_p2wsh_none_acp = H.testCase "SIGHASH_NONE|ANYONECANPAY" $
  assertP2shP2wshSighash SIGHASH_NONE_ANYONECANPAY
    "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a"

bip143_p2sh_p2wsh_single_acp :: TestTree
bip143_p2sh_p2wsh_single_acp = H.testCase "SIGHASH_SINGLE|ANYONECANPAY" $
  assertP2shP2wshSighash SIGHASH_SINGLE_ANYONECANPAY
    "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b"

-- Bitcoin Core sighash.json legacy vectors ----------------------------------

-- These exercise the raw 32-bit hashType code path. Bitcoin Core's
-- sighash.json uses non-canonical hashType values that commit the full
-- 32 bits to the preimage; the SighashType ADT can't construct them.
--
-- Source: github.com/bitcoin/bitcoin src/test/data/sighash.json (first
-- 20 entries). Expected hashes are stored big-endian (via
-- uint256::GetHex) so we reverse before comparing.
--
-- Bitcoin Core's hashType field is int32_t (signed); we cast to Word32.
bcHashType :: Int32 -> Word32
bcHashType = fromIntegral

-- | Run a Bitcoin-Core sighash.json legacy vector.
bcSighashCase
  :: TestName
  -> BS.ByteString  -- ^ raw tx hex
  -> BS.ByteString  -- ^ scriptCode hex
  -> Int            -- ^ input index
  -> Int32          -- ^ signed hashType
  -> BS.ByteString  -- ^ expected hash hex (big-endian display)
  -> TestTree
bcSighashCase name rawHex scriptHex idx ht expectedHex =
  H.testCase name $
    case from_base16 rawHex of
      Nothing -> H.assertFailure "failed to parse tx"
      Just tx ->
        let result   = sighash_legacy tx idx (hex scriptHex) (bcHashType ht)
            expected = BS.reverse (hex expectedHex)
        in  H.assertEqual "sighash mismatch" expected result

bc_sighash_1 :: TestTree
bc_sighash_1 = bcSighashCase
  "entry 1: idx=2, hashType=0x6f29291f (ALL)"
  (mconcat
    [ "907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696"
    , "526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c9"
    , "17a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052"
    , "ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f868"
    , "4cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008"
    , "535300516352515164370e010000000003006300ab2ec229"
    ])
  ""
  2
  1864164639
  "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e"

-- NOTE: raw hex is on a single line to avoid manual-splitting errors.
bc_sighash_2 :: TestTree
bc_sighash_2 = bcSighashCase
  "entry 2: idx=0, hashType=0xad118f9c (ALL|ACP)"
  "a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea1771d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e4682988785744602b8c87228fcef0695085edf19088af1a9db126e93000000000665516aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5aa8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b000000000000499e50030000000008636a00ac526563ac5051ee030000000003abacabd2b6fe000000000003516563910fb6b5"
  "65"
  0
  (-1391424484)
  "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175"

bc_sighash_4 :: TestTree
bc_sighash_4 = bcSighashCase
  "entry 4: idx=1, hashType=0x46fb4ce9 (ALL|ACP)"
  (mconcat
    [ "73107cbd025c22ebc8c3e0a47b2a760739216a528de8d4dab5d45cbeb3051ceb"
    , "ae73b01ca10200000007ab6353656a636affffffffe26816dffc670841e6a6c8"
    , "c61c586da401df1261a330a6c6b3dd9f9a0789bc9e000000000800ac6552ac6a"
    , "ac51ffffffff0174a8f0010000000004ac52515100000000"
    ])
  "5163ac63635151ac"
  1
  1190874345
  "06e328de263a87b09beabe222a21627a6ea5c7f560030da31610c4611f4a46bc"

bc_sighash_9 :: TestTree
bc_sighash_9 = bcSighashCase
  "entry 9: idx=0, hashType=0x8b07e3c3 (SINGLE|ACP)"
  (mconcat
    [ "d3b7421e011f4de0f1cea9ba7458bf3486bee722519efab711a963fa8c100970"
    , "cf7488b7bb0200000003525352dcd61b300148be5d05000000000000000000"
    ])
  "535251536aac536a"
  0
  (-1960128125)
  "29aa6d2d752d3310eba20442770ad345b7f6a35f96161ede5f07b33e92053e2a"

bc_sighash_14 :: TestTree
bc_sighash_14 = bcSighashCase
  "entry 14: idx=1, hashType=0x9604e295 (ALL|ACP, strips 2x 0xab)"
  "f40a750702af06efff3ea68e5d56e42bc41cdb8b6065c98f1221fe04a325a898cb61f3d7ee030000000363acacffffffffb5788174aef79788716f96af779d7959147a0c2e0e5bfb6c2dba2df5b4b97894030000000965510065535163ac6affffffff0445e6fd0200000000096aac536365526a526aa6546b000000000008acab656a6552535141a0fd010000000000c897ea030000000008526500ab526a6a631b39dba3"
  "00abab5163ac"
  1
  (-1778064747)
  "d76d0fc0abfa72d646df888bce08db957e627f72962647016eeae5a8412354cf"

bc_sighash_20 :: TestTree
bc_sighash_20 = bcSighashCase
  "entry 20: idx=0, hashType=0xcab2f825 (ALL)"
  (mconcat
    [ "c2b0b99001acfecf7da736de0ffaef8134a9676811602a6299ba5a2563a23bb0"
    , "9e8cbedf9300000000026300ffffffff042997c50300000000045252536a2724"
    , "37030000000007655353ab6363ac663752030000000002ab6a6d5c9000000000"
    , "00066a6a5265abab00000000"
    ])
  "52ac525163515251"
  0
  (-894181723)
  "8b300032a1915a4ac05cea2f7d44c26f2a08d109a71602636f15866563eaafdc"

-- strip_codeseparators tests -------------------------------------------------

-- A script containing 0x00, OP_1, OP_IF, OP_CHECKSIG and no 0xab. Strip
-- should be a no-op.
codesep_no_op :: TestTree
codesep_no_op = H.testCase "no 0xab: unchanged" $
  H.assertEqual "" (BS.pack [0x00, 0x51, 0x63, 0xac])
    (strip_codeseparators (BS.pack [0x00, 0x51, 0x63, 0xac]))

-- Two OP_CODESEPARATOR bytes in opcode position get stripped.
codesep_strip_simple :: TestTree
codesep_strip_simple = H.testCase "0xab at opcode position stripped" $
  H.assertEqual "" (BS.pack [0x00, 0x51, 0x63, 0xac])
    (strip_codeseparators (BS.pack [0x00, 0xab, 0xab, 0x51, 0x63, 0xac]))

-- A direct push (opcode 0x02) of two 0xab bytes: data preserved.
codesep_inside_push :: TestTree
codesep_inside_push = H.testCase "0xab inside push data preserved" $
  let s = BS.pack [0x02, 0xab, 0xab, 0x51]  -- push 2 bytes, then OP_1
  in  H.assertEqual "" s (strip_codeseparators s)

-- OP_PUSHDATA1 with 3 bytes of 0xab, followed by a lone 0xab opcode and
-- OP_1. The data must be preserved; the trailing 0xab opcode stripped.
codesep_inside_pushdata1 :: TestTree
codesep_inside_pushdata1 =
  H.testCase "OP_PUSHDATA1 data preserved, trailing 0xab stripped" $
    let input    = BS.pack [0x4c, 0x03, 0xab, 0xab, 0xab, 0xab, 0x51]
        expected = BS.pack [0x4c, 0x03, 0xab, 0xab, 0xab, 0x51]
    in  H.assertEqual "" expected (strip_codeseparators input)

-- | Arbitrary ByteString generator (QuickCheck has no built-in instance).
genByteString :: Gen BS.ByteString
genByteString = BS.pack <$> arbitrary

prop_strip_codesep_idempotent :: TestTree
prop_strip_codesep_idempotent =
  QC.testProperty "strip_codeseparators is idempotent" $
    forAll genByteString $ \s ->
      strip_codeseparators (strip_codeseparators s)
        === strip_codeseparators s

prop_strip_codesep_no_0xab_unchanged :: TestTree
prop_strip_codesep_no_0xab_unchanged =
  QC.testProperty "strip_codeseparators is no-op without 0xab bytes" $
    forAll (BS.pack . filter (/= 0xab) <$> arbitrary) $ \s ->
      strip_codeseparators s === s

