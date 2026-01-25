{-# LANGUAGE OverloadedStrings #-}

module Main where

import Bitcoin.Prim.Tx
import Bitcoin.Prim.Tx.Sighash
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NE
import Data.Word (Word64)
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
        ]
    , testGroup "txid" [
          txid_satoshi_hal
        ]
    , testGroup "edge cases" [
          edge_empty_scriptsig
        , edge_max_sequence
        , edge_zero_locktime
        , edge_multi_witness
        ]
    , testGroup "sighash" [
          testGroup "legacy" [
            ]
        , testGroup "BIP143 segwit" [
              bip143_native_p2wpkh
            , bip143_p2sh_p2wpkh
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
      case sighash_segwit tx inputIdx scriptCode value SIGHASH_ALL of
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
      case sighash_segwit tx inputIdx scriptCode value SIGHASH_ALL of
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
          BS.length (sighash_legacy tx 0 spk st) === 32

-- sighash_segwit returns Just 32 bytes for valid index
prop_sighash_segwit_32_bytes :: TestTree
prop_sighash_segwit_32_bytes =
  QC.testProperty "sighash_segwit is 32 bytes for valid index" $
    forAll genSegwitTx $ \tx ->
      forAll arbitraryScript $ \sc ->
        forAll (arbitrary :: Gen Word64) $ \val ->
          forAll arbitrary $ \st ->
            case sighash_segwit tx 0 sc val st of
              Nothing -> False  -- should succeed for index 0
              Just bs -> BS.length bs == 32

-- SIGHASH_SINGLE bug: returns 0x01 ++ 0x00*31 when index >= outputs
prop_sighash_single_bug :: TestTree
prop_sighash_single_bug =
  QC.testProperty "SIGHASH_SINGLE bug when index >= outputs" $
    forAll genLegacyTx $ \tx ->
      let numOutputs = NE.length (tx_outputs tx)
          bugValue = BS.cons 0x01 (BS.replicate 31 0x00)
      in  forAll arbitraryScript $ \spk ->
            sighash_legacy tx numOutputs spk SIGHASH_SINGLE === bugValue
