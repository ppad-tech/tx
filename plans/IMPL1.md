# IMPL1 - Core Types, Serialisation, and TxId

## Goal

Implement core transaction types, binary serialisation (legacy and segwit
formats), and txid computation.

## Scope

- `Bitcoin.Prim.Tx` module: types and serialisation
- CompactSize (varint) encoding/decoding
- Legacy and segwit tx formats
- TxId computation via double SHA256

## Types

Types are already defined in skeleton. Key points:

- `TxId`: 32-byte ByteString (stored as-is, displayed reversed per convention)
- `OutPoint`: TxId + Word32 vout
- `TxIn`: OutPoint + scriptSig + sequence
- `TxOut`: Word64 value + scriptPubKey
- `Witness`: list of stack items (ByteStrings)
- `Tx`: version + inputs + outputs + witnesses + locktime

## CompactSize Encoding

Internal helpers for Bitcoin's variable-length integer format:

```haskell
-- | Encode a Word64 as compactSize.
put_compact :: Word64 -> BS.ByteString

-- | Decode compactSize, returning (value, bytes_consumed).
get_compact :: BS.ByteString -> Maybe (Word64, Int)
```

Encoding rules:
- 0x00-0xfc: 1 byte (value itself)
- 0xfd-0xffff: 0xfd ++ 2 bytes LE
- 0x10000-0xffffffff: 0xfe ++ 4 bytes LE
- larger: 0xff ++ 8 bytes LE

## Serialisation Implementation

### Encoding (to_bytes)

Build output via `Data.ByteString.Builder` or direct unsafe writes:

```
to_bytes tx:
  if has_witnesses tx:
    put_word32_le version
    put_byte 0x00  -- marker
    put_byte 0x01  -- flag
    put_compact (length inputs)
    for each input: put_txin
    put_compact (length outputs)
    for each output: put_txout
    for each witness: put_witness
    put_word32_le locktime
  else:
    put_word32_le version
    put_compact (length inputs)
    for each input: put_txin
    put_compact (length outputs)
    for each output: put_txout
    put_word32_le locktime
```

Component encoders:
```haskell
put_txin :: TxIn -> Builder
  -- outpoint (32 + 4 bytes) + scriptSig (compact + bytes) + sequence (4)

put_txout :: TxOut -> Builder
  -- value (8 bytes LE) + scriptPubKey (compact + bytes)

put_witness :: Witness -> Builder
  -- compact count + for each item: compact len + bytes
```

### Decoding (from_bytes)

Parse with explicit offset tracking or a simple parser state:

```
from_bytes bs:
  version <- get_word32_le
  peek next byte:
    if 0x00 and following byte is 0x01:
      skip marker/flag
      parse as segwit
    else:
      parse as legacy

  -- segwit parse:
  input_count <- get_compact
  inputs <- replicateM input_count get_txin
  output_count <- get_compact
  outputs <- replicateM output_count get_txout
  witnesses <- replicateM input_count get_witness
  locktime <- get_word32_le

  -- legacy parse:
  input_count <- get_compact
  inputs <- replicateM input_count get_txin
  output_count <- get_compact
  outputs <- replicateM output_count get_txout
  locktime <- get_word32_le
  witnesses = []
```

Component decoders:
```haskell
get_txin :: Parser TxIn
get_txout :: Parser TxOut
get_witness :: Parser Witness
```

### Legacy Serialisation

```haskell
to_bytes_legacy :: Tx -> BS.ByteString
  -- Always legacy format (no marker/flag/witnesses)
  -- Used for txid computation
```

## TxId Computation

```haskell
txid :: Tx -> TxId
txid tx = TxId (SHA256.hash (SHA256.hash (to_bytes_legacy tx)))
```

The result is the raw 32-byte hash. Display convention (reversed hex) is
separate from storage.

## Internal Helpers

Little-endian word encoding/decoding:

```haskell
put_word32_le :: Word32 -> Builder
put_word64_le :: Word64 -> Builder
get_word32_le :: BS.ByteString -> Int -> Maybe Word32
get_word64_le :: BS.ByteString -> Int -> Maybe Word64
```

Use `Data.Bits` shifts or `Foreign.Storable` with explicit byte order.

## Work Items

### Phase 1: Encoding (independent)

1. Implement `put_compact` (compactSize encoding)
2. Implement `put_word32_le`, `put_word64_le`
3. Implement `put_txin`, `put_txout`, `put_witness`
4. Implement `to_bytes` and `to_bytes_legacy`

### Phase 2: Decoding (independent of Phase 1)

1. Implement `get_compact` (compactSize decoding)
2. Implement `get_word32_le`, `get_word64_le`
3. Implement `get_txin`, `get_txout`, `get_witness`
4. Implement `from_bytes` with format detection

### Phase 3: TxId (depends on Phase 1)

1. Implement `txid` using ppad-sha256

### Phase 4: Base16 wrappers

1. `to_base16` wraps `to_bytes` with B16.encode
2. `from_base16` decodes hex then calls `from_bytes`

## Tests

- Round-trip: `from_bytes (to_bytes tx) == Just tx`
- Known vectors: parse real Bitcoin transactions, verify txid
- Edge cases: empty inputs/outputs, max-size compactSize values
- Legacy vs segwit format detection

## Test Vectors

### Simple legacy tx (1 input, 1 output)

Use a known mainnet transaction, e.g., the pizza transaction or a
simple testnet tx with known txid.

### Segwit tx (P2WPKH)

Parse a native segwit transaction, verify witnesses preserved, verify
txid matches (should exclude witnesses).

### Sources

- BIP143 test vectors (have full tx hex + expected sighash)
- Bitcoin Core tx_valid.json
- Manually hex-dump transactions from block explorers

## Notes

- All integers are little-endian except where noted
- TxId is stored in natural byte order (not display order)
- Witnesses list length must equal inputs list length for segwit
- Empty witness list indicates legacy transaction
- CompactSize must use minimal encoding (enforced on decode)
