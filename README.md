# ppad-tx

[![](https://img.shields.io/hackage/v/ppad-tx?color=blue)](https://hackage.haskell.org/package/ppad-tx)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-tx-lightblue)](https://docs.ppad.tech/tx)

Minimal Bitcoin transaction primitives, including raw transaction
types, serialisation to/from bytes, txid computation, and sighash
calculation (legacy and BIP143 segwit).

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  > import qualified Data.ByteString as BS
  > import qualified Data.ByteString.Base16 as B16
  > import Bitcoin.Prim.Tx
  > import Bitcoin.Prim.Tx.Sighash
  >
  > -- parse a raw transaction from hex
  > let raw = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
  > let Just tx = from_base16 raw
  >
  > -- compute the txid
  > let TxId tid = txid tx
  > B16.encode (BS.reverse tid)
  "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
  >
  > -- round-trip serialisation
  > from_bytes (to_bytes tx) == Just tx
  True
  >
  > -- compute a legacy sighash
  > let scriptPubKey = BS.pack [0x76, 0xa9, 0x14]
  > let hash = sighash_legacy tx 0 scriptPubKey SIGHASH_ALL
  > BS.length hash
  32
```

## Documentation

Haddocks are hosted at [docs.ppad.tech/tx][hadoc].

## Security

This is a pre-release library that, at present, claims no security
properties whatsoever.

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled.
Enter a development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal build
$ cabal test
$ cabal bench
```

[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/tx
