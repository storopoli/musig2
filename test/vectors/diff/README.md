# Differential corpus

`corpus.json` holds NonceGen cases and complete BIP-327 signing sessions whose
expected values were computed by the BIP-327 reference implementation,
[`reference.py`](https://github.com/bitcoin/bips/blob/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0327/reference.py)
at bips commit `b34d9f751791d4feb22feff4f2ed00bcac83961b` (SHA-256 of
`reference.py`: `1167993fe159c39c004f74d9046e931ae700a2ce9203c4cf58a51a000c1294e8`).
`test/DiffCorpus.hs` replays every case through the library's public API and
the coordinator and compares every value byte for byte.

It has 48 NonceGen cases and 300 sessions with 1 to 8 signers: duplicate and
all-equal keys, KeySort, chains of plain, x-only and Taproot tweaks (including
0, n - 1, gacc = n - 1 and tweaks to infinity), empty, 32-byte and longer
than 255-byte messages, nonces bound to every combination of NonceGen's
optional inputs, DeterministicSign signers, aggregate nonces with infinity
halves, and failing PartialSigVerify cases. `scripts/gen-diff-corpus.py`
describes every field.

| File | SHA-256 |
| --- | --- |
| `corpus.json` | `ee7da0d791afd3a1ffe423c2886e5ec6744069a3b7ba56371bedf48ef99247f3` |

The test suite checks this checksum (`corpusSha256` in `test/DiffCorpus.hs`)
and that the corpus still covers each kind of case. Under `cabal test` the
working directory is the package root; to run the test binary from elsewhere,
set `MUSIG2_DIFF_CORPUS` to the path of `corpus.json`.

To regenerate it, from the package root:

```console
$ git clone https://github.com/bitcoin/bips /path/to/bips
$ git -C /path/to/bips checkout b34d9f751791d4feb22feff4f2ed00bcac83961b
$ python3 -I scripts/gen-diff-corpus.py /path/to/bips/bip-0327/reference.py > test/vectors/diff/corpus.json
```

The output depends only on the seed in the script and on `reference.py`, so
the same inputs give the same file. After changing the generator, update
the checksum here and in `test/DiffCorpus.hs`.
