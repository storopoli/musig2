# BIP-327 official test vectors

These files are unmodified copies of the official BIP-327 (MuSig2) test vectors
from <https://github.com/bitcoin/bips/tree/master/bip-0327/vectors>, taken at
commit [`b34d9f751791d4feb22feff4f2ed00bcac83961b`](https://github.com/bitcoin/bips/tree/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0327/vectors)
of `master`. The last upstream change to the vectors before that commit is
`1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439` ("bip327: minor fixes").

`test/OfficialVectors.hs` reads them when the test suite runs. Under
`cabal test` the working directory is the package root, so the files are
found at `test/vectors/bip327`. To run the test binary from elsewhere, set
`MUSIG2_BIP327_VECTORS` to this directory. If the files cannot be found,
the suite fails and says where it looked.

| File | SHA-256 |
| --- | --- |
| `key_sort_vectors.json` | `2389fa0c146cfd7455c643ca240ec32835dcfc916f430f50dd94d0b49c9ea16c` |
| `key_agg_vectors.json` | `03c02a97e4ef3f2edfbc8e6013c127496dfcfd5889cfca60ddf009a4e9091cab` |
| `nonce_gen_vectors.json` | `2e823580fc072427f0db0f000212cc9124ad2b9dca2b58357eb65088aee4358d` |
| `nonce_agg_vectors.json` | `8409e87b81ea769759598ad3ce53b277a78afffb3a490a86ce02c4d69984524b` |
| `sign_verify_vectors.json` | `692eecc101f3e515c29137f05031935e1210d2a01bab91e674eb0234f095c15c` |
| `tweak_vectors.json` | `80ce6385ce062644ad1f4edcb9d4797f70ddb0b74769e4099f51b3c9e6ab4aff` |
| `sig_agg_vectors.json` | `15f14c034fb2a5739d7ce638be94c5b37ea675a2e01159092dd93b59d69c3439` |
| `det_sign_vectors.json` | `3d4fdb64b24e31762f20830036dc0c59d39fa896649131b54b87906ffdc6e9e8` |

The test suite checks these checksums too (`pinnedFiles` in
`test/OfficialVectors.hs`). To update the vectors, copy the new files from
upstream without editing them, then update the commit and checksums here and
in `pinnedFiles`.
