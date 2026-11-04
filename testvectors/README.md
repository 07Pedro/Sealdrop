# Test files

Made-up keys (published for testing only, never used for anything real) and sealed files made with them
(PROTOCOL.md §13). Both sides must open the good files to exactly the expected content, and reject every broken
one with the expected reason.

| File | What |
|---|---|
| `keys.json` | the test keys: the collector's opening keys (current and retired) and signing key, the sender's two keys, a stranger's |
| `files/*.sealed` | the sealed files |
| `cases.json` | one entry per case: the file, who reads it (`collector` in `up/`, `sender` in `ack/`), optional `mutations`, and the expected header, content checksum, per-delivery results or manifest, or the reason it's rejected |
| `vectors.json` | small vectors: JSON rules, base64url, P-256 and Ed25519 signatures, HKDF (RFC 5869), HPKE (RFC 9180 A.2.1), sizes, names, the pairing MAC and fingerprint, QR offers, and manifests checked on their own (bundles, pairing requests, receipts) |
| `make_testvectors.py` | makes all of the above |
| `rfc9180_test_only.py` | a test-only RFC 9180 key schedule (Python's HPKE can't run the RFC's vector) |
| `check_android_files.py` | the other direction: opens what the Android tests sealed on the emulator ([../android/README.md](../android/README.md)) |

**Mutations** turn one good file into broken copies, so they aren't stored: `flip` (one bit at `offset`), `cut`
(keep the first `length` bytes), `append` (hex `bytes`), `remove` (`length` bytes at `offset`) and `swap` (the
`first` bytes at `offset` with the `second` bytes after them). They're applied in order.

**Making them again** gives exactly the same bytes: the one-time HPKE keys come from the test-only key schedule, and
ECDSA signs deterministically (RFC 6979). A test in `collector/tests` checks that. Run from the repository root:

```sh
python testvectors/make_testvectors.py
```
