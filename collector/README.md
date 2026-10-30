# The collector

The server side of Sealdrop: a Python 3 program that picks sealed files up from the inbox, checks and opens them,
and stores the deliveries (see [../docs/PROTOCOL.md](../docs/PROTOCOL.md) §10). It needs two packages,
`cryptography` (47 or newer) and `segno`.

**State: the format core is done** (sealing and opening files, manifests, receipts, pairing checks). The inbox
client, the store and the `pair` command come next.

| Module | What |
|---|---|
| `sealdrop/encoding.py` | §3: strict JSON (I-JSON), base64url, hex, base32 |
| `sealdrop/hkdf.py` | HKDF-SHA256 on HMAC |
| `sealdrop/sizes.py` | §4: padded lengths, possible sizes, the largest delivery |
| `sealdrop/keys.py` | §2, §3: Ed25519 and P-256 (`r ‖ s`, low-S), key IDs |
| `sealdrop/sealed.py` | §4: writing a sealed file, and reading it step by step |
| `sealdrop/manifests.py` | §5, §7: content, the bundle and pairing manifests, names, the delivery digest |
| `sealdrop/reading.py` | §4, §5, §7: uploads, deliveries, pairing requests and receipts, in the order of checks |
| `sealdrop/receipts.py`, `sealdrop/pairing.py` | §6, §7: receipt manifests; the offer, the MAC, the fingerprint |

## Tests

```sh
cd collector/tests
python -m unittest
```

They run against the shared test files in [../testvectors](../testvectors), which the Android side reads too.
