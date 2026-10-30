# Sealdrop protocol, version 1

**Status: third version, after two reviews; being built. Details may still change until the first release.**

Sealdrop moves files from apps on an Android phone to your own server at home, through an S3-compatible bucket (the
"inbox"). The storage provider only ever holds sealed files: it can't read them, and it can't make the server accept a
file that didn't come from your phone. This document fixes every byte, so the two sides (the Android app and the
collector on the server) can be written and tested independently.

The parts:
- **Sender:** the Sealdrop app on the phone (Android 17 or newer).
- **Inbox:** a private bucket with two locations: `up/` for uploads from the phone, `ack/` for receipts from the
  server (§8).
- **Collector:** a small Python program on your server (for example a Raspberry Pi) that picks the files up.
- **Apps:** the apps on the phone that hand files to Sealdrop, each approved once by the owner.

---

## 0. In short

```mermaid
sequenceDiagram
  autonumber
  participant App as An approved app
  participant S as Sealdrop (phone)
  participant I as Inbox (bucket)
  participant C as Collector (server)
  App->>S: Hands over a delivery<br/>(read-only files + checksums)
  S->>S: Copies and checks them
  S->>S: Packs a bundle, seals it for the collector,<br/>signs it with a key that can't leave the phone
  S->>I: Upload up/<random name>
  C->>I: Anything new?
  I-->>C: The sealed bundle
  C->>C: Checks the signature, opens it,<br/>checks every checksum, stores the files
  C->>I: Receipt ack/<random name><br/>(sealed for the phone, signed by the collector)
  C->>I: Deletes the upload
  S->>I: Any receipts?
  I-->>S: The receipt
  S->>S: Checks and opens it, drops its copies
  App->>S: Any news?
  S-->>App: Picked up at 18:12
```

- **Sealed:** each upload gets its own random key. The content is encrypted with it, and the key itself is locked so
  that only the collector can unlock it.
- **Signed:** the phone signs every upload with a key that Sealdrop creates in Android's Keystore (in the security
  chip if the phone has one, otherwise in the processor's protected area, the TEE), where it can't be copied out. The
  collector accepts nothing else.
- **Receipts the other way:** sealed for the phone and signed by the collector. Everything in the inbox is sealed for
  its reader and signed by its writer.
- **Nothing outside tells anything:** random names, no metadata, rounded sizes.
- **Pairing once,** with a QR code shown by the collector.
- **Every step can be repeated safely.** The collector stores first, then writes the receipt, then deletes the upload.
  The phone keeps its copies until the receipt.

---

## 1. Terms

| Term | Meaning |
|---|---|
| **Delivery** | A set of files from one app, with an ID chosen by the app. The ID must be unique for that app for ever, across phones, reinstalls and re-pairing: the collector files deliveries by app and ID only (`store/<app>/<delivery>/`), so a reused ID with other content becomes a conflict. An app that can't count reliably puts a random UUID (122 random bits) or more into the ID. Never changed once handed over. |
| **Bundle** | One upload: one or more whole deliveries, sealed together. |
| **Sealed file** | The encrypted, signed file format (§4). Three kinds: bundle, pairing request, receipt. |
| **Receipt** | A sealed file from the collector to one phone: what was stored, plus the collector's status (§6). |
| **Sender** | One install of Sealdrop on one phone. It has its own keys. A new phone or a reinstall is a new sender. |
| **Location** | Where uploads (`up`) or receipts (`ack`) go: an endpoint, region, bucket and prefix (§7, §8). |
| **Key ID** | SHA-256 of a public signing key in its encoding below (32 bytes). |

## 2. Keys

| Key | Algorithm | Private part lives | Public part known to |
|---|---|---|---|
| Collector opening key | X25519 | collector, plus the owner's password manager | sender (from the QR code) |
| Collector signing key | Ed25519 | collector, plus the owner's password manager | sender (from the QR code) |
| Sender signing key | ECDSA P-256 with SHA-256 | Android Keystore: StrongBox (the security chip) if the phone has one, otherwise the TEE. Can't be exported. | collector (from pairing) |
| Sender opening key | X25519 | Sealdrop's private storage, encrypted with a Keystore AES-256-GCM key (StrongBox if available) | collector (from pairing) |
| File key `K` | 32 random bytes | inside the sealed header of one file | nobody else |

- **Encodings:** X25519 and Ed25519 public keys as their raw 32 bytes; the P-256 public key as an uncompressed SEC1
  point (65 bytes: `0x04 ‖ X ‖ Y`).
- **The algorithm comes from the stored key, never from the file.** In version 1, senders always sign with P-256 and
  collectors always with Ed25519.
- **Why P-256 for the phone:** StrongBox (the security chip) only has to support P-256 among the signature curves;
  X25519 and Ed25519 aren't part of it. The chip also makes the random number each ECDSA signature needs.
- **Why the sender opening key is a software key:** Android's HPKE can't open with a Keystore key. So it's stored
  encrypted by a Keystore key and is only in memory while a receipt is opened.
- The Keystore keys' exact settings are in §9.4.

## 3. Building blocks

| Block | Choice |
|---|---|
| Sealing for a public key | **HPKE**, RFC 9180, mode base: DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`, ChaCha20-Poly1305 `0x0003`. One message per context ("single shot"): setup with the `info` of §4, then one seal with an empty `aad`. Output: `enc` (32 bytes) ‖ ciphertext. |
| Encrypting the content | **ChaCha20-Poly1305**, RFC 8439: 32-byte key, 12-byte nonce, 16-byte tag. |
| Deriving keys | **HKDF-SHA256**, RFC 5869. Sealdrop builds it on `Mac("HmacSHA256")` (about 15 lines) rather than rely on a platform class, and tests it with RFC 5869's SHA-256 test cases. |
| Signatures | **ECDSA P-256 with SHA-256** (FIPS 186-5), written as `r ‖ s`, each left-padded to 32 bytes, big-endian. Android produces DER, which is converted; about 1 signature in 128 has a shorter `r` or `s`. The phone writes the low-S form (if `s` > n/2, it writes n − `s`); readers accept both, and reject `r` or `s` equal to 0 or ≥ n. **Ed25519**, RFC 8032 (pure). |
| Checksums | SHA-256. |
| Random numbers | The platform's secure generator: `SecureRandom` on Android, `os.urandom` in Python. |
| Text | See below. |

**Text:**
- **JSON:** UTF-8 without a byte-order mark, I-JSON (RFC 7493). Readers reject duplicate names; numbers with a
  fraction or exponent; integers outside 0 … 2^53 − 1; NaN and infinities; unpaired surrogates, also as `\u`
  escapes; and nesting deeper than 8. `null` only where this document shows it; in `SenderInfo` it becomes 0.
- **base64url** (RFC 4648 §5) without padding, for keys and secrets. Readers reject padding, characters outside the
  alphabet, and unused bits that aren't zero.
- **Hex,** for IDs and checksums: lowercase only; readers reject capitals.
- **Base32,** only for the fingerprint: RFC 4648 §6, the alphabet `A–Z 2–7`, no padding.
- **Times:** integers, milliseconds since 1970-01-01 UTC.

Notes:
- Everything above is built into **Android 17** (`android.crypto.hpke`, Conscrypt; HKDF from HMAC) and into Python's
  **`cryptography`** package from version 47 on. No other crypto library is used.
- **ChaCha20 rather than AES:** many small servers (the Raspberry Pi 3 and 4, for example) have no AES instructions, and
  ChaCha20 is fast and timing-safe in plain software. Phones do both well.
- **Only the file key goes through HPKE:** Python's HPKE seals one message at a time and has no streaming. The content
  goes in 1 MiB pieces instead, so a large file never has to fit into memory. `age` is built the same way.

## 4. The sealed file

### Layout

| Offset | Size | Content |
|---|---|---|
| 0 | 32 | HPKE `enc`: the writer's one-time public key |
| 32 | 120 | the sealed header: the 104-byte header (below) plus its 16-byte tag |
| 152 | `L + 16·N` | the payload: `N` pieces, each piece 1 MiB of plaintext (the last one 1 byte to 1 MiB) plus a 16-byte tag |
| `152 + L + 16·N` | 64 | the signature |

- `L` is the padded payload length (below) and `N = ceil(L / 1 MiB)`; `L` is never 0, so `N ≥ 1`.
- **The file's size is therefore `152 + L + 16·N + 64`, exactly.** A reader computes it from the header and rejects
  any other size.
- Nothing in the file is readable without the opening key: no magic bytes, no version in the clear. To anyone else
  it looks like random bytes.

### The header (104 bytes, big-endian)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | format version: `1` |
| 1 | 1 | kind: `1` bundle, `2` pairing request, `3` receipt |
| 2 | 2 | reserved: `0` |
| 4 | 4 | piece size: `1048576` |
| 8 | 8 | created: milliseconds since 1970 (UTC), the writer's clock. Only shown, never trusted. |
| 16 | 8 | content length `n` in bytes |
| 24 | 16 | message ID: random |
| 40 | 32 | writer's key ID: SHA-256 of the writer's signing public key |
| 72 | 32 | file key `K`: random |

The header is sealed with HPKE for the reader's opening key, with an empty `aad` and an `info` (ASCII) for the
direction: `sealdrop/v1/header/to-collector` for kinds 1 and 2, `sealdrop/v1/header/to-sender` for kind 3. Readers
reject a version other than 1, a kind they don't expect (the collector: 1 and 2; the phone: 3), a reserved field
other than 0 and a piece size other than 1048576.

### The payload

- **Payload key:** `PK = HKDF-SHA256(IKM = K, salt = message ID, info = "sealdrop/v1/payload", length = 32)`.
- **Plaintext:** the content (`n` bytes, §5) followed by zero bytes up to `L`.
- **Pieces:** the plaintext is cut into 1 MiB pieces. Piece `i` (counting from 0) is sealed with ChaCha20-Poly1305
  under `PK`, an empty `aad`, and the nonce `i` as an 11-byte big-endian number followed by one flag byte: `0x01` for
  the last piece, `0x00` for every other one.
- Numbered pieces with a marked last one mean that a changed, missing, swapped or cut-off piece fails to decrypt.
- **The padding must be all zeros.** A reader checks it.

### Padded length `L` (rounded sizes)

| Kind | Rule |
|---|---|
| 1, bundle | `n` up to 4 MiB: rounded up to the next multiple of 256 KiB (at least 256 KiB). Above 4 MiB: rounded up to the next multiple of 4 MiB. |
| 2, pairing request | always 256 KiB (`L` = 262,144), the size of the smallest bundle; `n` at most 256 KiB |
| 3, receipt | rounded up to the next multiple of 4 KiB (at least 4 KiB); `n` at most 256 KiB |

- **Examples:**
  - a bundle with 300,000 bytes of content: `L = 524,288` and `N = 1`, so the file has 524,520 bytes;
  - a pairing request, and the smallest bundle: 262,376 bytes;
  - a receipt with 900 bytes of content: `L = 4,096`, so the file has 4,328 bytes.
- **Possible sizes:** in `up/` about 1,040 sizes up to 4 GiB are possible, in `ack/` 64. Readers check a listed size
  before downloading (§6, §10).
- Receipts get the small rounding because the phone reads them over mobile data too, and their size says nothing the
  number of uploads doesn't already show. A pairing request looks like a small bundle.

### The signature (the last 64 bytes)

- **Statement:** the ASCII text `sealdrop/v1/sig/sender` (written by a phone, kinds 1 and 2) or
  `sealdrop/v1/sig/collector` (kind 3), then one `0x00` byte, then the SHA-256 of every byte of the file before the
  signature.
- The phone signs the statement with ECDSA P-256/SHA-256; the collector signs it with Ed25519.
- Different texts for the two roles mean a signature from one role can never pass as the other's.

### Reading a sealed file, in this order

1. The size is possible (`152 + L + 16·N + 64` for an `L` the table allows for the kinds expected there) and within
   the reader's limit (§12).
2. Open the header with your opening key; a collector also tries its retired opening keys (§7, re-pairing). If it fails:
   reject.
3. Check the header fields, compute `L` and `N`, and check the file's size exactly.
4. Find the writer by its key ID: a paired sender for kind 1, the paired collector for kind 3. **Kind 2** is read
   only by the `pair` command while a pairing is waiting (a regular run rejects it here). It decrypts the payload
   first (`n` is at most 256 KiB), reads only `sender_sign` from the manifest, and checks that its SHA-256 equals the
   header's key ID; that key is the writer for step 5. An unknown writer: reject.
5. Hash everything before the signature and check the signature with the stored key. If it fails: reject.
6. Only now decrypt the pieces, one at a time, and check the padding.
7. Read the content (§5).

Steps 2 to 4 need only the first 152 bytes, so the collector fetches those alone before it downloads the rest (§10).

Opening the 120-byte header before the signature check is safe: it's a normal HPKE decryption, and nothing from the
content is used before the signature has been checked. For kind 2 the payload is decrypted before the signature check
too. It's at most 256 KiB, and nothing in it except `sender_sign` is used until the signature and the `mac` have been
checked.

## 5. The content

```
content = manifest length m (4 bytes, big-endian) ‖ manifest (m bytes, UTF-8 JSON) ‖ the files' bytes, one after another
```

- The files follow in the order the manifest lists them, with nothing in between.
- So `n = 4 + m + the sum of all file sizes`. A bundle's manifest is at most 4 MiB.
- Pairing requests and receipts carry only a manifest, no files.

### Bundle manifest (kind 1)

```json
{
  "v": 1,
  "type": "bundle",
  "deliveries": [
    {
      "app": "org.example.tracker",
      "delivery": "a1b2c3d4-000042",
      "created": 1789285265000,
      "files": [
        { "path": "manifest.json", "size": 1532, "sha256": "5d41…" },
        { "path": "data/2026-09-13.json.gz", "size": 268114, "sha256": "4be1…" },
        { "path": "photos/9f2b….jpg", "size": 812345, "sha256": "9f2b…" }
      ]
    }
  ]
}
```

*(Made-up example; checksums shortened with "…", real ones have 64 hex characters.)*

**Fields and names:**
- **`app`:** the sending app's package name, as Android reports it for the caller (never what the app claims): 1 to
  100 characters, two or more parts separated by `.`, each part starting with a letter and made of `A–Z a–z 0–9 _`
  (Android's own rule). The collector checks this before it uses `app` anywhere, in a path or in its log.
- **`created`:** Sealdrop's clock at `commit`.
- **`delivery`:** 1 to 100 characters from `A–Z a–z 0–9 . _ -`, starting with a letter or digit, following the part
  rules below; unique for its app for ever (§1).
- `app` and `delivery` are compared exactly (case matters), so the collector keeps `store/` on a case-sensitive
  filesystem (§10).
- **`path`:**
  - 1 to 8 parts separated by `/`, at most 255 bytes including the `/`;
  - each part 1 to 128 characters from `A–Z a–z 0–9 . _ -`, starting with a letter or digit and not ending with `.`;
  - no part is, before its first `.` and ignoring case, `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9` or `LPT0`–`LPT9`
    (Windows can't store them);
  - so no `..`, no hidden files and no absolute paths;
  - paths are compared after ASCII case folding (`A–Z` to `a–z` and nothing else, never a language's lower-casing):
    no two are equal, and none begins with another followed by `/` (a file can't also be a folder).
- **A delivery has 1 to 10,000 files.**

**Delivery digest:** SHA-256 over this UTF-8 text: for every file, sorted by `path` (byte order), the path, a line
break, the size in decimal, a line break, the hex checksum and a line break. Sender and collector both compute it;
receipts quote it (§6).

### Reading rules
- Unknown fields are ignored, so later versions can add optional ones.
- **Two levels of failure:**
  - **The whole file** is rejected only for an envelope failure: its size, the header, the signature, a piece's tag,
    the padding, or a manifest that can't be read (not valid under §3's rules, an unknown `v` or `type`, more than
    1,000 deliveries or 10,000 files, the same `app` and `delivery` twice, or file sizes that don't add up to `n`).
  - **Everything else is decided per delivery:** names (above), limits, a delivery without files, and each file's size
    and checksum. A delivery that fails is rejected alone (`"result": "rejected"` with a `reason`, §6); the bundle's
    other deliveries are stored as usual. The collector still reads through the rejected delivery's bytes, so every
    piece is checked, but none of them reach its disk (§10).

## 6. Receipts (kind 3)

A receipt is written by the collector for **one** sender: sealed for that sender's opening key, signed with the
collector's signing key, and uploaded to `ack/<random name>`.

```json
{
  "v": 1,
  "type": "receipt",
  "for": "<the sender's key ID, hex>",
  "time": 1789285999000,
  "stored": [
    {
      "message": "<message ID, hex>",
      "sealed_sha256": "<SHA-256 of the whole sealed file as uploaded, hex>",
      "received": 1789285900000,
      "deliveries": [
        { "app": "org.example.tracker", "delivery": "a1b2c3d4-000042", "digest": "<hex>", "result": "stored",
          "seq": 17 },
        { "app": "org.example.tracker", "delivery": "a1b2c3d4-000043", "digest": "<hex>", "result": "rejected",
          "reason": "bad-file" }
      ]
    }
  ],
  "rejected": [
    { "name": "<the upload's name without the prefix>", "sealed_sha256": "<hex>", "size": 262376,
      "reason": "bad-signature", "at": 1789285000000 }
  ],
  "status": {
    "collector": "1.0.0",
    "instance": "<16 bytes, hex>",
    "seq": 17,
    "last_pickup": 1789285900000,
    "last_backup": null,
    "free_bytes": 201234567890,
    "max_sealed": 4294967296,
    "warnings": [],
    "rejected_7d": 0,
    "rejected_more": 0,
    "vanished_7d": 0
  }
}
```

- **`result`:**
  - `stored`: new and stored. `seq` is the number the collector gave it: it counts the deliveries stored for this
    sender, 1, 2, 3 … (§10).
  - `duplicate`: already stored with the same digest (a repeated upload). It carries the delivery's `seq` if it was
    first stored for this same sender, and no `seq` otherwise.
  - `conflict`: the same app and delivery ID is already stored with other content. The new content is kept in
    `conflicts/<app>/<delivery>/<digest>/`, never overwritten, and the owner is warned once. The same conflicting
    content arriving again is reported as `conflict` again, with no new copy and no new warning.
  - `rejected`: this delivery broke a rule, and nothing of it is stored. `reason`: `bad-name`, `bad-file` (a size or
    checksum doesn't match) or `no-files`.
- **`rejected`:** whole uploads rejected since the last receipt. `name` is always there; `sealed_sha256` only if the
  file was downloaded (a file rejected by its size or its first 152 bytes isn't, §10). The collector can't tell who
  sent a rejected file, so every paired sender is told. The `reason` comes from the first check that fails (§4):
  - `damaged`: a size that isn't possible, a header that doesn't open or has wrong fields, a piece that doesn't open,
    padding that isn't zero;
  - `too-big`: over the collector's `max_sealed`;
  - `unknown-sender`: a writer that isn't paired, or a pairing request outside the `pair` command (§7);
  - `bad-signature`: the signature;
  - `bad-content`: the manifest (§5).
- **Size:** a receipt's content is at most 256 KiB.
  - `rejected` holds at most 100 entries, newest first, and goes into the first receipt of a run for that sender; any
    more are counted in `rejected_more` (0 if none).
  - If `stored` doesn't fit, the collector writes several receipts in the same run. An entry too big for one receipt
    is split by deliveries; each part repeats `message`, `sealed_sha256` and `received`. Every receipt carries the
    `status`.
  - The upload is deleted only after all of its receipts are uploaded (§10, step 12).
- **`status`:**
  - `instance`: the collector's instance ID (§10);
  - `seq`: the highest `seq` stored for this sender (0 if none);
  - `last_backup`: from the server's backup job, if there is one (§10); otherwise `null`;
  - `max_sealed`: the collector's limit for one sealed file; the phone packs by it (§9.2);
  - `warnings`: the collector's problems, as strings: `disk-full`, `inbox-flooded`, `conflict` (§10). Unknown ones
    are ignored;
  - `rejected_7d` and `vanished_7d`: counts over the last 7 days (§10).
- **Status receipt:** at the end of a run, the collector writes a receipt with an empty `stored` for each sender that
  got no receipt in the last 24 hours. So the phone can show the server's state even when nothing was sent.
- **Paired receipt:** the answer to a pairing request (§7).

**The phone with a receipt:**
1. It lists `ack/` and fetches every name it hasn't handled yet. A name whose listed size isn't possible for kind 3
   (§4) is skipped without downloading.
2. It reads it as in §4: the writer must be the paired collector, and `for` must be its own key ID (while it pairs
   again, either of its two, §7).
3. A receipt that doesn't open is meant for another phone, or is junk. It's ignored, and its name is remembered so it
   isn't fetched again. One that opens with the phone's key but fails the writer, signature or `for` check sets the
   warning "can't read receipts" at once: a collector key has changed, or something is wrong. If none passes for 3
   days although `ack/` had new ones, the phone warns too (§9.3).
4. **Matching:** an entry counts only for an upload the phone still has pending (§9.4): by `sealed_sha256`, or, for a
   `rejected` entry without one, by `name` and `size`. It counts once per upload; the same entry again changes
   nothing. Within it, each delivery is matched by (`app`, `delivery`, `digest`):
   - `stored` or `duplicate`: "picked up" at `received`; the copy is dropped.
   - `conflict`: the collector keeps this content apart (§10). The copy is dropped, and the app sees state 5.
   - `rejected`: see step 5.
   - The same app and delivery with another digest: a warning, never a confirmation.
   - Entries for any other upload change nothing, except that `stored` and `duplicate` still confirm a delivery that
     isn't final yet.
   - **Final states:** 4 (picked up), 5 (conflict) and 6 (failed) don't change through later receipts. The one
     exception is step 6, a collector that lost deliveries.
5. **Rejections and strikes:**
   - A **strike** is a `rejected` result for a delivery, or a whole-file rejection of an upload that held only that
     delivery. `unknown-sender` is never a strike: it only happens to uploads under an old key after pairing again,
     and those were sealed again for the new key (§7). Strikes are counted per (`app`, `delivery`, `digest`), once per
     upload.
   - A whole-file rejection of an upload with several deliveries is no strike for any of them. After `damaged` or
     `bad-signature` they're sealed again together, once. After a second whole-file rejection, or after `bad-content`,
     each is sent alone. After `too-big`, they're packed again by the collector's `max_sealed`.
   - After a strike, Sealdrop checks its copy against the checksums the app gave. A copy that fails is dropped and
     reported as unknown (state 0), so the app hands it over again (§9.1). Otherwise the delivery is sent again alone.
   - Everything sent again goes at the next sync run, under the normal network rules (§9.2).
   - **Two strikes: state 6, failed.** Sealdrop keeps the copy, sends nothing more and warns; the owner decides on
     Sealdrop's screen (§9.1).
6. **Replays, two collectors and lost deliveries:**
   - The phone takes `status` only from the receipt with the newest `time`, ignoring any receipt older than the newest
     it has seen. The provider can replay old receipts; with step 4's rules they change nothing.
   - **Two collectors:** it compares the `instance` of its receipts in the order of their `time`. Two instance IDs
     alternating (A, B, A) within 7 days, `vanished_7d` above 0, or a second loss (below) within 7 days: the warning
     "two collectors". A single change from A to B is a move, with no warning.
   - **Lost deliveries:** for each of its key IDs, the phone keeps the `seq` of every delivery confirmed with one. If
     the newest receipt's `status.seq` is lower than a `seq` it has had confirmed, or a receipt confirms another
     delivery under a `seq` it already knows, the collector has lost deliveries (it was restored from an older backup,
     for example). Every delivery confirmed with a higher `seq` (with a reused one: that `seq` and higher) that this
     receipt doesn't confirm again goes back to state 0, so its app hands it over again. Sealdrop warns "the collector
     lost N deliveries" and sets `lostAt` (§9.1). While the "two collectors" warning is on, nothing goes back.
7. Receipts disappear from `ack/` through the bucket's lifecycle rule (30 days); the phone forgets names that are gone
   from the listing.

## 7. Pairing

### The QR code (shown by the collector)

The owner runs the collector's `pair` command in their own terminal. It asks for the phone's two storage keys (pasted
from the password manager; the collector doesn't keep them) and shows a QR code, valid once and for 10 minutes, with
this UTF-8 JSON:

```json
{
  "sealdrop": 1,
  "type": "pair-offer",
  "pairing": "<16 random bytes, base64url>",
  "expires": 1789286400000,
  "storage": {
    "up":  { "endpoint": "https://s3.<region>.backblazeb2.com", "region": "<region>", "bucket": "<bucket name>",
             "prefix": "up/", "key": { "id": "<key ID>", "secret": "<key>" } },
    "ack": { "prefix": "ack/", "key": { "id": "<key ID>", "secret": "<key>" } }
  },
  "collector_open": "<32 bytes, base64url>",
  "collector_sign": "<32 bytes, base64url>",
  "code": "<16 random bytes, base64url>"
}
```

- **The locations:** `up` holds the upload key, `ack` the receipts key. `ack` may leave out any of `endpoint`,
  `region` and `bucket`; each one left out is the same as in `up`.
- **Their form** (the phone and the `pair` command refuse anything else):
  - `endpoint`: `https://`, a lowercase host name and an optional `:port`; no path, query or trailing `/`;
  - `region`: 1 to 32 characters from `a–z 0–9 -`;
  - `bucket`: 3 to 63 characters from `a–z 0–9 . -`, starting and ending with a letter or digit;
  - `prefix`: empty (a bucket of its own), or 1 to 64 characters made of parts from `a–z 0–9 _ -`, each followed by
    `/` (`up/`, `inbox/up/`);
  - key IDs and secrets: 1 to 128 characters from ASCII `!` to `~`;
  - if both locations are in the same bucket at the same endpoint, both prefixes are non-empty and neither begins
    with the other.
- **Size:** about 600 bytes (594 with real-length keys). It's drawn with `segno.make_qr(text, error="L",
  boost_error=False)`, so never as a Micro QR and always at level L (85 × 85 modules for 594 bytes), and printed with
  half-block characters (`terminal(compact=True)`). That needs modules + 8 columns and half as many rows: 93 × 47.
  The `pair` command checks the terminal's size first.

### Keeping the QR code secret

The QR code holds the phone's two storage keys and the one-time code, so it's treated as a secret.

- **Keys at a prompt:** the storage keys are pasted at a prompt that doesn't show them, never given as command-line
  arguments, so they can't end up in the shell history or the process list.
- **Memory only:** the `pair` command keeps the keys, the code and the QR code's content in memory. Nothing of it is
  ever written to the log, to `state/` or anywhere else on disk. The log only notes that a pairing started and how it
  ended, with the fingerprint.
- **Only on a terminal:** it refuses to show the QR code when its output goes to a file or a pipe.
- **Cleared afterwards:** as soon as a valid request arrives, and when the pairing is cancelled (Ctrl+C) or expires
  after 10 minutes, it clears the screen and asks the terminal to clear its scrollback as well (`ESC [3J`).
- **The terminal may still keep it.** Some terminals ignore that request, and session logging (in PuTTY, tmux or
  screen, for example) would have recorded the QR code. So pair from a terminal without session logging, and close
  the window afterwards. When `$TMUX` or `$STY` is set, the command warns before showing the QR code: tmux and
  screen keep their own history, which `ESC [3J` doesn't clear.
- **After the 10 minutes,** the code is useless, but the storage keys stay valid. If the QR code may have been seen or
  recorded, replace the phone's two storage keys and pair again.
- **On the phone,** Sealdrop keeps no camera image and never logs the scanned text. It stores the storage keys
  encrypted (§9.4) and forgets the code once pairing is over.

### What the phone does

1. It checks the offer: `sealdrop` is 1, the type, not expired (with 5 minutes' allowance for a wrong clock), and the
   locations follow the rules above.
2. It creates its signing key (P-256, in StrongBox if the phone has it) and its opening key (X25519, stored encrypted).
3. It shows the **fingerprint** (below).
4. It sends a **pairing request**: a sealed file of kind 2, signed with the new key, uploaded with the upload key.
   Its manifest:

```json
{
  "v": 1,
  "type": "pair",
  "pairing": "<as in the offer>",
  "sender_sign": "<65 bytes, base64url>",
  "sender_open": "<32 bytes, base64url>",
  "label": "Phone",
  "replaces": "<the old key ID, hex; only when pairing again>",
  "mac": "<32 bytes, base64url>"
}
```

   - **`label`:** a name the owner can change, to tell phones apart on the collector: 1 to 40 characters, counted in
     code points (`codePointCount` on Android, not `length`), with no control, format or bidi characters (Unicode
     categories Cc, Cf, Zl and Zp). The collector checks it before it prints or logs it.
   - **`replaces`:** only when this phone pairs again (below); 64 hex characters, never all zeros.
   - **`mac`:** `HMAC-SHA256(key, transcript)`, where:
     - `key = HKDF-SHA256(IKM = code, salt = pairing, info = "sealdrop/v1/pair-mac", length = 32)`;
     - `transcript` = the ASCII text `sealdrop/v1/pair` ‖ pairing (16 bytes) ‖ collector_open (32) ‖ collector_sign
       (32) ‖ sender_sign (65) ‖ sender_open (32) ‖ replaces (32, or 32 zero bytes when there's none).
   - The header's writer key ID is the SHA-256 of `sender_sign`.
5. It waits for the **paired receipt**: it checks `ack/` every 30 seconds while the pairing screen is open, and in
   the background until `expires` plus 10 minutes.

### What the collector does

The `pair` command does the waiting itself. It holds the collector's lock for up to 10 minutes (regular runs skip
meanwhile) and checks `up/` every 10 seconds. It handles only kind 2; everything else is left for the regular runs. A
pairing request that a regular run finds is rejected (`unknown-sender`). A pairing request is accepted only if
everything holds, checked in this order:
1. the manifest is valid under §3's rules, with `"type": "pair"`;
2. the header's key ID is the SHA-256 of `sender_sign`;
3. the signature checks out with `sender_sign`;
4. the padding is all zeros;
5. there's a waiting pairing with this `pairing`, not expired and not used;
6. the `label` and `replaces` follow the rules above;
7. the `mac` is right (compared in constant time).

Then the collector:
1. stores the sender (key ID, both public keys, label, time) and marks the pairing as used;
2. clears the QR code and shows the fingerprint;
3. writes a **paired receipt** (kind 3, sealed for `sender_open`):
   `{"v": 1, "type": "paired", "for": "<key ID, hex>", "pairing": "…", "time": …}`;
4. deletes the request from `up/`;
5. if the request has `replaces`, offers to retire that old sender, and does it only after the owner confirms.

A request that fails any check is rejected like any other file, and the `pair` command says which check failed
(without printing the label). The pairing stays open until it expires, so junk can't use it up: only a request made
with the code can.

### The fingerprint

`SHA-256("sealdrop/v1/fingerprint" ‖ pairing ‖ collector_open ‖ collector_sign ‖ sender_sign ‖ sender_open)`, the
first 10 bytes in base32 (§3), shown as four groups of four: `K7Q2 M3XD 4HTB WPLA`. Both screens show it, and the
owner compares them. If they differ, someone else used the QR code first: replace the phone's two storage keys,
unpair the stranger on the collector, and pair again.

### Unpairing and re-pairing

- **`unpair <fingerprint or label>`** on the collector removes a sender; its files are rejected from then on. The
  phone's storage keys are removed separately, in the storage provider's console (the collector has no right to).
- **Pairing again on the same phone** (new storage keys, a new collector key, or after a fingerprint mismatch):
  Sealdrop makes new keys and adds `"replaces": "<the old key ID, hex>"` to the pairing request. It keeps its old
  opening key and reads receipts with both until everything sent under the old keys is confirmed, or for 60 days.
  Right after the paired receipt, it reseals every unconfirmed delivery (new message IDs, new names). The `pair`
  command, seeing `replaces`, offers to retire the old sender: "Retire the phone's old entry now? Uploads from its old
  key that are still in the inbox will then be rejected; the phone has already sent them again." It does it only
  after the owner confirms. Until then, uploads signed with the old key are still accepted.
- **With new storage** (other locations or keys), the phone deletes the old storage keys and reads only the new
  locations. Whatever still waits in the old inbox is covered by the reseal.
- **A new collector opening key:** the collector keeps its old opening keys as retired keys, so files sealed for them
  can still be opened. The phone reseals every unconfirmed delivery for the new key after pairing again.

## 8. The inbox and its requests

- **The bucket (or buckets):** private, the provider's own encryption switched on (an extra layer only), no object
  lock.
- **Locations:** `up` (phone → collector) and `ack` (collector → phone), each an endpoint, region, bucket and prefix
  (§7). Wherever this document says `up/` or `ack/`, it means that location's prefix.
- **Names:** the location's prefix plus 32 characters from `a–z 2–7` (160 random bits). Nothing else is ever in a
  name, and the phone never reuses one.
- **What a provider must allow** (the setup script checks it): the phone's upload key can write into `up` but can't
  read, list or permanently delete there; the receipts key can only list and read `ack`; the collector's keys are
  limited the same way (table below); and both locations have an expiry rule. With Backblaze B2 that's one bucket
  with two prefixes. A provider that can limit a key to a whole bucket, but not to a prefix, uses two buckets with
  empty prefixes.
- **Without versioning:** the collector lists with `ListObjectsV2` and uses `null` as every version ID, as S3 reports
  it. A resumed download sends `If-Match` with the listed ETag; a `412` means the upload changed, and it's handled
  again from the start. Deletes go by name, with `If-Match: <ETag>` where the provider supports it. The phone never
  reuses a name. An upload key can then overwrite a waiting upload, which is a real delete; the phone's re-send after
  60 days is the only safety net (§14).
- **A spending cap** at the provider, if it has one, limits what a junk flood can cost.
- **Every request:**
  - HTTPS (TLS 1.2 or newer) with the system's certificate authorities only, never user-added ones;
  - path style: `https://<endpoint host>/<bucket>/<name>`, so the bucket name travels inside the encrypted connection;
  - AWS Signature Version 4 (service `s3`, the region from pairing), with `x-amz-content-sha256` set to the body's
    SHA-256 (a signed body, also for empty bodies);
  - `User-Agent: sealdrop`, on both sides (the collector sets it too, so its Python version isn't sent), nothing
    about the device;
  - uploads with `Content-Type: application/octet-stream`;
  - no metadata headers, tags, content disposition or other optional headers;
  - redirects are not followed.

| Who | Request | Key (permissions) |
|---|---|---|
| phone | `PutObject up/<name>`, for files up to 8 MiB | upload key (write, `up` only) |
| phone | `CreateMultipartUpload`, `UploadPart` (8 MiB parts, the last smaller), `CompleteMultipartUpload`, `AbortMultipartUpload` | upload key |
| phone | `ListObjectsV2` with the `ack` prefix; `GetObject ack/<name>` | receipts key (list + read, `ack` only) |
| collector | `ListObjectVersions` with the `up` prefix (sees hidden versions too) | pickup key (list + read + delete, `up` only) |
| collector | `GetObject up/<name>?versionId=…`, with `Range` for the first 152 bytes, the rest, and to resume | pickup key |
| collector | delete each handled version by its version ID: `DeleteObject …?versionId=…` (at Backblaze, that `deleteFiles` is enough for this is confirmed on the test bucket; if not, B2's own `b2_delete_file_version`) | pickup key |
| collector | `PutObject ack/<name>` | receipts key (write, `ack` only) |

- **Resuming:** the phone stores the upload ID and the parts' ETags, so it never needs to list (its key can't). If
  the provider no longer knows the upload (`NoSuchUpload`, e.g. after the lifecycle rule cancelled it), it starts over.
- **Retries:**
  - network errors, timeouts, `5xx` and `429`: retried with growing pauses (30 s, then 1, 2, 5 and 15 minutes, then
    hourly), honouring `Retry-After`. Each pause varies by ±20 % at random; the steps count per sync run.
  - `401` and `403`: no quick retries. The phone shows "storage cap reached" when the answer's `<Message>` contains
    `cap exceeded` (ASCII, any case), and "storage key refused" otherwise, and tries again once a day and at the next
    sync run. The wording is Backblaze's as clients have logged it, not a documented code; it can't be tested without
    stopping the whole account, so it's best effort. Both lead to the same retry.
  - The collector retries within a run with the first three pauses (30 s, 1 and 2 minutes), then ends the run; on
    `401` or `403` it ends the run at once (§10).
  - a clock error (`RequestTimeTooSkewed`): "the phone's clock is wrong".
- **Timeouts:** 15 s to connect, 60 s without data.

## 9. The sender (Sealdrop on Android)

### 9.1 Handing over files (between apps on the phone)

Apps talk to Sealdrop through a bound service with an AIDL interface (action `app.sealdrop.action.DELIVER`, package
`app.sealdrop`). Nothing goes through shared storage.

```aidl
interface ISealdrop {
    int apiVersion();                                   // 1
    BeginResult begin(String delivery, int network);    // network: 1 = may use mobile data, 2 = Wi-Fi only
    AddResult add(String handle, in FileOffer[] files); // up to 100 files and 1 GiB per call; one larger file alone
    int commit(String handle);                          // checks everything, then queues the delivery
    oneway void abort(String handle);
    oneway void hold(int seconds);                      // the caller's hold; clamped to 1 … 900 seconds
    oneway void release();                              // ends the caller's own hold only
    DeliveryState[] status(in String[] deliveries);     // the caller's own; at most 500 IDs, more gives null
    SenderInfo info();
    int sendNow(boolean allowMobileForWifiOnly);        // the caller's own deliveries; answers 0, 2 or 3
}
parcelable BeginResult { int code; String handle; }    // handle is set only when code is 0
parcelable AddResult { int code; int index; }           // index: the offer that failed, or -1
parcelable FileOffer { String path; long size; String sha256; ParcelFileDescriptor file; }
parcelable DeliveryState { String delivery; int state; long time; }
// state: 0 unknown, 1 queued, 2 uploading, 3 in the inbox (time is 0 for states 0 to 3),
//        4 picked up (time = received; final),
//        5 conflict (time = received; final, like picked up),
//        6 failed (time = the second strike; final until the owner sends it again, §6)
//        4 goes back to 0 only if the collector lost it (§6, step 6).
parcelable SenderInfo { boolean paired; String fingerprint; long lastPickup; long lastBackup;
                        int waiting; long oldestWaiting; int warnings; long maxDeliveryBytes; long lostAt; }
// waiting and oldestWaiting count the caller's own deliveries in states 1 to 3.
// maxDeliveryBytes: the most file bytes one delivery may hold (§9.2).
// lostAt: when Sealdrop last found that the collector had lost deliveries of the caller (§6, step 6); 0 if never.
// warnings, bit 0 first: waiting over 2 days, storage key refused, clock wrong, the collector rejected files,
//   not paired (also: a key is missing, pair again), two collectors, sending held for over 24 hours,
//   a delivery failed, storage cap reached, can't read receipts, the collector reports a problem,
//   the collector lost deliveries
```

- **Who may call:**
  - Sealdrop takes the caller from Android (`Binder.getCallingUid()`), never from the request. `app` is the only
    package of that UID (`PackageManager.getPackagesForUid`); a UID with more than one package is refused.
  - It accepts only apps the owner approved, by package name and the SHA-256 of their signing certificate, checked on
    every call with `PackageManager.hasSigningCertificate(uid, cert, CERT_INPUT_SHA256)`.
  - Every method except `apiVersion()` checks the caller first. An unapproved caller gets `2` (in `BeginResult` and
    `AddResult` too), an empty `status()`, a null `info()`, and its `hold()` and `release()` are ignored. Sealdrop
    shows the request once, so the owner can approve it after comparing the certificate.
- **Handles:**
  - A handle is 16 random bytes in hex and belongs to the calling UID. A call with another caller's handle, or with
    one that has ended, gets `10`; `abort` ignores it.
  - `begin` with a delivery ID that has an unfinished handle aborts the old one. For an ID that is already
    committed, `commit` decides: the same digest gives `1`, another digest `9`, and the new copy is dropped. A
    delivery in state 0 counts as never committed.
  - `add` is all or nothing: on any result other than `0`, none of that call's files are kept (`index` names the
    offer that failed), and the handle stays usable.
  - A handle ends with `commit`, `abort` or Sealdrop's process, or 1 hour after its last call ended; its copies are
    then deleted.
  - At most two `add` calls copy at the same time; a third gets `8`.
- **Files, not paths:** the app opens each file read-only and passes the open file. Sealdrop can read exactly those
  files and nothing else; it has no storage permission.
  - Sealdrop accepts only a regular file (`fstat`, `S_ISREG`) whose size equals `size`, before and after the copy. It
    reads with positional reads from offset 0, because the file offset is shared with the app.
  - A read that stalls for 60 seconds ends the call with `8`.
  - Every descriptor received is closed, also on errors.
- **During `add`,** Sealdrop copies each file into its private storage and checks its size and checksum. `commit`
  answers only once everything is copied and checked.
- **Results:**
  - `0` OK;
  - `1` already have it (same delivery, same digest);
  - `2` not approved;
  - `3` not paired;
  - `4` bad request (names, sizes, more than 100 files or 1 GiB in one call);
  - `5` checksum wrong;
  - `6` not enough space;
  - `7` too big: more than `maxDeliveryBytes`;
  - `8` busy, try later;
  - `9` conflict: the same delivery ID with other content;
  - `10` unknown handle (another caller's, aborted, or Sealdrop was restarted): begin again.
- **Apps call from a background thread**, never from a thread that matters (such as a recording). A hanging Sealdrop
  can only hang that one thread.
- **Hold:** holds are per app. Sealdrop sends and fetches nothing while any app holds, and `release()` ends only the
  caller's own hold. A running upload stops after the current part (a single upload is cancelled and repeated later).
  Each hold ends by `release()` or when its time runs out, so a crashed app can't block sending for long. Sealdrop's
  screen shows which app holds and since when, and lets the owner end an app's hold (until its next `hold()`) or
  withdraw its approval. It warns when sending has been held for over 24 hours: one or more apps holding, with no gap
  of 1 minute or more, for 24 hours.
- **Failed deliveries (state 6):** Sealdrop keeps the copy and sends nothing. Its screen offers, per delivery or for
  all: **Send again** (the strikes start from 0, and the state goes back to 1) and **Discard** (the copy is deleted,
  and the state stays 6). A failed delivery doesn't count as waiting.
- **An app keeps its own copy** until `status()` says "picked up" or "conflict". If Sealdrop says "unknown" (it lost
  the delivery, e.g. after a reinstall), the app hands it over again **with the same bytes**: the same ID with other
  content would be a conflict. An app that can't give the same bytes uses a new delivery ID.
- **`status()`** remembers deliveries in states 4 to 6 for at least 1 year. Apps stop asking once one is picked up,
  and watch `lostAt` instead.
- **Warning bits: whom they're about, and when they clear.**
  - 0: the caller's deliveries; clears when none of them has waited 2 days.
  - 1 and 8: everything; clear on the next request the storage accepts.
  - 2: everything; clears on the next request that isn't refused for the clock.
  - 3: any app's; set by a receipt entry that matches one of this phone's uploads; clears 7 days after the last one.
  - 4: everything; clears once paired with working keys.
  - 5: everything; clears 7 days after the last sign of a second collector.
  - 6: everything; clears when no app holds.
  - 7: the caller's deliveries; clears when none of them is failed with its copy still kept.
  - 9: everything; clears when a receipt passes every check.
  - 10: everything; clears when the newest status has no `warnings`.
  - 11: the caller's deliveries; clears 7 days after `lostAt`.

### 9.2 Bundling and sending

- **When:** a sync run starts 30 seconds after the last `commit` (so files handed over one after another travel
  together), when an allowed network comes back, on `sendNow`, and on the retry timer. Never during a hold.
- **Which network:**
  - On Wi-Fi without a metered flag: everything.
  - On mobile data, a phone hotspot or metered Wi-Fi: only deliveries marked "may use mobile data", up to **10 MiB of
    sealed files per run**. That counts sealed bytes, padding included, so at most 8 MiB of content goes over mobile
    data per run (8 MiB and 1 byte would be padded to 12 MiB). The rest waits for Wi-Fi.
  - Never while roaming. With Android's Data Saver on, only on Wi-Fi.
  - The owner's setting "Wi-Fi only" sends everything on Wi-Fi only.
  - `sendNow(true)` lets the caller's own Wi-Fi-only deliveries use mobile data. The calling app asks the owner first.
- **Packing:** the oldest waiting deliveries that the network allows go into one bundle, until the next would push it
  over a limit: 10 MiB on mobile data, 256 MiB of content on Wi-Fi, 1,000 deliveries, 10,000 files, a 4 MiB
  manifest, the collector's `max_sealed`. A single delivery that is bigger travels alone, on Wi-Fi.
- **The largest delivery** (`maxDeliveryBytes`): the largest `L` whose sealed file fits within `max_sealed` (§4),
  minus 4 MiB for the manifest and its length. Until the first receipt, `max_sealed` is taken as 4 GiB, which gives
  4,286,578,688 bytes of files. If the collector lowers its limit later, a waiting delivery over the new one gets
  state 6 at once.
- **Sealing and uploading:**
  - The bundle is sealed into a temporary file at upload time, and kept until the upload is complete, so it can
    resume.
  - Up to 8 MiB it goes in one request; above that, in 8 MiB parts.
  - A resealed bundle always gets a new name.
- **After the upload:** the deliveries are "in the inbox", and Sealdrop looks for the receipt.
- **No receipt after 60 days:** sealed again (a new message ID) and uploaded again, and again every 60 days, packed by
  the normal rules. The collector recognises deliveries it already has (§10).
- **The first run after a hold ends** is started as an expedited job, so Android's power saving doesn't delay it.

### 9.3 Receipts and warnings

- **When:** every 15 minutes while anything is "in the inbox"; after 24 hours without a new receipt, hourly; after 3
  days, every 6 hours; back to 15 minutes after the next upload. Otherwise once a day, plus right after `sendNow`.
  Never during a hold. Receipts are small, so they're fetched on mobile data too (unless the owner chose "Wi-Fi
  only").
- **Warnings** (in `SenderInfo`):
  - a delivery has waited in the inbox for more than 2 days;
  - the storage refused a key, or its spending cap is reached;
  - the phone's clock is wrong;
  - the collector reported rejected files, or a delivery failed (§6);
  - not paired, or a key is missing (pair again, §9.4);
  - two collectors (§6);
  - sending has been held for more than 24 hours;
  - can't read receipts: a receipt opened but failed its checks, or `ack/` had new receipts but none passed for 3
    days. The collector writes every sender at least one receipt a day, so this means something is wrong;
  - the collector reports a problem: its disk is full, the inbox is flooded, or a conflict (§10);
  - the collector lost deliveries, which are handed over again (§6).
- Each bit's scope, and when it clears, is in §9.1.

### 9.4 What Sealdrop keeps on the phone

- **Where:** everything in its private, credential-encrypted storage, so after a restart it does nothing until the
  first unlock. Android's cloud backup and device transfer are switched off for it (`allowBackup="false"`, data
  extraction rules), so its keys and copies never leave the phone that way.
- **Keys:** the storage keys from the QR code and the private opening key are stored encrypted with a Keystore key
  (StrongBox if available). The signing key never leaves the Keystore.
- **The Keystore keys, exactly:**
  - Signing key: purpose sign, `ECGenParameterSpec("secp256r1")`, digest SHA-256, `setIsStrongBoxBacked(true)`; on
    `StrongBoxUnavailableException`, made again without it (the TEE).
  - Wrapping key: AES, 256 bits, purpose encrypt and decrypt, GCM, no padding, random IVs (the default), StrongBox
    as above.
  - Both: no user authentication, no `setUnlockedDeviceRequired`, no user-presence requirement, no validity end. So
    they work while the phone is locked in a pocket, and a new screen lock or fingerprint doesn't invalidate them.
  - If either key is missing or unusable (`KeyPermanentlyInvalidatedException`, a cleared Keystore): Sealdrop stops
    sending, keeps every copy, and warns "pair again". After pairing again it reseals the copies (§7).
- **Copies:** a delivery's copy is deleted once a receipt says it's stored, a duplicate or a conflict, when the owner
  discards a failed delivery, and when the owner unpairs.
- **Pending uploads:** the name, size and SHA-256 of every sealed upload are kept until every delivery in it has a
  final state (§6, step 4), and the `seq` of every picked-up delivery for 1 year.
- **Logs** (logcat, which ends up in bug reports): only message IDs, sizes, result codes and reasons; never app
  names, delivery IDs, paths or keys. Release builds log only errors.

### 9.5 Network rules

- **One place opens connections,** and only to the hosts from pairing. It checks the host before every connection.
- **Unencrypted connections** are refused (network security config); no proxy is used unless the system sets one.
- **Permissions:** `INTERNET`, `ACCESS_NETWORK_STATE`, `CAMERA` (for the QR code, granted "only this time"), and what
  the job scheduler and notifications need. No storage, location or contacts permission.

## 10. The collector

A Python 3 program with two packages: `cryptography`, and `segno` (pure Python) to draw the pairing QR code.

**Runs:** every 10 minutes; only one at a time (a lock file). While the `pair` command waits, it holds the lock (§7).
A run starts only when the system clock is synchronized (`timedatectl show -p NTPSynchronized` says `yes`). Small
boards such as the Raspberry Pi have no clock of their own, and until it's set, signed requests fail and times would
be wrong.

### The folders (the data root, e.g. `/srv/sealdrop`)

```
config/      collector settings: the two locations, the collector's two storage keys (readable by the collector only)
keys/        the collector's opening and signing keys; retired/ holds old opening keys
senders/     one file per paired sender: key ID, both public keys, label, when it was paired
state/       what was handled (names, version IDs, sealed checksums, results, the digest and seq of every stored
             delivery), each sender's seq, the listing position, receipts still to write, status.json, instance,
             and last-backup (written by a backup job, if any)
incoming/    downloads, each named by the hex SHA-256 of: name ‖ 0x00 ‖ version ID
store/       THE RESULT: store/<app>/<delivery>/<path>
conflicts/   deliveries whose ID was already stored with other content: conflicts/<app>/<delivery>/<digest>/
rejected/    downloaded files that were rejected, each with a reason file; at most 1 GiB in all, the oldest go first
log/         the collector's log (rotated)
```

- **One filesystem** holds `store/` and `conflicts/`, so a rename can move a delivery into either. It's
  case-sensitive (ext4, for example), because `app` and `delivery` are compared exactly (§5).
- **Never in any of these folders, nor in the log:** the QR code's content, the one-time code, the phone's storage
  keys, or any file content.
- **The log** may hold message IDs, sizes, results, reasons, app names, delivery IDs, labels and fingerprints (app
  names and delivery IDs are folder names in `store/` anyway), never paths, keys or content. App names, delivery IDs
  and labels are logged only after they've passed §5's and §7's rules.
- **`state/` keeps** the entries of rejected files for 90 days (the `up` lifecycle), and those of stored deliveries for
  ever.
- **Instance:** the first time a data root is used, the collector makes 16 random bytes, its instance ID, and keeps
  them in `state/instance` with a machine checksum: the SHA-256 of the contents of `/etc/machine-id`, a `0x00` byte,
  and the `Serial` line of `/proc/cpuinfo` (empty if there's none; a Raspberry Pi has one). If the checksum doesn't
  match at start, it makes a new instance ID. So restoring the data root onto another machine, or moving the disk,
  is a new instance; a restart isn't. Receipts carry it (§6), so the phone notices two collectors on one inbox.
  - If `/etc/machine-id` is missing or empty, the collector doesn't start, and says why. In a container, mount the
    host's file, read-only.
  - A copy of a system disk keeps `/etc/machine-id`: delete `state/instance` on the copy before its first start (on a
    Raspberry Pi, its own serial makes it a new instance anyway).
- **Sequence numbers:** for each sender, `state/` counts the deliveries stored for it, and each new one gets the next
  number (`seq`, §6). Numbers are never reused. A restore from a backup takes them back along with everything else,
  which is how the phone notices deliveries that were lost (§6, step 6).

### Handling the inbox, in this order

1. **List** `up/` with `ListObjectVersions`, from where the last run stopped (the `key-marker` and
   `version-id-marker` kept in `state/`), at most 10,000 versions per run. After the end of the prefix it starts from
   the beginning again. If everything listed in a run is handled, the next run continues after it; otherwise it lists
   from the same place again. The status warns `inbox-flooded` while one walk through the prefix takes more than one
   run.
2. **Tidy up:** empty `store/.tmp/`, and delete every file in `incoming/` that belongs to no version listed in this run
   and is older than 7 days.
3. **Order:** the listed versions, sorted by `LastModified`, then name, then version ID. At most 200 are downloaded
   per run, oldest first. Hide markers left on their own, names that aren't the prefix plus 32 characters from
   `a–z 2–7`, and files rejected in steps 4 and 5 don't count toward the 200: they're all handled in the same run.
   The first two are deleted, and not listed in receipts.
4. **Size:** a size that isn't possible in `up/` (§4) is rejected (`damaged`), and one over `max_sealed` (`too-big`),
   without downloading.
5. **Header first:** the first 152 bytes are fetched alone (`Range`), and §4 steps 2 to 4 are done on them. A file
   that fails is rejected after those 152 bytes. A kind 2 file is `unknown-sender` here (§7).
6. **Download** the rest into `incoming/`, only if each filesystem that `incoming/` and `store/` live on has at least
   twice the sealed size plus 5 GiB free (a setting). Otherwise the upload is skipped for now, and the status warns
   `disk-full`. A download resumes with `Range` after a drop, a finished one is kept across runs, and both are
   written to disk (`fsync`).
7. **Known file?** If the SHA-256 of the whole file was handled before, the result is the same as then: a stored
   one gets its receipt written again if it went missing; a rejected one isn't listed again. Either way, the upload
   is deleted.
8. **Check and open** as in §4 (kind 1 only).
   - **Every name and limit of every delivery is checked from the manifest before anything is written** (§5). A
     delivery that fails is read through, and its pieces are checked, but none of its bytes reach the disk.
   - Files are created only below `store/.tmp/<message ID>/`, by paths that passed §5, opened with
     `O_CREAT | O_EXCL | O_NOFOLLOW`. No string from a manifest is joined into a path before it has passed §5.
   - Each file is checked against its size and checksum as it's written.
9. **Store:** for each delivery:
   - **new:** `store/<app>/<delivery>/` is moved into place in one step (a rename): `stored`, with the sender's next
     `seq`. `fsync`: each file, then each new folder, then the parent folder after the rename, and `store/` if
     `store/<app>/` is new.
   - **already there with the same digest:** `duplicate`, and the new copy is discarded;
   - **already there with other content:** `conflict`. Unless `conflicts/<app>/<delivery>/<digest>/` exists, the copy
     is moved there the same way (from `store/.tmp/`, by a rename, with the same `fsync`s), so after a crash there's
     either a complete folder or none. A warning in the log and the status (`conflict`), once per digest.
   - **rejected:** nothing of it was written; `rejected` with its reason.
   - A message ID handled before, but with a different file (anyone can re-wrap a header, and an ECDSA signature has
     two valid forms, §3), is processed normally: its deliveries come out as `duplicate` or `conflict` by digest.
10. **Note it** in `state/` (name, version ID, message ID, sealed checksum, results, digests, `seq`), written to disk.
11. **Receipts:** one or more per sender and run (§6), uploaded to `ack/`. If that fails, they stay in `state/`.
12. **Delete** the versions handled in this run, by version ID, plus the hide markers of that name older than them.
    A `404` or `204` counts as success. An upload whose receipts aren't all uploaded stays in the inbox until the next
    run.
13. **Clean up** the handled downloads in `incoming/`.

- **Local errors are never rejections.** If the collector can't read, write or `fsync` its own disk, runs out of
  memory, or the storage answers `401`, `403`, `5xx` or doesn't answer (after the retries in §8), the run stops at
  that upload. Nothing about it is noted in `state/` or listed in a receipt, and it waits for the next run. Rejection
  reasons come only from a file's bytes and size. On `401` or `403`, `status.json` and the log say "storage key
  refused" or "storage cap reached" (§8).
- **Vanished uploads:** a version counts as vanished only when the first GET of it, in the run that listed it, answers
  `404`, and only if it's younger than the `up` lifecycle rule's deletion age minus one day (96 days, a setting). It's
  logged and counted in `vanished_7d`: something else is taking uploads, another collector or the provider.
- **Every step can be repeated.** A power cut or a lost connection at any point means the next run picks up where it
  stopped. The order is store, then receipt, then delete, so nothing leaves the inbox before it's safe on disk and the
  phone has been told.
- **Rejected files** are noted in `state/` (by name and version ID, and by SHA-256 if downloaded), deleted from the
  inbox, and listed in the next receipts. A downloaded one is moved into `rejected/` with its reason before it's
  deleted from the inbox; nothing goes there for a file rejected before its download.
- **The status's `warnings`:** `disk-full` while uploads are skipped for space; `inbox-flooded` while one walk
  through `up/` takes more than one run; `conflict` for 7 days after a new conflict.

### The store: the contract with whatever reads it

- **`store/<app>/<delivery>/` holds exactly the files the app handed over,** with the paths it gave, byte for byte.
  Sealdrop adds nothing to these folders.
- **A delivery appears all at once** (by rename) or not at all. Anything starting with `.` (such as `store/.tmp`) is
  not a delivery and must be ignored.
- **The collector never changes or deletes anything in `store/`.** A reader (such as an importer for a website) only
  reads it and keeps its own notes of what it has handled.
- **Memory:** the collector streams everything; it needs about 30–50 MB, whatever the file size.

## 11. Versions

- **The sealed file:** the version byte and the texts (`sealdrop/v1/…`) carry the version. A change that an old reader
  couldn't handle becomes version 2, with new texts; during a change-over, collectors accept both. Once a sender has
  sent a version 2 file, the collector rejects version 1 files from it.
- **JSON:** new optional fields may be added within version 1; readers ignore fields they don't know.
- **The AIDL interface:** `apiVersion()` tells the version. Methods, parcelable fields, result codes, states and
  warning bits are only ever added at the end; none is removed or changes its meaning.
- **The QR code:** `"sealdrop": 1`.

## 12. Limits (version 1)

| What | Limit |
|---|---|
| A sealed file | `max_sealed`: 4 GiB unless the collector's setting lowers it; reported in the status |
| A bundle manifest | 4 MiB |
| A pairing request's or a receipt's content | 256 KiB |
| Deliveries per bundle | 1,000 |
| Files per bundle | 10,000 |
| Files per delivery | 1 to 10,000 |
| Bytes per delivery | `maxDeliveryBytes`: 4 GiB − 8 MiB with the default `max_sealed` (§9.2) |
| A path | 255 bytes including the `/`, 8 parts |
| One `add` call | 100 files and 1 GiB; one larger file alone |
| `status()` | 500 delivery IDs per call |
| `hold()` | 1 to 900 seconds |
| A handle without calls | ends after 1 hour |
| Free space on the collector before a download | twice the sealed size plus 5 GiB (a setting) |
| Versions listed per run; downloads per run | 10,000; 200 (rejections without a download don't count) |
| `rejected/` on the collector | 1 GiB |

## 13. Test files

- **`testvectors/`** in this repo holds made-up keys (published for testing only, never used for real) and sealed
  files made with them:
  - a bundle, a pairing request, a receipt;
  - broken copies: one changed bit in each part (header, each piece, signature), a missing piece, two pieces swapped,
    a cut-off end, non-zero padding, a wrong size, an impossible size, another sender's signature, a receipt signed by
    a sender;
  - a bundle with one bad delivery among good ones (only that one is rejected);
  - bundles whose `app` is `../x`, `/x`, `a` (one part) or contains a line break, and a delivery without files: each
    rejected alone, with nothing written outside `store/.tmp/`;
  - a manifest with the same delivery twice (the whole file is rejected);
  - a pairing request whose `replaces` is all zeros (rejected);
  - manifests that break §3's JSON rules (a duplicate name, `1.0`, `1e3`, a lone surrogate, padded base64url);
  - signatures with a short `r` and with a high `s` (both accepted), and with `r` = 0 and `s` ≥ n (rejected).
- **Both sides must** open the good files to exactly the expected content and reject every broken one.
- **HPKE picks a fresh one-time key each time,** so the same input never gives the same file. The test files are
  therefore made once, by the Python side. In addition, each side seals and the other opens, in a test that runs the
  Android code on the emulator.
- **RFC 9180's test vector** for this suite (appendix A.2) runs on Android directly. Python's HPKE can't run it (no
  `aad`, only the first message, no fixed one-time key), so `testvectors/` adds a small test-only RFC 9180 key
  schedule built on pyca's X25519, HKDF, HMAC and ChaCha20-Poly1305. It must reproduce A.2, and what it seals must
  open with pyca's HPKE, and the other way round.
- **HKDF** passes RFC 5869's SHA-256 test cases on both sides.

## 14. Security notes

| Who has what | Can | Can't |
|---|---|---|
| The storage provider, or anyone with the bucket | see the number, rounded sizes and times of uploads and receipts, when uploads are picked up, the addresses they came from, and which key made each request; delete files (the phone keeps its copies, warns after 2 days, sends again after 60); replay old receipts or hold back new ones (the phone trusts only the newest status and warns after 2 days without a pickup) | read anything; make the collector accept a file |
| The phone's upload key | upload junk (rejected, at most 1 GiB kept, reported) and so delay real uploads until the junk is cleared (§10); hide uploads or cancel unfinished ones (the collector sees hidden versions); without versioning, overwrite a waiting upload (§8) | read, list or, with versioning, really delete anything |
| The phone's receipts key | download sealed receipts | open them |
| The phone's opening key | open the receipts in the inbox (up to 30 days): app names, delivery IDs, times, the collector's status | open uploads; write a receipt the phone accepts |
| The collector's pickup key | download sealed uploads; delete them (as above: the phone keeps its copies) | open them |
| The collector's receipts key | upload junk receipts (the phone rejects them) | write a receipt the phone accepts |
| The collector's opening key | open uploads it can get: those still in the inbox, or copies someone kept | pass as the phone |
| The collector's signing key | write receipts the phone accepts, so the phone drops its copies early, and the apps may delete theirs too (§9.1) | read uploads |
| The unlocked phone | send anything as that phone | take the phone's signing key elsewhere; write anything on the collector outside `store/` (every name is checked before it's used, §5, §10) |
| An app on the phone that isn't approved | bind to Sealdrop and ask `apiVersion()`; make Sealdrop show one approval request | hand over files, hold or release sending, see any status |
| An approved app | send anything under its own name; fill Sealdrop's storage and the collector's disk up to the limits (§12, §10), and a full disk stops every app's pickups until the owner makes room; hold sending (the owner sees which app, and since when, and can end the hold) | send as another app; see, speed up or hold back other apps' deliveries |
| Someone watching the network (Wi-Fi, mobile operator) | see the storage host (DNS, TLS SNI), when the phone and the collector connect, the sizes and the polling rhythm | see the bucket, the names or anything inside |
| Someone who saw or recorded the pairing QR code (§7) | within its 10 minutes, try to pair a phone of their own first (the fingerprints then differ, and the owner unpairs it); afterwards, whatever the phone's two storage keys allow (rows above) until they're replaced | read anything; pair once the 10 minutes are over |

- **Repeats:** a repeated upload is recognised by the checksum of the whole file before it's opened, and a repeated
  delivery by its digest after the signature check. Neither changes anything.
- **Cut-off or reordered files:** caught by the numbered pieces with the marked last one, and by the signature over the
  whole file.
- **Downgrades:** the algorithms are fixed by the version, and each key's type is stored at pairing.
- **The one-time code** only protects against someone who has an upload key but didn't see the QR code.
- **No forward secrecy, honestly:** someone who keeps copies of sealed uploads and later steals the collector's
  opening key can open them. Uploads are normally gone from the inbox within minutes, and pairing again makes a new
  key.
- **Not covered by Sealdrop:** the phone's own storage (that's Android's encryption) and the collector's disk (the
  owner decides on disk encryption).
- **The public repository** contains no keys, addresses, bucket names or anyone's data. Examples use made-up names.

## 15. Not in version 1

- Sending to more than one collector.
- A check that the phone's key really is in its security chip (Android key attestation): planned for later.
- Post-quantum encryption: a later version (the format has a version number for that).
- Storage other than S3-compatible.

---

*Sources: [RFC 9180 (HPKE)](https://www.rfc-editor.org/rfc/rfc9180), [RFC 8439 (ChaCha20-Poly1305)](https://www.rfc-editor.org/rfc/rfc8439),
[RFC 5869 (HKDF)](https://www.rfc-editor.org/rfc/rfc5869), [RFC 8032 (Ed25519)](https://www.rfc-editor.org/rfc/rfc8032),
[RFC 7493 (I-JSON)](https://www.rfc-editor.org/rfc/rfc7493), [RFC 4648 (base64url, base32)](https://www.rfc-editor.org/rfc/rfc4648),
[Android HPKE](https://developer.android.com/reference/android/crypto/hpke/Hpke),
[Android Keystore and StrongBox](https://developer.android.com/privacy-and-security/keystore),
[PackageManager.hasSigningCertificate](https://developer.android.com/reference/android/content/pm/PackageManager#hasSigningCertificate(int,%20byte[],%20int)),
[pyca/cryptography HPKE](https://cryptography.io/en/latest/hazmat/primitives/hpke/),
[segno](https://segno.readthedocs.io/),
[age format](https://age-encryption.org/v1),
[Backblaze B2 S3-compatible API](https://www.backblaze.com/docs/cloud-storage-s3-compatible-api),
[B2 key capabilities](https://www.backblaze.com/docs/cloud-storage-application-key-capabilities).*
