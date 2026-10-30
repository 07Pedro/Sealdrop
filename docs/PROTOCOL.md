# Sealdrop protocol, version 1

**Status: draft for review. Nothing is built yet.**

Sealdrop moves files from apps on an Android phone to your own server at home, through an S3-compatible bucket (the
"inbox"). The storage provider only ever holds sealed files: it can't read them, and it can't make the server accept a
file that didn't come from your phone. This document fixes every byte, so the two sides (the Android app and the
collector on the server) can be written and tested independently.

The parts:
- **Sender:** the Sealdrop app on the phone (Android 17 or newer).
- **Inbox:** one private bucket with two folders: `up/` for uploads from the phone, `ack/` for receipts from the
  server.
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
  S->>S: Packs a bundle, seals it for the collector,<br/>signs it with the phone's chip
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
- **Signed:** the phone signs every upload with a key that lives in its security chip and can't be copied out. The
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
| **Delivery** | A set of files from one app, with an ID chosen by the app (unique per app). Never changed once handed over. |
| **Bundle** | One upload: one or more whole deliveries, sealed together. |
| **Sealed file** | The encrypted, signed file format (§4). Three kinds: bundle, pairing request, receipt. |
| **Receipt** | A sealed file from the collector to one phone: what was stored, plus the collector's status (§6). |
| **Sender** | One install of Sealdrop on one phone. It has its own keys. A new phone or a reinstall is a new sender. |
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
- **Why P-256 for the phone:** it's the only signature curve the Pixel's security chip (Titan M2) supports; X25519 and
  Ed25519 are refused there. The chip also makes the random number each ECDSA signature needs.
- **Why the sender opening key is a software key:** Android's HPKE can't open with a Keystore key. So it's stored
  encrypted by a Keystore key and is only in memory while a receipt is opened.

## 3. Building blocks

| Block | Choice |
|---|---|
| Sealing for a public key | **HPKE**, RFC 9180, mode base: DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`, ChaCha20-Poly1305 `0x0003`. One message per context ("single shot"): setup, then one seal with an empty `aad`. Output: `enc` (32 bytes) ‖ ciphertext. |
| Encrypting the content | **ChaCha20-Poly1305**, RFC 8439: 32-byte key, 12-byte nonce, 16-byte tag. |
| Deriving keys | **HKDF-SHA256**, RFC 5869. |
| Signatures | **ECDSA P-256 with SHA-256** (FIPS 186-5), written as `r ‖ s`, 32 bytes each, big-endian. Android produces DER, which is converted. **Ed25519**, RFC 8032 (pure). |
| Checksums | SHA-256. |
| Random numbers | The platform's secure generator: `SecureRandom` on Android, `os.urandom` in Python. |
| Text | UTF-8 JSON (RFC 8259), no byte-order mark. Binary values in JSON: keys and secrets as base64url without padding (RFC 4648 §5); IDs and checksums as lowercase hex. Times as integers, milliseconds since 1970-01-01 UTC. |

- Everything above is built into **Android 17** (`android.crypto.hpke`, Conscrypt) and into Python's **`cryptography`**
  package from version 47 on. No other crypto library is used.
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

The header is sealed with HPKE for the reader's opening key, with `info = "sealdrop/v1/header"` (ASCII) and an empty
`aad`. Readers reject a version other than 1, an unknown kind, a reserved field other than 0 and a piece size other
than 1048576.

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
| 2 and 3, pairing request and receipt | rounded up to the next multiple of 4 KiB (at least 4 KiB); `n` at most 1 MiB |

- **Examples:**
  - a bundle with 300,000 bytes of content: `L = 524,288` and `N = 1`, so the file has 524,520 bytes;
  - a receipt with 900 bytes of content: `L = 4,096`, so the file has 4,328 bytes.
- Receipts get the small rounding because the phone reads them over mobile data too, and their size says nothing the
  number of uploads doesn't already show.

### The signature (the last 64 bytes)

- **Statement:** the ASCII text `sealdrop/v1/sig/sender` (written by a phone, kinds 1 and 2) or
  `sealdrop/v1/sig/collector` (kind 3), then one `0x00` byte, then the SHA-256 of every byte of the file before the
  signature.
- The phone signs the statement with ECDSA P-256/SHA-256; the collector signs it with Ed25519.
- Different texts for the two roles mean a signature from one role can never pass as the other's.

### Reading a sealed file, in this order

1. The size is at least 152 + 4096 + 16 + 64 bytes and within the reader's limit (§12).
2. Open the header with your opening key; a collector also tries its retired opening keys (§7, re-pairing). If it fails:
   reject.
3. Check the header fields, compute `L` and `N`, and check the file's size exactly.
4. Find the writer by its key ID: a paired sender for kind 1, the paired collector for kind 3, and the rules of §7 for
   kind 2. An unknown writer: reject.
5. Hash everything before the signature and check the signature with the stored key. If it fails: reject.
6. Only now decrypt the pieces, one at a time, and check the padding.
7. Read the content (§5).

Opening the 120-byte header before the signature check is safe: it's a normal HPKE decryption, and nothing from the
content is used before the signature has been checked.

## 5. The content

```
content = manifest length m (4 bytes, big-endian) ‖ manifest (m bytes, UTF-8 JSON) ‖ the files' bytes, one after another
```

- The files follow in the order the manifest lists them, with nothing in between.
- So `n = 4 + m + the sum of all file sizes`, and the manifest is at most 1 MiB.
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

**Names:**
- **`app`:** the sending app's package name, as Android reports it for the caller (never what the app claims). At most
  100 characters.
- **`delivery`:** 1 to 100 characters from `A–Z a–z 0–9 . _ -`, starting with a letter or digit.
- **`path`:**
  - 1 to 8 parts separated by `/`, at most 255 bytes in all;
  - each part 1 to 128 characters from `A–Z a–z 0–9 . _ -`, starting with a letter or digit;
  - so no `..`, no hidden files and no absolute paths;
  - paths must be unique within a delivery, ignoring case (for servers whose disks ignore case).

**Delivery digest:** SHA-256 over this UTF-8 text: for every file, sorted by `path` (byte order), the path, a line
break, the size in decimal, a line break, the hex checksum and a line break. Sender and collector both compute it;
receipts quote it (§6).

### Reading rules
- Unknown fields are ignored, so later versions can add optional ones.
- An unknown `type`, or a `v` other than 1, is rejected.
- Every file is checked against its size and checksum while it's written. One wrong file rejects the whole bundle.

## 6. Receipts (kind 3)

A receipt is written by the collector for **one** sender: sealed for that sender's opening key, signed with the
collector's signing key, and uploaded as `ack/<random name>`.

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
        { "app": "org.example.tracker", "delivery": "a1b2c3d4-000042", "digest": "<hex>", "result": "stored" }
      ]
    }
  ],
  "rejected": [
    { "sealed_sha256": "<hex>", "size": 262360, "reason": "bad-signature", "at": 1789285000000 }
  ],
  "status": {
    "collector": "1.0.0",
    "last_pickup": 1789285900000,
    "last_backup": null,
    "free_bytes": 201234567890,
    "rejected_7d": 0
  }
}
```

- **`result`:**
  - `stored`: new and stored;
  - `duplicate`: already stored with the same digest (a repeated upload);
  - `conflict`: the same app and delivery ID is already stored **with other content**. The new one is kept
    separately, never overwritten, and the owner is warned.
- **`rejected`:** uploads rejected since the last receipt, with a short reason (`bad-signature`, `unknown-sender`,
  `damaged`, `bad-content`, `too-big`). The collector can't tell who sent a rejected file, so every paired sender is
  told.
- **`status`:** `last_backup` comes from the server's backup job, if there is one (§10); otherwise `null`.
- **Status receipt:** once every 24 hours the collector also writes a receipt with an empty `stored`, so the phone can
  show the server's state even when nothing was sent.
- **Paired receipt:** the answer to a pairing request (§7).

**The phone with a receipt:**
1. It lists `ack/` and fetches every name it hasn't handled yet.
2. It reads it as in §4 (the writer must be the paired collector, and `for` must be its own key ID).
3. A receipt it can't open is meant for another phone, or is junk. It's ignored, and its name is remembered so it isn't
   fetched again.
4. For each delivery whose `digest` matches what it sent: marked "picked up" at `received`, and the copies are dropped.
   On `conflict`: kept, with a warning.
5. Receipts disappear from `ack/` through the bucket's lifecycle rule (30 days); the phone forgets names that are gone
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
    "endpoint": "https://s3.<region>.backblazeb2.com",
    "region": "<region>",
    "bucket": "<bucket name>",
    "upload_key": { "id": "<key ID>", "secret": "<key>" },
    "receipts_key": { "id": "<key ID>", "secret": "<key>" }
  },
  "collector_open": "<32 bytes, base64url>",
  "collector_sign": "<32 bytes, base64url>",
  "code": "<16 random bytes, base64url>"
}
```

About 550 bytes: a QR code of about 85 × 85 modules, so the terminal needs to be at least 90 characters wide.

### Keeping the QR code secret

The QR code holds the phone's two storage keys and the one-time code, so it's treated as a secret.

- **Keys at a prompt:** the storage keys are pasted at a prompt that doesn't show them, never given as command-line
  arguments, so they can't end up in the shell history or the process list.
- **Memory only:** the `pair` command keeps the keys, the code and the QR code's content in memory. Nothing of it is
  ever written to the log, to `state/` or anywhere else on disk. The log only notes that a pairing started and how it
  ended, with the fingerprint.
- **Only on a terminal:** it refuses to show the QR code when its output goes to a file or a pipe.
- **Cleared afterwards:** when the pairing is done, cancelled (Ctrl+C) or expired after 10 minutes, it clears the screen
  and asks the terminal to clear its scrollback as well (`ESC [3J`).
- **The terminal may still keep it.** Some terminals ignore that request, and session logging (in PuTTY, tmux or
  screen, for example) would have recorded the QR code. So pair from a terminal without session logging, and close
  the window afterwards.
- **After the 10 minutes,** the code is useless, but the storage keys stay valid. If the QR code may have been seen or
  recorded, replace the phone's two storage keys and pair again.
- **On the phone,** Sealdrop keeps no camera image and never logs the scanned text. It stores the storage keys
  encrypted (§9.4) and forgets the code once pairing is over.

### What the phone does

1. It checks the offer: `sealdrop` is 1, the type, not expired (with 5 minutes' allowance for a wrong clock), and the
   endpoint is `https`.
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
  "mac": "<32 bytes, base64url>"
}
```

   - **`label`:** a name the owner can change, up to 40 characters, to tell phones apart on the collector.
   - **`mac`:** `HMAC-SHA256(key, transcript)`, where:
     - `key = HKDF-SHA256(IKM = code, salt = pairing, info = "sealdrop/v1/pair-mac", length = 32)`;
     - `transcript` = the ASCII text `sealdrop/v1/pair` ‖ pairing (16 bytes) ‖ collector_open (32) ‖ collector_sign
       (32) ‖ sender_sign (65) ‖ sender_open (32).
   - The header's writer key ID is the SHA-256 of `sender_sign`.
5. It waits for the **paired receipt**: it checks `ack/` every 30 seconds while the pairing screen is open.

### What the collector does

The `pair` command does the waiting itself. It holds the collector's lock for up to 10 minutes (regular runs skip
meanwhile) and checks `up/` every 10 seconds. A pairing request that a regular run finds while no pairing is waiting is
rejected. A pairing request is accepted only if everything holds:
- there's a waiting pairing with this `pairing`, not expired and not used;
- the header's key ID is the SHA-256 of `sender_sign`;
- the signature checks out with `sender_sign`;
- the `mac` is right (compared in constant time).

Then the collector:
1. stores the sender (key ID, both public keys, label, time) and marks the pairing as used;
2. shows the fingerprint;
3. writes a **paired receipt** (kind 3, sealed for `sender_open`):
   `{"v": 1, "type": "paired", "for": "<key ID, hex>", "pairing": "…", "time": …}`;
4. deletes the request from `up/`.

A request that fails any check is rejected like any other file. The pairing stays open until it expires, so junk
can't use it up: only a request made with the code can.

### The fingerprint

`SHA-256("sealdrop/v1/fingerprint" ‖ pairing ‖ collector_open ‖ collector_sign ‖ sender_sign ‖ sender_open)`, the
first 10 bytes in base32 (RFC 4648, capitals), shown as four groups of four: `K7Q2 M9XD 4HTB WPLA`. Both screens show
it, and the owner compares them. If they differ, someone else used the QR code first: unpair on the collector and pair
again.

### Unpairing and re-pairing

- **`unpair <fingerprint or label>`** on the collector removes a sender; its files are rejected from then on. The
  phone's storage keys are removed separately, in the storage provider's console (the collector has no right to).
- **A new collector opening key:** the collector keeps its old opening keys as retired keys, so files sealed for them
  can still be opened. The phone reseals every unconfirmed delivery for the new key after pairing again.

## 8. The inbox and its requests

- **The bucket:** private, the provider's own encryption switched on (an extra layer only), no object lock.
- **Folders:** `up/` (phone → collector) and `ack/` (collector → phone).
- **Names:** the folder plus 32 characters from `a–z 2–7` (160 random bits). Nothing else is ever in a name.
- **Every request:**
  - HTTPS (TLS 1.2 or newer) with the system's certificate authorities only, never user-added ones;
  - path style: `https://<endpoint host>/<bucket>/<name>`, so the bucket name travels inside the encrypted connection;
  - AWS Signature Version 4 (service `s3`, the region from pairing), with `x-amz-content-sha256` set to the body's
    SHA-256 (a signed body, also for empty bodies);
  - `User-Agent: sealdrop`, nothing about the device;
  - uploads with `Content-Type: application/octet-stream`;
  - no metadata headers, tags, content disposition or other optional headers;
  - redirects are not followed.

| Who | Request | Key (permissions) |
|---|---|---|
| phone | `PutObject up/<name>`, for files up to 8 MiB | upload key (write, `up/` only) |
| phone | `CreateMultipartUpload`, `UploadPart` (8 MiB parts, the last smaller), `CompleteMultipartUpload`, `AbortMultipartUpload` | upload key |
| phone | `ListObjectsV2` with `prefix=ack/`; `GetObject ack/<name>` | receipts key (list + read, `ack/` only) |
| collector | `ListObjectVersions` with `prefix=up/` (sees hidden versions too) | pickup key (list + read + delete, `up/` only) |
| collector | `GetObject up/<name>?versionId=…`, with `Range` to resume | pickup key |
| collector | delete each version and each hide marker of a picked-up name: `DeleteObject …?versionId=…`, or, if the provider demands write permission for that, Backblaze's own `b2_delete_file_version` (it needs only delete) | pickup key |
| collector | `PutObject ack/<name>` | receipts key (write, `ack/` only) |

- **Resuming:** the phone stores the upload ID and the parts' ETags, so it never needs to list (its key can't). If
  the provider no longer knows the upload (`NoSuchUpload`, e.g. after the lifecycle rule cancelled it), it starts over.
- **Retries:**
  - network errors, timeouts, `5xx` and `429`: retried with growing pauses (30 s, then 1, 2, 5 and 15 minutes, then
    hourly), honouring `Retry-After`;
  - `401` and `403`: no retries; the phone shows "storage key refused";
  - a clock error (`RequestTimeTooSkewed`): "the phone's clock is wrong".
- **Timeouts:** 15 s to connect, 60 s without data.

## 9. The sender (Sealdrop on Android)

### 9.1 Handing over files (between apps on the phone)

Apps talk to Sealdrop through a bound service with an AIDL interface (action `app.sealdrop.action.DELIVER`, package
`app.sealdrop`). Nothing goes through shared storage.

```aidl
interface ISealdrop {
    int apiVersion();                                   // 1
    String begin(String delivery, int network);         // network: 1 = may use mobile data, 2 = Wi-Fi only
    int add(String handle, in FileOffer[] files);       // up to 100 files per call
    int commit(String handle);                          // checks everything, then queues the delivery
    oneway void abort(String handle);
    oneway void hold(int seconds);                      // pause all sending, 1 to 900 seconds
    oneway void release();
    DeliveryState[] status(in String[] deliveries);
    SenderInfo info();
    int sendNow(boolean allowMobileForWifiOnly);
}
parcelable FileOffer { String path; long size; String sha256; ParcelFileDescriptor file; }
parcelable DeliveryState { String delivery; int state; long time; }
// state: 0 unknown, 1 queued, 2 uploading, 3 in the inbox, 4 picked up (time = received), 5 conflict
parcelable SenderInfo { boolean paired; String fingerprint; long lastPickup; long lastBackup;
                        int waiting; long oldestWaiting; int warnings; }
// warnings (bits): waiting over 2 days, storage key refused, clock wrong, the collector rejected files, not paired
```

- **Who may call:**
  - Sealdrop takes the caller from Android (`Binder.getCallingUid()`), never from the request.
  - It accepts only apps the owner approved in Sealdrop, by package name and the SHA-256 of their signing certificate
    (checked with `PackageManager.hasSigningCertificate`).
  - An unknown app gets "not approved", and Sealdrop shows the request once, so the owner can approve it after
    comparing the certificate.
- **Files, not paths:** the app opens each file read-only and passes the open file. Sealdrop can read exactly those
  files and nothing else; it has no storage permission.
- **During `add`,** Sealdrop copies each file into its private storage and checks its size and checksum. `commit`
  answers only once everything is copied and checked.
- **Results:**
  - `0` OK;
  - `1` already have it (same delivery, same digest);
  - `2` not approved;
  - `3` not paired;
  - `4` bad request (names, sizes, limits);
  - `5` checksum wrong;
  - `6` not enough space;
  - `7` too big;
  - `8` busy, try later;
  - `9` conflict: the same delivery ID with other content.
- **Apps call from a background thread**, never from a thread that matters (such as a recording). A hanging Sealdrop
  can only hang that one thread.
- **Hold:** while a hold is active, Sealdrop sends and fetches nothing. A running upload stops after the current part
  (a single upload is cancelled and repeated later). The hold ends by `release()` or when its time runs out, so a
  crashed app can't block sending for long.
- **An app keeps its own copy** until `status()` says "picked up". If Sealdrop says "unknown" (it lost the delivery,
  e.g. after a reinstall), the app hands it over again.

### 9.2 Bundling and sending

- **When:** a sync run starts 30 seconds after the last `commit` (so files handed over one after another travel
  together), when an allowed network comes back, on `sendNow`, and on the retry timer. Never during a hold.
- **Which network:**
  - On Wi-Fi without a metered flag: everything.
  - On mobile data, a phone hotspot or metered Wi-Fi: only deliveries marked "may use mobile data", up to **10 MiB of
    sealed files per run**. The rest waits for Wi-Fi.
  - Never while roaming. With Android's Data Saver on, only on Wi-Fi.
  - The owner's setting "Wi-Fi only" sends everything on Wi-Fi only.
  - `sendNow(true)` also allows Wi-Fi-only deliveries on mobile data. The calling app asks the owner first.
- **Packing:** the oldest waiting deliveries that the network allows go into one bundle, until the next would push it
  over the limit (10 MiB on mobile data, 256 MiB of content on Wi-Fi). A single delivery that is bigger travels alone,
  on Wi-Fi, up to the collector's limit.
- **Sealing and uploading:**
  - The bundle is sealed into a temporary file at upload time, and kept until the upload is complete, so it can
    resume.
  - Up to 8 MiB it goes in one request; above that, in 8 MiB parts.
- **After the upload:** the deliveries are "in the inbox", and Sealdrop looks for the receipt.
- **No receipt after 60 days:** sealed again (a new message ID) and uploaded again. The collector recognises
  deliveries it already has (§10).
- **The first run after a hold ends** is started as an expedited job, so Android's power saving doesn't delay it.

### 9.3 Receipts and warnings

- **When:** every 15 minutes while anything is "in the inbox", otherwise once a day, plus right after `sendNow`. Never
  during a hold. Receipts are small, so they're fetched on mobile data too (unless the owner chose "Wi-Fi only").
- **Warnings** (in `SenderInfo`):
  - a delivery has waited in the inbox for more than 2 days;
  - the storage refused a key;
  - the phone's clock is wrong;
  - the collector reported rejected files.

### 9.4 What Sealdrop keeps on the phone

- **Where:** everything in its private storage. Android's cloud backup and device transfer are switched off for it
  (`allowBackup="false"`, data extraction rules), so its keys and copies never leave the phone that way.
- **Keys:** the storage keys from the QR code and the private opening key are stored encrypted with a Keystore key
  (StrongBox if available). The signing key never leaves the Keystore.
- **Copies:** a delivery's copy is deleted once a receipt says it's stored or a duplicate, and when the owner unpairs.

### 9.5 Network rules

- **One place opens connections,** and only to the host from pairing. It checks the host before every connection.
- **Unencrypted connections** are refused (network security config); no proxy is used unless the system sets one.
- **Permissions:** `INTERNET`, `ACCESS_NETWORK_STATE`, `CAMERA` (for the QR code, granted "only this time"), and what
  the job scheduler and notifications need. No storage, location or contacts permission.

## 10. The collector

**Runs:** every 10 minutes; only one at a time (a lock file). While the `pair` command waits, it holds the lock (§7).

### The folders (the data root, e.g. `/srv/sealdrop`)

```
config/      collector settings: endpoint, region, bucket, the two storage keys (readable by the collector only)
keys/        the collector's opening and signing keys; retired/ holds old opening keys
senders/     one file per paired sender: key ID, both public keys, label, when it was paired
state/       what was handled (message IDs, sealed checksums, results), receipts still to write, status.json, and
             last-backup (written by a backup job, if there is one)
incoming/    downloads in progress
store/       THE RESULT: store/<app>/<delivery>/<path>
conflicts/   deliveries whose ID was already stored with other content: conflicts/<app>/<delivery>.<message ID>/
rejected/    rejected sealed files, each with a reason file; at most 1 GiB in all, the oldest go first
log/         the collector's log (rotated)
```

Never in any of these folders, nor in the log: the QR code's content, the one-time code, the phone's storage keys, or
any file content.

### Handling one upload, in this order

1. **List:** `ListObjectVersions` on `up/`, oldest first. Hide markers left on their own are deleted.
2. **Size:** too big or impossibly small: rejected without downloading.
3. **Download** into `incoming/`, resuming with `Range` after a drop; written to disk (`fsync`).
4. **Known?** The SHA-256 of the whole file, or its message ID, already handled: a duplicate. The receipt is written
   again if it went missing, and the upload is deleted.
5. **Check and open** as in §4; kinds 1 and 2 only. The files are written into `store/.tmp/<message ID>/`, each
   checked against its size and checksum.
6. **Store:** for each delivery, `store/<app>/<delivery>/` is written to disk and moved into place in one step (a
   rename, then `fsync` of the folder):
   - **new:** `stored`;
   - **already there with the same digest:** `duplicate`, and the new copy is discarded;
   - **already there with other content:** moved to `conflicts/`, `conflict`, and a warning in the log and the
     status.
7. **Note it** in `state/` (message ID, sealed checksum, results), written to disk.
8. **Receipt:** one per sender and run, uploaded to `ack/`. If that fails, it stays in `state/` and the upload stays
   in the inbox until the next run.
9. **Delete** the upload from `up/`: every version of that name.
10. **Clean up** `incoming/`.

- **Every step can be repeated.** A power cut or a lost connection at any point means the next run picks up where it
  stopped. The order is store, then receipt, then delete, so nothing leaves the inbox before it's safe on disk and the
  phone has been told.
- **Rejected files** go into `rejected/` with their reason, are deleted from the inbox and are listed in the next
  receipts.

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
  couldn't handle becomes version 2, with new texts; during a change-over, collectors accept both.
- **JSON:** new optional fields may be added within version 1; readers ignore fields they don't know.
- **The AIDL interface:** `apiVersion()` tells the version. New methods are only ever added at the end.
- **The QR code:** `"sealdrop": 1`.

## 12. Limits (version 1)

| What | Limit |
|---|---|
| A sealed file | 4 GiB (a collector setting) |
| A manifest; a whole pairing request or receipt | 1 MiB |
| Deliveries per bundle | 1,000 |
| Files per bundle | 10,000 |
| A path | 255 bytes, 8 parts |
| `rejected/` on the collector | 1 GiB |

## 13. Test files

- **`testvectors/`** in this repo holds made-up keys (published for testing only, never used for real) and sealed
  files made with them:
  - a bundle, a pairing request, a receipt;
  - broken copies: one changed bit in each part (header, each piece, signature), a missing piece, two pieces swapped,
    a cut-off end, non-zero padding, a wrong size, another sender's signature, a receipt signed by a sender.
- **Both sides must** open the good files to exactly the expected content and reject every broken one.
- **HPKE picks a fresh one-time key each time,** so the same input never gives the same file. The test files are
  therefore made once, by the Python side. In addition, each side seals and the other opens, in a test that runs the
  Android code on the emulator.
- Both sides also pass RFC 9180's own test vector for this suite (appendix A.2).

## 14. Security notes

| Who has what | Can | Can't |
|---|---|---|
| The storage provider, or anyone with the bucket | see the number, rounded sizes and times of uploads and the addresses they came from; delete files (the phone keeps its copies, warns after 2 days, sends again after 60) | read anything; make the collector accept a file |
| The phone's upload key | upload junk (rejected, at most 1 GiB kept, reported); hide uploads or cancel unfinished ones (the collector sees hidden versions) | read, list or really delete anything |
| The phone's receipts key | download sealed receipts | open them |
| The collector's pickup key | download sealed uploads; delete them (as above: the phone keeps its copies) | open them |
| The collector's receipts key | upload junk receipts (the phone rejects them) | write a receipt the phone accepts |
| The collector's opening key | open uploads it can get: those still in the inbox, or copies someone kept | pass as the phone |
| The collector's signing key | write receipts the phone accepts, so it drops its copies early | read uploads |
| The unlocked phone | send anything as that phone | take the phone's signing key elsewhere |
| Someone who saw or recorded the pairing QR code (§7) | within its 10 minutes, try to pair a phone of their own first (the fingerprints then differ, and the owner unpairs it); afterwards, whatever the phone's two storage keys allow (rows above) until they're replaced | read anything; pair once the 10 minutes are over |

- **Repeats:** a repeated upload is recognised by its message ID and checksum, and a repeated delivery by its digest.
  Neither changes anything.
- **Cut-off or reordered files:** caught by the numbered pieces with the marked last one, and by the signature over the
  whole file.
- **Downgrades:** the algorithms are fixed by the version, and each key's type is stored at pairing.
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
[Android HPKE](https://developer.android.com/reference/android/crypto/hpke/Hpke),
[Android Keystore and StrongBox](https://developer.android.com/privacy-and-security/keystore),
[pyca/cryptography HPKE](https://cryptography.io/en/latest/hazmat/primitives/hpke/),
[age format](https://age-encryption.org/v1),
[Backblaze B2 S3-compatible API](https://www.backblaze.com/docs/cloud-storage-s3-compatible-api),
[B2 key capabilities](https://www.backblaze.com/docs/cloud-storage-application-key-capabilities).*
