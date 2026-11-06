# The collector

The server side of Sealdrop: a Python 3 program that picks sealed files up from the inbox, checks and opens them,
and stores the deliveries (see [../docs/PROTOCOL.md](../docs/PROTOCOL.md) §10). It needs two packages,
`cryptography` (47 or newer) and `segno`.

**State: working.** The format core, the S3 client, the Backblaze B2 setup, pairing, and the inbox handling with the
store and the receipts (§7, §10). Tested against a Backblaze in memory, and end to end with the Android app and a
real test bucket ([../tools/e2e](../tools/e2e)). **On a server** (such as a Raspberry Pi): [INSTALL.md](INSTALL.md).

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
| `sealdrop/net.py`, `sealdrop/s3.py` | §8: HTTPS as the protocol wants it; the S3 requests, path style, Signature Version 4 |
| `sealdrop/b2.py`, `sealdrop/setup_b2.py` | §8: setting up an inbox at Backblaze B2, and trying its keys |
| `sealdrop/root.py`, `sealdrop/state.py` | §10: the data root (settings, keys, senders, instance) and what was handled |
| `sealdrop/run.py` | §10: one run over the inbox, in the protocol's order; the receipts (§6) |
| `sealdrop/pair.py` | §7: the `pair` command |
| `sealdrop/__main__.py` | the commands |
| `install/` | for a server: the install script, the locked packages, the systemd service and timer, the `sealdrop` command ([INSTALL.md](INSTALL.md)) |

## The commands

Run them as the collector's own user, from this folder (or with the package installed). On a server installed with
[INSTALL.md](INSTALL.md), the timer starts `run`, and the `sealdrop` command runs the others as the collector's user. The data root is `--root`,
`$SEALDROP_ROOT`, or `/srv/sealdrop`.

```sh
python3 -m sealdrop init        # the storage locations, the collector's storage keys (asked for, not shown), new keys
python3 -m sealdrop show-keys   # once: the collector's own keys, to keep safe
python3 -m sealdrop pair        # in your own terminal: the QR code for the phone, then compare the codes
python3 -m sealdrop run         # one run over the inbox; a timer starts it every 10 minutes
python3 -m sealdrop senders     # the paired phones;  unpair <fingerprint or label> removes one
python3 -m sealdrop status      # what the last run found
```

- **`init`** asks for the endpoint, region, bucket and the two `collector-…` keys. `--import-keys` takes the
  collector's own keys from `show-keys` (a new server for the same phones); `--clock-check off` is for a computer
  whose clock its host keeps (WSL); `--test-keys FILE` takes a test bucket's keys from `setup_b2 --test`.
- **`pair`** asks for the phone's two keys (`phone-upload`, `phone-receipts`) at prompts that don't show them, shows the
  QR code (valid once, for 10 minutes), and waits. When the phone's request arrives, the QR code is cleared and both
  screens show a code: confirm only if they're the same. Nothing from the QR code is written anywhere. Pair from a
  plain terminal window without session logging, and close it afterwards.
- **`run`** does nothing while `pair` waits, or (with the default `--clock-check`) until the clock is synchronized.
  It logs to `log/collector.log` (never paths, keys or content) and writes `state/status.json`.
- **The store:** `store/<app>/<delivery>/` holds exactly the files an app handed over. A delivery appears all at once
  or not at all; anything starting with `.` isn't a delivery. Readers only read it.

## Setting up the inbox at Backblaze B2

The setup makes the bucket and the four keys of §8, then tries each key with test files: that it can do its job,
and that everything else is refused. It needs only Python 3.11 or newer (no packages), and a fresh master application
key from Backblaze's web console (Application Keys). Run it **in your own terminal**, from this folder:

```sh
python3 -m sealdrop.setup_b2 --test   # a test bucket first: its keys go into ~/.config/sealdrop-test/storage.json
python3 -m sealdrop.setup_b2          # the inbox: its keys are shown once, to keep safe
python3 -m sealdrop.setup_b2 --keys   # lists Sealdrop's keys and deletes the ones you pick (a lost phone)
```

- **What it makes:** a private bucket (`inbox-` and random letters, or `--bucket NAME`) with Backblaze's encryption
  on, no object lock and the expiry rules, and four keys without an expiry date:

  | Key | Folder | Permissions (Backblaze's names) |
  |---|---|---|
  | `phone-upload` | `up/` | writeFiles |
  | `phone-receipts` | `ack/` | listFiles, readFiles |
  | `collector-pickup` | `up/` | listFiles, readFiles, deleteFiles |
  | `collector-receipts` | `ack/` | writeFiles |

  Expiry rules: `up/` hidden after 90 days and deleted 7 days later, unfinished uploads in parts cancelled after 7;
  `ack/` hidden after 30 days and deleted a day later.
- **It reads everything back** from Backblaze (the bucket's settings, each key's bucket, folder and permissions) and
  says if other keys of the account can reach the bucket too.
- **Then it tries the keys** over the S3 interface, about 40 checks: each allowed request works, each other one is
  refused. `FAIL` means a key can do more or less than it should; the setup then deletes the keys and the bucket it
  made. `NOTE` marks details that don't make a key unsafe, for example that deleting by version ID needs more than
  `deleteFiles` (the collector then deletes through Backblaze's own interface, which the setup tries too). The test
  files are deleted at the end.
- **The master key** is asked for at a prompt that doesn't show it, and is never saved. Afterwards, make a new master
  key in the console without saving it, so the one you pasted stops working.
- **The keys:** with `--test`, they go into a file readable by you only, and aren't shown. Without it, they're shown
  once; press Enter when they're stored safely, and the screen and its scrollback are cleared. A terminal
  that keeps its own history (tmux, screen, session logging) keeps them too.
- **`--keys`** lists the account's Sealdrop keys (by their names, the test ones too): bucket, folder, permissions and
  the last four characters of the key ID, to match them with your copy. Never a secret. You type the
  numbers of the keys to delete, confirm, and it checks that they're gone. Use it for a lost phone (its
  `phone-upload` and `phone-receipts`) or a lost server (its `collector-…` keys), and then replace the master key.
  Backblaze's web console doesn't always list keys made through its interface, so this is the reliable way.
- **Caps & Alerts** can't be set through an interface: set a daily cap for storage, downloads, Class B and Class C
  transactions in the console, so a flood of junk uploads can't run up a bill. An account without a payment method
  has its free limits as caps: when storage is full, uploads stop until a payment method is added; the daily limits
  (downloads, requests) reset each day. Sealdrop warns in plain words either way (PROTOCOL.md §9.3).

## Choices the protocol leaves open

- **State:** SQLite (`state/state.db`) for what was handled and what each sender was told.
- **`pair`** asks the owner to confirm that both screens show the same code before it writes the paired receipt.
- **Status receipts:** once a day for each sender, and at once when the collector's warnings change.
- **`--clock-check off`:** for a computer whose clock its host keeps (WSL), where `timedatectl` can't tell.

## Tests

```sh
cd collector/tests
python -m unittest
```

They run against the shared test files in [../testvectors](../testvectors), which the Android side reads too. The
setup runs against a Backblaze in memory (`tests/fake_b2.py`) that checks every request's signature; the signatures
are also checked against AWS's published examples.
