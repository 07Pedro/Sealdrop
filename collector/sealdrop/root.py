"""The collector's data root (PROTOCOL.md §10): its folders, settings, keys, paired senders and instance ID.

Everything secret here (the settings with the collector's storage keys, the private keys) is written readable by the
collector's user only. Nothing from a pairing's QR code is ever written (§7).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import encoding, keys, pairing, sizes
from .errors import FormatError
from .keys import Ed25519Signer, P256Verifier

FOLDERS = ("config", "keys", "keys/retired", "senders", "senders/removed", "state", "incoming", "store", "conflicts",
           "rejected", "log")
SETTINGS = "config/collector.json"
GiB = 1 << 30

# The settings and their defaults. `clock_check` is "timedatectl" (a run waits for NTP, §10) or "off" (a computer
# whose clock is kept by its host, such as WSL; the owner's choice).
DEFAULTS = {
    "max_sealed": sizes.DEFAULT_MAX_SEALED,
    "free_reserve": 5 * GiB,
    "vanish_days": 96,
    "rejected_limit": GiB,
    "clock_check": "timedatectl",
}


class RootError(Exception):
    """The data root can't be used as it is; the message says why, for the owner."""


def write_private(path: Path, data: bytes) -> None:
    """Atomically, readable by the owner only, and on disk before it counts."""
    temporary = path.with_name(path.name + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    fsync_dir(path.parent)


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@dataclass
class Location:
    endpoint: str
    region: str
    bucket: str
    prefix: str

    def as_dict(self) -> dict:
        return {"endpoint": self.endpoint, "region": self.region, "bucket": self.bucket, "prefix": self.prefix}


@dataclass
class Sender:
    key_id: bytes
    sign: bytes   # the 65-byte P-256 point
    open: bytes   # X25519, raw
    label: str
    paired: int
    fingerprint: str

    @property
    def hex(self) -> str:
        return self.key_id.hex()

    def verifier(self) -> P256Verifier:
        return P256Verifier(self.sign)

    def to_json(self) -> dict:
        return {"key_id": self.hex, "sign": encoding.b64url(self.sign), "open": encoding.b64url(self.open),
                "label": self.label, "paired": self.paired, "fingerprint": self.fingerprint}

    @classmethod
    def from_json(cls, d: dict) -> "Sender":
        return cls(encoding.unhex(d["key_id"], 32), encoding.unb64url(d["sign"], 65), encoding.unb64url(d["open"], 32),
                   d["label"], d["paired"], d["fingerprint"])


class Root:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)

    def __truediv__(self, name: str) -> Path:
        return self.path / name

    # --- setting up -----------------------------------------------------------------------------------------------

    def create(self, up: Location, ack: Location, pickup: tuple[str, str], receipts: tuple[str, str],
               settings: dict | None = None, opening: bytes | None = None, signing: bytes | None = None) -> None:
        """A new data root: the folders, the settings and the collector's keys (new ones, or the owner's own from their
        safe copy when moving to a new server)."""
        if (self / SETTINGS).exists():
            raise RootError(f"{self.path} is already set up")
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in FOLDERS:
            (self / name).mkdir(exist_ok=True, mode=0o700)
        check_locations(up, ack)
        config = {"up": up.as_dict(), "ack": ack.as_dict(),
                  "keys": {"pickup": {"id": pickup[0], "secret": pickup[1]},
                           "receipts": {"id": receipts[0], "secret": receipts[1]}},
                  **DEFAULTS, **(settings or {})}
        write_private(self / SETTINGS, json.dumps(config, indent=2).encode() + b"\n")
        open_key = X25519PrivateKey.from_private_bytes(opening) if opening else X25519PrivateKey.generate()
        sign_key = Ed25519PrivateKey.from_private_bytes(signing) if signing else Ed25519PrivateKey.generate()
        write_private(self / "keys/open.key", encoding.b64url(keys.x25519_private_bytes(open_key)).encode())
        write_private(self / "keys/sign.key", encoding.b64url(_ed25519_private_bytes(sign_key)).encode())

    def check(self) -> None:
        if not (self / SETTINGS).is_file():
            raise RootError(f"{self.path} isn't a collector's data root (no {SETTINGS}); run `init` first")
        for name in FOLDERS:
            (self / name).mkdir(exist_ok=True, mode=0o700)

    # --- settings ---------------------------------------------------------------------------------------------------

    def config(self) -> dict:
        config = json.loads((self / SETTINGS).read_text("utf-8"))
        return {**DEFAULTS, **config}

    def locations(self) -> tuple[Location, Location]:
        config = self.config()
        return Location(**config["up"]), Location(**config["ack"])

    # --- the collector's keys -------------------------------------------------------------------------------------

    def opening_keys(self) -> list[X25519PrivateKey]:
        """The current opening key first, then the retired ones (files sealed for them still open, §7)."""
        found = [self / "keys/open.key"] + sorted((self / "keys/retired").glob("*.key"))
        return [X25519PrivateKey.from_private_bytes(encoding.unb64url(p.read_text().strip(), 32)) for p in found]

    def signer(self) -> Ed25519Signer:
        raw = encoding.unb64url((self / "keys/sign.key").read_text().strip(), 32)
        return Ed25519Signer(Ed25519PrivateKey.from_private_bytes(raw))

    def public_keys(self) -> tuple[bytes, bytes]:
        """The collector's opening and signing public keys, as the QR code carries them."""
        return keys.x25519_public_bytes(self.opening_keys()[0].public_key()), self.signer().public

    def private_keys(self) -> tuple[bytes, bytes]:
        """For the owner's safe copy (`show-keys`), and nothing else."""
        open_key = self.opening_keys()[0]
        raw = encoding.unb64url((self / "keys/sign.key").read_text().strip(), 32)
        return keys.x25519_private_bytes(open_key), raw

    # --- senders ----------------------------------------------------------------------------------------------------

    def senders(self) -> dict[bytes, Sender]:
        found = {}
        for p in sorted((self / "senders").glob("*.json")):
            s = Sender.from_json(json.loads(p.read_text("utf-8")))
            found[s.key_id] = s
        return found

    def add_sender(self, sender: Sender) -> None:
        write_private(self / f"senders/{sender.hex}.json", json.dumps(sender.to_json(), indent=2).encode() + b"\n")

    def remove_sender(self, sender: Sender, when: int) -> None:
        """Unpair: kept under senders/removed/ for the record, never read for checks again."""
        path = self / f"senders/{sender.hex}.json"
        record = {**sender.to_json(), "removed": when}
        write_private(self / f"senders/removed/{sender.hex}.json", json.dumps(record, indent=2).encode() + b"\n")
        path.unlink()
        fsync_dir(path.parent)

    def find_sender(self, text: str) -> list[Sender]:
        """By fingerprint (with or without spaces, any case) or by label."""
        wanted = text.replace(" ", "").upper()
        return [s for s in self.senders().values()
                if s.fingerprint.replace(" ", "") == wanted or s.label == text]

    # --- the instance ID (§10) ------------------------------------------------------------------------------------

    def instance(self, machine_id: Path = Path("/etc/machine-id"), cpuinfo: Path = Path("/proc/cpuinfo")) -> bytes:
        checksum = machine_checksum(machine_id, cpuinfo)
        path = self / "state/instance"
        try:
            saved = json.loads(path.read_text("utf-8"))
            if saved.get("machine") == checksum:
                return encoding.unhex(saved["instance"], 16)
        except (OSError, ValueError, KeyError):
            pass
        instance = os.urandom(16)
        write_private(path, json.dumps({"instance": instance.hex(), "machine": checksum}).encode() + b"\n")
        return instance


def machine_checksum(machine_id: Path, cpuinfo: Path) -> str:
    try:
        mid = machine_id.read_bytes()
    except OSError:
        mid = b""
    if not mid.strip():
        raise RootError(f"{machine_id} is missing or empty. In a container, mount the host's file read-only.")
    serial = b""
    try:
        for line in cpuinfo.read_bytes().splitlines():
            if re.match(rb"Serial\s*:", line):
                serial = line
                break
    except OSError:
        pass
    return hashlib.sha256(mid + b"\x00" + serial).hexdigest()


def check_locations(up: Location, ack: Location) -> None:
    """The same rules the phone applies to the QR code (§7), so a pairing can't fail on them later."""
    offer = {"up": {**up.as_dict(), "key": {"id": "x", "secret": "x"}},
             "ack": {**ack.as_dict(), "key": {"id": "x", "secret": "x"}}}
    try:
        pairing.resolve_storage(offer)
    except FormatError as e:
        raise RootError(f"the storage locations aren't usable: {e}") from None


def _ed25519_private_bytes(key: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
