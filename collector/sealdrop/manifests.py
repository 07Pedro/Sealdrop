"""The content of a sealed file and its manifests (PROTOCOL.md §5, §6, §7)."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field

from . import encoding, errors, sizes
from .errors import FormatError, Rejected

MAX_DELIVERIES = 1000
MAX_FILES = 10_000
MAX_NAME = 100
MAX_PATH_BYTES = 255
MAX_PARTS = 8
MAX_PART = 128

_APP = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+")
_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RESERVED = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(10)} | {f"lpt{i}" for i in range(10)}
_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


# --- content = manifest length ‖ manifest ‖ files ---------------------------------------------------------------

def content_prefix(manifest: dict) -> bytes:
    raw = encoding.dumps(manifest)
    return len(raw).to_bytes(4, "big") + raw


def split_content(content: bytes, kind: int):
    """(manifest, the bytes after it) for content in memory; Rejected("bad-content") if it can't be read."""
    if len(content) < 4:
        raise Rejected(errors.BAD_CONTENT, "no manifest length")
    m = int.from_bytes(content[:4], "big")
    limit = sizes.MANIFEST_ROOM if kind == sizes.KIND_BUNDLE else sizes.SMALL_MAX
    if m > limit or 4 + m > len(content):
        raise Rejected(errors.BAD_CONTENT, "manifest length")
    if kind != sizes.KIND_BUNDLE and 4 + m != len(content):
        raise Rejected(errors.BAD_CONTENT, "bytes after the manifest")
    try:
        manifest = encoding.loads(content[4:4 + m])
    except FormatError as e:
        raise Rejected(errors.BAD_CONTENT, str(e)) from None
    return manifest, content[4 + m:]


# --- names ------------------------------------------------------------------------------------------------------

def fold(text: str) -> str:
    """ASCII case folding: A-Z to a-z and nothing else."""
    return text.translate(_FOLD)


def good_app(app: str) -> bool:
    return 1 <= len(app) <= MAX_NAME and _APP.fullmatch(app) is not None


def _good_part(part: str) -> bool:
    return (1 <= len(part) <= MAX_PART and _PART.fullmatch(part) is not None and not part.endswith(".")
            and fold(part.split(".", 1)[0]) not in _RESERVED)


def good_delivery(delivery: str) -> bool:
    return len(delivery) <= MAX_NAME and _good_part(delivery)


def good_path(path: str) -> bool:
    parts = path.split("/")
    return (len(path.encode("utf-8")) <= MAX_PATH_BYTES and 1 <= len(parts) <= MAX_PARTS
            and all(_good_part(part) for part in parts))


def paths_clash(paths: list[str]) -> bool:
    """Two paths equal after folding, or one a folder of another."""
    folded = sorted(fold(path) for path in paths)
    for a, b in zip(folded, folded[1:]):
        if a == b or b.startswith(a + "/"):
            return True
    return False


def good_label(label) -> bool:
    if not isinstance(label, str) or not 1 <= len(label) <= 40:
        return False
    return all(unicodedata.category(c) not in ("Cc", "Cf", "Zl", "Zp") for c in label)


# --- bundles (kind 1) -------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    sha256: str


@dataclass
class Delivery:
    app: str
    delivery: str
    created: int
    files: list[FileEntry]
    problem: str | None = None  # a per-delivery reason found in the manifest
    digest: str = field(init=False)

    def __post_init__(self):
        self.digest = delivery_digest(self.files)

    @property
    def size(self) -> int:
        return sum(f.size for f in self.files)


def delivery_digest(files: list[FileEntry]) -> str:
    """§5: SHA-256 over path, size and checksum of every file, sorted by path (byte order)."""
    text = "".join(f"{f.path}\n{f.size}\n{f.sha256}\n" for f in sorted(files, key=lambda f: f.path.encode()))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _envelope(condition: bool, detail: str) -> None:
    if not condition:
        raise Rejected(errors.BAD_CONTENT, detail)


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def check_bundle(manifest, n: int, m: int) -> list[Delivery]:
    """Every check of §5 that the manifest alone allows. Raises Rejected for an envelope failure; a delivery that
    breaks a name rule, has no files or has a malformed checksum comes back with its `problem` set."""
    _envelope(isinstance(manifest, dict), "not an object")
    _envelope(manifest.get("v") == 1 and manifest.get("type") == "bundle", "v or type")
    items = manifest.get("deliveries")
    _envelope(isinstance(items, list) and 1 <= len(items) <= MAX_DELIVERIES, "deliveries")
    deliveries, seen, total_files, total_bytes = [], set(), 0, 0
    for item in items:
        _envelope(isinstance(item, dict), "delivery not an object")
        app, delivery, created, files = (item.get(k) for k in ("app", "delivery", "created", "files"))
        _envelope(isinstance(app, str) and isinstance(delivery, str), "app or delivery")
        _envelope(len(app) <= MAX_NAME and len(delivery) <= MAX_NAME, "app or delivery too long")
        _envelope(_is_int(created) and isinstance(files, list), "created or files")
        _envelope((app, delivery) not in seen, "the same delivery twice")
        seen.add((app, delivery))
        entries = []
        for f in files:
            _envelope(isinstance(f, dict), "file not an object")
            path, size, sha = f.get("path"), f.get("size"), f.get("sha256")
            _envelope(isinstance(path, str) and _is_int(size) and isinstance(sha, str), "file fields")
            entries.append(FileEntry(path, size, sha))
            total_bytes += size
        total_files += len(entries)
        _envelope(total_files <= MAX_FILES, "more than 10,000 files")
        d = Delivery(app, delivery, created, entries)
        if not good_app(app) or not good_delivery(delivery) or not all(good_path(e.path) for e in entries) \
                or paths_clash([e.path for e in entries]):
            d.problem = errors.BAD_NAME
        elif not entries:
            d.problem = errors.NO_FILES
        elif not all(_SHA256.fullmatch(e.sha256) for e in entries):
            d.problem = errors.BAD_FILE
        deliveries.append(d)
    _envelope(4 + m + total_bytes == n, "file sizes don't add up")
    return deliveries


def bundle_manifest(deliveries: list[Delivery]) -> dict:
    return {
        "v": 1,
        "type": "bundle",
        "deliveries": [
            {"app": d.app, "delivery": d.delivery, "created": d.created,
             "files": [{"path": f.path, "size": f.size, "sha256": f.sha256} for f in d.files]}
            for d in deliveries
        ],
    }


# --- pairing requests (kind 2) ----------------------------------------------------------------------------------

@dataclass(frozen=True)
class PairRequest:
    pairing: bytes
    sender_sign: bytes
    sender_open: bytes
    label: str
    replaces: bytes | None
    mac: bytes


def parse_pair(manifest) -> PairRequest:
    """§7 step 1: the manifest's form. The label and `replaces` rules are step 6 (`check_pair_names`)."""
    try:
        if not isinstance(manifest, dict) or manifest.get("v") != 1 or manifest.get("type") != "pair":
            raise FormatError("v or type")
        replaces = manifest.get("replaces")
        label = manifest.get("label")
        if not isinstance(label, str):
            raise FormatError("label")
        return PairRequest(
            pairing=encoding.unb64url(manifest.get("pairing"), 16),
            sender_sign=encoding.unb64url(manifest.get("sender_sign"), 65),
            sender_open=encoding.unb64url(manifest.get("sender_open"), 32),
            label=label,
            replaces=None if replaces is None else encoding.unhex(replaces, 32),
            mac=encoding.unb64url(manifest.get("mac"), 32),
        )
    except FormatError as e:
        raise Rejected(errors.BAD_CONTENT, str(e)) from None


def check_pair_names(request: PairRequest) -> str | None:
    """§7 step 6: what's wrong with the label or `replaces`, or None."""
    if not good_label(request.label):
        return "label not allowed"
    if request.replaces is not None and request.replaces == bytes(32):
        return "replaces is all zeros"
    return None


def pair_manifest(pairing: bytes, sender_sign: bytes, sender_open: bytes, label: str, replaces: bytes | None,
                  mac: bytes) -> dict:
    manifest = {
        "v": 1,
        "type": "pair",
        "pairing": encoding.b64url(pairing),
        "sender_sign": encoding.b64url(sender_sign),
        "sender_open": encoding.b64url(sender_open),
        "label": label,
    }
    if replaces is not None:
        manifest["replaces"] = replaces.hex()
    manifest["mac"] = encoding.b64url(mac)
    return manifest
