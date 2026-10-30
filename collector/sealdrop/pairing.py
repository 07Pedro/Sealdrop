"""Pairing (PROTOCOL.md §7): the QR code's offer, the request's MAC and the fingerprint."""

from __future__ import annotations

import hashlib
import hmac
import re

from . import encoding
from .errors import FormatError
from .hkdf import hkdf_sha256

_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
_ENDPOINT = re.compile(rf"https://({_LABEL}(?:\.{_LABEL})*)(?::(\d{{1,5}}))?")
_REGION = re.compile(r"[a-z0-9-]{1,32}")
_BUCKET = re.compile(r"[a-z0-9](?:[a-z0-9.-]{1,61})[a-z0-9]")
_PREFIX = re.compile(r"(?:[a-z0-9_-]+/)*")
_KEY_TEXT = re.compile(r"[!-~]{1,128}")


def mac_transcript(pairing: bytes, collector_open: bytes, collector_sign: bytes, sender_sign: bytes,
                   sender_open: bytes, replaces: bytes | None) -> bytes:
    return (b"sealdrop/v1/pair" + pairing + collector_open + collector_sign + sender_sign + sender_open
            + (replaces if replaces is not None else bytes(32)))


def pair_mac(code: bytes, pairing: bytes, transcript: bytes) -> bytes:
    key = hkdf_sha256(code, pairing, b"sealdrop/v1/pair-mac", 32)
    return hmac.new(key, transcript, hashlib.sha256).digest()


def mac_ok(expected: bytes, given: bytes) -> bool:
    return hmac.compare_digest(expected, given)


def fingerprint(pairing: bytes, collector_open: bytes, collector_sign: bytes, sender_sign: bytes,
                sender_open: bytes) -> str:
    digest = hashlib.sha256(b"sealdrop/v1/fingerprint" + pairing + collector_open + collector_sign + sender_sign
                            + sender_open).digest()
    text = encoding.base32(digest[:10])
    return " ".join(text[i:i + 4] for i in range(0, 16, 4))


# --- the offer in the QR code ------------------------------------------------------------------------------------

def _check_location(loc, full: bool) -> dict:
    if not isinstance(loc, dict):
        raise FormatError("location")
    for name, pattern in (("endpoint", _ENDPOINT), ("region", _REGION), ("bucket", _BUCKET)):
        value = loc.get(name)
        if value is None and not full:
            continue
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise FormatError(name)
    endpoint = loc.get("endpoint")
    if endpoint is not None:
        port = _ENDPOINT.fullmatch(endpoint).group(2)
        if port is not None and not 1 <= int(port) <= 65535:
            raise FormatError("endpoint port")
    prefix = loc.get("prefix")
    if not isinstance(prefix, str) or len(prefix) > 64 or not _PREFIX.fullmatch(prefix):
        raise FormatError("prefix")
    key = loc.get("key")
    if not isinstance(key, dict) or not all(isinstance(key.get(k), str) and _KEY_TEXT.fullmatch(key[k])
                                            for k in ("id", "secret")):
        raise FormatError("key")
    return loc


def resolve_storage(storage) -> tuple[dict, dict]:
    """Both locations in full (`ack` takes what it leaves out from `up`); FormatError if they break §7's rules."""
    if not isinstance(storage, dict):
        raise FormatError("storage")
    up = _check_location(storage.get("up"), full=True)
    ack = _check_location(storage.get("ack"), full=False)
    ack = {**{k: up[k] for k in ("endpoint", "region", "bucket")},
           **{k: v for k, v in ack.items() if v is not None}}
    if (up["endpoint"], up["bucket"]) == (ack["endpoint"], ack["bucket"]):
        a, b = up["prefix"], ack["prefix"]
        if not a or not b or a.startswith(b) or b.startswith(a):
            raise FormatError("up and ack overlap in one bucket")
    return up, ack


def check_offer(offer, now_ms: int, allowance_ms: int = 5 * 60 * 1000) -> tuple[dict, dict]:
    """What the phone checks (§7, step 1), and the `pair` command before it shows the code."""
    if not isinstance(offer, dict) or offer.get("sealdrop") != 1 or offer.get("type") != "pair-offer":
        raise FormatError("sealdrop or type")
    encoding.unb64url(offer.get("pairing"), 16)
    encoding.unb64url(offer.get("collector_open"), 32)
    encoding.unb64url(offer.get("collector_sign"), 32)
    encoding.unb64url(offer.get("code"), 16)
    expires = offer.get("expires")
    if not isinstance(expires, int) or isinstance(expires, bool) or expires + allowance_ms < now_ms:
        raise FormatError("expired")
    return resolve_storage(offer.get("storage"))
