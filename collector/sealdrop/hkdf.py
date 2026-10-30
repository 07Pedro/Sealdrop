"""HKDF-SHA256 (RFC 5869), built on HMAC like the Android side (PROTOCOL.md §3)."""

from __future__ import annotations

import hashlib
import hmac


def extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def expand(prk: bytes, info: bytes, length: int) -> bytes:
    if not 0 < length <= 255 * 32:
        raise ValueError("HKDF length out of range")
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return expand(extract(salt, ikm), info, length)
