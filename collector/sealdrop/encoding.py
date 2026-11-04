"""Text rules (PROTOCOL.md §3): strict JSON, base64url, hex and base32."""

from __future__ import annotations

import base64
import json
import re

from .errors import FormatError

MAX_INT = 2**53 - 1
MAX_DEPTH = 8

_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_HEX = re.compile(r"(?:[0-9a-f]{2})*")


# --- JSON -------------------------------------------------------------------------------------------------------

def _no_float(text: str):
    raise FormatError(f"number with a fraction or exponent: {text[:20]}")


def _int(text: str) -> int:
    if text.startswith("-"):
        raise FormatError("negative number")
    value = int(text)
    if value > MAX_INT:
        raise FormatError("integer above 2^53 - 1")
    return value


def _no_constant(text: str):
    raise FormatError(f"not allowed: {text}")


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise FormatError(f"duplicate name: {key[:40]!r}")
        obj[key] = value
    return obj


def _check_tree(root) -> None:
    """Depth at most 8 and no unpaired surrogates, without recursion."""
    stack = [(root, 1)]
    while stack:
        value, depth = stack.pop()
        if isinstance(value, str):
            _check_str(value)
        elif isinstance(value, (dict, list)):
            if depth > MAX_DEPTH:
                raise FormatError("nested deeper than 8")
            if isinstance(value, dict):
                for key, item in value.items():
                    _check_str(key)
                    stack.append((item, depth + 1))
            else:
                stack.extend((item, depth + 1) for item in value)


def _check_str(text: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise FormatError("unpaired surrogate") from None


def loads(data: bytes):
    """Parse UTF-8 JSON under I-JSON (RFC 7493) and §3's extra rules."""
    if data.startswith(b"\xef\xbb\xbf"):
        raise FormatError("byte-order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise FormatError("not UTF-8") from None
    try:
        value = json.loads(text, object_pairs_hook=_unique, parse_float=_no_float, parse_int=_int,
                           parse_constant=_no_constant)
    except FormatError:
        raise
    except (ValueError, RecursionError) as e:
        raise FormatError(f"not JSON: {type(e).__name__}") from None
    _check_tree(value)
    return value


def dumps(value) -> bytes:
    """Compact UTF-8 JSON, as Sealdrop writes it."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def is_int(value) -> bool:
    """A JSON integer. Python counts true and false as 1 and 0, JSON doesn't."""
    return isinstance(value, int) and not isinstance(value, bool)


def is_one(value) -> bool:
    return is_int(value) and value == 1


# --- base64url, hex, base32 -------------------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str, length: int | None = None) -> bytes:
    """Strict base64url without padding; `length` checks the decoded size."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise FormatError("not base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url(data) != text:
        raise FormatError("base64url with unused bits set")
    if length is not None and len(data) != length:
        raise FormatError(f"expected {length} bytes, got {len(data)}")
    return data


def unhex(text: str, length: int | None = None) -> bytes:
    """Lowercase hex only; `length` checks the decoded size."""
    if not isinstance(text, str) or not _HEX.fullmatch(text):
        raise FormatError("not lowercase hex")
    data = bytes.fromhex(text)
    if length is not None and len(data) != length:
        raise FormatError(f"expected {length} bytes, got {len(data)}")
    return data


def base32(data: bytes) -> str:
    """RFC 4648 §6, alphabet A-Z 2-7, no padding."""
    return base64.b32encode(data).rstrip(b"=").decode("ascii")
