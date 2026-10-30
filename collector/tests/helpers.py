"""Shared helpers for the tests: paths, the test keys and the committed test files."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "testvectors"
sys.path.insert(0, str(ROOT / "collector"))
sys.path.insert(0, str(VECTORS))

from sealdrop import encoding  # noqa: E402


def load(name: str):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


KEYS = load("keys.json")
VECTOR = load("vectors.json")
CASES = load("cases.json")["cases"]


def x25519(name: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(encoding.unb64url(KEYS[name]["private"], 32))


def public(name: str) -> bytes:
    return encoding.unb64url(KEYS[name]["public"])


def mutate(data: bytes, ops: list[dict]) -> bytes:
    """Apply a case's mutations: the same operations the Android tests apply."""
    out = bytearray(data)
    for op in ops:
        kind = op["op"]
        if kind == "flip":
            out[op["offset"]] ^= 1 << op["bit"]
        elif kind == "cut":
            del out[op["length"]:]
        elif kind == "append":
            out += bytes.fromhex(op["bytes"])
        elif kind == "remove":
            del out[op["offset"]:op["offset"] + op["length"]]
        elif kind == "swap":
            o, a, b = op["offset"], op["first"], op["second"]
            out[o:o + a + b] = out[o + a:o + a + b] + out[o:o + a]
        else:
            raise ValueError(kind)
    return bytes(out)
