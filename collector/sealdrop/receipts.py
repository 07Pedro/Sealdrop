"""Receipts (PROTOCOL.md §6): the collector's side, plus a light reader for tests."""

from __future__ import annotations

from . import encoding, sizes
from .errors import FormatError

RESULTS = ("stored", "duplicate", "conflict", "rejected")


def receipt_manifest(for_key_id: bytes, time: int, stored: list, rejected: list, status: dict) -> dict:
    return {"v": 1, "type": "receipt", "for": for_key_id.hex(), "time": time, "stored": stored,
            "rejected": rejected, "status": status}


def paired_manifest(for_key_id: bytes, pairing: bytes, time: int) -> dict:
    return {"v": 1, "type": "paired", "for": for_key_id.hex(), "pairing": encoding.b64url(pairing), "time": time}


def content_fits(manifest: dict) -> bool:
    return 4 + len(encoding.dumps(manifest)) <= sizes.SMALL_MAX


def check_receipt(manifest, own_key_ids: list[bytes]) -> dict:
    """The receipt's form, as the phone reads it; FormatError if it's wrong or not for this phone."""
    if not isinstance(manifest, dict) or manifest.get("v") != 1:
        raise FormatError("v")
    if manifest.get("type") not in ("receipt", "paired"):
        raise FormatError("type")
    if encoding.unhex(manifest.get("for"), 32) not in own_key_ids:
        raise FormatError("for")
    if not isinstance(manifest.get("time"), int):
        raise FormatError("time")
    if manifest["type"] == "paired":
        encoding.unb64url(manifest.get("pairing"), 16)
        return manifest
    for entry in manifest.get("stored", []):
        encoding.unhex(entry["sealed_sha256"], 32)
        for d in entry["deliveries"]:
            if d["result"] not in RESULTS:
                raise FormatError("result")
    if not isinstance(manifest.get("status"), dict):
        raise FormatError("status")
    return manifest
