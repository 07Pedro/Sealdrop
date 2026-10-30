"""Padded lengths and the sizes a sealed file can have (PROTOCOL.md §4, §9.2)."""

from __future__ import annotations

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

PIECE = MiB
PREFIX = 152           # HPKE enc (32) + sealed header (120)
SIGNATURE = 64
TAG = 16
SMALL_MAX = 256 * KiB  # content limit of pairing requests and receipts
DEFAULT_MAX_SEALED = 4 * GiB
MANIFEST_ROOM = 4 * MiB

KIND_BUNDLE, KIND_PAIR, KIND_RECEIPT = 1, 2, 3


def _round_up(value: int, step: int) -> int:
    return -(-value // step) * step


def padded_length(kind: int, n: int) -> int:
    """`L` for content of `n` bytes; ValueError if `n` is too big for the kind."""
    if n < 0:
        raise ValueError("negative length")
    if kind == KIND_BUNDLE:
        if n <= 4 * MiB:
            return max(256 * KiB, _round_up(n, 256 * KiB))
        return _round_up(n, 4 * MiB)
    if kind == KIND_PAIR:
        if n > SMALL_MAX:
            raise ValueError("pairing request over 256 KiB")
        return 256 * KiB
    if kind == KIND_RECEIPT:
        if n > SMALL_MAX:
            raise ValueError("receipt over 256 KiB")
        return max(4 * KiB, _round_up(n, 4 * KiB))
    raise ValueError(f"unknown kind {kind}")


def pieces(length: int) -> int:
    return -(-length // PIECE)


def sealed_size(length: int) -> int:
    """The exact file size for a padded length `L`: 152 + L + 16·N + 64."""
    return PREFIX + length + TAG * pieces(length) + SIGNATURE


def possible_lengths(where: str, max_sealed: int = DEFAULT_MAX_SEALED) -> list[int]:
    """Every `L` that can appear in `up/` (bundles; a pairing request has the smallest size) or `ack/`."""
    if where == "ack":
        return [step * 4 * KiB for step in range(1, SMALL_MAX // (4 * KiB) + 1)]
    if where != "up":
        raise ValueError(where)
    lengths = [step * 256 * KiB for step in range(1, 17)]
    length = 8 * MiB
    while sealed_size(length) <= max_sealed:
        lengths.append(length)
        length += 4 * MiB
    return [length for length in lengths if sealed_size(length) <= max_sealed]


def length_for_size(where: str, size: int, max_sealed: int = DEFAULT_MAX_SEALED) -> int | None:
    """The `L` behind a listed size, or None if no file there can have that size (limit not applied)."""
    if size < PREFIX + SIGNATURE + TAG:
        return None
    if where == "ack":
        candidates = range(4 * KiB, SMALL_MAX + 1, 4 * KiB)
    elif size <= sealed_size(4 * MiB):
        candidates = range(256 * KiB, 4 * MiB + 1, 256 * KiB)
    else:
        # Above 4 MiB, L is a multiple of 4 MiB and N = L / 1 MiB, so size = 216 + L + 16·L/MiB.
        length = _round_up((size - PREFIX - SIGNATURE) * PIECE // (PIECE + TAG), 4 * MiB)
        candidates = (length - 4 * MiB, length)
    for length in candidates:
        if length > 0 and sealed_size(length) == size:
            return length
    return None


def max_delivery_bytes(max_sealed: int = DEFAULT_MAX_SEALED) -> int:
    """The most file bytes one delivery may hold (§9.2): the largest fitting `L` minus 4 MiB."""
    lengths = possible_lengths("up", max_sealed)
    if not lengths:
        return 0
    return max(0, lengths[-1] - MANIFEST_ROOM)
