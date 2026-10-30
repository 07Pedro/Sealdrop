"""The sealed file (PROTOCOL.md §4): writing it, and reading it in the order §4 gives."""

from __future__ import annotations

import hashlib
import io
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Callable, Iterable, Iterator, Protocol, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import errors, sizes
from .errors import Rejected
from .hkdf import hkdf_sha256
from .sizes import KIND_BUNDLE, KIND_PAIR, KIND_RECEIPT, PIECE, PREFIX, SIGNATURE, TAG

VERSION = 1
HEADER_LEN = 104
INFO_TO_COLLECTOR = b"sealdrop/v1/header/to-collector"
INFO_TO_SENDER = b"sealdrop/v1/header/to-sender"
PAYLOAD_INFO = b"sealdrop/v1/payload"
SIG_SENDER = b"sealdrop/v1/sig/sender"
SIG_COLLECTOR = b"sealdrop/v1/sig/collector"

_HEADER = struct.Struct(">BBHIQQ16s32s32s")
_SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
_HASH_CHUNK = PIECE


class Signer(Protocol):
    key_id: bytes

    def sign(self, statement: bytes) -> bytes: ...


class Verifier(Protocol):
    def verify(self, signature: bytes, statement: bytes) -> bool: ...


def header_info(kind: int) -> bytes:
    return INFO_TO_SENDER if kind == KIND_RECEIPT else INFO_TO_COLLECTOR


def statement(kind: int, digest_before_signature: bytes) -> bytes:
    text = SIG_COLLECTOR if kind == KIND_RECEIPT else SIG_SENDER
    return text + b"\x00" + digest_before_signature


def nonce(index: int, last: bool) -> bytes:
    return index.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


@dataclass(frozen=True)
class Header:
    kind: int
    created: int
    n: int
    message_id: bytes
    writer_key_id: bytes
    file_key: bytes

    @property
    def length(self) -> int:
        return sizes.padded_length(self.kind, self.n)

    @property
    def pieces(self) -> int:
        return sizes.pieces(self.length)

    @property
    def sealed_size(self) -> int:
        return sizes.sealed_size(self.length)

    def pack(self) -> bytes:
        return _HEADER.pack(VERSION, self.kind, 0, PIECE, self.created, self.n, self.message_id,
                            self.writer_key_id, self.file_key)

    @classmethod
    def unpack(cls, raw: bytes, expected_kinds: Sequence[int]) -> "Header":
        version, kind, reserved, piece, created, n, message_id, writer, key = _HEADER.unpack(raw)
        if version != VERSION or kind not in expected_kinds or reserved != 0 or piece != PIECE:
            raise Rejected(errors.DAMAGED, "header fields")
        header = cls(kind, created, n, message_id, writer, key)
        try:
            header.length
        except ValueError:
            raise Rejected(errors.DAMAGED, "content length too big for the kind") from None
        return header


@dataclass(frozen=True)
class SealResult:
    header: Header
    size: int
    sha256: str  # of the whole file, hex: a receipt's sealed_sha256


def _padded_pieces(content: Iterable[bytes], n: int, length: int) -> Iterator[bytes]:
    """Cut the content into 1 MiB pieces, zero-padded up to `length`."""
    buffer, seen = bytearray(), 0
    produced = 0
    for chunk in content:
        seen += len(chunk)
        if seen > n:
            raise ValueError("content longer than announced")
        buffer += chunk
        while len(buffer) >= PIECE:
            yield bytes(buffer[:PIECE])
            del buffer[:PIECE]
            produced += PIECE
    if seen != n:
        raise ValueError("content shorter than announced")
    # What's left is less than a piece; the padding follows it, then whole pieces of zeros if needed.
    while produced < length:
        size = min(PIECE, length - produced)
        yield bytes(buffer) + bytes(size - len(buffer))
        buffer.clear()
        produced += size


def seal(out: BinaryIO, kind: int, content: Iterable[bytes], n: int, reader: X25519PublicKey, signer: Signer,
         created: int, *, message_id: bytes | None = None, file_key: bytes | None = None) -> SealResult:
    """Write a sealed file of `kind` for `reader`, signed by `signer`. `content` yields exactly `n` bytes."""
    header = Header(kind, created, n, message_id or os.urandom(16), signer.key_id, file_key or os.urandom(32))
    length = header.length
    count = header.pieces
    before_sig = hashlib.sha256()

    def write(data: bytes) -> None:
        out.write(data)
        before_sig.update(data)

    write(_SUITE.encrypt(header.pack(), reader, info=header_info(kind)))
    aead = ChaCha20Poly1305(hkdf_sha256(header.file_key, header.message_id, PAYLOAD_INFO, 32))
    for index, piece in enumerate(_padded_pieces(content, n, length)):
        write(aead.encrypt(nonce(index, index == count - 1), piece, None))
    signature = signer.sign(statement(kind, before_sig.digest()))
    out.write(signature)
    whole = before_sig.copy()
    whole.update(signature)
    return SealResult(header, header.sealed_size, whole.hexdigest())


def check_listed_size(where: str, size: int, max_sealed: int = sizes.DEFAULT_MAX_SEALED) -> None:
    """Step 1: a size the location can hold, and within the limit (`up/` only)."""
    if sizes.length_for_size(where, size, max_sealed=max_sealed) is None:
        raise Rejected(errors.DAMAGED, "impossible size")
    if where == "up" and size > max_sealed:
        raise Rejected(errors.TOO_BIG)


def open_header(prefix: bytes, opening_keys: Sequence[X25519PrivateKey], info: bytes,
                expected_kinds: Sequence[int]) -> Header:
    """Step 2: open the 152-byte prefix with any of the reader's opening keys (the collector's retired ones too)."""
    if len(prefix) != PREFIX:
        raise Rejected(errors.DAMAGED, "short prefix")
    for key in opening_keys:
        try:
            raw = _SUITE.decrypt(prefix, key, info=info)
        except InvalidTag:
            continue
        if len(raw) != HEADER_LEN:
            raise Rejected(errors.DAMAGED, "header length")
        return Header.unpack(raw, expected_kinds)
    raise Rejected(errors.DAMAGED, "header doesn't open")


class SealedFile:
    """A sealed file on disk (or in memory), read in §4's order."""

    def __init__(self, f: BinaryIO, size: int):
        self.f = f
        self.size = size
        self.header: Header | None = None

    def read_at(self, offset: int, length: int) -> bytes:
        self.f.seek(offset)
        data = self.f.read(length)
        if len(data) != length:
            raise Rejected(errors.DAMAGED, "file shorter than its size")
        return data

    def open_header(self, opening_keys: Sequence[X25519PrivateKey], info: bytes,
                    expected_kinds: Sequence[int]) -> Header:
        """Steps 2 and 3: the header, then the exact size."""
        header = open_header(self.read_at(0, PREFIX), opening_keys, info, expected_kinds)
        if header.sealed_size != self.size:
            raise Rejected(errors.DAMAGED, "size doesn't match the header")
        self.header = header
        return header

    def digest_before_signature(self) -> bytes:
        digest = hashlib.sha256()
        self.f.seek(0)
        left = self.size - SIGNATURE
        while left:
            chunk = self.f.read(min(_HASH_CHUNK, left))
            if not chunk:
                raise Rejected(errors.DAMAGED, "file shorter than its size")
            digest.update(chunk)
            left -= len(chunk)
        return digest.digest()

    def verify(self, verifier: Verifier) -> None:
        """Step 5: the signature over everything before it."""
        signature = self.read_at(self.size - SIGNATURE, SIGNATURE)
        if not verifier.verify(signature, statement(self.header.kind, self.digest_before_signature())):
            raise Rejected(errors.BAD_SIGNATURE)

    def iter_content(self, check_padding: bool = True) -> Iterator[bytes]:
        """Step 6: decrypt piece by piece; yields exactly `n` content bytes, then checks the padding."""
        header = self.header
        aead = ChaCha20Poly1305(hkdf_sha256(header.file_key, header.message_id, PAYLOAD_INFO, 32))
        length, count, left = header.length, header.pieces, header.n
        padding_ok = True
        offset = PREFIX
        for index in range(count):
            plain_size = min(PIECE, length - index * PIECE)
            sealed_piece = self.read_at(offset, plain_size + TAG)
            offset += plain_size + TAG
            try:
                plain = aead.decrypt(nonce(index, index == count - 1), sealed_piece, None)
            except InvalidTag:
                raise Rejected(errors.DAMAGED, f"piece {index} doesn't open") from None
            if left >= len(plain):
                left -= len(plain)
                yield plain
            else:
                if left:
                    yield plain[:left]
                if plain[left:].count(0) != len(plain) - left:
                    padding_ok = False
                left = 0
        if check_padding and not padding_ok:
            raise Rejected(errors.DAMAGED, "padding isn't zero")
        self.padding_ok = padding_ok

    def read_content(self, check_padding: bool = True) -> bytes:
        return b"".join(self.iter_content(check_padding))


def open_small(data: bytes, opening_keys: Sequence[X25519PrivateKey], info: bytes, expected_kinds: Sequence[int],
               find_verifier: Callable[[Header], Verifier | None], where: str,
               max_sealed: int = sizes.DEFAULT_MAX_SEALED) -> tuple[Header, bytes]:
    """All of §4 for a file in memory (receipts, tests): size, header, writer, signature, content."""
    check_listed_size(where, len(data), max_sealed)
    sealed = SealedFile(io.BytesIO(data), len(data))
    header = sealed.open_header(opening_keys, info, expected_kinds)
    verifier = find_verifier(header)
    if verifier is None:
        raise Rejected(errors.UNKNOWN_SENDER)
    sealed.verify(verifier)
    return header, sealed.read_content()


__all__ = [
    "Header", "SealResult", "SealedFile", "Signer", "Verifier", "check_listed_size", "header_info", "nonce",
    "open_header", "open_small", "seal", "statement", "KIND_BUNDLE", "KIND_PAIR", "KIND_RECEIPT",
    "INFO_TO_COLLECTOR", "INFO_TO_SENDER",
]
