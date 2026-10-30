"""Reading uploads, pairing requests and receipts in the order PROTOCOL.md §4, §5 and §7 give.

Nothing here writes to disk: the collector's store builds on `check_deliveries`, and the tests use it as is.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from typing import BinaryIO, Callable, Iterator, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import encoding, errors, keys, manifests, sizes
from .errors import FormatError, Rejected
from .manifests import Delivery, PairRequest
from .sealed import INFO_TO_COLLECTOR, INFO_TO_SENDER, Header, SealedFile, Verifier, check_listed_size
from .sizes import KIND_BUNDLE, KIND_PAIR, KIND_RECEIPT


class _Stream:
    """Reads exact amounts from an iterator of byte chunks."""

    def __init__(self, chunks: Iterator[bytes]):
        self._chunks, self._buffer = chunks, bytearray()

    def read(self, length: int) -> bytes:
        while len(self._buffer) < length:
            chunk = next(self._chunks, None)
            if chunk is None:
                raise Rejected(errors.BAD_CONTENT, "content ends early")
            self._buffer += chunk
        data = bytes(self._buffer[:length])
        del self._buffer[:length]
        return data

    def copy(self, length: int, sink: Callable[[bytes], None]) -> None:
        while length:
            if not self._buffer:
                chunk = next(self._chunks, None)
                if chunk is None:
                    raise Rejected(errors.BAD_CONTENT, "content ends early")
                self._buffer += chunk
            take = min(length, len(self._buffer))
            sink(bytes(self._buffer[:take]))
            del self._buffer[:take]
            length -= take

    def drain(self) -> None:
        for _ in self._chunks:
            pass


def open_upload(f: BinaryIO, size: int, opening_keys: Sequence[X25519PrivateKey],
                senders: Mapping[bytes, Verifier], max_sealed: int = sizes.DEFAULT_MAX_SEALED) -> SealedFile:
    """§4 steps 1 to 5 for a file in `up/`, as a regular run reads it: a pairing request is `unknown-sender`."""
    check_listed_size("up", size, max_sealed)
    sealed = SealedFile(f, size)
    header = sealed.open_header(opening_keys, INFO_TO_COLLECTOR, (KIND_BUNDLE, KIND_PAIR))
    verifier = senders.get(header.writer_key_id) if header.kind == KIND_BUNDLE else None
    if verifier is None:
        raise Rejected(errors.UNKNOWN_SENDER)
    sealed.verify(verifier)
    return sealed


@dataclass
class Verdict:
    delivery: Delivery
    ok: bool
    reason: str | None = None


FileSink = Callable[[Delivery, manifests.FileEntry], Callable[[bytes], None] | None]


def check_deliveries(sealed: SealedFile, file_sink: FileSink | None = None) -> list[Verdict]:
    """§4 steps 6 and 7 with §5: decrypt, read the manifest, then every file against its size and checksum.

    `file_sink(delivery, entry)` may return a function that takes the file's bytes; it's only asked for deliveries
    whose names and limits passed, so a rejected delivery's bytes are checked but never handed out. A whole-file
    failure raises Rejected; anything else comes back per delivery."""
    header = sealed.header
    stream = _Stream(sealed.iter_content())
    m = int.from_bytes(stream.read(4), "big")
    if m > sizes.MANIFEST_ROOM or 4 + m > header.n:
        raise Rejected(errors.BAD_CONTENT, "manifest length")
    try:
        manifest = encoding.loads(stream.read(m))
    except FormatError as e:
        raise Rejected(errors.BAD_CONTENT, str(e)) from None
    deliveries = manifests.check_bundle(manifest, header.n, m)
    verdicts = []
    for delivery in deliveries:
        ok = delivery.problem is None
        for entry in delivery.files:
            digest = hashlib.sha256()
            sink = file_sink(delivery, entry) if (ok and file_sink) else None

            def take(data: bytes, sink=sink) -> None:
                digest.update(data)
                if sink is not None:
                    sink(data)

            stream.copy(entry.size, take)
            if digest.hexdigest() != entry.sha256:
                ok = False
        reason = delivery.problem or (None if ok else errors.BAD_FILE)
        verdicts.append(Verdict(delivery, ok, reason))
    stream.drain()  # the padding check runs at the end of the pieces
    return verdicts


@dataclass
class OpenedPairRequest:
    header: Header
    request: PairRequest
    manifest: dict


def open_pair_request(f: BinaryIO, size: int, opening_keys: Sequence[X25519PrivateKey]) -> OpenedPairRequest:
    """§7, what the `pair` command checks before it looks for a waiting pairing (steps 1 to 4)."""
    check_listed_size("up", size)
    sealed = SealedFile(f, size)
    header = sealed.open_header(opening_keys, INFO_TO_COLLECTOR, (KIND_PAIR,))
    content = sealed.read_content(check_padding=False)  # at most 256 KiB; padding is step 4
    manifest, _ = manifests.split_content(content, KIND_PAIR)
    request = manifests.parse_pair(manifest)
    if keys.key_id(request.sender_sign) != header.writer_key_id:
        raise Rejected(errors.UNKNOWN_SENDER, "sender_sign doesn't match the key ID")
    try:
        verifier = keys.P256Verifier(request.sender_sign)
    except ValueError:
        raise Rejected(errors.BAD_CONTENT, "sender_sign isn't a P-256 point") from None
    sealed.verify(verifier)
    if not sealed.padding_ok:
        raise Rejected(errors.DAMAGED, "padding isn't zero")
    return OpenedPairRequest(header, request, manifest)


def open_receipt(data: bytes, opening_keys: Sequence[X25519PrivateKey], collector: Verifier,
                 collector_key_id: bytes) -> tuple[Header, dict]:
    """The phone's side (§6, steps 1 to 3), in Python for the tests: size, header, writer, signature, content."""
    check_listed_size("ack", len(data))
    sealed = SealedFile(io.BytesIO(data), len(data))
    header = sealed.open_header(opening_keys, INFO_TO_SENDER, (KIND_RECEIPT,))
    if header.writer_key_id != collector_key_id:
        raise Rejected(errors.UNKNOWN_SENDER)
    sealed.verify(collector)
    manifest, _ = manifests.split_content(sealed.read_content(), KIND_RECEIPT)
    return header, manifest
