"""Makes the test files in this folder (PROTOCOL.md §13). Run from the repository root:

    python testvectors/make_testvectors.py [output folder]

Every key here is made up and published for testing only. The output is the same on every run: the one-time HPKE
keys come from the test-only key schedule (rfc9180_test_only.py) instead of a random generator, and ECDSA signs
deterministically (RFC 6979). A test checks that running this again gives exactly the committed files.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "collector"))
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

import rfc9180_test_only as hpke9180  # noqa: E402
from sealdrop import encoding, errors, keys, manifests, pairing, receipts, sealed, sizes  # noqa: E402
from sealdrop.errors import FormatError  # noqa: E402
from sealdrop.encoding import b64url  # noqa: E402
from sealdrop.manifests import Delivery, FileEntry  # noqa: E402

CREATED = 1789285265000  # 2026-09-13, made up
NOTE = "Made-up keys, published for testing only. Never use them for anything real."
APP = "org.example.tracker"


def seed(label: str) -> bytes:
    return hashlib.sha256(b"sealdrop test vectors: " + label.encode()).digest()


def stream(label: str, length: int) -> bytes:
    return hashlib.shake_256(b"sealdrop test bytes: " + label.encode()).digest(length)


# --- keys --------------------------------------------------------------------------------------------------------

def x25519(label):
    return X25519PrivateKey.from_private_bytes(seed(label))


def ed25519(label):
    return Ed25519PrivateKey.from_private_bytes(seed(label))


def p256(label):
    return ec.derive_private_key(int.from_bytes(seed(label), "big") % (keys.P256_N - 1) + 1, ec.SECP256R1())


class DeterministicP256(keys.P256Signer):
    def sign(self, statement: bytes) -> bytes:
        return keys.der_to_raw(self._private.sign(statement, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))


class OtherKeyId:
    """Signs with one key but claims another's key ID in the header."""

    def __init__(self, signer, key_id: bytes):
        self._signer, self.key_id = signer, key_id

    def sign(self, statement: bytes) -> bytes:
        return self._signer.sign(statement)


COLLECTOR_OPEN = x25519("collector open")
COLLECTOR_OPEN_RETIRED = x25519("collector open, retired")
COLLECTOR_SIGN = keys.Ed25519Signer(ed25519("collector sign"))
SENDER_SIGN_KEY = p256("sender sign")
SENDER_SIGN = DeterministicP256(SENDER_SIGN_KEY)
SENDER_OPEN = x25519("sender open")
STRANGER_SIGN = DeterministicP256(p256("stranger sign"))
STRANGER_OPEN = x25519("stranger open")


def pub(key) -> bytes:
    return keys.x25519_public_bytes(key.public_key())


def keys_json() -> dict:
    def x(key):
        return {"private": b64url(keys.x25519_private_bytes(key)), "public": b64url(pub(key))}

    def p(label, signer):
        scalar = p256(label).private_numbers().private_value.to_bytes(32, "big")
        return {"private": b64url(scalar), "public": b64url(signer.public), "key_id": signer.key_id.hex()}

    return {
        "note": NOTE,
        "collector_open": x(COLLECTOR_OPEN),
        "collector_open_retired": x(COLLECTOR_OPEN_RETIRED),
        "collector_sign": {"private": b64url(seed("collector sign")), "public": b64url(COLLECTOR_SIGN.public),
                           "key_id": COLLECTOR_SIGN.key_id.hex()},
        "sender_sign": p("sender sign", SENDER_SIGN),
        "sender_open": x(SENDER_OPEN),
        "stranger_sign": p("stranger sign", STRANGER_SIGN),
        "stranger_open": x(STRANGER_OPEN),
    }


# --- sealing with fixed one-time keys ------------------------------------------------------------------------------

class FixedSuite:
    """Stands in for pyca's HPKE suite while the files are made: same output format, a chosen one-time key."""

    def __init__(self, real):
        self.real, self.label = real, "unset"

    def encrypt(self, plaintext, public_key, info=None):
        return hpke9180.single_shot_seal(public_key, info, plaintext, hpke9180.derive_key_pair(seed(self.label)))

    def decrypt(self, ciphertext, private_key, info=None):
        return self.real.decrypt(ciphertext, private_key, info=info)


SUITE = FixedSuite(sealed._SUITE)


@contextlib.contextmanager
def fixed_hpke():
    real = sealed._SUITE
    sealed._SUITE = SUITE
    try:
        yield
    finally:
        sealed._SUITE = real


@contextlib.contextmanager
def nonzero_padding():
    real = sealed._padded_pieces

    def padded(content, n, length):
        data = b"".join(content)
        plain = data + b"\x5a" * (length - n)
        for i in range(0, length, sizes.PIECE):
            yield plain[i:i + sizes.PIECE]

    sealed._padded_pieces = padded
    try:
        yield
    finally:
        sealed._padded_pieces = real


def seal_bytes(name: str, kind: int, content: bytes, reader, signer, *, n: int | None = None) -> tuple[bytes, dict]:
    SUITE.label = name
    out = io.BytesIO()
    result = sealed.seal(out, kind, [content], len(content) if n is None else n, reader.public_key(), signer,
                         CREATED, message_id=seed(name + " message")[:16], file_key=seed(name + " file key"))
    header = result.header
    return out.getvalue(), {
        "kind": header.kind, "created": header.created, "n": header.n, "message_id": header.message_id.hex(),
        "writer_key_id": header.writer_key_id.hex(),
    }


def bundle_content(deliveries: list[tuple[str, str, list[tuple[str, bytes]]]], lie: dict | None = None):
    """Content and the Delivery objects; `lie` maps a path to the checksum to claim instead of the real one."""
    lie = lie or {}
    objects, blobs = [], []
    for app, delivery, files in deliveries:
        entries = []
        for path, data in files:
            entries.append(FileEntry(path, len(data), lie.get(path, hashlib.sha256(data).hexdigest())))
            blobs.append(data)
        objects.append(Delivery(app, delivery, CREATED - 1000, entries))
    return manifests.content_prefix(manifests.bundle_manifest(objects)) + b"".join(blobs), objects


# --- the cases ----------------------------------------------------------------------------------------------------

def make_files() -> tuple[dict[str, bytes], list[dict]]:
    files: dict[str, bytes] = {}
    cases: list[dict] = []

    def add(name, data, header, **case):
        files[name] = data
        cases.append({"id": name.removesuffix(".sealed"), "file": name, "size": len(data),
                      "sealed_sha256": hashlib.sha256(data).hexdigest(), "header": header, **case})

    collector_reader = {"reader": "collector", "where": "up"}
    phone_reader = {"reader": "sender", "where": "ack"}

    # A bundle with two deliveries, big enough for two pieces.
    two = [
        (APP, "a1b2c3d4-000001", [("manifest.json", stream("manifest 1", 1532)),
                                  ("data/2026-09-13.json.gz", stream("ride 1", 268114))]),
        (APP, "a1b2c3d4-000002", [("manifest.json", stream("manifest 2", 640)),
                                  ("rawlogs/log-0001.rlog", stream("raw log", 900_000))]),
    ]
    content, objects = bundle_content(two)
    data, header = seal_bytes("bundle-two-pieces", 1, content, COLLECTOR_OPEN, SENDER_SIGN)
    add("bundle-two-pieces.sealed", data, header, **collector_reader, expect="ok",
        content_sha256=hashlib.sha256(content).hexdigest(), length=sizes.padded_length(1, len(content)),
        pieces=sizes.pieces(sizes.padded_length(1, len(content))),
        deliveries=[{"app": d.app, "delivery": d.delivery, "digest": d.digest, "result": "stored"} for d in objects])
    piece0 = sizes.PIECE + sizes.TAG
    piece1 = len(data) - sizes.PREFIX - sizes.SIGNATURE - piece0
    mutations = [
        ("flip-enc", [{"op": "flip", "offset": 5, "bit": 0}], "damaged"),
        ("flip-header", [{"op": "flip", "offset": 60, "bit": 3}], "damaged"),
        ("flip-piece-0", [{"op": "flip", "offset": sizes.PREFIX + 1000, "bit": 7}], "bad-signature"),
        ("flip-piece-1", [{"op": "flip", "offset": sizes.PREFIX + piece0 + 100, "bit": 1}], "bad-signature"),
        ("flip-signature", [{"op": "flip", "offset": len(data) - 10, "bit": 4}], "bad-signature"),
        ("cut-end", [{"op": "cut", "length": len(data) - 64}], "damaged"),
        ("remove-piece-1", [{"op": "remove", "offset": sizes.PREFIX + piece0, "length": piece1}], "damaged"),
        ("swap-pieces", [{"op": "swap", "offset": sizes.PREFIX, "first": piece0, "second": piece1}],
         "bad-signature"),
        ("append-byte", [{"op": "append", "bytes": "00"}], "damaged"),
    ]
    for case_id, ops, reason in mutations:
        cases.append({"id": case_id, "file": "bundle-two-pieces.sealed", "mutations": ops, **collector_reader,
                      "expect": "reject", "reason": reason})
    cases.append({"id": "over-the-limit", "file": "bundle-two-pieces.sealed", **collector_reader,
                  "max_sealed": sizes.MiB, "expect": "reject", "reason": "too-big"})
    cases.append({"id": "opened-with-retired-key", "file": "bundle-retired-key.sealed", **collector_reader,
                  "expect": "ok"})

    small = [(APP, "a1b2c3d4-000003", [("manifest.json", stream("manifest 3", 700))])]

    content, objects = bundle_content(small)
    data, header = seal_bytes("bundle-retired-key", 1, content, COLLECTOR_OPEN_RETIRED, SENDER_SIGN)
    files["bundle-retired-key.sealed"] = data
    cases[-1].update(size=len(data), sealed_sha256=hashlib.sha256(data).hexdigest(), header=header,
                     content_sha256=hashlib.sha256(content).hexdigest(),
                     deliveries=[{"app": d.app, "delivery": d.delivery, "digest": d.digest, "result": "stored"}
                                 for d in objects])

    # One bad delivery among good ones: only that one is rejected.
    three = [
        (APP, "a1b2c3d4-000004", [("manifest.json", stream("manifest 4", 900))]),
        (APP, "a1b2c3d4-000005", [("manifest.json", stream("manifest 5", 901)),
                                  ("data/x.json.gz", stream("x", 5000))]),
        (APP, "a1b2c3d4-000006", [("manifest.json", stream("manifest 6", 902))]),
    ]
    content, objects = bundle_content(three, lie={"data/x.json.gz": "0" * 64})
    data, header = seal_bytes("bundle-one-bad-delivery", 1, content, COLLECTOR_OPEN, SENDER_SIGN)
    add("bundle-one-bad-delivery.sealed", data, header, **collector_reader, expect="ok",
        content_sha256=hashlib.sha256(content).hexdigest(),
        deliveries=[{"app": d.app, "delivery": d.delivery, "digest": d.digest, **r} for d, r in zip(objects, [
            {"result": "stored"}, {"result": "rejected", "reason": "bad-file"}, {"result": "stored"}])])

    # Names that must never reach the disk, and a delivery without files.
    one = [("manifest.json", stream("manifest n", 300))]
    named = [
        ("../x", "n-000001", one), ("/x", "n-000002", one), ("a", "n-000003", one), ("a\nb.c", "n-000004", one),
        (APP, "CON", one), (APP, "n-000005.", one), (APP, "n-000006", [("../etc/passwd", b"x")]),
        (APP, "n-000007", [("a", b"1"), ("A/b", b"2")]), (APP, "n-000008", []),
        (APP, "n-000009", one),
    ]
    reasons = ["bad-name"] * 8 + ["no-files", None]
    content, objects = bundle_content(named)
    data, header = seal_bytes("bundle-bad-names", 1, content, COLLECTOR_OPEN, SENDER_SIGN)
    add("bundle-bad-names.sealed", data, header, **collector_reader, expect="ok",
        content_sha256=hashlib.sha256(content).hexdigest(),
        deliveries=[{"app": d.app, "delivery": d.delivery, "digest": d.digest,
                     **({"result": "rejected", "reason": r} if r else {"result": "stored"})}
                    for d, r in zip(objects, reasons)])

    # Whole-file rejections.
    content, _ = bundle_content(small + small)
    data, header = seal_bytes("bundle-same-delivery-twice", 1, content, COLLECTOR_OPEN, SENDER_SIGN)
    add("bundle-same-delivery-twice.sealed", data, header, **collector_reader, expect="reject",
        reason="bad-content")

    content, _ = bundle_content(small)
    with nonzero_padding():
        data, header = seal_bytes("bundle-nonzero-padding", 1, content, COLLECTOR_OPEN, SENDER_SIGN)
    add("bundle-nonzero-padding.sealed", data, header, **collector_reader, expect="reject", reason="damaged")

    # The header claims 300,000 bytes of content (a 512 KiB file), but the file was made for 256 KiB.
    real_padded = sealed._padded_pieces
    sealed._padded_pieces = lambda chunks, n, length: real_padded(chunks, len(content), 256 * sizes.KiB)
    try:
        data, header = seal_bytes("bundle-wrong-size", 1, content, COLLECTOR_OPEN, SENDER_SIGN, n=300_000)
    finally:
        sealed._padded_pieces = real_padded
    add("bundle-wrong-size.sealed", data, header, **collector_reader, expect="reject", reason="damaged")

    data, header = seal_bytes("bundle-unknown-sender", 1, content, COLLECTOR_OPEN, STRANGER_SIGN)
    add("bundle-unknown-sender.sealed", data, header, **collector_reader, expect="reject", reason="unknown-sender")

    data, header = seal_bytes("bundle-other-signature", 1, content, COLLECTOR_OPEN,
                              OtherKeyId(STRANGER_SIGN, SENDER_SIGN.key_id))
    add("bundle-other-signature.sealed", data, header, **collector_reader, expect="reject", reason="bad-signature")

    data, header = seal_bytes("bundle-for-another-collector", 1, content, STRANGER_OPEN, SENDER_SIGN)
    add("bundle-for-another-collector.sealed", data, header, **collector_reader, expect="reject", reason="damaged")

    # Sealed for the collector with the right header text, but of a kind the collector never reads.
    real_info = sealed.header_info
    sealed.header_info = lambda kind: sealed.INFO_TO_COLLECTOR
    try:
        # Big enough for 256 KiB, a size that's possible in up/ too.
        data, header = seal_bytes("bundle-kind-3", 3, manifests.content_prefix({"v": 1, "pad": "x" * 259_000}),
                                  COLLECTOR_OPEN, SENDER_SIGN)
    finally:
        sealed.header_info = real_info
    add("bundle-kind-3.sealed", data, header, **collector_reader, expect="reject", reason="damaged")

    # Pairing requests.
    offer = pairing_offer()
    pairing_id = encoding.unb64url(offer["pairing"])
    code = encoding.unb64url(offer["code"])
    for name, replaces in (("pair-request", None), ("pair-request-again", seed("old key id")),
                           ("pair-request-zero-replaces", bytes(32))):
        transcript = pairing.mac_transcript(pairing_id, pub(COLLECTOR_OPEN), COLLECTOR_SIGN.public,
                                            SENDER_SIGN.public, pub(SENDER_OPEN), replaces)
        manifest = manifests.pair_manifest(pairing_id, SENDER_SIGN.public, pub(SENDER_OPEN), "Phone", replaces,
                                           pairing.pair_mac(code, pairing_id, transcript))
        content = manifests.content_prefix(manifest)
        data, header = seal_bytes(name, 2, content, COLLECTOR_OPEN, SENDER_SIGN)
        add(f"{name}.sealed", data, header, **collector_reader, expect="ok", manifest=manifest,
            pair_check=None if replaces != bytes(32) else "replaces is all zeros",
            fingerprint=pairing.fingerprint(pairing_id, pub(COLLECTOR_OPEN), COLLECTOR_SIGN.public,
                                            SENDER_SIGN.public, pub(SENDER_OPEN)))

    # Receipts, read by the phone.
    first = next(c for c in cases if c["id"] == "bundle-two-pieces")
    receipt = receipts.receipt_manifest(
        SENDER_SIGN.key_id, CREATED + 734000,
        stored=[{"message": first["header"]["message_id"], "sealed_sha256": first["sealed_sha256"],
                 "received": CREATED + 635000,
                 "deliveries": [{**d, "seq": i + 1} for i, d in enumerate(first["deliveries"])]}],
        rejected=[{"name": "abcdefghijklmnopqrstuvwxyz234567", "size": 262376, "reason": "damaged",
                   "at": CREATED + 600000}],
        status={"collector": "1.0.0", "instance": seed("instance")[:16].hex(), "seq": 2,
                "last_pickup": CREATED + 635000, "last_backup": None, "free_bytes": 201234567890,
                "max_sealed": sizes.DEFAULT_MAX_SEALED, "warnings": [], "rejected_7d": 1, "rejected_more": 0,
                "vanished_7d": 0})
    content = manifests.content_prefix(receipt)
    data, header = seal_bytes("receipt", 3, content, SENDER_OPEN, COLLECTOR_SIGN)
    add("receipt.sealed", data, header, **phone_reader, expect="ok", manifest=receipt)

    paired = receipts.paired_manifest(SENDER_SIGN.key_id, pairing_id, CREATED + 60000)
    data, header = seal_bytes("paired-receipt", 3, manifests.content_prefix(paired), SENDER_OPEN, COLLECTOR_SIGN)
    add("paired-receipt.sealed", data, header, **phone_reader, expect="ok", manifest=paired)

    data, header = seal_bytes("receipt-signed-by-sender", 3, content, SENDER_OPEN,
                              OtherKeyId(SENDER_SIGN, COLLECTOR_SIGN.key_id))
    add("receipt-signed-by-sender.sealed", data, header, **phone_reader, expect="reject", reason="bad-signature")

    data, header = seal_bytes("receipt-for-another-phone", 3, content, STRANGER_OPEN, COLLECTOR_SIGN)
    add("receipt-for-another-phone.sealed", data, header, **phone_reader, expect="reject", reason="damaged")

    # Sealed for the phone, but with the header text for the other direction.
    real_info = sealed.header_info
    sealed.header_info = lambda kind: sealed.INFO_TO_COLLECTOR
    try:
        data, header = seal_bytes("receipt-wrong-direction", 3, content, SENDER_OPEN, COLLECTOR_SIGN)
    finally:
        sealed.header_info = real_info
    add("receipt-wrong-direction.sealed", data, header, **phone_reader, expect="reject", reason="damaged")

    cases.append({"id": "receipt-cut", "file": "receipt.sealed", "mutations": [{"op": "cut", "length": 4000}],
                  **phone_reader, "expect": "reject", "reason": "damaged"})
    cases.append({"id": "bundle-read-as-receipt", "file": "bundle-retired-key.sealed", **phone_reader,
                  "expect": "reject", "reason": "damaged"})
    return files, cases


def pairing_offer() -> dict:
    return {
        "sealdrop": 1,
        "type": "pair-offer",
        "pairing": b64url(seed("pairing")[:16]),
        "expires": CREATED + 600000,
        "storage": {
            "up": {"endpoint": "https://s3.example-region.storage.example", "region": "example-region",
                   "bucket": "example-inbox", "prefix": "up/",
                   "key": {"id": "EXAMPLE-UPLOAD-KEY-ID", "secret": "example-upload-secret-not-real"}},
            "ack": {"prefix": "ack/",
                    "key": {"id": "EXAMPLE-RECEIPTS-KEY-ID", "secret": "example-receipts-secret-not-real"}},
        },
        "collector_open": b64url(pub(COLLECTOR_OPEN)),
        "collector_sign": b64url(COLLECTOR_SIGN.public),
        "code": b64url(seed("one-time code")[:16]),
    }


# --- small vectors -------------------------------------------------------------------------------------------------

def json_rules() -> list[dict]:
    def case(case_id, text: bytes, valid: bool):
        return {"id": case_id, "bytes": b64url(text), "valid": valid}

    return [
        case("plain", b'{"v":1,"type":"receipt","list":[1,2,null,true,"x"]}', True),
        case("duplicate-name", b'{"a":1,"a":2}', False),
        case("fraction", b'{"a":1.0}', False),
        case("exponent", b'{"a":1e3}', False),
        case("negative", b'{"a":-1}', False),
        case("minus-zero", b'{"a":-0}', False),
        case("largest-integer", b'{"a":9007199254740991}', True),
        case("integer-too-big", b'{"a":9007199254740992}', False),
        case("nan", b'{"a":NaN}', False),
        case("infinity", b'{"a":Infinity}', False),
        case("lone-surrogate-escape", b'{"a":"\\ud800"}', False),
        case("surrogate-pair-escape", b'{"a":"\\ud83d\\ude00"}', True),
        case("encoded-surrogate", b'{"a":"\xed\xa0\x80"}', False),
        case("not-utf8", b'{"a":"\xff"}', False),
        case("byte-order-mark", b'\xef\xbb\xbf{"a":1}', False),
        case("depth-8", b'{"a":' * 7 + b"[]" + b"}" * 7, True),
        case("depth-9", b'{"a":' * 8 + b"[]" + b"}" * 8, False),
        case("trailing-comma", b'{"a":1,}', False),
        case("leading-zero", b'{"a":01}', False),
        case("text-after", b'{"a":1} x', False),
    ]


def base64url_cases() -> list[dict]:
    return [
        {"text": "", "valid": True, "hex": ""},
        {"text": "AA", "valid": True, "hex": "00"},
        {"text": "AAE", "valid": True, "hex": "0001"},
        {"text": "_-8", "valid": True, "hex": "ffef"},
        {"text": "AA==", "valid": False},
        {"text": "AB", "valid": False},
        {"text": "A", "valid": False},
        {"text": "AA+", "valid": False},
        {"text": "AA/", "valid": False},
        {"text": "AA A", "valid": False},
    ]


def signature_cases() -> dict:
    signer = SENDER_SIGN
    found_short = None
    for i in range(100_000):
        message = f"short r {i}".encode()
        raw = signer.sign(message)
        if raw[0] == 0:
            found_short = (message, raw)
            break
    message = b"sealdrop/v1/sig/sender\x00" + bytes(32)
    raw = signer.sign(message)
    r, s = raw[:32], int.from_bytes(raw[32:], "big")
    high = r + (keys.P256_N - s).to_bytes(32, "big")
    n = keys.P256_N.to_bytes(32, "big")
    p256_cases = [
        {"id": "low-s", "statement": message.hex(), "signature": raw.hex(), "valid": True},
        {"id": "high-s", "statement": message.hex(), "signature": high.hex(), "valid": True},
        {"id": "short-r", "statement": found_short[0].hex(), "signature": found_short[1].hex(), "valid": True},
        {"id": "r-zero", "statement": message.hex(), "signature": (bytes(32) + raw[32:]).hex(), "valid": False},
        {"id": "s-zero", "statement": message.hex(), "signature": (r + bytes(32)).hex(), "valid": False},
        {"id": "s-is-n", "statement": message.hex(), "signature": (r + n).hex(), "valid": False},
        {"id": "r-is-n", "statement": message.hex(), "signature": (n + raw[32:]).hex(), "valid": False},
        {"id": "other-statement", "statement": (message + b"x").hex(), "signature": raw.hex(), "valid": False},
    ]
    ed_message = b"sealdrop/v1/sig/collector\x00" + bytes(32)
    ed_raw = COLLECTOR_SIGN.sign(ed_message)
    ed_flipped = bytes([ed_raw[0] ^ 1]) + ed_raw[1:]
    return {
        "p256": {"public": b64url(signer.public), "cases": p256_cases},
        "ed25519": {"public": b64url(COLLECTOR_SIGN.public), "cases": [
            {"id": "good", "statement": ed_message.hex(), "signature": ed_raw.hex(), "valid": True},
            {"id": "flipped", "statement": ed_message.hex(), "signature": ed_flipped.hex(), "valid": False},
        ]},
    }


def hkdf_cases() -> list[dict]:
    return [  # RFC 5869, appendix A.1 to A.3
        {"ikm": "0b" * 22, "salt": "000102030405060708090a0b0c", "info": "f0f1f2f3f4f5f6f7f8f9", "length": 42,
         "okm": "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
        {"ikm": bytes(range(0x00, 0x50)).hex(), "salt": bytes(range(0x60, 0xb0)).hex(),
         "info": bytes(range(0xb0, 0x100)).hex(), "length": 82,
         "okm": "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09"
                "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"},
        {"ikm": "0b" * 22, "salt": "", "info": "", "length": 42,
         "okm": "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"},
    ]


def hpke_case() -> dict:
    return {  # RFC 9180, appendix A.2.1 (base mode), first encryption
        "info": "4f6465206f6e2061204772656369616e2055726e",
        "ikmE": "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
        "skEm": "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
        "pkEm": "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        "ikmR": "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
        "skRm": "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        "pkRm": "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        "enc": "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        "shared_secret": "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
        "key_schedule_context": "00431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5b69c5718a60cc5876c"
                                "358d3f7fc31ddb598503f67be58ea1e798c0bb19eb9796",
        "secret": "5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6",
        "key": "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
        "base_nonce": "5c4d98150661b848853b547f",
        "exporter_secret": "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922",
        "encryptions": [
            {"seq": 0, "aad": "436f756e742d30", "ct": "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db"
                                                       "21993c62ce81883d2dd1b51a28"},
            {"seq": 1, "aad": "436f756e742d31", "ct": "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e"
                                                       "85285337cc95ba5f59992dc98c"},
            {"seq": 255, "aad": "436f756e742d323535",
             "ct": "18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c"},
        ],
        "pt": "4265617574792069732074727574682c20747275746820626561757479",
        "exports": [
            {"context": "", "length": 32, "value": "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e"},
            {"context": "00", "length": 32,
             "value": "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69"},
        ],
    }


def size_cases() -> dict:
    examples = []
    for kind, n in ((1, 300_000), (1, 4), (1, 262_144), (1, 262_145), (1, 4 * sizes.MiB), (1, 4 * sizes.MiB + 1),
                    (1, 8 * sizes.MiB), (1, 8 * sizes.MiB + 1), (2, 900), (3, 900), (3, 4096), (3, 4097),
                    (3, sizes.SMALL_MAX)):
        length = sizes.padded_length(kind, n)
        examples.append({"kind": kind, "n": n, "length": length, "pieces": sizes.pieces(length),
                         "size": sizes.sealed_size(length)})
    return {
        "examples": examples,
        "up_sizes": len(sizes.possible_lengths("up")),
        "ack_sizes": len(sizes.possible_lengths("ack")),
        "max_delivery_bytes": sizes.max_delivery_bytes(),
        "max_delivery_bytes_at_1_gib": sizes.max_delivery_bytes(sizes.GiB),
        "impossible_up_sizes": [262_375, 262_377, 524_519, 1_048_808 + 1, 4 * sizes.GiB],
    }


def name_cases() -> dict:
    return {
        "app": {"good": ["org.example.tracker", "a.b", "A_1.b2"],
                "bad": ["", "a", ".a", "a.", "a..b", "1a.b", "a.1b", "a-b.c", "../x", "/x", "a\nb.c", "a." * 60 + "a"]},
        "delivery": {"good": ["a1b2c3d4-000042", "8c41d2e0-5b7a-4f0e-9d33-0a6c2f8e71b4-000042", "X", "a.b_c-d"],
                     "bad": ["", "-a", ".a", "a.", "CON", "con.txt", "Lpt9", "a/b", "a b", "x" * 101]},
        "path": {"good": ["manifest.json", "data/2026-09-13.json.gz", "/".join(["p"] * 8), "conx/a", "COM10"],
                 "bad": ["", "/a", "a/", "a//b", "../a", "a/../b", ".hidden", "a/.b", "a.", "nul", "NUL.txt",
                         "/".join(["p"] * 9), "a" * 129, "/".join(["a" * 127] * 2) + "/x", "a\\b", "ä"]},
        "clashes": [
            {"paths": ["a", "b"], "clash": False},
            {"paths": ["a", "A"], "clash": True},
            {"paths": ["a", "a/b"], "clash": True},
            {"paths": ["A", "a/b"], "clash": True},
            {"paths": ["a.b", "a/b"], "clash": False},
            {"paths": ["a", "a.x", "a/b"], "clash": True},
            {"paths": ["A", "a-b", "a/b/c"], "clash": True},
            {"paths": ["a-b", "a/b"], "clash": False},
        ],
        "labels": {"good": ["Phone", "Sam's phone 2", "📱 x" , "x" * 40],
                   "bad": ["", "x" * 41, "a\nb", "a​b", "a b", "a b", "‮abc"]},
    }


def pairing_cases() -> dict:
    offer = pairing_offer()
    p = encoding.unb64url(offer["pairing"])
    code = encoding.unb64url(offer["code"])
    out = []
    for replaces in (None, seed("old key id")):
        transcript = pairing.mac_transcript(p, pub(COLLECTOR_OPEN), COLLECTOR_SIGN.public, SENDER_SIGN.public,
                                            pub(SENDER_OPEN), replaces)
        out.append({"replaces": None if replaces is None else replaces.hex(), "transcript": transcript.hex(),
                    "mac": pairing.pair_mac(code, p, transcript).hex()})
    return {
        "offer": offer,
        "offer_text_bytes": len(encoding.dumps(offer)),
        "macs": out,
        "fingerprint": pairing.fingerprint(p, pub(COLLECTOR_OPEN), COLLECTOR_SIGN.public, SENDER_SIGN.public,
                                           pub(SENDER_OPEN)),
    }


def offer_cases() -> list[dict]:
    base = pairing_offer()

    def variant(case_id, valid, up=None, ack=None):
        offer = json.loads(json.dumps(base))
        offer["storage"]["up"].update(up or {})
        offer["storage"]["ack"].update(ack or {})
        offer["storage"]["up"] = {k: v for k, v in offer["storage"]["up"].items() if v is not None}
        offer["storage"]["ack"] = {k: v for k, v in offer["storage"]["ack"].items() if v is not None}
        return {"id": case_id, "valid": valid, "offer": offer}

    return [
        variant("as-is", True),
        variant("two-buckets", True, up={"prefix": ""}, ack={"bucket": "example-receipts", "prefix": ""}),
        variant("port", True, up={"endpoint": "https://storage.example:9000"}),
        variant("same-bucket-empty-prefix", False, up={"prefix": ""}),
        variant("prefixes-overlap", False, up={"prefix": "in/"}, ack={"prefix": "in/ack/"}),
        variant("same-prefix", False, ack={"prefix": "up/"}),
        variant("http", False, up={"endpoint": "http://s3.example-region.storage.example"}),
        variant("endpoint-path", False, up={"endpoint": "https://storage.example/x"}),
        variant("endpoint-slash", False, up={"endpoint": "https://storage.example/"}),
        variant("endpoint-capitals", False, up={"endpoint": "https://Storage.example"}),
        variant("bucket-capitals", False, up={"bucket": "Example-inbox"}),
        variant("bucket-short", False, up={"bucket": "ab"}),
        variant("prefix-no-slash", False, up={"prefix": "up"}),
        variant("prefix-capitals", False, up={"prefix": "Up/"}),
        variant("region-bad", False, up={"region": "eu central"}),
        variant("key-space", False, up={"key": {"id": "a b", "secret": "x"}}),
        variant("up-without-bucket", False, up={"bucket": None}),
        variant("port-zero", False, up={"endpoint": "https://storage.example:0"}),
        variant("port-too-big", False, up={"endpoint": "https://storage.example:65536"}),
        variant("port-other-digits", False, up={"endpoint": "https://storage.example:٨٠"}),
        {**variant("sealdrop-true", False), "offer": {**base, "sealdrop": True}},
        {"id": "ack-bucket-null", "valid": False, "offer": {**base, "storage": {
            **base["storage"], "ack": {**base["storage"]["ack"], "bucket": None}}}},
    ]


def manifest_cases() -> dict:
    """Manifests checked on their own, without sealing (§5, §6, §7). `text` is the manifest (base64url); for a
    bundle, `n` is the content length its header would give. Every expectation is checked here against the Python
    code while the vectors are made."""
    sha = hashlib.sha256(b"x").hexdigest()

    def files(*paths, size=1, checksum=sha):
        return [{"path": p, "size": size, "sha256": checksum} for p in paths]

    def delivery(delivery_id="d-000001", fs=None, app=APP, **extra):
        return {"app": app, "delivery": delivery_id, "created": CREATED,
                "files": files("manifest.json") if fs is None else fs, **extra}

    bundles = []

    def bundle(case_id, deliveries, problems=None, v=1, n_offset=0, **extra):
        raw = encoding.dumps({"v": v, "type": "bundle", "deliveries": deliveries, **extra})
        sizes_given = [f["size"] for d in deliveries for f in d["files"] if encoding.is_int(f["size"])]
        n = 4 + len(raw) + sum(sizes_given) + n_offset
        try:
            got = [d.problem for d in manifests.check_bundle(encoding.loads(raw), n, len(raw))]
        except errors.Rejected as e:
            got = e.reason
        expected = "bad-content" if problems is None else problems
        assert got == expected, (case_id, got)
        bundles.append({"id": case_id, "text": b64url(raw), "n": n,
                        **({"reject": "bad-content"} if problems is None else {"problems": problems})})

    bundle("good", [delivery()], [None])
    bundle("unknown-fields", [delivery(note="x")], [None], extra_field=[1, 2])
    bundle("several", [delivery("d-1"), delivery("d-2", files("a", "A/b")), delivery("d-3", [])],
           [None, "bad-name", "no-files"])
    bundle("v-true", [delivery()], v=True)
    bundle("v-two", [delivery()], v=2)
    bundle("created-true", [{**delivery(), "created": True}])
    bundle("size-false", [delivery(fs=files("a", size=False))])
    bundle("sizes-dont-add-up", [delivery()], n_offset=1)
    bundle("no-deliveries", [])
    bundle("same-delivery-twice", [delivery(), delivery()])
    bundle("delivery-101-characters", [delivery("x" * 101)])
    bundle("app-101-characters", [delivery(app="a." * 50 + "a")])
    # 60 characters, but 120 UTF-16 units: within the 100 characters, so only this delivery is rejected.
    bundle("delivery-60-emoji", [delivery("\U0001F4F1" * 60)], ["bad-name"])
    bundle("file-and-folder-with-a-sibling", [delivery(fs=files("a", "a.x", "a/b"))], ["bad-name"])
    bundle("file-and-folder-in-other-case", [delivery(fs=files("A", "a-b", "a/b"))], ["bad-name"])
    bundle("no-clash", [delivery(fs=files("a-b", "a/b"))], [None])
    bundle("checksum-in-capitals", [delivery(fs=files("a", checksum=sha.upper()))], ["bad-file"])

    offer = pairing_offer()
    pairing_id, code = encoding.unb64url(offer["pairing"]), encoding.unb64url(offer["code"])
    transcript = pairing.mac_transcript(pairing_id, pub(COLLECTOR_OPEN), COLLECTOR_SIGN.public, SENDER_SIGN.public,
                                        pub(SENDER_OPEN), None)
    good_pair = manifests.pair_manifest(pairing_id, SENDER_SIGN.public, pub(SENDER_OPEN), "Phone", None,
                                        pairing.pair_mac(code, pairing_id, transcript))
    pairs = []

    def pair(case_id, manifest, check="invalid"):
        raw = encoding.dumps(manifest)
        try:
            got = manifests.check_pair_names(manifests.parse_pair(encoding.loads(raw)))
        except errors.Rejected:
            got = "invalid"
        assert got == check, (case_id, got)
        pairs.append({"id": case_id, "text": b64url(raw), "valid": check != "invalid",
                      **({"check": check} if check != "invalid" else {})})

    pair("good", good_pair, None)
    pair("unknown-field", {**good_pair, "note": "x"}, None)
    pair("label-with-a-line-break", {**good_pair, "label": "a\nb"}, "label not allowed")
    pair("v-true", {**good_pair, "v": True})
    pair("label-a-number", {**good_pair, "label": 1})
    pair("replaces-in-capitals", {**good_pair, "replaces": seed("old key id").hex().upper()})
    pair("mac-padded", {**good_pair, "mac": good_pair["mac"] + "="})
    pair("replaces-null", {**good_pair, "replaces": None})

    own = SENDER_SIGN.key_id
    good_receipt = receipts.receipt_manifest(
        own, CREATED + 734000,
        stored=[{"message": seed("m")[:16].hex(), "sealed_sha256": seed("s").hex(), "received": CREATED,
                 "deliveries": [{"app": APP, "delivery": "d-1", "digest": seed("d").hex(), "result": "stored",
                                 "seq": 1}]}],
        rejected=[], status={"collector": "1.0.0", "instance": seed("instance")[:16].hex(), "seq": 1,
                             "last_pickup": CREATED, "last_backup": None, "free_bytes": 1, "max_sealed": 2**32,
                             "warnings": [], "rejected_7d": 0, "rejected_more": 0, "vanished_7d": 0})
    good_paired = receipts.paired_manifest(own, pairing_id, CREATED)
    receipt_list = []

    def receipt(case_id, manifest, valid=False):
        raw = encoding.dumps(manifest)
        try:
            receipts.check_receipt(encoding.loads(raw), [own])
            got = True
        except FormatError:
            got = False
        assert got == valid, (case_id, got)
        receipt_list.append({"id": case_id, "text": b64url(raw), "valid": valid})

    receipt("receipt", good_receipt, True)
    receipt("paired", good_paired, True)
    receipt("v-true", {**good_receipt, "v": True})
    receipt("time-true", {**good_paired, "time": True})
    receipt("for-another-phone", {**good_receipt, "for": STRANGER_SIGN.key_id.hex()})
    receipt("for-in-capitals", {**good_receipt, "for": own.hex().upper()})
    receipt("type-other", {**good_receipt, "type": "bundle"})
    receipt("result-unknown", {**good_receipt, "stored": [
        {**good_receipt["stored"][0], "deliveries": [{**good_receipt["stored"][0]["deliveries"][0], "result": "ok"}]}]})
    return {"own_key_id": own.hex(), "bundles": bundles, "pairs": pairs, "receipts": receipt_list}


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "files").mkdir(exist_ok=True)
    with fixed_hpke():
        files, cases = make_files()
    for name, data in files.items():
        (out_dir / "files" / name).write_bytes(data)

    def write_json(name, value):
        (out_dir / name).write_text(json.dumps(value, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    write_json("keys.json", keys_json())
    write_json("cases.json", {"note": NOTE, "cases": cases})
    write_json("vectors.json", {
        "note": NOTE, "json": json_rules(), "base64url": base64url_cases(), "signatures": signature_cases(),
        "hkdf": hkdf_cases(), "hpke": hpke_case(), "sizes": size_cases(), "names": name_cases(),
        "pairing": pairing_cases(), "offers": offer_cases(), "manifests": manifest_cases(),
    })


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else HERE)
