"""Sealing and opening with fresh keys: every kind, piece boundaries, large content, and the order of checks."""

import hashlib
import io
import os
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import helpers  # noqa: F401  (sets the import path)
from sealdrop import errors, keys, manifests, reading, receipts, sealed, sizes
from sealdrop.errors import Rejected
from sealdrop.manifests import Delivery, FileEntry

MiB = sizes.MiB


class Keys:
    def __init__(self):
        self.collector_open = X25519PrivateKey.generate()
        self.collector_sign = keys.Ed25519Signer(Ed25519PrivateKey.generate())
        self.sender_sign = keys.P256Signer(ec.generate_private_key(ec.SECP256R1()))
        self.sender_open = X25519PrivateKey.generate()
        self.senders = {self.sender_sign.key_id: keys.P256Verifier(self.sender_sign.public)}


def bundle(deliveries):
    objects, blobs = [], []
    for app, delivery, files in deliveries:
        objects.append(Delivery(app, delivery, 1, [FileEntry(p, len(d), hashlib.sha256(d).hexdigest())
                                                   for p, d in files]))
        blobs += [d for _, d in files]
    return manifests.content_prefix(manifests.bundle_manifest(objects)) + b"".join(blobs)


def seal_bytes(k: Keys, kind: int, content: bytes, reader=None, signer=None) -> bytes:
    out = io.BytesIO()
    reader = reader or (k.sender_open if kind == 3 else k.collector_open)
    signer = signer or (k.collector_sign if kind == 3 else k.sender_sign)
    result = sealed.seal(out, kind, [content], len(content), reader.public_key(), signer, 1789285265000)
    data = out.getvalue()
    assert result.size == len(data) and result.sha256 == hashlib.sha256(data).hexdigest()
    return data


class RoundTrip(unittest.TestCase):
    def setUp(self):
        self.k = Keys()

    def open_bundle(self, data: bytes, max_sealed=sizes.DEFAULT_MAX_SEALED):
        f = io.BytesIO(data)
        s = reading.open_upload(f, len(data), [self.k.collector_open], self.k.senders, max_sealed)
        return s, reading.check_deliveries(s)

    def test_piece_boundaries(self):
        for n in (4 + 30, 256 * 1024, MiB - 1, MiB, MiB + 1, 2 * MiB, 4 * MiB, 4 * MiB + 1, 9 * MiB + 7):
            with self.subTest(n=n):
                data = os.urandom(n - 4 - 2) if n > 6 else b""
                content = (2).to_bytes(4, "big") + b"{}" + data
                sealed_bytes = seal_bytes(self.k, 1, content[:n])
                s = sealed.SealedFile(io.BytesIO(sealed_bytes), len(sealed_bytes))
                header = s.open_header([self.k.collector_open], sealed.INFO_TO_COLLECTOR, (1,))
                self.assertEqual(header.n, n)
                self.assertEqual(len(sealed_bytes), sizes.sealed_size(sizes.padded_length(1, n)))
                s.verify(self.k.senders[self.k.sender_sign.key_id])
                self.assertEqual(s.read_content(), content[:n])

    def test_bundle_streams_from_disk(self):
        big = os.urandom(3 * MiB + 12345)
        content = bundle([("org.example.app", "d-1", [("manifest.json", b"{}"), ("big.bin", big)]),
                          ("org.example.app", "d-2", [("a/b.txt", b"hello")])])
        with tempfile.TemporaryFile() as f:
            r = sealed.seal(f, 1, (content[i:i + 100_000] for i in range(0, len(content), 100_000)),
                            len(content), self.k.collector_open.public_key(), self.k.sender_sign, 1)
            f.flush()
            s = reading.open_upload(f, r.size, [self.k.collector_open], self.k.senders)
            got = {}
            verdicts = reading.check_deliveries(
                s, lambda d, e: (lambda data, key=(d.delivery, e.path): got.setdefault(key, bytearray()).extend(data)))
        self.assertEqual([v.ok for v in verdicts], [True, True])
        self.assertEqual(bytes(got[("d-1", "big.bin")]), big)
        self.assertEqual(bytes(got[("d-2", "a/b.txt")]), b"hello")

    def test_rejected_delivery_never_reaches_the_sink(self):
        content = bundle([("../evil", "d-1", [("x", b"secret")]), ("org.example.app", "d-2", [("y", b"ok")])])
        data = seal_bytes(self.k, 1, content)
        s = reading.open_upload(io.BytesIO(data), len(data), [self.k.collector_open], self.k.senders)
        asked = []
        verdicts = reading.check_deliveries(s, lambda d, e: asked.append(d.app) or (lambda b: None))
        self.assertEqual([(v.ok, v.reason) for v in verdicts], [(False, "bad-name"), (True, None)])
        self.assertEqual(asked, ["org.example.app"])

    def test_receipt_round_trip(self):
        manifest = receipts.receipt_manifest(self.k.sender_sign.key_id, 5, [], [], {"seq": 0})
        data = seal_bytes(self.k, 3, manifests.content_prefix(manifest))
        self.assertEqual(len(data), 4328)
        header, got = reading.open_receipt(data, [self.k.sender_open],
                                           keys.Ed25519Verifier(self.k.collector_sign.public),
                                           self.k.collector_sign.key_id)
        self.assertEqual(got, manifest)
        receipts.check_receipt(got, [self.k.sender_sign.key_id])

    def test_a_sender_signature_never_passes_as_the_collectors(self):
        # Same key type aside: the statement texts differ, so a phone's signature over a receipt can't verify.
        content = manifests.content_prefix({"v": 1})
        data = seal_bytes(self.k, 3, content)
        s = sealed.SealedFile(io.BytesIO(data), len(data))
        s.open_header([self.k.sender_open], sealed.INFO_TO_SENDER, (3,))
        digest = s.digest_before_signature()
        self.assertNotEqual(sealed.statement(1, digest), sealed.statement(3, digest))

    def test_order_of_checks(self):
        content = bundle([("org.example.app", "d-1", [("x", b"1")])])
        data = seal_bytes(self.k, 1, content)
        stranger = keys.P256Signer(ec.generate_private_key(ec.SECP256R1()))
        for label, blob, reason in (
            ("impossible size", data[:-1], errors.DAMAGED),
            ("other collector", seal_bytes(self.k, 1, content, reader=X25519PrivateKey.generate()), errors.DAMAGED),
            ("unknown sender", seal_bytes(self.k, 1, content, signer=stranger), errors.UNKNOWN_SENDER),
            ("bad signature", data[:-1] + bytes([data[-1] ^ 1]), errors.BAD_SIGNATURE),
        ):
            with self.subTest(label), self.assertRaises(Rejected) as e:
                self.open_bundle(blob)
            self.assertEqual(e.exception.reason, reason)

    def test_pairing_request_is_unknown_sender_in_a_regular_run(self):
        data = seal_bytes(self.k, 2, manifests.content_prefix({"v": 1, "type": "pair"}))
        with self.assertRaises(Rejected) as e:
            self.open_bundle(data)
        self.assertEqual(e.exception.reason, errors.UNKNOWN_SENDER)

    def test_content_must_match_n(self):
        with self.assertRaises(ValueError):
            sealed.seal(io.BytesIO(), 1, [b"abc"], 4, self.k.collector_open.public_key(), self.k.sender_sign, 1)
        with self.assertRaises(ValueError):
            sealed.seal(io.BytesIO(), 1, [b"abcde"], 4, self.k.collector_open.public_key(), self.k.sender_sign, 1)


if __name__ == "__main__":
    unittest.main()
