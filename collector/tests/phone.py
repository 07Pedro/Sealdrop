"""A phone in Python, for the collector's tests: it pairs, seals bundles and reads receipts the way PROTOCOL.md says
Sealdrop does. The real phone is the Android app; this one only has to be right about the files it makes."""

from __future__ import annotations

import hashlib
import io
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from sealdrop import encoding, keys, manifests, pairing, s3
from sealdrop.manifests import Delivery, FileEntry
from sealdrop.reading import open_receipt
from sealdrop.run import random_name
from sealdrop.sealed import seal
from sealdrop.sizes import KIND_BUNDLE, KIND_PAIR


class Phone:
    def __init__(self, transport, offer: dict, label: str = "Phone", clock=None):
        up, ack = pairing.resolve_storage(offer["storage"])
        self.up, self.ack = up, ack
        self.offer = offer
        self.uploader = s3.Client(up["endpoint"], up["region"], s3.Credentials(up["key"]["id"], up["key"]["secret"]),
                                  context=object(), transport=transport, **({"clock": clock} if clock else {}))
        self.reader = s3.Client(ack["endpoint"], ack["region"],
                                s3.Credentials(ack["key"]["id"], ack["key"]["secret"]), context=object(),
                                transport=transport, **({"clock": clock} if clock else {}))
        self.signer = keys.P256Signer(ec.generate_private_key(ec.SECP256R1()))
        self.opening = X25519PrivateKey.generate()
        self.label = label
        self.collector_open = encoding.unb64url(offer["collector_open"], 32)
        self.collector_sign = encoding.unb64url(offer["collector_sign"], 32)
        self.seen: set[str] = set()

    @property
    def key_id(self) -> bytes:
        return self.signer.key_id

    def fingerprint(self) -> str:
        return pairing.fingerprint(encoding.unb64url(self.offer["pairing"], 16), self.collector_open,
                                   self.collector_sign, self.signer.public, self._open_public())

    def _open_public(self) -> bytes:
        return keys.x25519_public_bytes(self.opening.public_key())

    def pair_request(self, *, code: bytes | None = None, replaces: bytes | None = None, label: str | None = None
                     ) -> bytes:
        pairing_id = encoding.unb64url(self.offer["pairing"], 16)
        transcript = pairing.mac_transcript(pairing_id, self.collector_open, self.collector_sign, self.signer.public,
                                            self._open_public(), replaces)
        mac = pairing.pair_mac(code or encoding.unb64url(self.offer["code"], 16), pairing_id, transcript)
        manifest = manifests.pair_manifest(pairing_id, self.signer.public, self._open_public(),
                                           label or self.label, replaces, mac)
        content = manifests.content_prefix(manifest)
        out = io.BytesIO()
        seal(out, KIND_PAIR, [content], len(content), X25519PublicKey.from_public_bytes(self.collector_open),
             self.signer, 1_790_000_000_000)
        return out.getvalue()

    def put(self, data: bytes, name: str | None = None) -> str:
        name = name or self.up["prefix"] + random_name()
        self.uploader.put_object(self.up["bucket"], name, data)
        return name

    def bundle(self, deliveries: list[tuple[str, str, dict[str, bytes]]], *, signer=None) -> tuple[bytes, list]:
        """A sealed bundle of (app, delivery ID, {path: bytes}); also gives the deliveries' digests."""
        items = []
        for app, delivery, files in deliveries:
            entries = [FileEntry(p, len(b), hashlib.sha256(b).hexdigest()) for p, b in files.items()]
            items.append(Delivery(app, delivery, 1_790_000_000_000, entries))
        manifest = manifests.bundle_manifest(items)
        prefix = manifests.content_prefix(manifest)
        body = b"".join(b for _, _, files in deliveries for b in files.values())
        out = io.BytesIO()
        seal(out, KIND_BUNDLE, [prefix, body], len(prefix) + len(body),
             X25519PublicKey.from_public_bytes(self.collector_open), signer or self.signer, 1_790_000_000_000)
        return out.getvalue(), [d.digest for d in items]

    def send(self, deliveries, **kw) -> tuple[str, str, list]:
        """Seal and upload: the name, the sealed SHA-256 and the digests."""
        data, digests = self.bundle(deliveries, **kw)
        return self.put(data), hashlib.sha256(data).hexdigest(), digests

    def receipts(self) -> list[dict]:
        """New receipts that open and pass, as manifests; the rest are remembered and skipped, like the phone."""
        found = []
        listed, token = [], None
        while True:
            page, token = self.reader.list_objects(self.ack["bucket"], self.ack["prefix"], token)
            listed += page
            if token is None:
                break
        for entry in listed:
            if entry.name in self.seen:
                continue
            self.seen.add(entry.name)
            data = self.reader.get_object(self.ack["bucket"], entry.name).body
            try:
                _, manifest = open_receipt(data, [self.opening], keys.Ed25519Verifier(self.collector_sign),
                                           keys.key_id(self.collector_sign))
            except Exception:
                continue
            if manifest.get("for") == self.key_id.hex():
                found.append(manifest)
        return found


def offer_for_tests(root, b2_keys: dict, now: int) -> dict:
    """The offer the `pair` command would show, made directly (the tests that don't test pairing itself)."""
    from sealdrop.pair import make_offer
    return make_offer(root, (b2_keys["phone-upload"].id, b2_keys["phone-upload"].secret),
                      (b2_keys["phone-receipts"].id, b2_keys["phone-receipts"].secret), now, os.urandom(16))
