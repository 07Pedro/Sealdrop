"""Signing keys, their encodings and key IDs (PROTOCOL.md §2, §3)."""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

# The order of the P-256 group.
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

_RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def key_id(public_encoding: bytes) -> bytes:
    """SHA-256 of a public signing key in its encoding (raw 32 bytes, or the 65-byte SEC1 point)."""
    return hashlib.sha256(public_encoding).digest()


def x25519_public_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(*_RAW)


def x25519_private_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


# --- the collector: Ed25519 -------------------------------------------------------------------------------------

class Ed25519Signer:
    def __init__(self, private: Ed25519PrivateKey):
        self._private = private
        self.public = private.public_key().public_bytes(*_RAW)
        self.key_id = key_id(self.public)

    def sign(self, statement: bytes) -> bytes:
        return self._private.sign(statement)


class Ed25519Verifier:
    def __init__(self, public: bytes):
        if len(public) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        self._public = Ed25519PublicKey.from_public_bytes(public)
        self.key_id = key_id(public)

    def verify(self, signature: bytes, statement: bytes) -> bool:
        if len(signature) != 64:
            return False
        try:
            self._public.verify(signature, statement)
            return True
        except InvalidSignature:
            return False


# --- the phone: ECDSA P-256 with SHA-256, written as r ‖ s -------------------------------------------------------

def p256_point(public: ec.EllipticCurvePublicKey) -> bytes:
    return public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def p256_public(point: bytes) -> ec.EllipticCurvePublicKey:
    """Load a 65-byte uncompressed point; ValueError if it isn't one on the curve."""
    if len(point) != 65 or point[0] != 0x04:
        raise ValueError("P-256 key must be an uncompressed 65-byte point")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


def der_to_raw(der: bytes, low_s: bool = True) -> bytes:
    r, s = decode_dss_signature(der)
    if low_s and s > P256_N // 2:
        s = P256_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_to_der(raw: bytes) -> bytes | None:
    """DER for a 64-byte r ‖ s, or None if r or s is 0 or not below n."""
    if len(raw) != 64:
        return None
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    if not (0 < r < P256_N and 0 < s < P256_N):
        return None
    return encode_dss_signature(r, s)


class P256Signer:
    """A phone's signing key. In Sealdrop it lives in the Keystore; here only for tests and test files."""

    def __init__(self, private: ec.EllipticCurvePrivateKey):
        self._private = private
        self.public = p256_point(private.public_key())
        self.key_id = key_id(self.public)

    def sign(self, statement: bytes) -> bytes:
        return der_to_raw(self._private.sign(statement, ec.ECDSA(hashes.SHA256())))


class P256Verifier:
    def __init__(self, point: bytes):
        self._public = p256_public(point)
        self.key_id = key_id(point)

    def verify(self, signature: bytes, statement: bytes) -> bool:
        der = raw_to_der(signature)
        if der is None:
            return False
        try:
            self._public.verify(der, statement, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
