"""A small RFC 9180 key schedule, for tests only (PROTOCOL.md §13).

Python's HPKE can't run RFC 9180's test vector: it has no `aad`, seals only the first message, and won't take a
fixed one-time key. This module does exactly the base mode of DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
ChaCha20-Poly1305, built on pyca's primitives, so the test vector can be checked and compared with pyca's HPKE.
Sealdrop itself never uses it.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0003
KEM_SUITE = b"KEM" + KEM_ID.to_bytes(2, "big")
HPKE_SUITE = b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big") + AEAD_ID.to_bytes(2, "big")
N_SECRET, N_K, N_N, N_H = 32, 32, 12, 32


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or bytes(N_H), ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return _expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, length)


def _raw(public: X25519PublicKey) -> bytes:
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive_key_pair(ikm: bytes) -> X25519PrivateKey:
    prk = labeled_extract(KEM_SUITE, b"", b"dkp_prk", ikm)
    return X25519PrivateKey.from_private_bytes(labeled_expand(KEM_SUITE, prk, b"sk", b"", 32))


def _shared_secret(dh: bytes, enc: bytes, pk_r: bytes) -> bytes:
    prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    return labeled_expand(KEM_SUITE, prk, b"shared_secret", enc + pk_r, N_SECRET)


def encap(pk_r: X25519PublicKey, sk_e: X25519PrivateKey) -> tuple[bytes, bytes]:
    enc = _raw(sk_e.public_key())
    return _shared_secret(sk_e.exchange(pk_r), enc, _raw(pk_r)), enc


def decap(enc: bytes, sk_r: X25519PrivateKey) -> bytes:
    dh = sk_r.exchange(X25519PublicKey.from_public_bytes(enc))
    return _shared_secret(dh, enc, _raw(sk_r.public_key()))


class Context:
    def __init__(self, shared_secret: bytes, info: bytes):
        psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
        info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
        self.key_schedule_context = b"\x00" + psk_id_hash + info_hash
        self.secret = labeled_extract(HPKE_SUITE, shared_secret, b"secret", b"")
        self.key = labeled_expand(HPKE_SUITE, self.secret, b"key", self.key_schedule_context, N_K)
        self.base_nonce = labeled_expand(HPKE_SUITE, self.secret, b"base_nonce", self.key_schedule_context, N_N)
        self.exporter_secret = labeled_expand(HPKE_SUITE, self.secret, b"exp", self.key_schedule_context, N_H)
        self._aead = ChaCha20Poly1305(self.key)

    def nonce(self, seq: int) -> bytes:
        return bytes(a ^ b for a, b in zip(self.base_nonce, seq.to_bytes(N_N, "big")))

    def seal(self, seq: int, aad: bytes, plaintext: bytes) -> bytes:
        return self._aead.encrypt(self.nonce(seq), plaintext, aad)

    def open(self, seq: int, aad: bytes, ciphertext: bytes) -> bytes:
        return self._aead.decrypt(self.nonce(seq), ciphertext, aad)

    def export(self, context: bytes, length: int) -> bytes:
        return labeled_expand(HPKE_SUITE, self.exporter_secret, b"sec", context, length)


def single_shot_seal(pk_r: X25519PublicKey, info: bytes, plaintext: bytes,
                     sk_e: X25519PrivateKey | None = None) -> bytes:
    """enc ‖ ciphertext, like pyca's Suite.encrypt (empty aad, the first message)."""
    shared, enc = encap(pk_r, sk_e or X25519PrivateKey.generate())
    return enc + Context(shared, info).seal(0, b"", plaintext)


def single_shot_open(sk_r: X25519PrivateKey, info: bytes, sealed: bytes) -> bytes:
    enc, ciphertext = sealed[:32], sealed[32:]
    return Context(decap(enc, sk_r), info).open(0, b"", ciphertext)
