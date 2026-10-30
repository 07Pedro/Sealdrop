"""§3's text rules, HKDF, HPKE (RFC 9180), signatures, sizes and names, against testvectors/vectors.json."""

import unittest

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from helpers import VECTOR
from sealdrop import encoding, hkdf, keys, manifests, sizes
from sealdrop.errors import FormatError

import rfc9180_test_only as rfc9180


class TextRules(unittest.TestCase):
    def test_json(self):
        for case in VECTOR["json"]:
            with self.subTest(case["id"]):
                data = encoding.unb64url(case["bytes"])
                if case["valid"]:
                    encoding.loads(data)
                else:
                    with self.assertRaises(FormatError):
                        encoding.loads(data)

    def test_deep_nesting_is_refused_not_crashing(self):
        with self.assertRaises(FormatError):
            encoding.loads(b"[" * 100_000 + b"]" * 100_000)

    def test_base64url(self):
        for case in VECTOR["base64url"]:
            with self.subTest(case["text"]):
                if case["valid"]:
                    self.assertEqual(encoding.unb64url(case["text"]).hex(), case["hex"])
                    self.assertEqual(encoding.b64url(bytes.fromhex(case["hex"])), case["text"])
                else:
                    with self.assertRaises(FormatError):
                        encoding.unb64url(case["text"])

    def test_hex(self):
        self.assertEqual(encoding.unhex("00ff"), b"\x00\xff")
        for bad in ("00FF", "0", "zz", " 00"):
            with self.assertRaises(FormatError):
                encoding.unhex(bad)


class Hkdf(unittest.TestCase):
    def test_rfc5869(self):
        for i, case in enumerate(VECTOR["hkdf"], 1):
            with self.subTest(f"A.{i}"):
                okm = hkdf.hkdf_sha256(bytes.fromhex(case["ikm"]), bytes.fromhex(case["salt"]),
                                       bytes.fromhex(case["info"]), case["length"])
                self.assertEqual(okm.hex(), case["okm"])


class Hpke(unittest.TestCase):
    SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)

    def test_rfc9180_a2(self):
        v = VECTOR["hpke"]
        sk_e = rfc9180.derive_key_pair(bytes.fromhex(v["ikmE"]))
        sk_r = rfc9180.derive_key_pair(bytes.fromhex(v["ikmR"]))
        self.assertEqual(keys.x25519_private_bytes(sk_e).hex(), v["skEm"])
        self.assertEqual(keys.x25519_private_bytes(sk_r).hex(), v["skRm"])
        self.assertEqual(keys.x25519_public_bytes(sk_r.public_key()).hex(), v["pkRm"])
        shared, enc = rfc9180.encap(sk_r.public_key(), sk_e)
        self.assertEqual(enc.hex(), v["enc"])
        self.assertEqual(shared.hex(), v["shared_secret"])
        self.assertEqual(rfc9180.decap(enc, sk_r), shared)
        ctx = rfc9180.Context(shared, bytes.fromhex(v["info"]))
        self.assertEqual(ctx.key_schedule_context.hex(), v["key_schedule_context"])
        self.assertEqual(ctx.secret.hex(), v["secret"])
        self.assertEqual(ctx.key.hex(), v["key"])
        self.assertEqual(ctx.base_nonce.hex(), v["base_nonce"])
        self.assertEqual(ctx.exporter_secret.hex(), v["exporter_secret"])
        for e in v["encryptions"]:
            self.assertEqual(ctx.seal(e["seq"], bytes.fromhex(e["aad"]), bytes.fromhex(v["pt"])).hex(), e["ct"])
        for x in v["exports"]:
            self.assertEqual(ctx.export(bytes.fromhex(x["context"]), x["length"]).hex(), x["value"])

    def test_same_as_pyca_both_ways(self):
        sk = X25519PrivateKey.generate()
        info, message = b"sealdrop/v1/header/to-collector", bytes(range(104))
        self.assertEqual(self.SUITE.decrypt(rfc9180.single_shot_seal(sk.public_key(), info, message), sk,
                                            info=info), message)
        self.assertEqual(rfc9180.single_shot_open(sk, info, self.SUITE.encrypt(message, sk.public_key(),
                                                                                  info=info)), message)


class Signatures(unittest.TestCase):
    def test_p256(self):
        v = VECTOR["signatures"]["p256"]
        verifier = keys.P256Verifier(encoding.unb64url(v["public"]))
        for case in v["cases"]:
            with self.subTest(case["id"]):
                self.assertEqual(verifier.verify(bytes.fromhex(case["signature"]), bytes.fromhex(case["statement"])),
                                 case["valid"])

    def test_ed25519(self):
        v = VECTOR["signatures"]["ed25519"]
        verifier = keys.Ed25519Verifier(encoding.unb64url(v["public"]))
        for case in v["cases"]:
            with self.subTest(case["id"]):
                self.assertEqual(verifier.verify(bytes.fromhex(case["signature"]), bytes.fromhex(case["statement"])),
                                 case["valid"])

    def test_phone_writes_low_s(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        signer = keys.P256Signer(ec.generate_private_key(ec.SECP256R1()))
        for i in range(50):
            raw = signer.sign(b"x%d" % i)
            self.assertLessEqual(int.from_bytes(raw[32:], "big"), keys.P256_N // 2)
            self.assertTrue(keys.P256Verifier(signer.public).verify(raw, b"x%d" % i))


class Sizes(unittest.TestCase):
    def test_examples(self):
        for e in VECTOR["sizes"]["examples"]:
            with self.subTest(e):
                length = sizes.padded_length(e["kind"], e["n"])
                self.assertEqual((length, sizes.pieces(length), sizes.sealed_size(length)),
                                 (e["length"], e["pieces"], e["size"]))

    def test_counts_and_limits(self):
        v = VECTOR["sizes"]
        self.assertEqual(len(sizes.possible_lengths("up")), v["up_sizes"])
        self.assertEqual(v["up_sizes"], 1038)
        self.assertEqual(len(sizes.possible_lengths("ack")), v["ack_sizes"])
        self.assertEqual(v["ack_sizes"], 64)
        self.assertEqual(sizes.max_delivery_bytes(), v["max_delivery_bytes"])
        self.assertEqual(v["max_delivery_bytes"], 4 * sizes.GiB - 8 * sizes.MiB)
        self.assertEqual(sizes.max_delivery_bytes(sizes.GiB), v["max_delivery_bytes_at_1_gib"])

    def test_every_size_maps_back(self):
        for where in ("up", "ack"):
            for length in sizes.possible_lengths(where):
                self.assertEqual(sizes.length_for_size(where, sizes.sealed_size(length)), length)
        for size in VECTOR["sizes"]["impossible_up_sizes"]:
            self.assertIsNone(sizes.length_for_size("up", size), size)

    def test_kind_limits(self):
        with self.assertRaises(ValueError):
            sizes.padded_length(3, sizes.SMALL_MAX + 1)
        self.assertEqual(sizes.padded_length(2, 0), 256 * sizes.KiB)


class Names(unittest.TestCase):
    def test_names(self):
        v = VECTOR["names"]
        for kind, check in (("app", manifests.good_app), ("delivery", manifests.good_delivery),
                            ("path", manifests.good_path), ("labels", manifests.good_label)):
            for name in v[kind]["good"]:
                self.assertTrue(check(name), (kind, name))
            for name in v[kind]["bad"]:
                self.assertFalse(check(name), (kind, name))

    def test_clashes(self):
        for case in VECTOR["names"]["clashes"]:
            self.assertEqual(manifests.paths_clash(case["paths"]), case["clash"], case)


if __name__ == "__main__":
    unittest.main()
