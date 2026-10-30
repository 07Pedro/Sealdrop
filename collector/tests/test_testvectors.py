"""The committed test files (testvectors/): every case opens or fails exactly as cases.json says, pairing and offer
vectors hold, and making the files again gives the same bytes."""

import hashlib
import io
import tempfile
import unittest
from pathlib import Path

from helpers import CASES, KEYS, VECTOR, VECTORS, mutate, public, x25519
from sealdrop import encoding, keys, manifests, pairing, reading, sizes
from sealdrop.errors import FormatError, Rejected

SENDERS = {keys.key_id(public("sender_sign")): keys.P256Verifier(public("sender_sign"))}
COLLECTOR_KEYS = [x25519("collector_open"), x25519("collector_open_retired")]


def read_case(case):
    data = (VECTORS / "files" / case["file"]).read_bytes()
    data = mutate(data, case.get("mutations", []))
    if case["reader"] == "sender":
        header, manifest = reading.open_receipt(data, [x25519("sender_open")],
                                                keys.Ed25519Verifier(public("collector_sign")),
                                                keys.key_id(public("collector_sign")))
        return data, header, {"manifest": manifest}
    if case["file"].startswith("pair-request"):
        opened = reading.open_pair_request(io.BytesIO(data), len(data), COLLECTOR_KEYS)
        return data, opened.header, {"manifest": opened.manifest, "request": opened.request}
    f = io.BytesIO(data)
    s = reading.open_upload(f, len(data), COLLECTOR_KEYS, SENDERS, case.get("max_sealed", sizes.DEFAULT_MAX_SEALED))
    content = bytearray()
    s2 = reading.open_upload(io.BytesIO(data), len(data), COLLECTOR_KEYS, SENDERS)
    for chunk in s2.iter_content():
        content += chunk
    return data, s.header, {"verdicts": reading.check_deliveries(s), "content": bytes(content)}


class Cases(unittest.TestCase):
    def test_every_case(self):
        self.assertGreater(len(CASES), 30)
        for case in CASES:
            with self.subTest(case["id"]):
                if case["expect"] == "reject":
                    with self.assertRaises(Rejected) as e:
                        read_case(case)
                    self.assertEqual(e.exception.reason, case["reason"], e.exception.detail)
                    continue
                data, header, got = read_case(case)
                self.assertEqual(hashlib.sha256(data).hexdigest(), case["sealed_sha256"])
                self.assertEqual(len(data), case["size"])
                expected = case["header"]
                self.assertEqual((header.kind, header.created, header.n, header.message_id.hex(),
                                  header.writer_key_id.hex()),
                                 (expected["kind"], expected["created"], expected["n"], expected["message_id"],
                                  expected["writer_key_id"]))
                if "content_sha256" in case:
                    self.assertEqual(hashlib.sha256(got["content"]).hexdigest(), case["content_sha256"])
                if "deliveries" in case:
                    self.assertEqual(
                        [{"app": v.delivery.app, "delivery": v.delivery.delivery, "digest": v.delivery.digest,
                          **({"result": "stored"} if v.ok else {"result": "rejected", "reason": v.reason})}
                         for v in got["verdicts"]],
                        [{k: d[k] for k in ("app", "delivery", "digest", "result", "reason") if k in d}
                         for d in case["deliveries"]])
                if "manifest" in case:
                    self.assertEqual(got["manifest"], case["manifest"])
                if "pair_check" in case:
                    self.assertEqual(manifests.check_pair_names(got["request"]), case["pair_check"])
                    offer = VECTOR["pairing"]["offer"]
                    request = got["request"]
                    transcript = pairing.mac_transcript(request.pairing, public("collector_open"),
                                                        public("collector_sign"), request.sender_sign,
                                                        request.sender_open, request.replaces)
                    mac = pairing.pair_mac(encoding.unb64url(offer["code"]), request.pairing, transcript)
                    self.assertTrue(pairing.mac_ok(mac, request.mac))
                    self.assertEqual(pairing.fingerprint(request.pairing, public("collector_open"),
                                                         public("collector_sign"), request.sender_sign,
                                                         request.sender_open), case["fingerprint"])


class Pairing(unittest.TestCase):
    def test_macs_and_fingerprint(self):
        v = VECTOR["pairing"]
        offer = v["offer"]
        p, code = encoding.unb64url(offer["pairing"]), encoding.unb64url(offer["code"])
        for m in v["macs"]:
            replaces = None if m["replaces"] is None else bytes.fromhex(m["replaces"])
            transcript = pairing.mac_transcript(p, public("collector_open"), public("collector_sign"),
                                                public("sender_sign"), public("sender_open"), replaces)
            self.assertEqual(transcript.hex(), m["transcript"])
            self.assertEqual(pairing.pair_mac(code, p, transcript).hex(), m["mac"])
        self.assertRegex(v["fingerprint"], r"^[A-Z2-7]{4}( [A-Z2-7]{4}){3}$")

    def test_offers(self):
        now = VECTOR["pairing"]["offer"]["expires"] - 1
        for case in VECTOR["offers"]:
            with self.subTest(case["id"]):
                if case["valid"]:
                    up, ack = pairing.check_offer(case["offer"], now)
                    self.assertTrue(ack["endpoint"].startswith("https://"))
                else:
                    with self.assertRaises(FormatError):
                        pairing.check_offer(case["offer"], now)

    def test_expired_offer(self):
        offer = VECTOR["pairing"]["offer"]
        pairing.check_offer(offer, offer["expires"] + 5 * 60 * 1000)
        with self.assertRaises(FormatError):
            pairing.check_offer(offer, offer["expires"] + 5 * 60 * 1000 + 1)


class Reproducible(unittest.TestCase):
    def test_making_them_again_gives_the_same_files(self):
        import make_testvectors

        with tempfile.TemporaryDirectory() as tmp:
            make_testvectors.main(Path(tmp))
            for path in sorted(Path(tmp).rglob("*")):
                if path.is_file():
                    committed = VECTORS / path.relative_to(tmp)
                    with self.subTest(str(path.relative_to(tmp))):
                        self.assertTrue(committed.exists())
                        self.assertEqual(path.read_bytes(), committed.read_bytes())

    def test_keys_are_marked_as_test_keys(self):
        self.assertIn("testing only", KEYS["note"])


if __name__ == "__main__":
    unittest.main()
