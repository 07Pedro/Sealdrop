"""The collector against an in-memory inbox: pairing, pickup, receipts, cleanup, and the failure cases of
PROTOCOL.md §10 (tampered files, junk, duplicates, conflicts, cut connections, crashes in between)."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401  (puts the collector on the path)
from fake_b2 import REGION, S3_HOST, FakeB2, Key
from phone import Phone, offer_for_tests

from sealdrop import encoding, errors, pair as pairing_cmd, s3
from sealdrop.root import Location, Root
from sealdrop.run import Collector, Storage, pack_receipts
from sealdrop.setup_b2 import ROLES
from sealdrop.state import DAY

ENDPOINT = f"https://{S3_HOST}"
APP = "org.example.tracker"


def make_inbox(fake: FakeB2, bucket: str = "inbox-test") -> dict[str, Key]:
    """A bucket and the four keys, limited as setup_b2 makes them."""
    bucket_id = "bucket000001"
    fake.buckets[bucket_id] = {"bucketId": bucket_id, "bucketName": bucket, "bucketType": "allPrivate"}
    found = {}
    for role, (prefix, capabilities) in ROLES.items():
        key = Key(f"00{role[:6]}{len(found)}", f"K{role}secret", role, sorted(capabilities), [bucket_id], prefix)
        fake.keys[key.id] = key
        found[role] = key
    return found


class Clock:
    def __init__(self, now: int = 1_790_000_100_000):
        self.now = now

    def __call__(self) -> int:
        return self.now


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.fake = FakeB2()
        self.keys = make_inbox(self.fake)
        self.clock = Clock()
        self.sleeps: list[float] = []
        (self.tmp / "machine-id").write_text("0123456789abcdef\n")
        self.root = Root(self.tmp / "root")
        up = Location(ENDPOINT, REGION, "inbox-test", "up/")
        ack = Location(ENDPOINT, REGION, "inbox-test", "ack/")
        k = self.keys
        self.root.create(up, ack, (k["collector-pickup"].id, k["collector-pickup"].secret),
                         (k["collector-receipts"].id, k["collector-receipts"].secret),
                         {"clock_check": "off", "free_reserve": 0})
        self.storage = Storage(up, ack, self.client("collector-pickup"), self.client("collector-receipts"),
                               self.sleeps.append)

    def client(self, role: str) -> s3.Client:
        k = self.keys[role]
        return s3.Client(ENDPOINT, REGION, s3.Credentials(k.id, k.secret), context=object(), transport=self.fake)

    def collector(self) -> Collector:
        return Collector(self.root, self.storage, now=self.clock, machine_id=self.tmp / "machine-id",
                         cpuinfo=self.tmp / "no-cpuinfo")

    def run_once(self):
        return self.collector().run()

    def paired_phone(self, label: str = "Phone") -> Phone:
        """A phone paired directly (the pairing itself is tested in Pairing)."""
        offer = offer_for_tests(self.root, self.keys, self.clock())
        phone = Phone(self.fake, offer, label)
        from sealdrop.root import Sender
        self.root.add_sender(Sender(phone.key_id, phone.signer.public, phone._open_public(), label, self.clock(),
                                    phone.fingerprint()))
        return phone

    def up_names(self) -> list[str]:
        return sorted({f.name for f in self.fake.files if f.name.startswith("up/") and f.action != "start"})

    def stored(self, app: str, delivery: str) -> dict[str, bytes]:
        folder = self.root / "store" / app / delivery
        return {p.relative_to(folder).as_posix(): p.read_bytes() for p in folder.rglob("*") if p.is_file()}

    @staticmethod
    def results(receipts: list[dict]) -> list[tuple[str, str, str]]:
        return [(d["delivery"], d["result"], d.get("seq", d.get("reason")))
                for r in receipts if r["type"] == "receipt" for e in r["stored"] for d in e["deliveries"]]


class Setup(Base):
    def test_folders_and_keys_are_private(self):
        for name in ("config", "keys", "state", "store", "incoming"):
            self.assertEqual((self.root / name).stat().st_mode & 0o777, 0o700, name)
        for name in ("config/collector.json", "keys/open.key", "keys/sign.key"):
            self.assertEqual((self.root / name).stat().st_mode & 0o777, 0o600, name)

    def test_a_second_init_is_refused(self):
        from sealdrop.root import RootError
        with self.assertRaises(RootError):
            self.root.create(*self.root.locations(), ("a", "b"), ("c", "d"))

    def test_instance_stays_and_changes_with_the_machine(self):
        first = self.root.instance(self.tmp / "machine-id", self.tmp / "none")
        self.assertEqual(first, self.root.instance(self.tmp / "machine-id", self.tmp / "none"))
        (self.tmp / "machine-id").write_text("another machine\n")
        self.assertNotEqual(first, self.root.instance(self.tmp / "machine-id", self.tmp / "none"))

    def test_no_machine_id_no_start(self):
        from sealdrop.root import RootError
        (self.tmp / "machine-id").write_text("")
        with self.assertRaises(RootError):
            self.root.instance(self.tmp / "machine-id", self.tmp / "none")


class Pairing(Base):
    class Ui(pairing_cmd.PairUi):
        def __init__(self, test, confirm=True):
            self.test, self.answer, self.said, self.cleared, self.text = test, confirm, [], 0, None
            self.secrets = iter([test.keys["phone-upload"].id, test.keys["phone-upload"].secret,
                                 test.keys["phone-receipts"].id, test.keys["phone-receipts"].secret])

        def say(self, text=""):
            self.said.append(text)

        def secret(self, prompt):
            return next(self.secrets)

        def confirm(self, prompt):
            self.said.append(prompt)
            return self.answer

        def show_qr(self, qr, text):
            self.text = text

        def clear(self):
            self.cleared += 1

    def pair_with(self, ui, phone_acts):
        """Runs `pair`; the phone acts during the first pause."""
        def sleep(seconds):
            if phone_acts:
                phone_acts.pop(0)(json.loads(ui.text))
            self.clock.now += int(seconds * 1000)
        return pairing_cmd.pair(self.root, ui, storage=self.storage, now=self.clock, sleep=sleep)

    def test_pairs_and_the_phone_gets_the_paired_receipt(self):
        ui = self.Ui(self)
        phones = []

        def act(offer):
            phone = Phone(self.fake, offer)
            phone.put(phone.pair_request())
            phones.append(phone)
        sender = self.pair_with(ui, [act])
        phone = phones[0]
        self.assertIsNotNone(sender)
        self.assertEqual(sender.fingerprint, phone.fingerprint())
        self.assertIn("    " + phone.fingerprint(), ui.said)
        self.assertGreaterEqual(ui.cleared, 1)
        self.assertEqual(list(self.root.senders()), [phone.key_id])
        (paired,) = phone.receipts()
        self.assertEqual(paired["type"], "paired")
        self.assertEqual(paired["pairing"], json.loads(ui.text)["pairing"])
        self.assertEqual(self.up_names(), [])  # the request is gone from the inbox
        # Nothing from the QR code reached the disk.
        secret = self.keys["phone-upload"].secret.encode()
        code = json.loads(ui.text)["code"].encode()
        for p in self.root.path.rglob("*"):
            if p.is_file():
                data = p.read_bytes()
                self.assertNotIn(secret, data, p)
                self.assertNotIn(code, data, p)

    def test_a_request_without_the_code_is_rejected_and_the_pairing_stays_open(self):
        ui = self.Ui(self)
        phones = []

        def stranger(offer):
            phone = Phone(self.fake, offer)
            phone.put(phone.pair_request(code=os.urandom(16)))

        def owner(offer):
            phone = Phone(self.fake, offer)
            phone.put(phone.pair_request())
            phones.append(phone)
        sender = self.pair_with(ui, [stranger, owner])
        self.assertEqual(sender.key_id, phones[0].key_id)
        self.assertTrue(any("rejected: unknown-sender" in s for s in ui.said))

    def test_codes_that_differ_pair_nothing(self):
        ui = self.Ui(self, confirm=False)
        self.assertIsNone(self.pair_with(ui, [lambda offer: Phone(self.fake, offer).put(
            Phone(self.fake, offer).pair_request())]))
        self.assertEqual(self.root.senders(), {})

    def test_expires_after_ten_minutes(self):
        ui = self.Ui(self)
        self.assertIsNone(self.pair_with(ui, []))
        self.assertTrue(any("expired" in s for s in ui.said))

    def test_a_regular_run_rejects_a_pairing_request(self):
        offer = offer_for_tests(self.root, self.keys, self.clock())
        phone = Phone(self.fake, offer)
        phone.put(phone.pair_request())
        outcome = self.run_once()
        self.assertEqual(outcome.rejected, 1)
        self.assertEqual(self.up_names(), [])

    def test_replaces_offers_to_retire_the_old_entry(self):
        old = self.paired_phone("Old")
        ui = self.Ui(self)

        def act(offer):
            Phone(self.fake, offer).put(Phone(self.fake, offer).pair_request(replaces=old.key_id))
        # Two Phone objects: the request is made by the second; what matters here is `replaces`.
        self.pair_with(ui, [act])
        self.assertNotIn(old.key_id, self.root.senders())
        self.assertTrue((self.root / f"senders/removed/{old.key_id.hex()}.json").exists())


class Pickup(Base):
    def test_stores_and_answers_then_deletes(self):
        phone = self.paired_phone()
        files = {"manifest.json": b'{"a": 1}', "data/day.json.gz": os.urandom(300_000), "empty.txt": b""}
        name, sha, digests = phone.send([(APP, "d-000001", files), (APP, "d-000002", {"x.bin": b"x" * 10})])
        outcome = self.run_once()
        self.assertEqual((outcome.downloaded, outcome.stored, outcome.receipts, outcome.deleted), (1, 2, 1, 1))
        self.assertEqual(self.stored(APP, "d-000001"), files)
        (receipt,) = phone.receipts()
        (entry,) = receipt["stored"]
        self.assertEqual(entry["sealed_sha256"], sha)
        self.assertEqual(self.results([receipt]), [("d-000001", "stored", 1), ("d-000002", "stored", 2)])
        self.assertEqual([d["digest"] for d in entry["deliveries"]], digests)
        self.assertEqual(receipt["status"]["seq"], 2)
        self.assertEqual(receipt["status"]["last_pickup"], self.clock())
        self.assertEqual(self.up_names(), [])
        self.assertEqual(list((self.root / "incoming").iterdir()), [])
        self.assertFalse((self.root / "store/.tmp").exists() and any((self.root / "store/.tmp").iterdir()))

    def test_a_large_bundle_streams_through(self):
        phone = self.paired_phone()
        big = os.urandom(5 * 1024 * 1024 + 123)
        phone.send([(APP, "big", {"a.bin": big})])
        self.assertEqual(self.run_once().stored, 1)
        self.assertEqual(self.stored(APP, "big"), {"a.bin": big})

    def test_duplicates_carry_their_seq_and_a_conflict_is_kept_apart(self):
        phone = self.paired_phone()
        phone.send([(APP, "d1", {"a": b"one"})])
        self.run_once()
        phone.send([(APP, "d1", {"a": b"one"})])          # the same again: duplicate
        phone.send([(APP, "d1", {"a": b"other content"})])  # the same ID, other content: conflict
        self.clock.now += 1000
        outcome = self.run_once()
        self.assertEqual((outcome.duplicates, outcome.conflicts), (1, 1))
        results = self.results(phone.receipts())
        self.assertIn(("d1", "duplicate", 1), results)
        self.assertIn(("d1", "conflict", None), results)
        self.assertEqual(self.stored(APP, "d1"), {"a": b"one"})  # never overwritten
        (kept,) = (self.root / "conflicts" / APP / "d1").iterdir()
        self.assertEqual((kept / "a").read_bytes(), b"other content")
        self.assertIn("conflict", json.loads((self.root / "state/status.json").read_text())["warnings"])

    def test_a_duplicate_from_another_phone_has_no_seq(self):
        a, b = self.paired_phone("A"), self.paired_phone("B")
        a.send([(APP, "d1", {"a": b"one"})])
        self.run_once()
        b.send([(APP, "d1", {"a": b"one"})])
        self.run_once()
        self.assertEqual(self.results(b.receipts()), [("d1", "duplicate", None)])

    def test_one_bad_delivery_is_rejected_alone(self):
        phone = self.paired_phone()
        phone.send([(APP, "good", {"a": b"1"}), ("org.example.tracker", "bad", {"../x": b"2"}),
                    ("a", "one-part-app", {"b": b"3"}), (APP, "also-good", {"c": b"4"})])
        self.run_once()
        self.assertEqual(sorted(p.name for p in (self.root / "store" / APP).iterdir()), ["also-good", "good"])
        self.assertFalse((self.root / "store" / "a").exists())
        results = self.results(phone.receipts())
        self.assertIn(("bad", "rejected", "bad-name"), results)
        self.assertIn(("one-part-app", "rejected", "bad-name"), results)
        self.assertNotIn("x", [p.name for p in self.root.path.rglob("*")])


class Rejections(Base):
    """Whole files that are rejected: nothing stored, every phone told, the upload deleted."""

    def setUp(self):
        super().setUp()
        self.phone = self.paired_phone()

    def rejected_reasons(self) -> list[str]:
        return [e["reason"] for r in self.phone.receipts() if r["type"] == "receipt" for e in r["rejected"]]

    def test_a_flipped_bit_in_each_part(self):
        data, _ = self.phone.bundle([(APP, "d1", {"a": os.urandom(1000)})])
        for offset in (0, 40, 200, len(data) - 70, len(data) - 1):  # enc, header, piece, padding area, signature
            tampered = bytearray(data)
            tampered[offset] ^= 1
            self.phone.put(bytes(tampered))
        outcome = self.run_once()
        self.assertEqual(outcome.rejected, 5)
        self.assertEqual(sorted(self.rejected_reasons()),
                         ["bad-signature", "bad-signature", "bad-signature", "damaged", "damaged"])
        self.assertEqual(self.up_names(), [])
        self.assertFalse((self.root / "store" / APP).exists())
        self.assertEqual(len(list((self.root / "rejected").glob("*.sealed"))), 3)  # the downloaded ones

    def test_junk_of_every_kind(self):
        self.phone.put(os.urandom(262_376))                 # a possible size, but no header: damaged
        self.phone.put(os.urandom(1000))                    # an impossible size: damaged, never downloaded
        self.phone.put(b"x", name="up/not-a-sealdrop-name")  # a wrong name: deleted, not reported
        stranger = Phone(self.fake, offer_for_tests(self.root, self.keys, self.clock()))
        stranger.send([(APP, "d1", {"a": b"1"})])           # not paired: unknown-sender
        outcome = self.run_once()
        self.assertEqual(sorted(self.rejected_reasons()), ["damaged", "damaged", "unknown-sender"])
        self.assertEqual(outcome.downloaded, 0)  # all three were rejected by their size or first 152 bytes
        self.assertEqual(self.up_names(), [])

    def test_signed_by_another_phone(self):
        other = Phone(self.fake, offer_for_tests(self.root, self.keys, self.clock()))
        data, _ = self.phone.bundle([(APP, "d1", {"a": b"1"})], signer=other.signer)
        self.phone.put(data)
        self.run_once()
        self.assertEqual(self.rejected_reasons(), ["unknown-sender"])

    def test_known_file_again_under_a_new_name(self):
        data, _ = self.phone.bundle([(APP, "d1", {"a": b"1"})])
        self.phone.put(data)
        self.run_once()
        self.phone.receipts()
        self.phone.put(data)  # a replay of the same sealed file
        outcome = self.run_once()
        self.assertEqual((outcome.stored, outcome.duplicates), (0, 0))
        self.assertEqual(self.results(self.phone.receipts()), [("d1", "stored", 1)])  # the same result as then
        self.assertEqual(self.up_names(), [])


class Interruptions(Base):
    def setUp(self):
        super().setUp()
        self.phone = self.paired_phone()

    def test_a_cut_download_resumes(self):
        content = os.urandom(3_000_000)
        self.phone.send([(APP, "d1", {"a": content})])
        self.fake.faults += [("get", "ok"), ("get", ("cut", 1_000_000)), ("get", "net")]  # after the header
        outcome = self.run_once()
        self.assertEqual(outcome.stored, 1)
        self.assertEqual(self.stored(APP, "d1"), {"a": content})
        self.assertEqual(len(self.sleeps), 2)  # two pauses, then it went on where it was

    def test_no_network_ends_the_run_and_the_next_one_finishes(self):
        content = os.urandom(2_000_000)
        self.phone.send([(APP, "d1", {"a": content})])
        self.fake.faults += [("get", "ok"), ("get", ("cut", 700_000))] + [("get", "net")] * 3
        outcome = self.run_once()
        self.assertEqual(outcome.stopped, "network")
        self.assertEqual(outcome.stored, 0)
        self.assertEqual(len(self.up_names()), 1)  # still in the inbox
        self.assertTrue(any((self.root / "incoming").iterdir()))  # the part already downloaded is kept
        outcome = self.run_once()
        self.assertEqual(outcome.stored, 1)
        self.assertEqual(self.stored(APP, "d1"), {"a": content})

    def test_a_receipt_that_fails_keeps_the_upload_until_it_is_written(self):
        self.phone.send([(APP, "d1", {"a": b"1"})])
        self.fake.faults += [("put", 503)] * 4
        outcome = self.run_once()
        self.assertEqual((outcome.stored, outcome.receipts, outcome.deleted), (1, 0, 0))
        self.assertEqual(len(self.up_names()), 1)
        outcome = self.run_once()
        self.assertEqual((outcome.stored, outcome.receipts, outcome.deleted), (0, 1, 1))
        self.assertEqual(self.results(self.phone.receipts()), [("d1", "stored", 1)])

    def test_a_crash_after_the_move_before_the_note(self):
        content = {"a": b"1", "b/c": b"2"}
        self.phone.send([(APP, "d1", content)])
        collector = self.collector()
        original = collector._open_and_store

        def crash_after_store(v, path, sha, sender, out):
            collector.state.note_stored = lambda *a, **k: (_ for _ in ()).throw(OSError("power cut"))
            original(v, path, sha, sender, out)
        collector._open_and_store = crash_after_store
        self.assertEqual(collector.run().stopped, "local")
        self.assertEqual(self.stored(APP, "d1"), content)  # moved into place
        outcome = self.run_once()  # the same upload again: its delivery is already there
        self.assertEqual(self.results(self.phone.receipts()), [("d1", "duplicate", 1)])
        self.assertEqual(outcome.deleted, 1)

    def test_key_refused_and_storage_cap(self):
        self.fake.faults.append(("list", 403))
        self.assertEqual(self.run_once().stopped, "key-refused")
        status = json.loads((self.root / "state/status.json").read_text())
        self.assertEqual(status["storage"], "storage key refused")
        self.phone.send([(APP, "d1", {"a": b"1"})])
        self.fake.faults.append(("get", 403))
        self.fake._s3_error_message = "Transaction cap exceeded"
        original = self.fake._s3_error

        def cap(status, code, message=""):
            return original(status, code, "Transaction cap exceeded" if message == "fault" else message)
        self.fake._s3_error = cap
        outcome = self.run_once()
        self.assertEqual(outcome.stopped, "storage-cap")
        self.assertIn("storage-cap", outcome.warnings)
        # The receipt that the phone gets says so too: receipts still work with the other key.
        statuses = [r["status"]["warnings"] for r in self.phone.receipts() if r["type"] == "receipt"]
        self.assertIn(["storage-cap"], statuses)

    def test_vanished_upload(self):
        name, _, _ = self.phone.send([(APP, "d1", {"a": b"1"})])
        collector = self.collector()
        original = collector._list

        def list_then_vanish():
            found = original()
            self.fake.files = [f for f in self.fake.files if f.name != name]
            return found
        collector._list = list_then_vanish
        outcome = collector.run()
        self.assertEqual(outcome.vanished, 1)
        (receipt,) = self.phone.receipts()
        self.assertEqual(receipt["status"]["vanished_7d"], 1)

    def test_a_locked_root_skips(self):
        from sealdrop.run import Lock
        with Lock(self.root / "state/lock"):
            self.assertEqual(self.run_once().skipped, "locked")


class Receipts(Base):
    def test_a_status_receipt_once_a_day(self):
        phone = self.paired_phone()
        self.run_once()
        self.assertEqual(len(phone.receipts()), 1)  # the first status
        self.clock.now += DAY // 2
        self.run_once()
        self.assertEqual(phone.receipts(), [])
        self.clock.now += DAY // 2 + 1
        self.run_once()
        (status,) = phone.receipts()
        self.assertEqual(status["stored"], [])

    def test_rejections_go_to_every_phone_once(self):
        a, b = self.paired_phone("A"), self.paired_phone("B")
        name = a.put(os.urandom(262_376))
        self.run_once()
        for phone in (a, b):
            (r,) = phone.receipts()
            self.assertEqual([e["reason"] for e in r["rejected"]], ["damaged"])
            self.assertEqual([e["name"] for e in r["rejected"]], [name.removeprefix(a.up["prefix"])])  # as on the phone
        self.clock.now += DAY + 1
        self.run_once()
        for phone in (a, b):
            (r,) = phone.receipts()
            self.assertEqual(r["rejected"], [])

    def test_a_big_receipt_is_split(self):
        app = "org.example." + "a" * 88  # the longest names: one entry is then too big for one receipt
        deliveries = [{"app": app, "delivery": f"d-{i:06d}-" + "x" * 90, "digest": "0" * 64, "result": "stored",
                       "seq": i} for i in range(1000)]
        entry = {"message": "0" * 32, "sealed_sha256": "1" * 64, "received": 1, "deliveries": deliveries}
        manifests = pack_receipts(b"\x01" * 32, 1, [entry, entry], [], {"seq": 1})
        self.assertGreaterEqual(len(manifests), 3)
        from sealdrop import receipts
        for m in manifests:
            self.assertTrue(receipts.content_fits(m))
            for e in m["stored"]:
                self.assertEqual((e["message"], e["sealed_sha256"], e["received"]), ("0" * 32, "1" * 64, 1))
        self.assertEqual(sum(len(e["deliveries"]) for m in manifests for e in m["stored"]), 2000)


class Commands(Base):
    def test_unpair_by_label(self):
        from sealdrop.__main__ import main
        self.paired_phone("Work phone")

        class Ui(Pairing.Ui):
            pass
        ui = Ui(self)
        self.assertEqual(main(["unpair", "Work phone", "--root", str(self.root.path)], ui), 0)
        self.assertEqual(self.root.senders(), {})

    def test_init_from_test_keys(self):
        from sealdrop.__main__ import main
        keys = {"endpoint": ENDPOINT, "region": REGION, "bucket": "inbox-test",
                "keys": {r: {"id": k.id, "secret": k.secret} for r, k in self.keys.items()}}
        path = self.tmp / "storage.json"
        path.write_text(json.dumps(keys))
        ui = Pairing.Ui(self)
        self.assertEqual(main(["init", "--root", str(self.tmp / "r2"), "--test-keys", str(path),
                               "--clock-check", "off"], ui), 0)
        config = Root(self.tmp / "r2").config()
        self.assertEqual(config["keys"]["pickup"]["id"], self.keys["collector-pickup"].id)
        self.assertEqual(config["clock_check"], "off")


if __name__ == "__main__":
    unittest.main()
