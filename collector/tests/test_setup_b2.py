"""The Backblaze setup, run against a Backblaze in memory (`fake_b2.py`): what it makes, how it tries the keys, and
that it undoes everything when a key can do more than its job."""

from __future__ import annotations

import argparse
import functools
import json
import os
import stat
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import helpers  # noqa: F401  (paths)
from fake_b2 import FakeB2, Key

from sealdrop import b2, s3, setup_b2


class FakeUi(setup_b2.Ui):
    def __init__(self, answers=("000master", "K000mastersecret"), confirm=True):
        self.answers = list(answers)
        self.confirmed = confirm
        self.lines: list[str] = []
        self.events: list[str] = []

    def say(self, text=""):
        self.lines.append(text)

    def secret(self, prompt):
        self.events.append("secret")
        return self.answers.pop(0)

    def confirm(self, prompt):
        self.lines.append(prompt)
        return self.confirmed

    def pause(self, prompt):
        self.events.append(f"pause after {len(self.lines)} lines")

    def clear(self):
        self.events.append(f"clear after {len(self.lines)} lines")

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


class Setup(unittest.TestCase):
    def setUp(self):
        self.fake = FakeB2()
        self.folder = tempfile.TemporaryDirectory()
        self.keys_file = Path(self.folder.name, "sub", "storage.json")

    def tearDown(self):
        self.folder.cleanup()

    def run_setup(self, ui=None, test=True, bucket=None):
        ui = ui or FakeUi()
        args = argparse.Namespace(test=test, bucket=bucket, test_keys=str(self.keys_file))
        code = setup_b2.run(args, ui, account_factory=functools.partial(b2.Account, transport=self.fake),
                            client_factory=functools.partial(s3.Client, transport=self.fake), sleep=lambda s: None)
        return code, ui

    def secrets(self) -> list[str]:
        return [self.fake.master.secret] + [k.secret for k in self.fake.keys.values()]

    def test_test_bucket(self):
        code, ui = self.run_setup()
        self.assertEqual(code, 0, ui.text)
        # the bucket, as the protocol wants it
        (bucket,) = self.fake.buckets.values()
        self.assertRegex(bucket["bucketName"], r"^test-inbox-[a-z2-7]{16}$")
        self.assertEqual(setup_b2.bucket_problems(bucket), [])
        self.assertEqual(self.fake.files, [])  # the test files are gone
        # four keys, each for its folder and job
        self.assertEqual(sorted((k.name, k.prefix, tuple(sorted(k.capabilities)), tuple(k.bucket_ids))
                                for k in self.fake.keys.values()), [
            ("test-collector-pickup", "up/", ("deleteFiles", "listFiles", "readFiles"), (bucket["bucketId"],)),
            ("test-collector-receipts", "ack/", ("writeFiles",), (bucket["bucketId"],)),
            ("test-phone-receipts", "ack/", ("listFiles", "readFiles"), (bucket["bucketId"],)),
            ("test-phone-upload", "up/", ("writeFiles",), (bucket["bucketId"],)),
        ])
        # every check passed, the details included
        self.assertNotIn("FAIL", ui.text)
        self.assertNotIn("NOTE", ui.text)
        self.assertGreaterEqual(ui.text.count("    OK  "), 35)
        self.assertIn("deletes an upload by its version ID over S3 (deleteFiles is enough)", ui.text)
        # the keys went into the file, readable by the owner only, and never onto the screen
        saved = json.loads(self.keys_file.read_text())
        self.assertEqual(saved["bucket"], bucket["bucketName"])
        self.assertEqual((saved["endpoint"], saved["region"]), ("https://s3.eu-central-005.backblazeb2.com",
                                                                "eu-central-005"))
        self.assertEqual(saved["keys"]["phone-upload"]["secret"], self.fake.key("test-phone-upload").secret)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.keys_file.stat().st_mode), 0o600)
        for secret in self.secrets():
            self.assertNotIn(secret, ui.text)
        self.assertEqual(ui.events, ["secret", "secret"])
        self.assertIn("Generate New Master Application Key", ui.text)

    def test_inbox_shows_the_keys_once(self):
        code, ui = self.run_setup(test=False)
        self.assertEqual(code, 0, ui.text)
        self.assertFalse(self.keys_file.exists())  # never written anywhere
        self.assertEqual(sorted(k.name for k in self.fake.keys.values()),
                         ["collector-pickup", "collector-receipts", "phone-receipts", "phone-upload"])
        self.assertRegex(next(iter(self.fake.buckets.values()))["bucketName"], r"^inbox-[a-z2-7]{16}$")
        shown = [i for i, line in enumerate(ui.lines) if any(k.secret in line for k in self.fake.keys.values())]
        self.assertEqual(len(shown), 4)
        self.assertNotIn(self.fake.master.secret, ui.text)
        # shown, then a pause, then the screen is cleared before anything else is said
        self.assertEqual(ui.events[2:], [f"pause after {max(shown) + 4} lines", f"clear after {max(shown) + 4} lines"])

    def test_own_bucket_name(self):
        code, ui = self.run_setup(bucket="my-own-inbox")
        self.assertEqual(code, 0, ui.text)
        self.assertIsNotNone(self.fake.bucket_by_name("my-own-inbox"))
        for bad in ("b2-reserved", "UPPER-case", "short", "with.dot-x", "-starts-with-dash"):
            with self.subTest(bad), self.assertRaises(setup_b2.SetupError):
                self.run_setup(bucket=bad)

    def test_delete_by_version_needs_more(self):
        """If Backblaze wanted the write permission too for deleting by version ID, the collector would delete
        through Backblaze's own interface: the setup tries that and passes, with a note."""
        self.fake.delete_by_version_needs_write = True
        code, ui = self.run_setup()
        self.assertEqual(code, 0, ui.text)
        self.assertIn("NOTE  deletes an upload by its version ID over S3", ui.text)
        self.assertIn("OK    deletes it through Backblaze's own interface instead", ui.text)
        self.assertIn("OK    deletes the remaining versions and hide markers; up/ is empty", ui.text)

    def test_if_match_ignored_is_a_note(self):
        self.fake.ignore_if_match = True
        code, ui = self.run_setup()
        self.assertEqual(code, 0, ui.text)
        self.assertIn("NOTE  a read for a changed file is refused (If-Match, 412)  (the storage ignored If-Match)",
                      ui.text)

    def assert_undone(self):
        self.assertEqual(self.fake.keys, {})
        self.assertEqual(self.fake.buckets, {})
        self.assertEqual(self.fake.files, [])
        self.assertFalse(self.keys_file.exists())

    def test_a_key_that_can_do_more_is_caught(self):
        for role, capability, line in [
            ("test-collector-pickup", "writeFiles", "FAIL  can't upload  (it was allowed)"),
            ("test-phone-upload", "readFiles", "FAIL  can't read an upload  (it was allowed)"),
            ("test-phone-upload", "deleteFiles", "FAIL  can't delete an upload for good  (it was allowed)"),
            ("test-phone-receipts", "writeFiles", "FAIL  can't write a receipt  (it was allowed)"),
            ("test-collector-receipts", "listFiles", "FAIL  can't list the receipts  (it was allowed)"),
        ]:
            with self.subTest(role=role, capability=capability):
                self.tearDown()
                self.setUp()
                self.fake.extra_capability = (role, capability)
                ui = FakeUi()
                with self.assertRaises(setup_b2.SetupError) as caught:
                    self.run_setup(ui)
                # it's caught by reading the key back already, before any test file is uploaded
                self.assertIn(f"the key {role.removeprefix('test-')} isn't as it should be", str(caught.exception))
                self.assert_undone()
                self.assertIn("Undoing what was made", ui.text)
                # and if the read-back missed it, the trial would catch it
                self.tearDown()
                self.setUp()
                self.fake.extra_capability = (role, capability)
                ui = FakeUi()
                with unittest.mock.patch.object(setup_b2, "key_problems", return_value=[]), \
                        self.assertRaises(setup_b2.SetupError) as caught:
                    self.run_setup(ui)
                self.assertIn("checks failed", str(caught.exception))
                self.assertIn(line, ui.text)
                self.assert_undone()

    def test_bucket_not_as_asked(self):
        self.fake.lifecycle_dropped = True
        with self.assertRaises(setup_b2.SetupError) as caught:
            self.run_setup()
        self.assertIn("expiry rules differ", str(caught.exception))
        self.assert_undone()

    def test_cancelled_midway(self):
        self.fake.interrupt_at = "complete"
        ui = FakeUi()
        with self.assertRaises(setup_b2.SetupError) as caught:
            self.run_setup(ui)
        self.assertEqual(str(caught.exception), "cancelled")
        self.assert_undone()

    def test_wrong_or_weak_key(self):
        with self.assertRaises(setup_b2.SetupError) as caught:
            self.run_setup(FakeUi(answers=("000master", "wrong")))
        self.assertIn("didn't accept the key", str(caught.exception))
        self.fake.keys["005weak"] = Key("005weak", "Kweak", "weak", ["listFiles"])
        with self.assertRaises(setup_b2.SetupError) as caught:
            self.run_setup(FakeUi(answers=("005weak", "Kweak")))
        self.assertIn("use the master application key", str(caught.exception))
        self.assertEqual(self.fake.buckets, {})

    def test_clock_off(self):
        self.fake.date = "Mon, 01 Jan 2024 00:00:00 GMT"
        with self.assertRaises(setup_b2.SetupError) as caught:
            self.run_setup()
        self.assertIn("clock is off", str(caught.exception))
        self.assertEqual(self.fake.buckets, {})  # checked before anything is made

    def test_existing_bucket_left_alone(self):
        self.run_setup(bucket="taken-name")
        before = dict(self.fake.buckets)
        with self.assertRaises(setup_b2.SetupError) as caught:
            self.run_setup(bucket="taken-name")
        self.assertIn("exists already", str(caught.exception))
        self.assertEqual(self.fake.buckets, before)

    def test_no_means_nothing_made(self):
        code, ui = self.run_setup(FakeUi(confirm=False))
        self.assertEqual(code, 1)
        self.assertEqual((self.fake.buckets, self.fake.keys), ({}, {}))

    def test_other_keys_noted(self):
        self.fake.keys["005all"] = Key("005all", "Kall", "laptop-backup", ["listFiles"])
        code, ui = self.run_setup()
        self.assertEqual(code, 0, ui.text)
        self.assertIn("other keys of the account can reach this bucket too: laptop-backup", ui.text)


class ReadBack(unittest.TestCase):
    def test_rules_compared_without_nulls_and_order(self):
        bucket = {"bucketType": "allPrivate",
                  "defaultServerSideEncryption": {"value": {"mode": "SSE-B2", "algorithm": "AES256"}},
                  "fileLockConfiguration": {"value": {"isFileLockEnabled": False}},
                  "lifecycleRules": [{**setup_b2.LIFECYCLE[1], "daysFromStartingToCancelingUnfinishedLargeFiles": None},
                                     setup_b2.LIFECYCLE[0]]}
        self.assertEqual(setup_b2.bucket_problems(bucket), [])
        self.assertEqual(len(setup_b2.bucket_problems({**bucket, "bucketType": "allPublic"})), 1)
        self.assertEqual(len(setup_b2.bucket_problems({**bucket, "defaultServerSideEncryption": {"value": None}})), 1)
        self.assertEqual(len(setup_b2.bucket_problems(
            {**bucket, "fileLockConfiguration": {"value": {"isFileLockEnabled": True}}})), 1)
        changed = [dict(setup_b2.LIFECYCLE[0], daysFromHidingToDeleting=1), setup_b2.LIFECYCLE[1]]
        self.assertEqual(len(setup_b2.bucket_problems({**bucket, "lifecycleRules": changed})), 1)

    def test_key_read_back(self):
        good = {"capabilities": ["readFiles", "listFiles"], "bucketIds": ["b1"], "namePrefix": "ack/"}
        self.assertEqual(setup_b2.key_problems(good, "b1", "ack/", ["listFiles", "readFiles"]), [])
        self.assertEqual(len(setup_b2.key_problems({**good, "bucketIds": None}, "b1", "ack/", ["listFiles", "readFiles"])), 1)
        self.assertEqual(len(setup_b2.key_problems({**good, "namePrefix": None}, "b1", "ack/", ["listFiles", "readFiles"])), 1)
        self.assertEqual(len(setup_b2.key_problems({**good, "expirationTimestamp": 1}, "b1", "ack/",
                                                   ["listFiles", "readFiles"])), 1)

    def test_names(self):
        self.assertRegex(setup_b2.random_name("up/"), r"^up/[a-z2-7]{32}$")


if __name__ == "__main__":
    unittest.main()
