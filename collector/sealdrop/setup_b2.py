"""Sets up an inbox at Backblaze B2 (PROTOCOL.md §8) and tries every key: can it do its job, and nothing else?

Run it in your own terminal, with a fresh master application key at hand:

    python -m sealdrop.setup_b2 --test    # a test bucket; its keys go into a file, for trying Sealdrop out
    python -m sealdrop.setup_b2           # the inbox; its keys are shown once, for your password manager
    python -m sealdrop.setup_b2 --keys    # lists Sealdrop's keys, and deletes the ones you choose (a lost phone)

It makes a private bucket with Backblaze's encryption, no object lock and the expiry rules, and four keys, each
limited to one folder and one job. Then it tries each key over the S3 interface, with test files it deletes again.
If a key can do more or less than it should, it deletes the keys and the bucket it made, and says what went wrong.
The master key is asked for at a prompt that doesn't show it, and is never saved. No key's secret is ever shown
except the new ones, once; of key IDs only the last four characters, to match them with your password manager.
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import hashlib
import io
import json
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import b2, encoding, net, s3

UP, ACK = "up/", "ack/"

# PROTOCOL.md §8 and §6: uploads never picked up go after 90 + 7 days, receipts after 30 + 1, unfinished uploads in
# parts after 7.
LIFECYCLE = [
    {"fileNamePrefix": UP, "daysFromUploadingToHiding": 90, "daysFromHidingToDeleting": 7,
     "daysFromStartingToCancelingUnfinishedLargeFiles": 7},
    {"fileNamePrefix": ACK, "daysFromUploadingToHiding": 30, "daysFromHidingToDeleting": 1},
]

# PROTOCOL.md §8, the table: each key's folder and permissions (Backblaze's names).
ROLES = {
    "phone-upload": (UP, ["writeFiles"]),
    "phone-receipts": (ACK, ["listFiles", "readFiles"]),
    "collector-pickup": (UP, ["listFiles", "readFiles", "deleteFiles"]),
    "collector-receipts": (ACK, ["writeFiles"]),
}

KEY_NAMES = set(ROLES) | {f"test-{role}" for role in ROLES}
NEEDED_FOR_KEYS = {"listKeys", "deleteKeys", "listBuckets"}
NEEDED = {"listBuckets", "writeBuckets", "deleteBuckets", "readBucketEncryption", "writeBucketEncryption",
          "listKeys", "writeKeys", "deleteKeys", "listFiles", "deleteFiles", "writeFiles"}

_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{4,61}[a-z0-9]")
# Answers that mean the request itself was wrong, not that the key was refused.
_NOT_A_REFUSAL = {"InvalidAccessKeyId", "SignatureDoesNotMatch", "RequestTimeTooSkewed", "AuthorizationHeaderMalformed"}
PART = 8 << 20


class SetupError(Exception):
    """Stops the setup, with a message for the user."""


class Wrong(Exception):
    """A check's action worked, but not as it should (the detail says how)."""


def random_name(prefix: str) -> str:
    """PROTOCOL.md §8: the prefix plus 32 characters from a–z 2–7."""
    return prefix + encoding.base32(secrets.token_bytes(20)).lower()


def default_bucket(test: bool) -> str:
    return ("test-inbox-" if test else "inbox-") + encoding.base32(secrets.token_bytes(10)).lower()


# --- what was made, read back -------------------------------------------------------------------------------------

def _rules(rules) -> list[dict]:
    return sorted(({k: v for k, v in rule.items() if v is not None} for rule in rules or []),
                  key=lambda rule: rule.get("fileNamePrefix", ""))


def bucket_problems(bucket: dict) -> list[str]:
    """What's not as it should be in a bucket as `b2_list_buckets` shows it."""
    problems = []
    if bucket.get("bucketType") != "allPrivate":
        problems.append(f"not private ({bucket.get('bucketType')})")
    encryption = (bucket.get("defaultServerSideEncryption") or {}).get("value") or {}
    if encryption.get("mode") != "SSE-B2":
        problems.append(f"Backblaze's encryption not on ({encryption.get('mode')})")
    lock = (bucket.get("fileLockConfiguration") or {}).get("value") or {}
    if lock.get("isFileLockEnabled"):
        problems.append("object lock is on")
    if _rules(bucket.get("lifecycleRules")) != _rules(LIFECYCLE):
        problems.append(f"expiry rules differ: {json.dumps(bucket.get('lifecycleRules'))}")
    return problems


def key_problems(key: dict, bucket_id: str, prefix: str, capabilities: list[str]) -> list[str]:
    """What's not as it should be in a key as `b2_list_keys` shows it."""
    problems = []
    if sorted(key.get("capabilities") or []) != sorted(capabilities):
        problems.append(f"permissions {sorted(key.get('capabilities') or [])}")
    if key.get("bucketIds") != [bucket_id]:
        problems.append(f"buckets {key.get('bucketIds')}")
    if key.get("namePrefix") != prefix:
        problems.append(f"folder {key.get('namePrefix')!r}")
    if key.get("expirationTimestamp") is not None:
        problems.append("expires")
    return problems


def other_keys(keys: list[dict], bucket_id: str, made: set[str]) -> list[str]:
    """Names of the account's other keys that can reach the bucket (all buckets, or this one)."""
    return sorted(k.get("keyName", "?") for k in keys
                  if k.get("applicationKeyId") not in made and (not k.get("bucketIds") or bucket_id in k["bucketIds"]))


# --- trying the keys ------------------------------------------------------------------------------------------------

@dataclass
class Check:
    text: str
    passed: bool
    detail: str
    required: bool


@dataclass
class Trial:
    """Runs the checks and remembers each outcome. A required check that fails makes the whole setup fail;
    the others settle details for the collector and are reported."""
    say: Callable[[str], None]
    checks: list[Check] = field(default_factory=list)

    def _record(self, text: str, passed: bool, detail: str, required: bool) -> None:
        self.checks.append(Check(text, passed, detail, required))
        mark = "OK  " if passed else ("FAIL" if required else "NOTE")
        self.say(f"    {mark}  {text}" + (f"  ({detail})" if detail else ""))

    def allowed(self, text: str, action: Callable[[], object], required: bool = True):
        """The action must work; its result (True if it has none), or None if it didn't."""
        try:
            result = action()
        except Wrong as e:
            self._record(text, False, str(e), required)
            return None
        except (s3.S3Error, b2.B2Error, net.NetError) as e:
            self._record(text, False, f"answer: {e}", required)
            return None
        self._record(text, True, "", required)
        return True if result is None else result

    def refused(self, text: str, action: Callable[[], object], required: bool = True) -> bool:
        """The storage must refuse the action: 401 or 403, for the key's permissions."""
        try:
            action()
        except s3.S3Error as e:
            refused = e.status in (401, 403) and e.code not in _NOT_A_REFUSAL
            self._record(text, refused, f"refused: {e.code}" if refused else f"answer: {e}", required)
            return refused
        except net.NetError as e:
            self._record(text, False, f"no answer: {e}", required)
            return False
        self._record(text, False, "it was allowed", required)
        return False

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.required and not c.passed]


def same(got, want, what: str = "wrong content") -> None:
    if got != want:
        raise Wrong(what)


def all_versions(client: s3.Client, bucket: str, prefix: str) -> list[s3.Version]:
    versions, marker = [], None
    while True:
        page, marker = client.list_object_versions(bucket, prefix, marker)
        versions += page
        if marker is None:
            return versions


def all_names(client: s3.Client, bucket: str, prefix: str) -> list[str]:
    names, token = [], None
    while True:
        page, token = client.list_objects(bucket, prefix, token)
        names += [entry.name for entry in page]
        if token is None:
            return names


def wait_until_known(client: s3.Client, bucket: str, prefix: str, sleep=time.sleep, tries: int = 30) -> None:
    """A new key can take a moment to reach the S3 interface."""
    for _ in range(tries):
        try:
            client.list_objects(bucket, prefix)
            return
        except s3.S3Error as e:
            if e.code != "InvalidAccessKeyId":
                return
        except net.NetError:
            pass
        sleep(2)
    raise SetupError("the new keys didn't start working within a minute; try again later")


def try_keys(trial: Trial, bucket: str, clients: dict[str, s3.Client], version_of: Callable[[str], str],
             native_delete: Callable[[str, str], None]) -> None:
    """Every key's job, and what it must not do (PROTOCOL.md §8). `version_of(name)` finds a file's version ID
    without the keys under test; `native_delete(name, version_id)` deletes with the pickup key through Backblaze's
    own interface."""
    up, receipts = clients["phone-upload"], clients["phone-receipts"]
    pickup, acks = clients["collector-pickup"], clients["collector-receipts"]
    small, receipt = secrets.token_bytes(1000), secrets.token_bytes(600)
    big = secrets.token_bytes(PART + 1000)
    n1, n2, n3, n4, r1 = random_name(UP), random_name(UP), random_name(UP), random_name(UP), random_name(ACK)

    trial.say("phone-upload (Sealdrop sends with it):")
    trial.allowed("uploads a file", lambda: up.put_object(bucket, n1, small))

    def in_parts():
        upload = up.create_multipart_upload(bucket, n2)
        etags = [up.upload_part(bucket, n2, upload, 1, big[:PART]), up.upload_part(bucket, n2, upload, 2, big[PART:])]
        up.complete_multipart_upload(bucket, n2, upload, etags)

    trial.allowed("uploads a file in parts (8 MiB, then the rest)", in_parts)

    def cancelled():
        upload = up.create_multipart_upload(bucket, n3)
        up.upload_part(bucket, n3, upload, 1, small)
        up.abort_multipart_upload(bucket, n3, upload)

    trial.allowed("cancels an upload in parts", cancelled)
    trial.allowed("uploads one more file", lambda: up.put_object(bucket, n4, small))
    v1 = version_of(n1)
    trial.refused("can't read an upload", lambda: up.get_object(bucket, n1))
    trial.refused("can't list the uploads", lambda: up.list_objects(bucket, UP))
    trial.refused("can't list the upload versions", lambda: up.list_object_versions(bucket, UP))
    trial.refused("can't delete an upload for good", lambda: up.delete_object(bucket, n1, version_id=v1))
    trial.refused("can't write into ack/", lambda: up.put_object(bucket, random_name(ACK), small))
    trial.refused("can't list the receipts", lambda: up.list_objects(bucket, ACK))
    hidden = trial.allowed("can hide an upload by name (Backblaze's write permission allows it; the collector "
                           "still finds it)", lambda: up.delete_object(bucket, n4), required=False)

    trial.say("collector-receipts (the collector writes receipts with it):")
    trial.allowed("writes a receipt", lambda: acks.put_object(bucket, r1, receipt))
    rv = version_of(r1)
    trial.refused("can't list the receipts", lambda: acks.list_objects(bucket, ACK))
    trial.refused("can't read a receipt", lambda: acks.get_object(bucket, r1))
    trial.refused("can't delete a receipt for good", lambda: acks.delete_object(bucket, r1, version_id=rv))
    trial.refused("can't write into up/", lambda: acks.put_object(bucket, random_name(UP), small))
    trial.refused("can't read an upload", lambda: acks.get_object(bucket, n1))
    trial.refused("can't hide an upload", lambda: acks.delete_object(bucket, n1))

    trial.say("phone-receipts (Sealdrop reads receipts with it):")
    trial.allowed("lists the receipts",
                  lambda: same(r1 in all_names(receipts, bucket, ACK), True, "receipt not listed"))
    trial.allowed("reads a receipt", lambda: same(receipts.get_object(bucket, r1).body, receipt))
    trial.refused("can't write a receipt", lambda: receipts.put_object(bucket, random_name(ACK), small))
    trial.refused("can't hide a receipt", lambda: receipts.delete_object(bucket, r1))
    trial.refused("can't delete a receipt for good", lambda: receipts.delete_object(bucket, r1, version_id=rv))
    trial.refused("can't list the uploads", lambda: receipts.list_objects(bucket, UP))
    trial.refused("can't read an upload", lambda: receipts.get_object(bucket, n1))

    trial.say("collector-pickup (the collector picks uploads up with it):")

    def listed():
        versions = all_versions(pickup, bucket, UP)
        files = sorted(v.name for v in versions if not v.hidden)
        markers = sorted(v.name for v in versions if v.hidden)
        same(files, sorted([n1, n2, n4]), f"listed {len(files)} of the 3 uploads")
        same(markers, [n4] if hidden else [], f"listed {len(markers)} hide markers")
        return versions

    versions = trial.allowed("lists the uploads with their versions, hidden ones too", listed) or []
    by_name = {v.name: v for v in versions if not v.hidden}
    etag = by_name[n1].etag if n1 in by_name else '"?"'
    trial.allowed("reads an upload's first 152 bytes, then the rest", lambda: same(
        pickup.get_object(bucket, n1, version_id=v1, first=0, last=151, if_match=etag).body
        + pickup.get_object(bucket, n1, version_id=v1, first=152, if_match=etag).body, small))

    def if_match_refused():
        try:
            pickup.get_object(bucket, n1, version_id=v1, first=0, last=151, if_match='"0123456789abcdef"')
        except s3.S3Error as e:
            same(e.status, 412, f"answer: {e}")
            return
        raise Wrong("the storage ignored If-Match")

    trial.allowed("a read for a changed file is refused (If-Match, 412)", if_match_refused, required=False)

    def big_read():
        out = io.BytesIO()
        pickup.get_object(bucket, n2, version_id=version_of(n2), out=out)
        same(hashlib.sha256(out.getvalue()).digest(), hashlib.sha256(big).digest())

    trial.allowed("reads an upload made in parts", big_read)
    if hidden:
        trial.allowed("reads a hidden upload by its version ID",
                      lambda: same(pickup.get_object(bucket, n4, version_id=version_of(n4)).body, small),
                      required=False)
    trial.refused("can't upload", lambda: pickup.put_object(bucket, random_name(UP), small))
    trial.refused("can't hide an upload (a delete by name needs the write permission)",
                  lambda: pickup.delete_object(bucket, n1))
    trial.refused("can't list the receipts", lambda: pickup.list_objects(bucket, ACK))
    trial.refused("can't read a receipt", lambda: pickup.get_object(bucket, r1))
    trial.refused("can't write into ack/", lambda: pickup.put_object(bucket, random_name(ACK), small))

    s3_delete = trial.allowed("deletes an upload by its version ID over S3 (deleteFiles is enough)",
                              lambda: pickup.delete_object(bucket, n1, version_id=v1), required=False)
    if not s3_delete:
        trial.allowed("deletes it through Backblaze's own interface instead", lambda: native_delete(n1, v1))

    def emptied():
        for v in all_versions(pickup, bucket, UP):
            if s3_delete:
                pickup.delete_object(bucket, v.name, version_id=v.version_id)
            else:
                native_delete(v.name, v.version_id)
        same(all_versions(pickup, bucket, UP), [], "versions left")

    trial.allowed("deletes the remaining versions and hide markers; up/ is empty", emptied)


# --- the command --------------------------------------------------------------------------------------------------

@dataclass
class Made:
    bucket_id: str | None = None
    keys: dict[str, dict] = field(default_factory=dict)  # role: b2_create_key's answer (with the secret)


class Ui:
    """The terminal. Tests put their own in."""

    def say(self, text: str = "") -> None:
        print(text, flush=True)

    def secret(self, prompt: str) -> str:
        return getpass.getpass(prompt)

    def confirm(self, prompt: str) -> bool:
        return input(prompt + " [y/N] ").strip().lower() in ("y", "yes")

    def ask(self, prompt: str) -> str:
        return input(prompt)

    def pause(self, prompt: str) -> None:
        input(prompt)

    def clear(self) -> None:
        sys.stdout.write("\033[H\033[2J\033[3J")  # the screen and, where the terminal allows, its scrollback
        sys.stdout.flush()


def save_test_keys(path: Path, storage: dict) -> None:
    """Readable by the owner only. Only for a test bucket: the real keys are never written anywhere."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(storage, f, indent=2)
        f.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _role_name(role: str, test: bool) -> str:
    return f"test-{role}" if test else role


def login(ui: Ui, account_factory, needed: set[str]) -> b2.Account:
    ui.say("Paste a fresh master application key (Backblaze web console → Application Keys). It isn't shown or saved.")
    key_id = ui.secret("Master application key ID: ").strip()
    key = ui.secret("Master application key: ").strip()
    if not key_id or not key:
        raise SetupError("no key given")
    try:
        account = account_factory(key_id, key)
    except b2.B2Error as e:
        raise SetupError(f"Backblaze didn't accept the key ({e.code}). Copy both parts again, or make a new master "
                         "key.") from e
    missing = needed - account.capabilities
    if missing:
        raise SetupError("this key can't manage buckets and keys for the whole account: use the master application "
                         f"key (missing: {', '.join(sorted(missing))})")
    return account


def run(args, ui: Ui, account_factory=b2.Account, client_factory=s3.Client, sleep=time.sleep,
        now=lambda: datetime.datetime.now(datetime.UTC)) -> int:
    test = args.test
    ui.say(f"Sealdrop: setting up {'a test inbox' if test else 'the inbox'} at Backblaze B2")
    ui.say()
    account = login(ui, account_factory, NEEDED)
    if not account.region:
        raise SetupError(f"can't tell the region from {account.s3_url}")
    if account.server_time and abs((now() - account.server_time).total_seconds()) > 10 * 60:
        raise SetupError(f"this computer's clock is off by more than 10 minutes (Backblaze's time: "
                         f"{account.server_time:%Y-%m-%d %H:%M} UTC), and signed requests would fail. Set it right "
                         "and run this again. (In WSL, `wsl --shutdown` in Windows fixes a clock that drifted while "
                         "the computer slept.)")

    name = args.bucket or default_bucket(test)
    if not _BUCKET.fullmatch(name) or name.startswith("b2-"):
        raise SetupError("a bucket name is 6 to 63 characters from a–z 0–9 -, starting and ending with a letter or "
                         "digit")
    if account.find_bucket(name) is not None:
        raise SetupError(f"the bucket {name} exists already. This script only sets up a new bucket.")
    ui.say(f"Region of the account: {account.region} (endpoint {account.s3_url}).")
    if not ui.confirm(f"Make the bucket {name} there, with four keys{' (test-…)' if test else ''}?"):
        ui.say("Nothing made.")
        return 1

    made = Made()
    try:
        bucket = account.create_bucket(name, LIFECYCLE)
        made.bucket_id = bucket["bucketId"]
        found = account.find_bucket(name)
        problems = bucket_problems(found) if found else ["not found again"]
        if problems:
            raise SetupError(f"the bucket isn't as it should be: {'; '.join(problems)}")
        ui.say(f"Bucket {name}: made, and read back: private, Backblaze's encryption on, no object lock, the expiry "
               "rules.")

        for role, (prefix, capabilities) in ROLES.items():
            made.keys[role] = account.create_key(_role_name(role, test), capabilities, made.bucket_id, prefix)
        listed = {k["applicationKeyId"]: k for k in account.list_keys()}
        for role, (prefix, capabilities) in ROLES.items():
            found_key = listed.get(made.keys[role]["applicationKeyId"])
            problems = key_problems(found_key, made.bucket_id, prefix, capabilities) if found_key else ["not found"]
            if problems:
                raise SetupError(f"the key {role} isn't as it should be: {'; '.join(problems)}")
        ui.say(f"Keys: {', '.join(_role_name(r, test) for r in ROLES)}: made, and read back: each for this bucket "
               "and its folder only, no expiry date.")
        others = other_keys(list(listed.values()), made.bucket_id, {k["applicationKeyId"] for k in made.keys.values()})
        if others:
            ui.say(f"Note: other keys of the account can reach this bucket too: {', '.join(others)}. Only the master "
                   "key should, besides these four.")

        clients = {role: client_factory(account.s3_url, account.region,
                                        s3.Credentials(made.keys[role]["applicationKeyId"],
                                                       made.keys[role]["applicationKey"]))
                   for role in ROLES}
        for role, (prefix, _) in ROLES.items():
            wait_until_known(clients[role], name, prefix, sleep=sleep)

        def version_of(file_name: str) -> str:
            ids = [v["fileId"] for v in account.file_versions(made.bucket_id)
                   if v["fileName"] == file_name and v.get("action") == "upload"]
            return ids[0] if ids else "unknown"

        pickup_native = []

        def native_delete(file_name: str, version_id: str) -> None:
            if not pickup_native:
                pickup_native.append(account_factory(made.keys["collector-pickup"]["applicationKeyId"],
                                                     made.keys["collector-pickup"]["applicationKey"]))
            pickup_native[0].call("b2_delete_file_version", {"fileName": file_name, "fileId": version_id})

        ui.say()
        ui.say("Trying the keys, with test files:")
        trial = Trial(lambda text: ui.say(text if text.startswith("    ") else "  " + text))
        try_keys(trial, name, clients, version_of, native_delete)

        account.empty_bucket(made.bucket_id)
        if account.file_versions(made.bucket_id) or account.unfinished_uploads(made.bucket_id):
            raise SetupError("the test files couldn't all be deleted")
        ui.say("Test files deleted; the bucket is empty.")
        ui.say()
        notes = [c for c in trial.checks if not c.required and not c.passed]
        if trial.failed:
            raise SetupError(f"{len(trial.failed)} of {len(trial.checks)} checks failed (FAIL above): the keys "
                             "don't do exactly their job.")
        more = {0: "", 1: " One detail to know about: NOTE above."}
        ui.say(f"All {len(trial.checks) - len(notes)} required checks passed."
               + more.get(len(notes), f" {len(notes)} details to know about: NOTE above."))
    except BaseException as e:
        _undo(account, made, ui)
        if isinstance(e, SetupError):
            raise
        if isinstance(e, KeyboardInterrupt):
            raise SetupError("cancelled") from e
        if isinstance(e, (b2.B2Error, s3.S3Error, net.NetError)):
            raise SetupError(f"the storage answered unexpectedly: {e}") from e
        raise

    storage = {"endpoint": account.s3_url, "region": account.region, "bucket": name,
               "keys": {role: {"name": made.keys[role]["keyName"], "id": made.keys[role]["applicationKeyId"],
                               "secret": made.keys[role]["applicationKey"]} for role in ROLES}}
    if test:
        path = Path(args.test_keys).expanduser()
        save_test_keys(path, {"note": "Keys of a TEST bucket, made by sealdrop.setup_b2 --test. Delete this file "
                                      "once the test bucket is gone.", **storage})
        ui.say(f"The test keys are in {path} (readable by you only). They're not shown here.")
    else:
        show_keys(ui, storage)
    ui.say()
    next_steps(ui, name, test)
    return 0


def _undo(account, made: Made, ui: Ui) -> None:
    """Deletes what this run made, so nothing half-made stays."""
    ui.say()
    ui.say("Undoing what was made …")
    for role, key in made.keys.items():
        try:
            account.delete_key(key["applicationKeyId"])
        except Exception as e:  # keep going: the user is told what's left
            ui.say(f"  the key {key.get('keyName', role)} couldn't be deleted ({e}): delete it in the web console")
    if made.bucket_id:
        try:
            account.empty_bucket(made.bucket_id)
            account.delete_bucket(made.bucket_id)
        except Exception as e:
            ui.say(f"  the bucket couldn't be deleted ({e}): delete it in the web console")
    ui.say("  done: no new keys or bucket are left, unless said just above.")


def show_keys(ui: Ui, storage: dict) -> None:
    ui.say("The keys. They're shown only this once: put them into your password manager now.")
    ui.say()
    ui.say(f"  endpoint  {storage['endpoint']}")
    ui.say(f"  region    {storage['region']}")
    ui.say(f"  bucket    {storage['bucket']}")
    for role, key in storage["keys"].items():
        ui.say()
        ui.say(f"  {role}")
        ui.say(f"    key ID  {key['id']}")
        ui.say(f"    key     {key['secret']}")
    ui.say()
    ui.say("  The phone-… keys are pasted when pairing (the collector's pair command asks for them); the "
           "collector-… keys go into the collector's settings.")
    ui.say()
    ui.pause("Press Enter once they're saved. The screen is then cleared. ")
    ui.clear()
    ui.say("Screen cleared. If your terminal keeps its own history (tmux, screen, session logging), clear it too, and "
           "close this window when you're done.")


def next_steps(ui: Ui, bucket: str, test: bool) -> None:
    names = ", ".join(_role_name(r, test) for r in ROLES)
    ui.say("What's left, in the Backblaze web console:")
    ui.say("  1. Application Keys → Generate New Master Application Key → Yes. Close it without copying the new key:")
    ui.say("     the master key you pasted here then stops working. The four new keys keep working.")
    ui.say(f"  2. Buckets → {bucket}: Private, encryption enabled, and Lifecycle Settings with two rules")
    ui.say("     (up/: hide after 90 days, delete 7 days later; ack/: hide after 30 days, delete 1 day later).")
    ui.say(f"  3. Application Keys: the four keys {names}, each for the bucket {bucket} only.")
    ui.say("  4. Caps & Alerts, once for the account (Backblaze has no interface for it, so this script can't):")
    ui.say("     a daily cap for storage, downloads, Class B and Class C transactions, for example $0.05 each.")
    ui.say("     Everyday use stays far below; a flood of junk uploads can't cost more than that a day.")


def manage_keys(ui: Ui, account_factory=b2.Account) -> int:
    """Lists Sealdrop's keys (by their names) and deletes the ones the owner picks. Never shows a secret: Backblaze
    doesn't give them out again anyway, and of each key ID only the last four characters are shown."""
    ui.say("Sealdrop: the storage keys at Backblaze B2")
    ui.say()
    account = login(ui, account_factory, NEEDED_FOR_KEYS)
    buckets = {b["bucketId"]: b["bucketName"]
               for b in account.call("b2_list_buckets", {"accountId": account.account_id})["buckets"]}
    keys = account.list_keys()
    ours = sorted((k for k in keys if k.get("keyName") in KEY_NAMES),
                  key=lambda k: (k["keyName"].startswith("test-"),
                                 [buckets.get(b, "?") for b in k.get("bucketIds") or []], k["keyName"]))
    ui.say()
    if not ours:
        ui.say(f"No Sealdrop keys in this account ({len(keys)} other keys)." if keys else "No keys in this account.")
        return 0
    ui.say("Sealdrop's keys:")
    for number, k in enumerate(ours, 1):
        where = ", ".join(buckets.get(b, "a deleted bucket") for b in k.get("bucketIds") or []) or "ALL buckets"
        ui.say(f"  {number:>2}. {k['keyName']:<24} key ID …{k['applicationKeyId'][-4:]}   "
               f"{where} {k.get('namePrefix') or ''}   {', '.join(sorted(k.get('capabilities') or []))}")
    if len(keys) > len(ours):
        ui.say(f"  ({len(keys) - len(ours)} other keys of the account aren't Sealdrop's and aren't shown.)")
    ui.say()
    ui.say("A lost phone: delete its phone-upload and phone-receipts. The key ID's end is in your password manager.")
    answer = ui.ask("Numbers of the keys to delete (for example: 1 2), or just Enter to delete none: ").strip()
    if not answer:
        ui.say("Nothing deleted.")
        return 0
    try:
        numbers = sorted({int(part) for part in answer.replace(",", " ").split()})
    except ValueError:
        raise SetupError("only numbers from the list, please; nothing was deleted") from None
    if not numbers or numbers[0] < 1 or numbers[-1] > len(ours):
        raise SetupError(f"the numbers go from 1 to {len(ours)}; nothing was deleted")
    chosen = [ours[n - 1] for n in numbers]
    for k in chosen:
        ui.say(f"  {k['keyName']}  (key ID …{k['applicationKeyId'][-4:]})")
    if not ui.confirm(f"Delete {'this key' if len(chosen) == 1 else f'these {len(chosen)} keys'} for good? Whatever "
                      "uses it stops working at once."):
        ui.say("Nothing deleted.")
        return 0
    for k in chosen:
        account.delete_key(k["applicationKeyId"])
    left = {k["applicationKeyId"] for k in account.list_keys()}
    if any(k["applicationKeyId"] in left for k in chosen):
        raise SetupError("Backblaze still lists a key that was deleted; run this again to check")
    ui.say(f"Deleted, and checked: {'it is' if len(chosen) == 1 else 'they are'} gone.")
    ui.say()
    ui.say("Now replace the master key: web console → Application Keys → Generate New Master Application Key → Yes,")
    ui.say("and close it without copying the new one.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sealdrop.setup_b2",
                                     description="Sets up a Sealdrop inbox at Backblaze B2 and tries its keys.")
    parser.add_argument("--test", action="store_true", help="a test bucket; its keys go into a file instead")
    parser.add_argument("--bucket", help="the bucket's name (default: inbox- or test-inbox- and random letters)")
    parser.add_argument("--test-keys", default="~/.config/sealdrop-test/storage.json",
                        help="with --test: where the keys go (default: %(default)s)")
    parser.add_argument("--keys", action="store_true",
                        help="list Sealdrop's keys and delete the ones you choose, instead of setting up")
    args = parser.parse_args(argv)
    if args.keys and (args.test or args.bucket):
        parser.error("--keys goes alone")
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Run this in a terminal: it asks for a key and shows the result on screen, never into a file or pipe.",
              file=sys.stderr)
        return 2
    if not args.test and not args.keys and (os.environ.get("TMUX") or os.environ.get("STY")):
        print("Note: tmux and screen keep their own history of what's shown, and the keys will be shown once.")
    try:
        return manage_keys(Ui()) if args.keys else run(args, Ui())
    except SetupError as e:
        print(f"\nStopped: {e}", file=sys.stderr)
        print("\nThe master key you pasted still works. Unless you run this again right away, replace it: web console "
              "→ Application Keys → Generate New Master Application Key, without copying the new one.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
