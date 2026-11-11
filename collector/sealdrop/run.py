"""One run of the collector over the inbox (PROTOCOL.md §10, "Handling the inbox, in this order").

The order is store, then receipt, then delete: nothing leaves the inbox before it's safe on disk and the phone has
been told. A run that stops anywhere (a power cut, no network, a full disk) is picked up by the next one.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import logging
import os
import random
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import __version__, encoding, errors, net, receipts, s3
from .errors import Rejected
from .manifests import Delivery, FileEntry, content_prefix, delivery_digest, good_app, good_delivery
from .reading import check_deliveries, open_upload
from .root import Location, Root, Sender, fsync_dir, write_private
from .sealed import INFO_TO_COLLECTOR, check_listed_size, open_header, seal
from .sizes import KIND_BUNDLE, KIND_PAIR, KIND_RECEIPT, PREFIX
from .state import DAY, State

log = logging.getLogger("sealdrop")

MAX_LISTED = 10_000
MAX_DOWNLOADS = 200
PAUSES = (30, 60, 120)  # §8: the collector's retries within a run
STATUS_EVERY = DAY      # a status receipt for each sender that got none for a day
_NAME = re.compile(r"[a-z2-7]{32}")


class Stop(Exception):
    """The run ends here (§10, "Local errors are never rejections"): `why` is network, key-refused, storage-cap or
    local."""

    def __init__(self, why: str, detail: str = ""):
        super().__init__(f"{why}: {detail}" if detail else why)
        self.why = why


def random_name() -> str:
    """32 characters from a–z 2–7: 160 random bits (§8)."""
    return encoding.base32(os.urandom(20)).lower()


class Storage:
    """The two locations, each with its own key, and §8's retries."""

    def __init__(self, up: Location, ack: Location, up_client: s3.Client, ack_client: s3.Client,
                 sleep: Callable[[float], None] = time.sleep):
        self.up, self.ack = up, ack
        self.up_client, self.ack_client = up_client, ack_client
        self.sleep = sleep

    def retrying(self, attempt: Callable[[], object]):
        """Network errors, 5xx and 429 are tried again after 30 s, 1 and 2 minutes; then the run ends. 401 and 403
        end it at once."""
        for tries in range(len(PAUSES) + 1):
            try:
                return attempt()
            except net.NetError as e:
                problem = str(e)
            except s3.S3Error as e:
                if e.status in (401, 403):
                    raise Stop("storage-cap" if "cap exceeded" in e.message.lower() else "key-refused",
                               e.code) from None
                if e.status != 429 and e.status < 500:
                    raise
                problem = f"{e.status} {e.code}"
            if tries == len(PAUSES):
                raise Stop("network", problem)
            pause = PAUSES[tries] * random.uniform(0.8, 1.2)
            log.info("storage didn't answer (%s); trying again in %d s", problem, pause)
            self.sleep(pause)


@dataclass
class Outcome:
    """What a run did, for the log, `status.json` and the tests."""
    skipped: str | None = None  # the lock was taken, or the clock isn't set
    listed: int = 0
    downloaded: int = 0
    stored: int = 0
    duplicates: int = 0
    conflicts: int = 0
    rejected: int = 0
    receipts: int = 0
    deleted: int = 0
    vanished: int = 0
    stopped: str | None = None
    warnings: list[str] = field(default_factory=list)
    left: int | None = None  # uploads still in the inbox after the run; None if the listing failed
    oldest_left: int | None = None  # the oldest of them (LastModified)


@dataclass
class _Listed:
    version: s3.Version
    others: list[s3.Version] = field(default_factory=list)  # hide markers of the same name


class Collector:
    def __init__(self, root: Root, storage: Storage | None = None, *, now: Callable[[], int] | None = None,
                 machine_id: Path = Path("/etc/machine-id"), cpuinfo: Path = Path("/proc/cpuinfo")):
        self.root = root
        self.config = root.config()
        self.storage = storage or make_storage(root)
        self.now = now or (lambda: int(time.time() * 1000))
        self.machine_id, self.cpuinfo = machine_id, cpuinfo

    # --- the run ----------------------------------------------------------------------------------------------------

    def run(self) -> Outcome:
        self.root.check()
        with Lock(self.root / "state/lock") as locked:
            if not locked:
                log.info("another run, a pairing, a check or a backup holds the lock; skipped")
                return Outcome(skipped="locked")
            if not clock_ok(self.config["clock_check"]):
                log.warning("the system clock isn't synchronized yet; skipped")
                return Outcome(skipped="clock")
            state = State(self.root / "state/state.db")
            try:
                return self._run(state)
            finally:
                state.close()

    def _run(self, state: State) -> Outcome:
        out = Outcome()
        self.state = state
        self.senders = self.root.senders()
        self.opening = self.root.opening_keys()
        self.instance = self.root.instance(self.machine_id, self.cpuinfo)
        self.disk_full = False
        self.downloads = 0
        self.limited = False  # the download limit left uploads for the next run
        self.first_get: set[tuple[str, str]] = set()
        now = self.now()
        try:
            listed, end_reached, start, after = self._list()
        except Stop as e:
            out.stopped = e.why
            log.warning("the run stopped while listing: %s", e)
            self._write_receipts(out)  # writing receipts may still work (another key)
            self._finish(out)
            return out
        out.listed = len(listed)
        self._tidy(listed)
        items, strays = self._order(listed)
        left_over = 0
        for item in items:
            if out.stopped:
                left_over += 1
                continue
            try:
                if not self._handle(item.version, out):
                    left_over += 1
            except Stop as e:
                out.stopped = e.why
                left_over += 1
                log.warning("the run stopped at an upload: %s", e)
            except OSError as e:
                out.stopped = "local"
                left_over += 1
                log.error("a local error stopped the run (nothing was noted for this upload): %s", e)
        # A walk through `up/` that takes more than one run, for its size alone: the inbox is flooded (step 1).
        flooded = not end_reached or self.limited
        state.put("flooded", flooded)
        self._write_receipts(out)
        deleted = self._delete(items, strays, out)
        left = [i.version for i in items if (i.version.name, i.version.version_id) not in deleted]
        out.left = len(left)
        out.oldest_left = min((v.modified for v in left if v.modified), default=None)
        # The listing continues after this run's part only if all of it was handled (step 1).
        if left_over == 0 and not out.stopped:
            state.put("marker", None if end_reached else after)
        else:
            state.put("marker", start)
        state.forget_old(now)
        self._finish(out)
        return out

    # --- step 1: list -----------------------------------------------------------------------------------------------

    def _list(self):
        up = self.storage.up
        start = self.state.get("marker")
        marker = tuple(start) if start else None
        versions: list[s3.Version] = []
        while True:
            page, nxt = self.storage.retrying(
                lambda m=marker: self.storage.up_client.list_object_versions(up.bucket, up.prefix, m))
            versions += page
            if nxt is None:
                return versions, True, start, None
            marker = nxt
            if len(versions) >= MAX_LISTED:
                return versions, False, start, list(nxt)

    # --- step 2: tidy up --------------------------------------------------------------------------------------------

    def _tidy(self, listed: list[s3.Version]) -> None:
        tmp = self.root / "store/.tmp"
        if tmp.exists():
            shutil.rmtree(tmp)
        known = {incoming_name(v.name, v.version_id) for v in listed}
        week = time.time() - 7 * 24 * 3600
        for p in (self.root / "incoming").iterdir():
            if p.name not in known and p.stat().st_mtime < week:
                p.unlink()

    # --- step 3: order ----------------------------------------------------------------------------------------------

    def _order(self, listed: list[s3.Version]) -> tuple[list[_Listed], list[s3.Version]]:
        """File versions oldest first; hide markers go with their name's versions. Strays (hide markers on their
        own, names that aren't a prefix plus 32 characters) are deleted and never reported."""
        prefix = self.storage.up.prefix
        by_name: dict[str, list[s3.Version]] = {}
        for v in listed:
            by_name.setdefault(v.name, []).append(v)
        items, strays = [], []
        for name, versions in by_name.items():
            files = [v for v in versions if not v.hidden]
            markers = [v for v in versions if v.hidden]
            if not name.startswith(prefix) or not _NAME.fullmatch(name[len(prefix):]) or not files:
                strays += versions
                continue
            for f in files:
                items.append(_Listed(f, [m for m in markers if m.modified <= f.modified]))
        items.sort(key=lambda i: (i.version.modified, i.version.name, i.version.version_id))
        return items, strays

    # --- steps 4 to 10: one upload ------------------------------------------------------------------------------

    def _handle(self, v: s3.Version, out: Outcome) -> bool:
        """False if the upload waits for a later run (the download limit, space)."""
        state = self.state
        if state.handled(v.name, v.version_id) is not None:
            return True  # noted before: only its receipts or its delete are left
        now = self.now()
        max_sealed = self.config["max_sealed"]
        # Step 4: the size, without downloading.
        try:
            check_listed_size("up", v.size, max_sealed)
        except Rejected as r:
            return self._reject(v, None, r, out, now)
        # Step 5: the first 152 bytes alone.
        path = self.root / "incoming" / incoming_name(v.name, v.version_id)
        try:
            prefix = self._prefix(v, path)
        except _Vanished:
            self._vanished(v, out, now)
            return True
        try:
            header = open_header(prefix, self.opening, INFO_TO_COLLECTOR, (KIND_BUNDLE, KIND_PAIR))
            if header.sealed_size != v.size:
                raise Rejected(errors.DAMAGED, "size doesn't match the header")
            sender = self.senders.get(header.writer_key_id) if header.kind == KIND_BUNDLE else None
            if sender is None:
                raise Rejected(errors.UNKNOWN_SENDER)
        except Rejected as r:
            path.unlink(missing_ok=True)
            return self._reject(v, None, r, out, now)
        # Step 6: the rest, if there's room and this run may still download.
        if self.downloads >= MAX_DOWNLOADS:
            self.limited = True
            return False
        if not self._room_for(v.size):
            self.disk_full = True
            log.warning("not enough free space for an upload of %d bytes; it waits", v.size)
            return False
        try:
            self._download(v, path)
        except _Vanished:
            self._vanished(v, out, now)
            return True
        self.downloads += 1
        out.downloaded += 1
        sha = file_sha256(path)
        # Step 7: a file handled before.
        if state.known_file(sha) is not None:
            with state.transaction():
                state.note_known(v.name, v.version_id, sha, v.size, now)
            path.unlink()
            log.info("upload %s… is a file handled before; same result as then", v.name[-8:])
            return True
        # Steps 8 to 10: check, open, store, note.
        self._open_and_store(v, path, sha, sender, out)
        return True

    def _prefix(self, v: s3.Version, path: Path) -> bytes:
        if path.exists() and path.stat().st_size >= PREFIX:
            with open(path, "rb") as f:
                return f.read(PREFIX)
        reply = self.storage.retrying(lambda: self._get(v, 0, PREFIX - 1))
        if len(reply.body) != PREFIX:
            raise Stop("network", "short header reply")
        with open(path, "wb") as f:
            f.write(reply.body)
            f.flush()
            os.fsync(f.fileno())
        return reply.body

    def _get(self, v: s3.Version, first: int, last: int | None, out=None) -> net.Reply:
        """A GET of this version; the first one in a run that answers 404 means it vanished (§10)."""
        up = self.storage.up
        key = (v.name, v.version_id)
        first_in_run = key not in self.first_get
        self.first_get.add(key)
        try:
            return self.storage.up_client.get_object(up.bucket, v.name, version_id=v.version_id, first=first,
                                                     last=last, if_match=v.etag if first else None, out=out)
        except s3.S3Error as e:
            if e.status == 404 and first_in_run:
                raise _Vanished() from None
            raise

    def _download(self, v: s3.Version, path: Path) -> None:
        """The rest after what's already on disk, resumed with `Range` after a drop; written to disk."""
        restarted = False
        while True:
            have = path.stat().st_size if path.exists() else 0
            if have == v.size:
                return
            if have > v.size:
                path.unlink()
                continue

            def attempt():
                with open(path, "ab") as f:
                    try:
                        start = f.tell()
                        self._get(v, start, None, out=f)
                    finally:
                        f.flush()
                        os.fsync(f.fileno())
            try:
                self.storage.retrying(attempt)
            except s3.S3Error as e:
                if e.status == 412 and not restarted:  # the upload changed under the same name: from the start
                    path.unlink()
                    restarted = True
                    continue
                raise Stop("network", f"{e.status} {e.code}") from None

    def _room_for(self, size: int) -> bool:
        need = 2 * size + self.config["free_reserve"]
        return all(shutil.disk_usage(self.root / name).free >= need for name in ("incoming", "store"))

    def _vanished(self, v: s3.Version, out: Outcome, now: int) -> None:
        if v.modified and v.modified > now - self.config["vanish_days"] * DAY:
            with self.state.transaction():
                self.state.add_vanished(v.name, v.version_id, now)
            out.vanished += 1
            log.warning("upload %s… vanished before it was picked up: is something else taking uploads?",
                        v.name[-8:])

    def _reject(self, v: s3.Version, sha: str | None, r: Rejected, out: Outcome, now: int) -> bool:
        with self.state.transaction():
            self.state.note_rejected(v.name, v.version_id, sha, v.size, r.reason, now, self.storage.up.prefix)
        out.rejected += 1
        log.warning("upload %s… (%d bytes) rejected: %s", v.name[-8:], v.size, r.reason)
        return True

    def _open_and_store(self, v: s3.Version, path: Path, sha: str, sender: Sender, out: Outcome) -> None:
        now = self.now()
        tmp_root = self.root / "store/.tmp"
        writer = None
        try:
            with open(path, "rb") as f:
                sealed = open_upload(f, v.size, self.opening, {sender.key_id: sender.verifier()},
                                     self.config["max_sealed"])
                message = sealed.header.message_id.hex()
                writer = _TmpWriter(tmp_root / message)
                verdicts = check_deliveries(sealed, writer.sink)
                writer.close()
        except Rejected as r:
            if writer is not None:
                writer.discard()
            self._keep_rejected(path, sha, r.reason, now)
            self._reject(v, sha, r, out, now)
            return
        results = []
        for index, verdict in enumerate(verdicts):
            d = verdict.delivery
            entry = {"app": d.app, "delivery": d.delivery, "digest": d.digest}
            if not verdict.ok:
                writer.discard_delivery(d)
                results.append({**entry, "result": "rejected", "reason": verdict.reason})
                log.warning("a delivery in upload %s… rejected: %s", v.name[-8:], verdict.reason)
                continue
            results.append({**entry, **self._store(d, writer.folder_of(d), sender, now, out)})
        stored_entry = {"message": message, "sealed_sha256": sha, "received": now, "deliveries": results}
        with self.state.transaction():
            self.state.note_stored(v.name, v.version_id, sha, v.size, sender.hex, stored_entry, now)
            self.state.put("last_pickup", now)
        writer.discard()
        path.unlink()
        log.info("upload %s… (%d bytes) picked up from %s: %d deliveries", v.name[-8:], v.size, sender.label,
                 len(results))

    def _store(self, d: Delivery, src: Path, sender: Sender, now: int, out: Outcome) -> dict:
        """Step 9 for one delivery whose files are complete and checked in `src`."""
        state = self.state
        known = state.delivery(d.app, d.delivery)
        if known is not None:
            digest, first_sender, seq = known
            if digest == d.digest:
                out.duplicates += 1
                shutil.rmtree(src)
                return {"result": "duplicate", **({"seq": seq} if first_sender == sender.hex else {})}
            return self._conflict(d, src, now, out)
        dest_app = self.root / "store" / d.app
        dest = dest_app / d.delivery
        new_app = not dest_app.exists()
        if new_app:
            dest_app.mkdir(mode=0o700)
            fsync_dir(self.root / "store")
        fsync_tree(src)
        try:
            os.rename(src, dest)
        except OSError as e:
            if e.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                raise
            # Moved in by a run that stopped before noting it: the same content counts as this one.
            if folder_digest(dest) != d.digest:
                return self._conflict(d, src, now, out)
            shutil.rmtree(src)
        fsync_dir(dest_app)
        with state.transaction():
            seq = state.next_seq(sender.hex)
            state.add_delivery(d.app, d.delivery, d.digest, sender.hex, seq, now)
        out.stored += 1
        return {"result": "stored", "seq": seq}

    def _conflict(self, d: Delivery, src: Path, now: int, out: Outcome) -> dict:
        out.conflicts += 1
        target = self.root / "conflicts" / d.app / d.delivery / d.digest
        if target.exists():
            shutil.rmtree(src)
        else:
            parent = target.parent
            made = []
            for folder in (parent.parent, parent):
                if not folder.exists():
                    folder.mkdir(mode=0o700)
                    made.append(folder)
            fsync_tree(src)
            os.rename(src, target)
            fsync_dir(parent)
            for folder in made:
                fsync_dir(folder.parent)
        if not self.state.conflict_known(d.app, d.delivery, d.digest):
            with self.state.transaction():
                self.state.add_conflict(d.app, d.delivery, d.digest, now)
            log.warning("conflict: %s delivery %s was already stored with other content; the new content is in "
                        "conflicts/", d.app, d.delivery)
        return {"result": "conflict"}

    def _keep_rejected(self, path: Path, sha: str, reason: str, now: int) -> None:
        """A downloaded file that was rejected goes to rejected/ with its reason; at most 1 GiB in all."""
        folder = self.root / "rejected"
        target = folder / f"{sha}.sealed"
        os.replace(path, target)
        (folder / f"{sha}.reason").write_text(json.dumps({"reason": reason, "at": now}) + "\n")
        fsync_dir(folder)
        files = sorted(folder.glob("*.sealed"), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in files)
        while files and total > self.config["rejected_limit"]:
            oldest = files.pop(0)
            total -= oldest.stat().st_size
            oldest.unlink()
            oldest.with_suffix(".reason").unlink(missing_ok=True)

    # --- step 11: receipts ------------------------------------------------------------------------------------------

    def _write_receipts(self, out: Outcome) -> None:
        state, now = self.state, self.now()
        owed = state.receipts_owed()
        for sender_hex, entries in owed.items():
            if encoding.unhex(sender_hex, 32) not in self.senders:  # unpaired since: nobody to tell
                with state.transaction():
                    state.receipts_written([(n, vid) for n, vid, _ in entries])
        status = self.status(out)
        for sender in self.senders.values():
            entries = owed.get(sender.hex, [])
            rejected, more, last_id = state.rejections_for(sender.hex, sender.paired)
            # A status receipt once a day, and at once when the collector's warnings change (so a phone hears of a
            # full disk or the storage cap without waiting a day).
            changed = state.get(f"warned:{sender.hex}", []) != status["warnings"]
            if not entries and not rejected and not changed and now - state.last_receipt(sender.hex) < STATUS_EVERY:
                continue
            manifests = pack_receipts(sender.key_id, now, [e for _, _, e in entries], rejected,
                                      {**status, "seq": state.seq(sender.hex), "rejected_more": more})
            try:
                for manifest in manifests:
                    self._upload_receipt(sender, manifest, now)
                    out.receipts += 1
            except Stop as e:
                out.stopped = out.stopped or e.why
                log.warning("couldn't upload a receipt (it's written next run): %s", e)
                return
            with state.transaction():
                state.receipts_written([(n, vid) for n, vid, _ in entries])
                state.told(sender.hex, last_id, now, status["warnings"])

    def _upload_receipt(self, sender: Sender, manifest: dict, now: int) -> None:
        import io
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        content = content_prefix(manifest)
        sealed = io.BytesIO()
        seal(sealed, KIND_RECEIPT, [content], len(content), X25519PublicKey.from_public_bytes(sender.open),
             self.root.signer(), now)
        ack = self.storage.ack
        name = ack.prefix + random_name()
        self.storage.retrying(lambda: self.storage.ack_client.put_object(ack.bucket, name, sealed.getvalue()))

    def status(self, out: Outcome) -> dict:
        """§6 `status`, without the per-sender `seq` and `rejected_more`."""
        now = self.now()
        week = now - 7 * DAY
        return {
            "collector": __version__,
            "instance": self.instance.hex(),
            "seq": 0,
            "last_pickup": self.state.get("last_pickup"),
            "last_backup": last_backup(self.root),
            "free_bytes": shutil.disk_usage(self.root / "store").free,
            "max_sealed": self.config["max_sealed"],
            "warnings": self.warnings(out),
            "rejected_7d": self.state.rejected_since(week),
            "rejected_more": 0,
            "vanished_7d": self.state.vanished_since(week),
        }

    def warnings(self, out: Outcome) -> list[str]:
        found = []
        if self.disk_full:
            found.append("disk-full")
        if self.state.get("flooded", False):
            found.append("inbox-flooded")
        if self.now() - self.state.last_conflict() < 7 * DAY:
            found.append("conflict")
        if out.stopped == "storage-cap":
            found.append("storage-cap")
        return found

    # --- step 12: delete --------------------------------------------------------------------------------------------

    def _delete(self, items: list[_Listed], strays: list[s3.Version], out: Outcome) -> set[tuple[str, str]]:
        """Deletes what was handled; returns the (name, version ID) pairs that are gone."""
        waiting = self.state.waiting_for_receipt()
        gone: set[tuple[str, str]] = set()
        doomed = list(strays)
        for item in items:
            v = item.version
            if self.state.handled(v.name, v.version_id) is None or (v.name, v.version_id) in waiting:
                continue
            doomed += [v] + item.others
        up = self.storage.up
        for v in doomed:
            def attempt(v=v):
                try:
                    self.storage.up_client.delete_object(up.bucket, v.name, version_id=v.version_id)
                except s3.S3Error as e:
                    if e.status != 404:
                        raise
            try:
                self.storage.retrying(attempt)
                out.deleted += 1
                gone.add((v.name, v.version_id))
            except Stop as e:
                out.stopped = out.stopped or e.why
                log.warning("couldn't delete a handled upload (it's deleted next run): %s", e)
                return gone
            except s3.S3Error as e:
                log.warning("couldn't delete upload %s…: %s", v.name[-8:], e)
        return gone

    # --- status.json ------------------------------------------------------------------------------------------------

    def _finish(self, out: Outcome) -> None:
        out.warnings = self.warnings(out)
        report = {"time": self.now(), "instance": self.instance.hex(), "last_pickup": self.state.get("last_pickup"),
                  "warnings": out.warnings, "stopped": out.stopped,
                  "storage": {"key-refused": "storage key refused", "storage-cap": "storage cap reached",
                              "network": "storage didn't answer"}.get(out.stopped or ""),
                  "run": {k: getattr(out, k) for k in ("listed", "downloaded", "stored", "duplicates", "conflicts",
                                                       "rejected", "receipts", "deleted", "vanished")},
                  **self._overview(out)}
        write_private(self.root / "state/status.json", json.dumps(report, indent=2).encode() + b"\n")
        log.info("run done: %s", json.dumps(report["run"]))

    def _overview(self, out: Outcome) -> dict:
        """For `status --json` (a dashboard): no keys, no file names, nothing the storage could use."""
        state, now = self.state, self.now()
        return {
            "inbox": None if out.left is None else {
                "left": out.left, "oldest": out.oldest_left, "whole": not state.get("flooded", False)},
            "senders": {s.hex: {"last_upload": state.last_delivery(s.hex), "last_receipt": state.last_receipt(s.hex) or None,
                                "deliveries": state.delivery_count(s.hex)} for s in self.senders.values()},
            "rejected": {"last_7_days": state.rejected_since(now - 7 * DAY), "recent": state.recent_rejections(5)},
            "store": {"deliveries": state.delivery_count(), "free_bytes": shutil.disk_usage(self.root / "store").free},
        }


# --- receipts: packing within 256 KiB ---------------------------------------------------------------------------

def pack_receipts(for_key_id: bytes, now: int, stored: list[dict], rejected: list[dict], status: dict) -> list[dict]:
    """One or more receipt manifests (§6, Size): `rejected` in the first; an entry too big for one receipt is split
    by deliveries, each part repeating `message`, `sealed_sha256` and `received`."""
    manifests = []
    current = receipts.receipt_manifest(for_key_id, now, [], rejected, status)
    for entry in stored:
        parts = [entry]
        while parts:
            part = parts.pop(0)
            current["stored"].append(part)
            if receipts.content_fits(current):
                continue
            current["stored"].pop()
            if current["stored"] or current["rejected"]:
                manifests.append(current)
                current = receipts.receipt_manifest(for_key_id, now, [], [], status)
                parts.insert(0, part)
                continue
            half = len(part["deliveries"]) // 2
            if half == 0:
                raise ValueError("a single delivery entry doesn't fit into a receipt")
            parts[:0] = [{**part, "deliveries": part["deliveries"][:half]},
                         {**part, "deliveries": part["deliveries"][half:]}]
    manifests.append(current)
    return manifests


# --- files ------------------------------------------------------------------------------------------------------

class _Vanished(Exception):
    pass


class _TmpWriter:
    """Writes the files of the deliveries that passed §5 below `store/.tmp/<message ID>/<n>/`, n counting the
    deliveries. Paths come only from manifests that passed §5; files are created with O_EXCL and O_NOFOLLOW."""

    def __init__(self, folder: Path):
        self.folder = folder
        self.index: dict[int, int] = {}
        self.fd: int | None = None
        folder.parent.mkdir(exist_ok=True, mode=0o700)
        folder.mkdir(mode=0o700)

    def folder_of(self, d: Delivery) -> Path:
        return self.folder / str(self.index.get(id(d), -1))

    def sink(self, d: Delivery, entry: FileEntry):
        # The names were checked by check_bundle; checked again here, as no unchecked string may reach a path.
        assert d.problem is None and good_app(d.app) and good_delivery(d.delivery)
        self.close()
        n = self.index.setdefault(id(d), len(self.index))
        target = self.folder / str(n)
        parts = entry.path.split("/")
        for part in parts[:-1]:
            target = target / part
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.fd = os.open(target / parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        fd = self.fd

        def write(data: bytes) -> None:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        return write

    def close(self) -> None:
        if self.fd is not None:
            os.fsync(self.fd)
            os.close(self.fd)
            self.fd = None

    def discard_delivery(self, d: Delivery) -> None:
        if id(d) in self.index:
            shutil.rmtree(self.folder_of(d), ignore_errors=True)

    def discard(self) -> None:
        self.close()
        shutil.rmtree(self.folder, ignore_errors=True)


def fsync_tree(folder: Path) -> None:
    """Every folder below and including `folder` (the files were synced as they were closed)."""
    for current, dirs, _ in os.walk(folder, topdown=False):
        fsync_dir(Path(current))


def folder_digest(folder: Path) -> str:
    entries = []
    for current, _, files in os.walk(folder):
        for name in files:
            p = Path(current) / name
            entries.append(FileEntry(p.relative_to(folder).as_posix(), p.stat().st_size, file_sha256(p)))
    return delivery_digest(entries)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def incoming_name(name: str, version_id: str) -> str:
    return hashlib.sha256(name.encode() + b"\x00" + version_id.encode()).hexdigest()


def last_backup(root: Root) -> int | None:
    """`state/last-backup`, written by the server's backup job if it has one: milliseconds since 1970."""
    try:
        value = int((root / "state/last-backup").read_text().strip())
        return value if value >= 0 else None
    except (OSError, ValueError):
        return None


def clock_ok(check: str) -> bool:
    if check == "off":
        return True
    try:
        result = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], capture_output=True,
                                text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.stdout.strip() == "yes"


def make_storage(root: Root, sleep: Callable[[float], None] = time.sleep) -> Storage:
    config = root.config()
    up, ack = root.locations()
    pickup, receipts_key = config["keys"]["pickup"], config["keys"]["receipts"]
    return Storage(up, ack,
                   s3.Client(up.endpoint, up.region, s3.Credentials(pickup["id"], pickup["secret"])),
                   s3.Client(ack.endpoint, ack.region, s3.Credentials(receipts_key["id"], receipts_key["secret"])),
                   sleep)


class Lock:
    """One run at a time (§10). The `pair` command holds it while it waits, `verify` while it checks, and a backup job
    may hold it for its snapshot (`flock` on `state/lock`): runs skip meanwhile."""

    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None

    def __enter__(self) -> bool:
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            os.close(self.fd)
            self.fd = None
            return False

    def __exit__(self, *exc) -> None:
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None
