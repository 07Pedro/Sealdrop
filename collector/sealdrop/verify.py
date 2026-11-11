"""`sealdrop verify`: checks the store against the collector's notes, and changes neither.

For every delivery the notes list (`state/state.db`), its folder in `store/` must be there and hold exactly the files
it was stored with: the same digest as at pickup (§4). Folders in `store/` that the notes don't list are counted too.

It holds the collector's lock while it checks, so no run moves a delivery in meanwhile; runs skip and carry on after.
The only thing it writes is its result, `state/verify.json` (counts and times, no names), for `status --json`. It also
works on a restored copy of a data root, without the keys and settings, and then writes nothing if it can't.
"""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

from .root import Root, write_private
from .run import folder_digest

RESULT = "state/verify.json"


@dataclass
class Found:
    deliveries: int = 0
    missing: list[str] = field(default_factory=list)     # noted, but no folder in the store
    changed: list[str] = field(default_factory=list)     # the files differ from what was stored
    unreadable: list[str] = field(default_factory=list)  # the disk couldn't read a file
    unknown: list[str] = field(default_factory=list)     # in the store, but not in the notes

    @property
    def ok(self) -> bool:
        return not (self.missing or self.changed or self.unreadable or self.unknown)

    def record(self, time_ms: int, took_ms: int) -> dict:
        """What `state/verify.json` keeps: counts only, never names."""
        return {"time": time_ms, "took_ms": took_ms, "ok": self.ok, "deliveries": self.deliveries,
                "missing": len(self.missing), "changed": len(self.changed), "unreadable": len(self.unreadable),
                "unknown": len(self.unknown)}


class NoNotes(Exception):
    """The folder has no collector notes to check against."""


def noted_deliveries(root: Root) -> list[tuple[str, str, str]]:
    """(app, delivery, digest) of every stored delivery, from the notes, opened read-only.

    Called with the lock held (or on a copy), so nothing writes to the notes meanwhile. A run closes them completely,
    so there's normally no write-ahead log: then they're read as a fixed file, and nothing is created next to them.
    Only after a crash that left one are they opened the usual way, which reads it."""
    path = root / "state/state.db"
    if not path.is_file():
        raise NoNotes(f"{root.path} has no collector notes (state/state.db)")
    wal = path.with_name(path.name + "-wal")
    mode = "mode=ro" if wal.exists() and wal.stat().st_size > 0 else "immutable=1"
    db = sqlite3.connect(f"file:{urllib.parse.quote(str(path))}?{mode}", uri=True)
    try:
        return db.execute("SELECT app, delivery, digest FROM deliveries ORDER BY app, delivery").fetchall()
    finally:
        db.close()


def check(root: Root) -> Found:
    found = Found()
    noted = noted_deliveries(root)
    found.deliveries = len(noted)
    store = root / "store"
    for app, delivery, digest in noted:
        folder = store / app / delivery
        name = f"{app}/{delivery}"
        if not folder.is_dir() or folder.is_symlink():
            found.missing.append(name)
            continue
        try:
            if folder_digest(folder) != digest:
                found.changed.append(name)
        except OSError:
            found.unreadable.append(name)
    known = {(app, delivery) for app, delivery, _ in noted}
    # Anything starting with "." isn't a delivery (store/.tmp is the collector's own).
    for app in sorted(os.listdir(store)) if store.is_dir() else []:
        if app.startswith("."):
            continue
        if not (store / app).is_dir() or (store / app).is_symlink():
            found.unknown.append(app)
            continue
        for delivery in sorted(os.listdir(store / app)):
            if not delivery.startswith(".") and (app, delivery) not in known:
                found.unknown.append(f"{app}/{delivery}")
    return found


def holding_the_lock(root: Root, waiting: Callable[[], None]) -> int | None:
    """Takes the collector's lock, waiting for a run or a pairing in progress. None on a copy without a lock file."""
    try:
        fd = os.open(root / "state/lock", os.O_RDONLY)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        waiting()
        fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def verify(root: Root, waiting: Callable[[], None] = lambda: None,
           clock: Callable[[], int] = lambda: int(time.time() * 1000)) -> tuple[Found, dict, bool]:
    """Checks, and writes `state/verify.json` if it can: the result, its record, and whether it was written."""
    fd = holding_the_lock(root, waiting)
    try:
        start = clock()
        found = check(root)
        record = found.record(start, clock() - start)
        try:
            write_private(root / RESULT, json.dumps(record, indent=2).encode() + b"\n")
            written = True
        except OSError:
            written = False
        return found, record, written
    finally:
        if fd is not None:
            os.close(fd)


def last_result(root: Root) -> dict | None:
    """For `status --json`: the last check's counts, or None if there was none."""
    try:
        record = json.loads((root / RESULT).read_text("utf-8"))
    except (OSError, ValueError):
        return None
    keys = ("time", "took_ms", "ok", "deliveries", "missing", "changed", "unreadable", "unknown")
    return {k: record.get(k) for k in keys} if isinstance(record, dict) else None
