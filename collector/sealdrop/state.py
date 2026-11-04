"""What the collector has handled (PROTOCOL.md §10, `state/`): one SQLite database, written to disk at each step.

- `handled`: every upload version handled, with its result. A stored one keeps its receipt entry until every
  receipt for it is uploaded (`receipt_done`), so a run that stops before that writes it again next time.
- `sealed`: results by the SHA-256 of the whole file (step 7, a known file).
- `deliveries`: every stored delivery, for ever: its digest, its sender and `seq`.
- `rejections`: whole files rejected, listed in the next receipt of every sender (`reported`).
Entries of rejected files are kept for 90 days, those of stored deliveries for ever.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

DAY = 24 * 3600 * 1000
KEEP_REJECTED = 90 * DAY

_SCHEMA = """
CREATE TABLE IF NOT EXISTS handled (
    name TEXT NOT NULL, version_id TEXT NOT NULL, sealed_sha256 TEXT, size INTEGER NOT NULL,
    outcome TEXT NOT NULL, reason TEXT, sender TEXT, entry TEXT, at INTEGER NOT NULL,
    receipt_done INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (name, version_id));
CREATE TABLE IF NOT EXISTS sealed (
    sha256 TEXT PRIMARY KEY, outcome TEXT NOT NULL, reason TEXT, sender TEXT, entry TEXT, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS deliveries (
    app TEXT NOT NULL, delivery TEXT NOT NULL, digest TEXT NOT NULL, sender TEXT NOT NULL, seq INTEGER NOT NULL,
    at INTEGER NOT NULL, PRIMARY KEY (app, delivery));
CREATE TABLE IF NOT EXISTS conflicts (
    app TEXT NOT NULL, delivery TEXT NOT NULL, digest TEXT NOT NULL, at INTEGER NOT NULL,
    PRIMARY KEY (app, delivery, digest));
CREATE TABLE IF NOT EXISTS seqs (sender TEXT PRIMARY KEY, seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rejections (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, sealed_sha256 TEXT, size INTEGER NOT NULL,
    reason TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reported (
    sender TEXT PRIMARY KEY, last_rejection INTEGER NOT NULL DEFAULT 0, last_receipt INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS vanished (
    name TEXT NOT NULL, version_id TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (name, version_id));
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


class State:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")  # a commit is on disk before the next step
        self.db.executescript(_SCHEMA)

    def close(self) -> None:
        self.db.close()

    def transaction(self):
        return _Transaction(self.db)

    # --- small values -----------------------------------------------------------------------------------------------

    def get(self, key: str, default=None):
        row = self.db.execute("SELECT v FROM kv WHERE k = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key: str, value) -> None:
        self.db.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (key, json.dumps(value)))

    # --- uploads ----------------------------------------------------------------------------------------------------

    def handled(self, name: str, version_id: str) -> sqlite3.Row | None:
        self.db.row_factory = sqlite3.Row
        try:
            return self.db.execute("SELECT * FROM handled WHERE name = ? AND version_id = ?",
                                   (name, version_id)).fetchone()
        finally:
            self.db.row_factory = None

    def known_file(self, sha256: str) -> tuple | None:
        return self.db.execute("SELECT outcome, reason, sender, entry FROM sealed WHERE sha256 = ?",
                               (sha256,)).fetchone()

    def note_stored(self, name: str, version_id: str, sha256: str, size: int, sender: str, entry: dict,
                    at: int) -> None:
        text = json.dumps(entry, separators=(",", ":"))
        self.db.execute("INSERT OR REPLACE INTO handled (name, version_id, sealed_sha256, size, outcome, sender, "
                        "entry, at) VALUES (?, ?, ?, ?, 'stored', ?, ?, ?)",
                        (name, version_id, sha256, size, sender, text, at))
        self.db.execute("INSERT OR IGNORE INTO sealed (sha256, outcome, sender, entry, at) "
                        "VALUES (?, 'stored', ?, ?, ?)", (sha256, sender, text, at))

    def note_rejected(self, name: str, version_id: str, sha256: str | None, size: int, reason: str, at: int) -> None:
        self.db.execute("INSERT OR REPLACE INTO handled (name, version_id, sealed_sha256, size, outcome, reason, at, "
                        "receipt_done) VALUES (?, ?, ?, ?, 'rejected', ?, ?, 1)",
                        (name, version_id, sha256, size, reason, at))
        if sha256 is not None:
            self.db.execute("INSERT OR IGNORE INTO sealed (sha256, outcome, reason, at) VALUES (?, 'rejected', ?, ?)",
                            (sha256, reason, at))
        self.db.execute("INSERT INTO rejections (name, sealed_sha256, size, reason, at) VALUES (?, ?, ?, ?, ?)",
                        (name, sha256, size, reason, at))

    def note_known(self, name: str, version_id: str, sha256: str, size: int, at: int) -> None:
        """A file handled before under another name or version (step 7): the same result, nothing new to report
        for a rejected one."""
        outcome, reason, sender, entry = self.known_file(sha256)
        done = 1 if outcome == "rejected" else 0
        self.db.execute("INSERT OR REPLACE INTO handled (name, version_id, sealed_sha256, size, outcome, reason, "
                        "sender, entry, at, receipt_done) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (name, version_id, sha256, size, outcome, reason, sender, entry, at, done))

    def receipts_owed(self) -> dict[str, list[tuple[str, str, dict]]]:
        """Stored uploads whose receipts aren't all uploaded yet, by sender: (name, version ID, entry)."""
        owed: dict[str, list] = {}
        for name, version_id, sender, entry in self.db.execute(
                "SELECT name, version_id, sender, entry FROM handled WHERE outcome = 'stored' AND receipt_done = 0 "
                "ORDER BY at, name"):
            owed.setdefault(sender, []).append((name, version_id, json.loads(entry)))
        return owed

    def receipts_written(self, uploads: list[tuple[str, str]]) -> None:
        self.db.executemany("UPDATE handled SET receipt_done = 1 WHERE name = ? AND version_id = ?", uploads)

    def waiting_for_receipt(self) -> set[tuple[str, str]]:
        return set(self.db.execute("SELECT name, version_id FROM handled WHERE receipt_done = 0"))

    # --- deliveries -------------------------------------------------------------------------------------------------

    def delivery(self, app: str, delivery: str) -> tuple | None:
        return self.db.execute("SELECT digest, sender, seq FROM deliveries WHERE app = ? AND delivery = ?",
                               (app, delivery)).fetchone()

    def next_seq(self, sender: str) -> int:
        row = self.db.execute("SELECT seq FROM seqs WHERE sender = ?", (sender,)).fetchone()
        seq = (row[0] if row else 0) + 1
        self.db.execute("INSERT OR REPLACE INTO seqs (sender, seq) VALUES (?, ?)", (sender, seq))
        return seq

    def seq(self, sender: str) -> int:
        row = self.db.execute("SELECT seq FROM seqs WHERE sender = ?", (sender,)).fetchone()
        return row[0] if row else 0

    def add_delivery(self, app: str, delivery: str, digest: str, sender: str, seq: int, at: int) -> None:
        self.db.execute("INSERT INTO deliveries (app, delivery, digest, sender, seq, at) VALUES (?, ?, ?, ?, ?, ?)",
                        (app, delivery, digest, sender, seq, at))

    def conflict_known(self, app: str, delivery: str, digest: str) -> bool:
        return self.db.execute("SELECT 1 FROM conflicts WHERE app = ? AND delivery = ? AND digest = ?",
                               (app, delivery, digest)).fetchone() is not None

    def add_conflict(self, app: str, delivery: str, digest: str, at: int) -> None:
        self.db.execute("INSERT OR IGNORE INTO conflicts (app, delivery, digest, at) VALUES (?, ?, ?, ?)",
                        (app, delivery, digest, at))

    def last_conflict(self) -> int:
        return self.db.execute("SELECT COALESCE(MAX(at), 0) FROM conflicts").fetchone()[0]

    # --- rejections and what each sender has been told -------------------------------------------------------------

    def rejections_for(self, sender: str, paired: int) -> tuple[list[dict], int, int]:
        """Rejections this sender hasn't been told about (none from before it was paired): the newest 100, how
        many more, and the last ID."""
        row = self.db.execute("SELECT last_rejection FROM reported WHERE sender = ?", (sender,)).fetchone()
        after = row[0] if row else 0
        rows = self.db.execute("SELECT id, name, sealed_sha256, size, reason, at FROM rejections WHERE id > ? "
                               "AND at >= ? ORDER BY id DESC", (after, paired)).fetchall()
        entries = []
        for _, name, sha, size, reason, at in rows[:100]:
            entry = {"name": name}
            if sha is not None:
                entry["sealed_sha256"] = sha
            entries.append({**entry, "size": size, "reason": reason, "at": at})
        return entries, max(0, len(rows) - 100), rows[0][0] if rows else after

    def told(self, sender: str, last_rejection: int, at: int, warnings: list[str] | None = None) -> None:
        self.db.execute("INSERT OR REPLACE INTO reported (sender, last_rejection, last_receipt) VALUES (?, ?, ?)",
                        (sender, last_rejection, at))
        if warnings is not None:
            self.put(f"warned:{sender}", warnings)

    def last_receipt(self, sender: str) -> int:
        row = self.db.execute("SELECT last_receipt FROM reported WHERE sender = ?", (sender,)).fetchone()
        return row[0] if row else 0

    def rejected_since(self, since: int) -> int:
        return self.db.execute("SELECT COUNT(*) FROM rejections WHERE at >= ?", (since,)).fetchone()[0]

    # --- vanished uploads -------------------------------------------------------------------------------------------

    def add_vanished(self, name: str, version_id: str, at: int) -> None:
        self.db.execute("INSERT OR IGNORE INTO vanished (name, version_id, at) VALUES (?, ?, ?)",
                        (name, version_id, at))

    def vanished_since(self, since: int) -> int:
        return self.db.execute("SELECT COUNT(*) FROM vanished WHERE at >= ?", (since,)).fetchone()[0]

    # --- tidying ----------------------------------------------------------------------------------------------------

    def forget_old(self, now: int) -> None:
        """Entries of rejected files after 90 days (the `up` lifecycle); stored deliveries stay for ever."""
        cutoff = now - KEEP_REJECTED
        self.db.execute("DELETE FROM handled WHERE outcome = 'rejected' AND at < ?", (cutoff,))
        self.db.execute("DELETE FROM sealed WHERE outcome = 'rejected' AND at < ?", (cutoff,))
        self.db.execute("DELETE FROM rejections WHERE at < ?", (cutoff,))
        self.db.execute("DELETE FROM vanished WHERE at < ?", (cutoff,))


class _Transaction:
    def __init__(self, db: sqlite3.Connection):
        self.db = db

    def __enter__(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, kind, value, tb):
        self.db.execute("COMMIT" if kind is None else "ROLLBACK")
        return False
