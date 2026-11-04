"""The `pair` command (PROTOCOL.md §7): shows the QR code, waits for the phone's pairing request, and pairs.

The QR code holds the phone's two storage keys and the one-time code. They stay in memory only: never in the log, in
`state/` or anywhere else on disk. The screen (and, where the terminal allows, its scrollback) is cleared as soon as a
request arrives, and when the pairing is cancelled or expires.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import shutil
import sys
import time
from typing import Callable

import segno
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from . import encoding, errors, manifests, pairing, receipts, s3, sizes
from .errors import Rejected
from .manifests import content_prefix
from .reading import open_pair_request
from .root import Root, Sender
from .run import Lock, Stop, Storage, make_storage, random_name
from .sealed import INFO_TO_COLLECTOR, open_header, seal
from .setup_b2 import Ui
from .sizes import KIND_BUNDLE, KIND_PAIR, KIND_RECEIPT, PREFIX
from .state import State

log = logging.getLogger("sealdrop")

VALID_MS = 10 * 60 * 1000  # the QR code is valid once and for 10 minutes
POLL_SECONDS = 10
REQUEST_SIZE = sizes.sealed_size(sizes.padded_length(KIND_PAIR, 1))  # 262,376 bytes, like the smallest bundle
_KEY_TEXT = re.compile(r"[!-~]{1,128}")


class PairError(Exception):
    """The pairing can't start or ended without a pair; the message is for the owner."""


class PairUi(Ui):
    """The terminal, plus the QR code. The tests and the end-to-end check put their own in."""

    def show_qr(self, qr: segno.QRCode, text: str) -> None:
        """`text` is the QR code's content; the terminal shows only the code itself."""
        if not sys.stdout.isatty():
            raise PairError("the QR code is shown only on a terminal, never into a file or a pipe")
        width, height = qr.symbol_size(border=4)
        columns, rows = shutil.get_terminal_size((0, 0))
        if columns < width or rows < (height + 1) // 2 + 4:
            raise PairError(f"the terminal is too small for the QR code: it needs {width} × {(height + 1) // 2 + 4} "
                            f"characters, this one has {columns} × {rows}. Make the window bigger or the font smaller.")
        self.clear()
        qr.terminal(compact=True)
        self.say("Scan this with Sealdrop on the phone (valid once, for 10 minutes; Ctrl+C cancels).")


def check_key_text(text: str, what: str) -> str:
    text = text.strip()
    if not _KEY_TEXT.fullmatch(text):
        raise PairError(f"that doesn't look like a {what} (1 to 128 printable characters, no spaces)")
    return text


def make_offer(root: Root, upload: tuple[str, str], receipts_key: tuple[str, str], now: int,
               pairing_id: bytes | None = None, code: bytes | None = None) -> dict:
    """The QR code's content (§7). It holds secrets: it's only ever in memory."""
    up, ack = root.locations()
    collector_open, collector_sign = root.public_keys()
    ack_location = {"prefix": ack.prefix, "key": {"id": receipts_key[0], "secret": receipts_key[1]}}
    for name in ("endpoint", "region", "bucket"):  # left out where it's the same as in `up`
        if getattr(ack, name) != getattr(up, name):
            ack_location[name] = getattr(ack, name)
    offer = {
        "sealdrop": 1,
        "type": "pair-offer",
        "pairing": encoding.b64url(pairing_id or os.urandom(16)),
        "expires": now + VALID_MS,
        "storage": {
            "up": {**up.as_dict(), "key": {"id": upload[0], "secret": upload[1]}},
            "ack": ack_location,
        },
        "collector_open": encoding.b64url(collector_open),
        "collector_sign": encoding.b64url(collector_sign),
        "code": encoding.b64url(code or os.urandom(16)),
    }
    pairing.check_offer(offer, now)  # the same rules the phone applies
    return offer


def offer_text(offer: dict) -> str:
    return json.dumps(offer, separators=(",", ":"), ensure_ascii=False)


def qr_of(text: str) -> segno.QRCode:
    return segno.make_qr(text, error="L", boost_error=False)


class Pairing:
    """One waiting pairing: what the `pair` command checks requests against (§7, "What the collector does")."""

    def __init__(self, root: Root, offer: dict):
        self.root = root
        self.pairing = encoding.unb64url(offer["pairing"], 16)
        self.code = encoding.unb64url(offer["code"], 16)
        self.expires = offer["expires"]
        self.collector_open = encoding.unb64url(offer["collector_open"], 32)
        self.collector_sign = encoding.unb64url(offer["collector_sign"], 32)
        self.used = False

    def check(self, data: bytes, now: int) -> tuple[manifests.PairRequest, bytes, str]:
        """Steps 1 to 7 for a kind 2 file; raises Rejected. Gives the request, its key ID and the fingerprint."""
        opened = open_pair_request(io.BytesIO(data), len(data), self.root.opening_keys())  # steps 1 to 4
        request = opened.request
        if request.pairing != self.pairing or self.used or now > self.expires:
            raise Rejected(errors.UNKNOWN_SENDER, "no waiting pairing with this ID")  # step 5
        problem = manifests.check_pair_names(request)
        if problem:
            raise Rejected(errors.BAD_CONTENT, problem)  # step 6
        transcript = pairing.mac_transcript(self.pairing, self.collector_open, self.collector_sign,
                                            request.sender_sign, request.sender_open, request.replaces)
        if not pairing.mac_ok(pairing.pair_mac(self.code, self.pairing, transcript), request.mac):
            raise Rejected(errors.UNKNOWN_SENDER, "the mac doesn't match the one-time code")  # step 7
        fingerprint = pairing.fingerprint(self.pairing, self.collector_open, self.collector_sign,
                                          request.sender_sign, request.sender_open)
        return request, opened.header.writer_key_id, fingerprint


def pair(root: Root, ui: PairUi, *, storage: Storage | None = None, now: Callable[[], int] | None = None,
         sleep: Callable[[float], None] = time.sleep) -> Sender | None:
    """The whole command. Returns the new sender, or None if it ended without one."""
    root.check()
    now = now or (lambda: int(time.time() * 1000))
    storage = storage or make_storage(root)
    if os.environ.get("TMUX") or os.environ.get("STY"):
        ui.say("Warning: this is tmux or screen. They keep their own history of the screen, which clearing doesn't "
               "reach, and the QR code holds the phone's storage keys. Better pair in a plain terminal window, "
               "and close it afterwards.")
        if not ui.confirm("Show the QR code here anyway?"):
            return None
    with Lock(root / "state/lock") as locked:
        if not locked:
            raise PairError("a collector run is going on right now; try again in a minute")
        ui.say("Paste the phone's two storage keys from your password manager (phone-upload and phone-receipts). "
               "They aren't shown, and the collector doesn't keep them.")
        upload = (check_key_text(ui.secret("phone-upload key ID: "), "key ID"),
                  check_key_text(ui.secret("phone-upload key: "), "key"))
        receipts_key = (check_key_text(ui.secret("phone-receipts key ID: "), "key ID"),
                        check_key_text(ui.secret("phone-receipts key: "), "key"))
        offer = make_offer(root, upload, receipts_key, now())
        waiting = Pairing(root, offer)
        state = State(root / "state/state.db")
        shown = True
        log.info("pairing started")
        try:
            text = offer_text(offer)
            ui.show_qr(qr_of(text), text)
            del offer, text, upload, receipts_key
            while now() <= waiting.expires:
                sender = _look(root, storage, state, waiting, ui, now)
                if waiting.used:
                    shown = False
                    return sender
                sleep(POLL_SECONDS)
            ui.clear()
            shown = False
            ui.say("The pairing expired after 10 minutes. Run the pair command again for a new QR code.")
            log.info("pairing expired")
            return None
        except KeyboardInterrupt:
            ui.clear()
            shown = False
            ui.say("Pairing cancelled.")
            log.info("pairing cancelled")
            return None
        finally:
            if shown:
                ui.clear()
            state.close()


def _look(root: Root, storage: Storage, state: State, waiting: Pairing, ui: PairUi, now) -> Sender | None:
    """One look into `up/`: kind 2 files only; everything else is left for the regular runs."""
    up = storage.up
    marker, versions = None, []
    while True:
        page, marker = storage.retrying(
            lambda m=marker: storage.up_client.list_object_versions(up.bucket, up.prefix, m))
        versions += page
        if marker is None:
            break
    for v in versions:
        if v.hidden or v.size != REQUEST_SIZE or state.handled(v.name, v.version_id) is not None:
            continue
        reply = storage.retrying(lambda v=v: storage.up_client.get_object(up.bucket, v.name, version_id=v.version_id))
        data = reply.body
        try:
            header = open_header(data[:PREFIX], root.opening_keys(), INFO_TO_COLLECTOR, (KIND_BUNDLE, KIND_PAIR))
        except Rejected:
            continue  # a regular run rejects it
        if header.kind != KIND_PAIR:
            continue
        try:
            request, key_id, fingerprint = waiting.check(data, now())
        except Rejected as r:
            ui.say(f"A pairing request was rejected: {r.reason} ({r.detail}). Still waiting.")
            log.warning("a pairing request was rejected: %s", r.reason)
            with state.transaction():
                state.note_rejected(v.name, v.version_id, _sha(data), v.size, r.reason, now())
            _delete(storage, v)
            continue
        # A valid request: the QR code goes away at once; then the owner compares the codes.
        waiting.used = True
        ui.clear()
        ui.say("The phone sent its pairing request. Compare this code with the one on the phone:")
        ui.say("")
        ui.say(f"    {fingerprint}")
        ui.say("")
        if not ui.confirm("Does the phone show exactly the same code?"):
            ui.say("Not paired. Someone else may have used the QR code first. Make new storage keys for the phone "
                   "(setup_b2 --keys deletes the old ones), then pair again.")
            log.warning("pairing not confirmed by the owner (fingerprint %s)", fingerprint)
            with state.transaction():
                state.note_rejected(v.name, v.version_id, _sha(data), v.size, errors.UNKNOWN_SENDER, now())
            _delete(storage, v)
            return None
        sender = Sender(key_id, request.sender_sign, request.sender_open, request.label, now(), fingerprint)
        root.add_sender(sender)
        with state.transaction():
            last = state.db.execute("SELECT COALESCE(MAX(id), 0) FROM rejections").fetchone()[0]
            state.told(sender.hex, last, now())
            state.db.execute("INSERT OR REPLACE INTO handled (name, version_id, sealed_sha256, size, outcome, at, "
                             "receipt_done) VALUES (?, ?, ?, ?, 'paired', ?, 1)",
                             (v.name, v.version_id, _sha(data), v.size, now()))
        log.info("paired with %s (fingerprint %s)", request.label, fingerprint)
        try:
            write_paired_receipt(root, storage, sender, waiting.pairing, now())
        except Stop as e:
            ui.say(f"Paired, but the answer to the phone couldn't be uploaded ({e}). Pair again in a while.")
            return sender
        _delete(storage, v)
        ui.say(f"Paired with “{request.label}”. The phone confirms on its own within a minute.")
        if request.replaces is not None:
            old = root.senders().get(request.replaces)
            if old is not None and ui.confirm("Retire the phone's old entry now? Uploads from its old key that are "
                                              "still in the inbox will then be rejected; the phone has already sent "
                                              "them again."):
                root.remove_sender(old, now())
                log.info("retired the old entry of %s (fingerprint %s)", old.label, old.fingerprint)
        return sender
    return None


def write_paired_receipt(root: Root, storage: Storage, sender: Sender, pairing_id: bytes, now: int) -> None:
    manifest = receipts.paired_manifest(sender.key_id, pairing_id, now)
    content = content_prefix(manifest)
    out = io.BytesIO()
    seal(out, KIND_RECEIPT, [content], len(content), X25519PublicKey.from_public_bytes(sender.open), root.signer(),
         now)
    ack = storage.ack
    name = ack.prefix + random_name()
    storage.retrying(lambda: storage.ack_client.put_object(ack.bucket, name, out.getvalue()))


def _delete(storage: Storage, v: s3.Version) -> None:
    up = storage.up

    def attempt():
        try:
            storage.up_client.delete_object(up.bucket, v.name, version_id=v.version_id)
        except s3.S3Error as e:
            if e.status != 404:
                raise
    try:
        storage.retrying(attempt)
    except Stop:
        pass  # the next regular run deletes it (it's noted as handled)


def _sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()
