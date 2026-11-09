"""The collector's commands: `python3 -m sealdrop <command> [--root DIR]`.

    init        set up a data root: the storage locations, the collector's keys and its storage keys
    pair        show the pairing QR code and pair a phone (in your own terminal)
    run         one run over the inbox (from a timer, every 10 minutes)
    senders     the paired phones
    unpair      remove a phone: `unpair <fingerprint or label>`
    status      what the last run found; `--json` for a dashboard (reads only the state, never keys or settings)
    show-keys   the collector's private keys, to keep safe

The data root is `--root`, or `$SEALDROP_ROOT`, or /srv/sealdrop.
"""

from __future__ import annotations

import argparse
import datetime
import fcntl
import json
import logging
import logging.handlers
import os
import sys
from pathlib import Path

from . import __version__, encoding
from .pair import PairError, PairUi, pair
from .root import Location, Root, RootError
from .run import Collector

DEFAULT_ROOT = "/srv/sealdrop"


def _log_to(root: Root, also_terminal: bool) -> None:
    logger = logging.getLogger("sealdrop")
    logger.setLevel(logging.INFO)
    (root / "log").mkdir(parents=True, exist_ok=True, mode=0o700)
    handler = logging.handlers.RotatingFileHandler(root / "log/collector.log", maxBytes=1 << 20, backupCount=5,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    if also_terminal:
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        logger.addHandler(console)


def _when(millis: int | None) -> str:
    if not millis:
        return "never"
    return datetime.datetime.fromtimestamp(millis / 1000).strftime("%Y-%m-%d %H:%M")


def cmd_init(root: Root, args, ui: PairUi) -> int:
    settings = {"clock_check": args.clock_check} if args.clock_check else {}
    if args.test_keys:
        # A test bucket made by `setup_b2 --test`: its keys are in a file already (never the real ones).
        test = json.loads(Path(args.test_keys).expanduser().read_text("utf-8"))
        endpoint, region, bucket = test["endpoint"], test["region"], test["bucket"]
        pickup = (test["keys"]["collector-pickup"]["id"], test["keys"]["collector-pickup"]["secret"])
        receipts = (test["keys"]["collector-receipts"]["id"], test["keys"]["collector-receipts"]["secret"])
    else:
        endpoint = args.endpoint or ui.ask("Storage endpoint (e.g. https://s3.us-west-004.backblazeb2.com): ")
        region = args.region or ui.ask("Region (e.g. us-west-004): ")
        bucket = args.bucket or ui.ask("Inbox bucket name: ")
        ui.say("Paste the collector's two storage keys from where you keep your keys. They aren't shown.")
        pickup = (ui.secret("collector-pickup key ID: ").strip(), ui.secret("collector-pickup key: ").strip())
        receipts = (ui.secret("collector-receipts key ID: ").strip(), ui.secret("collector-receipts key: ").strip())
    opening = signing = None
    if args.import_keys:
        ui.say("Paste the collector's own keys from where you keep your keys (from `show-keys` on the old server).")
        opening = encoding.unb64url(ui.secret("opening key: ").strip(), 32)
        signing = encoding.unb64url(ui.secret("signing key: ").strip(), 32)
    up = Location(endpoint.strip(), region.strip(), bucket.strip(), args.up_prefix)
    ack = Location(endpoint.strip(), region.strip(), bucket.strip(), args.ack_prefix)
    root.create(up, ack, pickup, receipts, settings, opening, signing)
    ui.say(f"Set up {root.path}. Next: `show-keys` once, to keep the keys safe; then `pair`.")
    return 0


def cmd_pair(root: Root, args, ui: PairUi) -> int:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        ui.say("pair runs only in a terminal: the QR code is never written into a file or a pipe.")
        return 2
    sender = pair(root, ui)
    return 0 if sender else 1


def cmd_run(root: Root, args, ui: PairUi) -> int:
    outcome = Collector(root).run()
    if args.verbose:
        ui.say(json.dumps(outcome.__dict__, indent=2))
    return 0 if not outcome.stopped else 3


def cmd_senders(root: Root, args, ui: PairUi) -> int:
    senders = root.senders()
    if not senders:
        ui.say("No phone is paired.")
    for s in senders.values():
        ui.say(f"{s.fingerprint}  {s.label}  (paired {_when(s.paired)})")
    return 0


def cmd_unpair(root: Root, args, ui: PairUi) -> int:
    found = root.find_sender(args.which)
    if len(found) != 1:
        ui.say("No phone matches that." if not found else "More than one phone matches; use the fingerprint.")
        return 1
    sender = found[0]
    if not ui.confirm(f"Unpair “{sender.label}” ({sender.fingerprint})? Its uploads are rejected from then on."):
        return 1
    import time
    root.remove_sender(sender, int(time.time() * 1000))
    logging.getLogger("sealdrop").info("unpaired %s (fingerprint %s)", sender.label, sender.fingerprint)
    ui.say("Unpaired. Delete the phone's two storage keys too: `python3 -m sealdrop.setup_b2 --keys`.")
    return 0


def _busy(root: Root) -> bool:
    """A run or a pairing holds the lock right now."""
    try:
        fd = os.open(root / "state/lock", os.O_RDONLY)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except BlockingIOError:
        return True
    finally:
        os.close(fd)


def status_report(root: Root, now: int) -> dict:
    """`status --json`: the last run's report and the paired phones. Reads `state/status.json`, `state/lock` and
    `senders/` only, so it works from a read-only copy without the keys, the settings or the database."""
    try:
        last = json.loads((root / "state/status.json").read_text("utf-8"))
    except (OSError, ValueError):
        last = None
    stats = (last or {}).get("senders") or {}
    senders = []
    for path in sorted((root / "senders").glob("*.json")):
        try:
            s = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            continue
        seen = stats.get(s.get("key_id"), {})
        senders.append({"label": s.get("label"), "fingerprint": s.get("fingerprint"), "paired": s.get("paired"),
                        "last_upload": seen.get("last_upload"), "last_receipt": seen.get("last_receipt"),
                        "deliveries": seen.get("deliveries")})
    return {
        "format": "sealdrop-status", "version": 1, "collector": __version__, "time": now, "busy": _busy(root),
        "last_run": None if last is None else {k: last.get(k) for k in ("time", "stopped", "storage", "warnings", "run")},
        "last_pickup": (last or {}).get("last_pickup"),
        "inbox": (last or {}).get("inbox"),
        "rejected": (last or {}).get("rejected"),
        "store": (last or {}).get("store"),
        "senders": senders,
    }


def cmd_status(root: Root, args, ui: PairUi) -> int:
    busy = _busy(root)
    try:
        status = json.loads((root / "state/status.json").read_text("utf-8"))
    except OSError:
        ui.say("The first run is in progress." if busy else "No run yet.")
        return 0
    if busy:
        ui.say("Running now:   a run or a pairing is in progress")
    ui.say(f"Last run:      {_when(status['time'])}")
    ui.say(f"Last pickup:   {_when(status.get('last_pickup'))}")
    ui.say(f"Warnings:      {', '.join(status['warnings']) or 'none'}")
    if status.get("storage"):
        ui.say(f"Storage:       {status['storage']}")
    ui.say("That run:      " + ", ".join(f"{k} {v}" for k, v in status["run"].items()))
    return 0


def cmd_show_keys(root: Root, args, ui: PairUi) -> int:
    if not sys.stdout.isatty():
        ui.say("show-keys prints only to a terminal.")
        return 2
    opening, signing = root.private_keys()
    ui.say("The collector's own keys. Store them safely; with them, a new server can open what "
           "the phones sealed and sign receipts they accept (`init --import-keys`).")
    ui.say(f"  opening key  {encoding.b64url(opening)}")
    ui.say(f"  signing key  {encoding.b64url(signing)}")
    ui.pause("Press Enter once they're saved; the screen is then cleared.")
    ui.clear()
    return 0


COMMANDS = {"init": cmd_init, "pair": cmd_pair, "run": cmd_run, "senders": cmd_senders, "unpair": cmd_unpair,
            "status": cmd_status, "show-keys": cmd_show_keys}


def main(argv: list[str] | None = None, ui: PairUi | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m sealdrop", description=__doc__.split("\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("which", nargs="?", help="for unpair: the phone's fingerprint or label")
    parser.add_argument("--root", default=os.environ.get("SEALDROP_ROOT", DEFAULT_ROOT))
    parser.add_argument("--endpoint")
    parser.add_argument("--region")
    parser.add_argument("--bucket")
    parser.add_argument("--up-prefix", default="up/")
    parser.add_argument("--ack-prefix", default="ack/")
    parser.add_argument("--clock-check", choices=("timedatectl", "off"))
    parser.add_argument("--test-keys", help="init from a test bucket's key file (setup_b2 --test)")
    parser.add_argument("--import-keys", action="store_true", help="init with the collector's keys from before")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--json", action="store_true", help="for status: machine-readable, for a dashboard")
    args = parser.parse_args(argv)
    if args.command == "unpair" and not args.which:
        parser.error("unpair needs the phone's fingerprint or label")
    ui = ui or PairUi()
    root = Root(args.root)
    if args.command == "status" and args.json:
        # Before the checks: it must work from a read-only copy of the state, without the settings, and log nothing.
        import time
        sys.stdout.write(json.dumps(status_report(root, int(time.time() * 1000)), indent=2) + "\n")
        return 0
    try:
        if args.command != "init":
            root.check()
            _log_to(root, also_terminal=args.verbose)
        return COMMANDS[args.command](root, args, ui)
    except (RootError, PairError) as e:
        ui.say(f"Not done: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
