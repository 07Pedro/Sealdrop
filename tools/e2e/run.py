#!/usr/bin/env python3
"""The end-to-end check: Sealdrop and a made-up sending app on an Android emulator, the collector here (WSL or any
Linux, standing in for the server), and a TEST bucket made by `setup_b2 --test`.

A delivery travels phone → inbox → collector → receipt → back to the phone, and so do the failure cases of
PROTOCOL.md: tampered files, a cut connection on both sides, duplicates, conflicts and junk. Meanwhile the harness
watches the phone's connections: Sealdrop may talk to the storage's host only.

    python3 tools/e2e/run.py --adb /path/to/adb [--serial emulator-5554]

It uses only the test bucket's keys (`~/.config/sealdrop-test/storage.json`) and never prints them, the bucket or
the endpoint. Sealdrop's and the sending app's data on the emulator are cleared first; never point it at a phone.
The APKs are built beforehand (android/: `gradlew :app:assembleDebug :app:assembleDebugAndroidTest
:demo:assembleDebug :demo:assembleDebugAndroidTest`).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pty
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import urllib.parse
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
COLLECTOR = REPO / "collector"
ANDROID = REPO / "android"
sys.path.insert(0, str(COLLECTOR))

from sealdrop import s3  # noqa: E402  (the collector's own client, for tampering and junk)

APP = "app.sealdrop"
DEMO = "org.example.sender"
RUNNER = "androidx.test.runner.AndroidJUnitRunner"
STEPS = "app.sealdrop.E2eSteps"
SENDER = "org.example.sender.E2eSender"
REQUEST_SIZE = 262_376

# Delivery states (§9.1).
QUEUED, UPLOADING, IN_INBOX, PICKED_UP, CONFLICT, FAILED = 1, 2, 3, 4, 5, 6
# Warning bits (§9.1).
REJECTED, COLLECTOR_PROBLEM = 1 << 3, 1 << 10


class Failed(Exception):
    pass


def say(text: str = "") -> None:
    print(text, flush=True)


def check(condition: bool, what: str) -> None:
    if not condition:
        raise Failed(what)
    say(f"  ok: {what}")


def made_up(seed: str, index: int, size: int) -> bytes:
    """The sending app's file `index` for `seed` (E2eSender.madeUp)."""
    out = bytearray()
    k = 0
    while len(out) < size:
        out += hashlib.sha256(f"{seed}:{index}:{k}".encode()).digest()
        k += 1
    return bytes(out[:size])


# --- the emulator ---------------------------------------------------------------------------------------------------

class Device:
    def __init__(self, adb: str, serial: str):
        self.adb, self.serial = adb, serial
        self.windows = adb.lower().endswith(".exe")

    def path(self, p: Path) -> str:
        return subprocess.check_output(["wslpath", "-w", str(p)], text=True).strip() if self.windows else str(p)

    def run(self, *args: str, stdin: bytes | None = None, check_ok: bool = True, timeout: int = 900) -> str:
        r = subprocess.run([self.adb, "-s", self.serial, *args], input=stdin, capture_output=True, timeout=timeout)
        out = (r.stdout + r.stderr).decode("utf-8", "replace").replace("\r", "")
        if check_ok and r.returncode != 0:
            raise Failed(f"adb {' '.join(args[:3])}: {out.strip()[-300:]}")
        return out

    def shell(self, command: str, **kw) -> str:
        return self.run("shell", command, **kw)

    def install(self, apk: Path) -> None:
        if not apk.exists():
            raise Failed(f"{apk.relative_to(REPO)} isn't built (see the docstring)")
        self.run("install", "-r", "-t", self.path(apk))

    def uid(self, package: str) -> int:
        m = re.search(rf"package:{re.escape(package)} uid:(\d+)", self.shell(f"pm list packages -U {package}"))
        if not m:
            raise Failed(f"{package} isn't installed")
        return int(m.group(1))

    def instrument(self, test_package: str, test: str, **args) -> dict[str, str]:
        command = ["shell", "am", "instrument", "-w", "-e", "e2e", "1", "-e", "class", test]
        for k, v in args.items():
            command += ["-e", k, str(v)]
        command.append(f"{test_package}/{RUNNER}")
        out = self.run(*command)
        values = dict(re.findall(r"INSTRUMENTATION_STATUS: (\w+)=(.*)", out))
        for k in ("class", "current", "id", "numtests", "stream", "test"):
            values.pop(k, None)
        if "OK (1 test)" not in out:
            problem = re.findall(r"^(?:java\.lang\.\w+|org\.junit\.\w+|\w+Error|\w+Exception).*$", out, re.M)
            raise Failed(f"{test.split('.')[-1]} failed: {problem[:2] or out.strip()[-400:]}")
        return values

    def app_step(self, step: str, **args) -> dict[str, str]:
        return self.instrument(f"{APP}.test", f"{STEPS}#{step}", **args)

    def sender_step(self, step: str, **args) -> dict[str, str]:
        return self.instrument(f"{DEMO}.test", f"{SENDER}#{step}", **args)

    def put_private(self, package: str, name: str, data: bytes) -> None:
        """Into the app's private files, through `run-as` (debug builds only); nothing on shared storage."""
        self.run("exec-in", "run-as", package, "sh", "-c", f"mkdir -p files && cat > files/{name}", stdin=data)


# --- the collector --------------------------------------------------------------------------------------------------

class Collector:
    def __init__(self, root: Path, python: str):
        self.root, self.python = root, python
        self.env = {**os.environ, "SEALDROP_ROOT": str(root)}
        self.env.pop("TMUX", None)
        self.env.pop("STY", None)

    def cli(self, *args: str, script: Path | None = None, extra: dict | None = None) -> str:
        command = [self.python, str(script)] if script else [self.python, "-m", "sealdrop", *args]
        r = subprocess.run(command, cwd=COLLECTOR, env={**self.env, **(extra or {})}, capture_output=True, text=True,
                           timeout=900)
        if r.returncode != 0:
            raise Failed(f"collector {' '.join(args) or script.name}: {(r.stdout + r.stderr).strip()[-500:]}")
        return r.stdout + r.stderr

    def run(self) -> dict:
        """One regular run; what it did (state/status.json's `run`)."""
        self.cli("run", "-v")
        return self.status()["run"]

    def status(self) -> dict:
        return json.loads((self.root / "state/status.json").read_text())

    def files_in(self, folder: str) -> list[Path]:
        base = self.root / folder
        return sorted(p for p in base.rglob("*") if p.is_file()) if base.exists() else []


# --- pairing through the real terminal ------------------------------------------------------------------------------

def qr_png(lines: list[str], scale: int = 6) -> bytes:
    """The half-block QR code the `pair` command printed, as a PNG: '█' is two light modules, ' ' two dark ones."""
    rows: list[list[bool]] = []  # True: dark
    for line in lines:
        top, bottom = [], []
        for c in line:
            top.append(c in " ▄")
            bottom.append(c in " ▀")
        rows += [top, bottom]
    width = max(len(r) for r in rows) + 8
    raw = bytearray()
    for r in [[False] * width] * 4 + [[False] * 4 + r + [False] * (width - 4 - len(r)) for r in rows] + [[False] * width] * 4:
        line = bytes(0 if dark else 255 for dark in r for _ in range(scale))
        for _ in range(scale):
            raw += b"\x00" + line

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    height = len(raw) // (width * scale + 1)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width * scale, height, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


class Terminal:
    """The `pair` command on a pseudo-terminal, as the owner would see it. What it prints holds the QR code, so
    the keys: it's kept in memory only and never printed."""

    def __init__(self, collector: Collector):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(COLLECTOR)
            os.execve(collector.python, [collector.python, "-m", "sealdrop", "pair"], collector.env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 64, 140, 0, 0))
        self.buffer = ""

    def expect(self, text: str, timeout: float = 120) -> str:
        end = time.time() + timeout
        while text not in self.buffer:
            left = end - time.time()
            if left <= 0:
                raise Failed(f"the pair command didn't get to “{text}”")
            ready, _, _ = select.select([self.fd], [], [], left)
            if ready:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    data = b""
                if not data:
                    raise Failed(f"the pair command ended before “{text}”")
                self.buffer += data.decode("utf-8", "replace")
        before, _, after = self.buffer.partition(text)
        self.buffer = after
        return before

    def send(self, line: str) -> None:
        os.write(self.fd, line.encode() + b"\n")

    def wait(self) -> int:
        try:
            while os.read(self.fd, 65536):
                pass
        except OSError:
            pass
        return os.waitpid(self.pid, 0)[1]


def pair(device: Device, collector: Collector, keys: dict) -> str:
    say("Pairing: the collector's `pair` command on a terminal, its QR code read by Sealdrop")
    t = Terminal(collector)
    for role, part, prompt in (("phone-upload", "id", "phone-upload key ID: "), ("phone-upload", "secret", "phone-upload key: "),
                               ("phone-receipts", "id", "phone-receipts key ID: "),
                               ("phone-receipts", "secret", "phone-receipts key: ")):
        t.expect(prompt)
        t.send(keys["keys"][role][part])
    screen = t.expect("Scan this with Sealdrop")
    check("\x1b[3J" in screen, "the screen and its scrollback are cleared before the QR code")
    qr = [line for line in screen.split("\x1b[3J")[-1].replace("\r", "").split("\n") if line and set(line) <= set("█▀▄ ")]
    png = qr_png(qr)
    del screen, qr
    device.put_private(APP, "e2e-qr.png", png)
    del png
    phone = device.app_step("pairFromQr", label="Emulator")["fingerprint"]
    check(device.shell(f"run-as {APP} ls files", check_ok=False).find("e2e-qr.png") < 0, "the QR image is gone from the phone")
    shown = t.expect("Does the phone show exactly the same code?")
    check("\x1b[3J" in shown, "the QR code is cleared once the request arrived")
    server = re.search(r"([A-Z2-7]{4} [A-Z2-7]{4} [A-Z2-7]{4} [A-Z2-7]{4})", shown).group(1)
    same = server == phone
    t.send("y" if same else "n")
    check(same, f"the fingerprints are the same on both screens ({phone})")
    t.expect("Paired with")
    t.buffer = ""
    status = t.wait()
    check(status == 0, "the pair command ended well")
    device.app_step("waitPaired")
    check(True, "Sealdrop got the paired receipt")
    log = (collector.root / "log/collector.log").read_text("utf-8", "replace")
    secrets = [keys["keys"][r][p] for r in ("phone-upload", "phone-receipts") for p in ("id", "secret")]
    check(not any(s in log for s in secrets), "no storage key in the collector's log")
    state_files = b"".join(p.read_bytes() for p in (collector.root / "state").rglob("*") if p.is_file())
    check(not any(s.encode() in state_files for s in secrets), "no storage key in the collector's state")
    return phone


# --- the inbox, with the test keys ----------------------------------------------------------------------------------

class Inbox:
    def __init__(self, keys: dict):
        endpoint, region = keys["endpoint"], keys["region"]
        self.bucket = keys["bucket"]
        k = keys["keys"]
        self.pickup = s3.Client(endpoint, region, s3.Credentials(k["collector-pickup"]["id"], k["collector-pickup"]["secret"]))
        self.upload = s3.Client(endpoint, region, s3.Credentials(k["phone-upload"]["id"], k["phone-upload"]["secret"]))
        self.receipts = s3.Client(endpoint, region,
                                  s3.Credentials(k["collector-receipts"]["id"], k["collector-receipts"]["secret"]))
        self.host = urllib.parse.urlsplit(endpoint).hostname

    def versions(self) -> list[s3.Version]:
        found, marker = [], None
        while True:
            page, marker = self.pickup.list_object_versions(self.bucket, "up/", marker)
            found += page
            if marker is None:
                return found

    def uploads(self) -> list[s3.Version]:
        return [v for v in self.versions() if not v.hidden and v.latest]

    def empty(self) -> int:
        n = 0
        for v in self.versions():
            self.pickup.delete_object(self.bucket, v.name, version_id=v.version_id)
            n += 1
        return n

    def take(self, v: s3.Version) -> bytes:
        """Downloads an upload and deletes every version of it."""
        data = self.pickup.get_object(self.bucket, v.name, version_id=v.version_id).body
        for other in self.versions():
            if other.name == v.name:
                self.pickup.delete_object(self.bucket, other.name, version_id=other.version_id)
        return data

    def put_up(self, name: str, data: bytes) -> None:
        self.upload.put_object(self.bucket, name, data)

    def put_ack(self, name: str, data: bytes) -> None:
        self.receipts.put_object(self.bucket, name, data)


def random_name() -> str:
    import base64
    return base64.b32encode(os.urandom(20)).decode().lower()


# --- the phone's connections ----------------------------------------------------------------------------------------

class Watch:
    """Polls the emulator's TCP tables for Sealdrop's UID and notes every remote address it connects to."""

    def __init__(self, device: Device, uid: int):
        self.device, self.uid = device, uid
        self.seen: set[tuple[str, int]] = set()
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    @staticmethod
    def _address(text: str) -> tuple[str, int]:
        host, port = text.split(":")
        raw = bytes.fromhex(host)
        words = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
        if len(words) == 4:
            ip = socket.inet_ntop(socket.AF_INET, words)
        elif words[:12] == b"\0" * 10 + b"\xff\xff":
            ip = socket.inet_ntop(socket.AF_INET, words[12:])
        else:
            ip = socket.inet_ntop(socket.AF_INET6, words)
        return ip, int(port, 16)

    def _loop(self) -> None:
        while self.running:
            try:
                table = self.device.shell("cat /proc/net/tcp /proc/net/tcp6", check_ok=False, timeout=20)
            except subprocess.TimeoutExpired:
                continue
            for line in table.splitlines():
                parts = line.split()
                if len(parts) > 7 and parts[0].endswith(":") and parts[7] == str(self.uid) and parts[3] != "0A":
                    remote = self._address(parts[2])
                    if remote[0] not in ("0.0.0.0", "::"):
                        self.seen.add(remote)
            time.sleep(0.3)

    def stop(self) -> set[tuple[str, int]]:
        self.running = False
        self.thread.join(timeout=30)
        return self.seen


# --- the check ------------------------------------------------------------------------------------------------------

def states(device: Device, *deliveries: str) -> list[int]:
    text = device.sender_step("state", deliveries=",".join(deliveries))["states"]
    return [int(x.rsplit(":", 1)[1]) for x in text.split()]


def hand_over(device: Device, delivery: str, expect: int = 0, **kw) -> None:
    code = int(device.sender_step("handOver", delivery=delivery, **kw)["code"])
    if code != expect:
        raise Failed(f"hand-over of {delivery}: result {code}, expected {expect}")


def sync(device: Device, **kw) -> dict[str, str]:
    return device.app_step("sync", **kw)


def stored_ok(collector: Collector, delivery: str, seed: str, files: int, size: int) -> bool:
    base = collector.root / "store" / DEMO / delivery
    for i in range(files):
        f = base / "e2e" / f"f{i}.bin"
        if not f.is_file() or hashlib.sha256(f.read_bytes()).digest() != hashlib.sha256(made_up(seed, i, size)).digest():
            return False
    return True


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--adb", default=os.environ.get("ADB", "adb"))
    p.add_argument("--serial", default="emulator-5554")
    p.add_argument("--keys", default="~/.config/sealdrop-test/storage.json")
    p.add_argument("--root", default="~/.cache/sealdrop-e2e")
    p.add_argument("--python", default=sys.executable, help="the Python with the collector's requirements")
    a = p.parse_args()

    device = Device(a.adb, a.serial)
    if not a.serial.startswith("emulator-"):
        raise SystemExit("The end-to-end check clears app data: it runs on an emulator only.")
    keys = json.loads(Path(a.keys).expanduser().read_text())
    root = Path(a.root).expanduser()
    shutil.rmtree(root, ignore_errors=True)
    root.parent.mkdir(parents=True, exist_ok=True)
    collector = Collector(root, a.python)
    inbox = Inbox(keys)
    started = time.time()

    say("Setting up: the APKs, fresh app data, an empty inbox and a new collector")
    for apk in ("app/build/outputs/apk/debug/app-debug.apk", "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk",
                "demo/build/outputs/apk/debug/demo-debug.apk",
                "demo/build/outputs/apk/androidTest/debug/demo-debug-androidTest.apk"):
        device.install(ANDROID / apk)
    for package in (APP, DEMO):
        device.shell(f"pm clear {package}")
    say(f"  inbox emptied ({inbox.empty()} old versions)")
    collector.cli("init", "--test-keys", str(Path(a.keys).expanduser()), "--clock-check", "off")
    uid = device.uid(APP)

    watch = Watch(device, uid)
    allowed: set[str] = set()

    def note_addresses() -> None:
        allowed.update(device.app_step("resolve")["addresses"].split(","))
        allowed.update(info[4][0] for info in socket.getaddrinfo(inbox.host, 443, proto=socket.IPPROTO_TCP))

    try:
        pair(device, collector, keys)
        note_addresses()

        say("Approval: the sending app asks first, the owner approves it once")
        hand_over(device, "d1", expect=2, files=3, size=100_000)
        device.app_step("approve", app=DEMO)
        check(True, "approved (by the certificate Sealdrop recorded)")

        say("A delivery, sent by Sealdrop's own job 30 seconds after the hand-over")
        hand_over(device, "d1", files=3, size=100_000)
        check(states(device, "d1") == [QUEUED], "queued at once")
        for _ in range(40):
            time.sleep(3)
            if states(device, "d1") == [IN_INBOX]:
                break
        check(states(device, "d1") == [IN_INBOX], "uploaded by the job: in the inbox")
        copy = inbox.uploads()
        check(len(copy) == 1, "one upload in up/")
        kept = inbox.pickup.get_object(inbox.bucket, copy[0].name, version_id=copy[0].version_id).body
        check(collector.run()["stored"] == 1, "the collector picked it up")
        check(stored_ok(collector, "d1", "d1", 3, 100_000), "the 3 files are stored, byte for byte")
        device.shell(f"cmd jobscheduler run -f {APP} 2")  # the receipts job, now instead of in 15 minutes
        for _ in range(20):
            time.sleep(3)
            if states(device, "d1") == [PICKED_UP]:
                break
        check(states(device, "d1") == [PICKED_UP], "the receipt came back: picked up")
        note_addresses()

        say("Duplicates")
        hand_over(device, "d1", expect=1, files=3, size=100_000)
        check(True, "the same delivery again: “already have it”")
        inbox.put_up("up/" + random_name(), kept)  # a replay of the same sealed file under a new name
        run = collector.run()
        check(run["stored"] == 0 and len(collector.files_in(f"store/{DEMO}/d1")) == 3, "a replayed upload stores nothing new")
        hand_over(device, "d2", files=1, size=5000)
        sync(device)
        device.app_step("age")  # no receipt for 61 days: sealed again
        sync(device)
        check(len(inbox.uploads()) == 2, "after 60 days without a receipt, sealed again under a new name")
        run = collector.run()
        check(run["stored"] == 1 and run["duplicates"] == 1, "both copies: stored once, the second a duplicate")
        device.app_step("receipts")
        check(states(device, "d2") == [PICKED_UP], "picked up")

        say("Conflicts")
        device.app_step("forget", app=DEMO, delivery="d1")  # as after a reinstall of Sealdrop
        hand_over(device, "d1", files=1, size=777, seed="other")
        sync(device)
        check(collector.run()["conflicts"] == 1, "the collector found a conflict")
        check(len(collector.files_in(f"conflicts/{DEMO}/d1")) == 1, "the other content is kept apart in conflicts/")
        check(len(collector.files_in(f"store/{DEMO}/d1")) == 3, "the stored delivery is untouched")
        device.app_step("receipts")
        check(states(device, "d1") == [CONFLICT], "the app sees “conflict”")
        check(int(device.sender_step("info")["warnings"]) & COLLECTOR_PROBLEM != 0,
              "and the warning that the collector reports a problem (for 7 days, §10)")
        hand_over(device, "d1", expect=9, files=1, size=778, seed="third")
        check(True, "and Sealdrop answers 9 for yet other content")

        say("Tampered files")
        hand_over(device, "t1", files=1, size=3000)
        sync(device)
        [v] = inbox.uploads()
        data = bytearray(inbox.take(v))
        data[10] ^= 1  # inside the sealed header
        inbox.put_up(v.name, bytes(data))
        check(collector.run()["rejected"] == 1, "a damaged header is rejected")
        device.app_step("receipts")
        check(states(device, "t1") == [QUEUED], "the phone matched the rejection by name and size: sent again, alone")
        sync(device)
        collector.run()
        device.app_step("receipts")
        check(states(device, "t1") == [PICKED_UP] and stored_ok(collector, "t1", "t1", 1, 3000), "and then stored")
        hand_over(device, "t2", files=1, size=3000)
        sync(device)
        [v] = inbox.uploads()
        data = bytearray(inbox.take(v))
        data[400] ^= 1  # inside the first piece: the signature fails
        inbox.put_up(v.name, bytes(data))
        check(collector.run()["rejected"] == 1, "a changed piece is rejected")
        check(len(collector.files_in("rejected")) >= 1, "and kept in rejected/ for a look")
        device.app_step("receipts")
        check(states(device, "t2") == [IN_INBOX], "it names another SHA-256, so the phone keeps waiting")
        device.app_step("age")
        sync(device)
        collector.run()
        device.app_step("receipts")
        check(states(device, "t2") == [PICKED_UP], "the re-send after 60 days gets it there")

        say("A cut connection")
        hand_over(device, "big", files=1, size=15 << 20)  # sealed: 16 MiB and a little, so 3 parts
        parts = sync(device, cut=2)
        check(parts["parts"] == "1" and states(device, "big") == [UPLOADING], "the phone's upload stopped after part 1")
        parts = sync(device)
        check(parts["parts"] == "2,3" and states(device, "big") == [IN_INBOX], "resumed with part 2: parts 2 and 3 sent")
        out = collector.cli(script=HERE / "cut_collector.py", extra={"E2E_CUT_AFTER": str(3 << 20)})
        check("e2e: connection cut" in out and "e2e: download resumed from byte" in out,
              "the collector's download was cut and resumed where it stopped")
        check(stored_ok(collector, "big", "big", 1, 15 << 20), "the 15 MiB file is stored, byte for byte")
        device.app_step("receipts")
        check(states(device, "big") == [PICKED_UP], "picked up")

        say("Junk")
        inbox.put_up("up/" + random_name(), os.urandom(REQUEST_SIZE))  # a possible size
        inbox.put_up("up/" + random_name(), os.urandom(1000))  # an impossible one
        inbox.put_ack("ack/" + random_name(), os.urandom(4096 + 152 + 16 + 64))
        warned = device.sender_step("info")["warnings"]
        check(collector.run()["rejected"] == 2, "both junk files in up/ are rejected")
        check(inbox.uploads() == [], "and gone from the inbox")
        device.app_step("receipts")
        info = device.sender_step("info")
        check(info["warnings"] == warned, "no new warning on the phone: junk isn't this phone's, ack/ junk is ignored")
        # Still on from above: the damaged header was this phone's upload (rejected files, 7 days, §9.1), and the
        # collector reports the conflict (7 days, §10).
        check(int(info["warnings"]) & ~(REJECTED | COLLECTOR_PROBLEM) == 0, f"no other warning (bits {info['warnings']})")

        say("What's left")
        shown = device.app_step("show")
        check(shown["uploads"] == "0" and shown["outbox"] == "0", "no upload pending, nothing in the outbox")
        check(shown["copies"] == "0", "no copy left on the phone: everything is confirmed")
        device.app_step("gateRefusesOthers")
        check(True, "the gate refuses other hosts and plain HTTP")
        note_addresses()
    finally:
        seen = watch.stop()

    say("Sealdrop's connections")
    unexpected = {(ip, port) for ip, port in seen if ip not in allowed or port != 443}
    check(bool(seen), f"its connections were seen ({len(seen)} addresses)")
    check(not unexpected, "every one went to the storage's host, port 443" + (f" (not: {sorted(unexpected)})" if unexpected else ""))
    say(f"\nAll checks passed in {int(time.time() - started)} s.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failed as e:
        say(f"\nFAILED: {e}")
        sys.exit(1)
