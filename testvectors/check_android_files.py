"""Opens the files that Sealdrop's Android code sealed on the emulator (PROTOCOL.md §13, the other direction).

The Android test `CrossFilesTest` writes them with the test keys, plus `expected.json` with what each must open to.
Run from the repository root:

    adb pull /sdcard/Android/data/app.sealdrop.core.test/files/cross <folder>
    python testvectors/check_android_files.py <folder>
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "collector"))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

from sealdrop import encoding, keys, manifests, pairing, reading, receipts  # noqa: E402

KEYS = json.loads((HERE / "keys.json").read_text(encoding="utf-8"))
OFFER = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))["pairing"]["offer"]


def public(name: str) -> bytes:
    return encoding.unb64url(KEYS[name]["public"])


def x25519(name: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(encoding.unb64url(KEYS[name]["private"]))


SENDERS = {keys.key_id(public("sender_sign")): keys.P256Verifier(public("sender_sign"))}
COLLECTOR_KEYS = [x25519("collector_open")]


def check(folder: Path, entry: dict) -> list[str]:
    """What's wrong with one file, or nothing."""
    data = (folder / entry["file"]).read_bytes()
    problems = []

    def expect(what, got, want):
        if got != want:
            problems.append(f"{what}: {got!r}, expected {want!r}")

    expect("size", len(data), entry["size"])
    expect("sealed_sha256", hashlib.sha256(data).hexdigest(), entry["sealed_sha256"])
    if entry["reader"] == "collector":
        sealed = reading.open_upload(io.BytesIO(data), len(data), COLLECTOR_KEYS, SENDERS)
        content = b"".join(reading.open_upload(io.BytesIO(data), len(data), COLLECTOR_KEYS, SENDERS).iter_content())
        verdicts = reading.check_deliveries(sealed)
        expect("deliveries", [{"app": v.delivery.app, "delivery": v.delivery.delivery, "digest": v.delivery.digest,
                               **({"result": "stored"} if v.ok else {"result": "rejected", "reason": v.reason})}
                              for v in verdicts], entry["deliveries"])
        header = sealed.header
    elif entry["reader"] == "pair":
        opened = reading.open_pair_request(io.BytesIO(data), len(data), COLLECTOR_KEYS)
        r, header = opened.request, opened.header
        content = None
        expect("manifest", opened.manifest, entry["manifest"])
        expect("pair check", manifests.check_pair_names(r), None)
        transcript = pairing.mac_transcript(r.pairing, public("collector_open"), public("collector_sign"), r.sender_sign,
                                            r.sender_open, r.replaces)
        expect("mac", pairing.mac_ok(pairing.pair_mac(encoding.unb64url(OFFER["code"]), r.pairing, transcript), r.mac),
               True)
        expect("fingerprint", pairing.fingerprint(r.pairing, public("collector_open"), public("collector_sign"),
                                                  r.sender_sign, r.sender_open), entry["fingerprint"])
    else:
        header, manifest = reading.open_receipt(data, [x25519("sender_open")],
                                                keys.Ed25519Verifier(public("collector_sign")),
                                                keys.key_id(public("collector_sign")))
        content = None
        receipts.check_receipt(manifest, [keys.key_id(public("sender_sign"))])
        expect("manifest", manifest, entry["manifest"])
    want = entry["header"]
    expect("header", {"kind": header.kind, "created": header.created, "n": header.n,
                      "message_id": header.message_id.hex(), "writer_key_id": header.writer_key_id.hex()}, want)
    if content is not None:
        expect("content_sha256", hashlib.sha256(content).hexdigest(), entry["content_sha256"])
    return problems


def main(folder: Path) -> int:
    expected = json.loads((folder / "expected.json").read_text(encoding="utf-8"))["files"]
    failed = 0
    for entry in expected:
        try:
            problems = check(folder, entry)
        except Exception as e:  # a rejection or a crash: either way it didn't open as it should
            problems = [f"{type(e).__name__}: {e}"]
        print(("OK    " if not problems else "FAIL  ") + entry["file"])
        for p in problems:
            print("      " + p)
        failed += bool(problems)
    print(f"{len(expected) - failed} of {len(expected)} files open as expected")
    return 1 if failed or not expected else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
