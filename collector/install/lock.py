"""Writes requirements.txt: exact versions, each with the sha256 of every file a 64-bit Linux server (glibc, x86_64 or
aarch64, CPython) could install, as PyPI publishes them.

    python3 lock.py cryptography==50.0.2 cffi==2.1.1 pycparser==3.12 segno==1.6.6 > requirements.txt

List every package the collector needs, the dependencies of dependencies too (`pip list` in a tested venv).
Only the standard library.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request

HEADER = """\
# The collector's packages for a server, exactly these versions and files (install.sh installs them with
# --require-hashes). Only the files a 64-bit Linux with glibc (x86_64 or aarch64) and CPython 3.11 or newer can use.
# Written by lock.py; to update, pick the new versions, run the tests with them, then lock.py and install.sh again."""


def usable(filename: str) -> bool:
    if filename.endswith("-none-any.whl"):
        return True
    return (re.search(r"manylinux\S*_(x86_64|aarch64)\.whl$", filename) is not None
            and re.search(r"-cp3\d+-(cp3\d+|abi3)", filename) is not None
            and not re.search(r"cp3\d+t", filename))  # the free-threaded builds


def main(pins: list[str]) -> int:
    if not pins or any("==" not in p for p in pins):
        print(__doc__, file=sys.stderr)
        return 2
    print(HEADER)
    for pin in pins:
        name, version = pin.split("==")
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as reply:
            files = [f for f in json.load(reply)["urls"] if usable(f["filename"])]
        if not files:
            print(f"{pin}: no file for a 64-bit Linux server", file=sys.stderr)
            return 1
        files.sort(key=lambda f: f["filename"])
        print(f"{name}=={version} \\")
        print(" \\\n".join(f"    --hash=sha256:{f['digests']['sha256']}" for f in files))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
