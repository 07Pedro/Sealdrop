"""One collector run whose connection drops once, in the middle of a download: the end-to-end check's way to see the
collector resume (PROTOCOL.md §8: `Range` with `If-Match`). Everything else is the real `run` command."""

from __future__ import annotations

import os
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "collector"))

from sealdrop import s3  # noqa: E402
from sealdrop.__main__ import main  # noqa: E402

CUT_AFTER = int(os.environ.get("E2E_CUT_AFTER", str(3 << 20)))
_received = 0
_cut = False
_recv_into = ssl.SSLSocket.recv_into


def recv_into(self, buffer, nbytes=0, flags=0):
    global _received, _cut
    n = _recv_into(self, buffer, nbytes, flags)
    _received += n
    if not _cut and _received > CUT_AFTER:
        _cut = True
        print(f"e2e: connection cut after {_received} bytes", flush=True)
        raise ConnectionResetError("cut by the end-to-end check")
    return n


_get_object = s3.Client.get_object


def get_object(self, bucket, name, **kw):
    if kw.get("first"):
        print(f"e2e: download resumed from byte {kw['first']}", flush=True)
    return _get_object(self, bucket, name, **kw)


ssl.SSLSocket.recv_into = recv_into
s3.Client.get_object = get_object

if __name__ == "__main__":
    sys.exit(main(["run", "-v"]))
