"""HTTPS requests as PROTOCOL.md §8 wants them: TLS 1.2 or newer with the system's certificate authorities, 15 s to
connect, 60 s without data, `User-Agent: sealdrop`, and redirects never followed. Only the standard library."""

from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass
from typing import BinaryIO, Callable

USER_AGENT = "sealdrop"
CONNECT_TIMEOUT = 15
READ_TIMEOUT = 60
MAX_REPLY = 16 << 20  # a reply read into memory (listings, errors); file content goes to `out`
_CHUNK = 1 << 20


class NetError(Exception):
    """No answer: the connection failed, timed out or broke off."""


@dataclass
class Reply:
    status: int
    headers: dict[str, str]  # names in lower case
    body: bytes


def system_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def exchange(host: str, port: int, method: str, target: str, headers: dict[str, str], body: bytes | None, *,
             context: ssl.SSLContext, out: BinaryIO | None = None) -> Reply:
    """One request on its own connection. With `out`, a 2xx reply's body is written there instead of kept."""
    conn = http.client.HTTPSConnection(host, port, timeout=CONNECT_TIMEOUT, context=context)
    try:
        conn.connect()
        conn.sock.settimeout(READ_TIMEOUT)
        conn.request(method, target, body=body, headers={"User-Agent": USER_AGENT, **headers})
        response = conn.getresponse()
        reply_headers = {name.lower(): value for name, value in response.getheaders()}
        if out is not None and 200 <= response.status < 300:
            while chunk := response.read(_CHUNK):
                out.write(chunk)
            data = b""
        else:
            data = response.read(MAX_REPLY + 1)
            if len(data) > MAX_REPLY:
                raise NetError("reply too long")
        return Reply(response.status, reply_headers, data)
    except (OSError, http.client.HTTPException) as e:
        raise NetError(f"{type(e).__name__}: {e}") from e
    finally:
        conn.close()


Transport = Callable[..., Reply]
