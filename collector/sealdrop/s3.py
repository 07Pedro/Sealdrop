"""The inbox's requests (PROTOCOL.md §8): S3 over HTTPS, path style, AWS Signature Version 4 with a signed body.

No metadata, tags or other optional headers; uploads are `application/octet-stream`."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import ssl
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import BinaryIO, Callable

from . import net

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


@dataclass(frozen=True)
class Credentials:
    key_id: str
    secret: str

    def __repr__(self) -> str:  # never the secret, also not in a traceback
        return f"Credentials({self.key_id!r}, secret=…)"


class S3Error(Exception):
    """The storage answered with an error."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{status} {code}: {message}" if message else f"{status} {code}")
        self.status = status
        self.code = code
        self.message = message


@dataclass
class Version:
    """One entry of `ListObjectVersions`: a file version, or a delete marker (`hidden`)."""
    name: str
    version_id: str
    latest: bool
    hidden: bool
    etag: str | None = None
    size: int | None = None


@dataclass
class Listed:
    """One entry of `ListObjectsV2`."""
    name: str
    etag: str
    size: int


# --- Signature Version 4 -----------------------------------------------------------------------------------------

def uri_encode(text: str, keep_slash: bool = False) -> str:
    """AWS's encoding: everything but `A–Z a–z 0–9 - _ . ~` as UTF-8 %XX (and `/` too, unless kept)."""
    return urllib.parse.quote(text, safe="/" if keep_slash else "")


def _hmac(key: bytes, text: str) -> bytes:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest()


def sign(method: str, host: str, path: str, query: list[tuple[str, str]], headers: dict[str, str], body_sha256: str,
         credentials: Credentials, region: str, when: datetime.datetime, service: str = "s3") -> dict[str, str]:
    """The headers to send: `headers` plus host, x-amz-date, x-amz-content-sha256 and Authorization, all signed."""
    amz_date = when.astimezone(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    sent = {**headers, "host": host, "x-amz-date": amz_date, "x-amz-content-sha256": body_sha256}
    canonical_headers = {name.lower(): " ".join(str(value).split()) for name, value in sent.items()}
    names = sorted(canonical_headers)
    canonical = "\n".join([
        method,
        uri_encode(path, keep_slash=True),
        "&".join(f"{k}={v}" for k, v in sorted((uri_encode(k), uri_encode(v)) for k, v in query)),
        "".join(f"{name}:{canonical_headers[name]}\n" for name in names),
        ";".join(names),
        body_sha256,
    ])
    scope = f"{amz_date[:8]}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode("utf-8")).hexdigest()])
    key = _hmac(("AWS4" + credentials.secret).encode("utf-8"), amz_date[:8])
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    signature = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    sent["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={credentials.key_id}/{scope}, "
                             f"SignedHeaders={';'.join(names)}, Signature={signature}")
    return sent


# --- XML ---------------------------------------------------------------------------------------------------------

def _xml(data: bytes) -> ET.Element:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise S3Error(0, "BadReply", f"not XML: {e}") from e
    for element in root.iter():  # S3's namespace, or none
        if element.tag.startswith(_NS):
            element.tag = element.tag[len(_NS):]
    return root


def _text(element: ET.Element, tag: str, default: str | None = None) -> str:
    found = element.find(tag)
    if found is None or found.text is None:
        if default is None:
            raise S3Error(0, "BadReply", f"no {tag}")
        return default
    return found.text


def error_of(status: int, body: bytes) -> S3Error:
    try:
        root = _xml(body)
        return S3Error(status, _text(root, "Code", "?"), _text(root, "Message", ""))
    except S3Error:
        return S3Error(status, "?", "")


# --- the client --------------------------------------------------------------------------------------------------

class Client:
    """Requests to one endpoint with one key. Every method raises `S3Error` for an error answer and `net.NetError`
    when there's no answer."""

    def __init__(self, endpoint: str, region: str, credentials: Credentials, *,
                 context: ssl.SSLContext | None = None, transport: net.Transport = net.exchange,
                 clock: Callable[[], datetime.datetime] = lambda: datetime.datetime.now(datetime.UTC)):
        url = urllib.parse.urlsplit(endpoint)
        if url.scheme != "https" or not url.hostname or url.path or url.query or url.fragment or url.username:
            raise ValueError("the endpoint must be https://host[:port]")
        self.host = url.hostname
        self.port = url.port or 443
        self._host_header = self.host if self.port == 443 else f"{self.host}:{self.port}"
        self.region = region
        self.credentials = credentials
        self._context = context or net.system_context()
        self._transport = transport
        self._clock = clock

    def request(self, method: str, bucket: str, name: str = "", query: list[tuple[str, str]] = (),
                headers: dict[str, str] | None = None, body: bytes = b"", ok: tuple[int, ...] = (200,),
                out: BinaryIO | None = None) -> net.Reply:
        path = f"/{bucket}/{name}" if name else f"/{bucket}"
        body_sha256 = hashlib.sha256(body).hexdigest()
        sent = sign(method, self._host_header, path, list(query), headers or {}, body_sha256, self.credentials,
                    self.region, self._clock())
        target = uri_encode(path, keep_slash=True)
        if query:
            target += "?" + "&".join(uri_encode(k) + (f"={uri_encode(v)}" if v else "") for k, v in query)
        reply = self._transport(self.host, self.port, method, target, sent,
                                body if body or method in ("PUT", "POST") else None, context=self._context, out=out)
        if reply.status not in ok:
            raise error_of(reply.status, reply.body)
        return reply

    # objects

    def put_object(self, bucket: str, name: str, body: bytes) -> net.Reply:
        return self.request("PUT", bucket, name, headers={"Content-Type": "application/octet-stream"}, body=body)

    def get_object(self, bucket: str, name: str, *, version_id: str | None = None, first: int | None = None,
                   last: int | None = None, if_match: str | None = None, out: BinaryIO | None = None) -> net.Reply:
        """`first`/`last`: a byte range (`last` None: to the end)."""
        headers = {}
        if first is not None:
            headers["Range"] = f"bytes={first}-{'' if last is None else last}"
        if if_match is not None:
            headers["If-Match"] = if_match
        query = [("versionId", version_id)] if version_id else []
        return self.request("GET", bucket, name, query, headers, ok=(200, 206), out=out)

    def delete_object(self, bucket: str, name: str, *, version_id: str | None = None,
                      if_match: str | None = None) -> net.Reply:
        headers = {"If-Match": if_match} if if_match is not None else {}
        query = [("versionId", version_id)] if version_id else []
        return self.request("DELETE", bucket, name, query, headers, ok=(200, 204))

    # listings

    def list_objects(self, bucket: str, prefix: str, token: str | None = None) -> tuple[list[Listed], str | None]:
        """One page of `ListObjectsV2`, and the token for the next one (None: that was the last)."""
        query = [("list-type", "2"), ("prefix", prefix)] + ([("continuation-token", token)] if token else [])
        root = _xml(self.request("GET", bucket, query=query).body)
        entries = [Listed(_text(c, "Key"), _text(c, "ETag", ""), int(_text(c, "Size", "0")))
                   for c in root.findall("Contents")]
        more = _text(root, "IsTruncated", "false") == "true"
        return entries, (_text(root, "NextContinuationToken") if more else None)

    def list_object_versions(self, bucket: str, prefix: str, marker: tuple[str, str] | None = None
                             ) -> tuple[list[Version], tuple[str, str] | None]:
        """One page of `ListObjectVersions` (file versions and delete markers, in the order listed), and the
        (key, version ID) marker for the next one."""
        query = [("versions", ""), ("prefix", prefix)]
        if marker:
            query += [("key-marker", marker[0]), ("version-id-marker", marker[1])]
        root = _xml(self.request("GET", bucket, query=query).body)
        entries = []
        for child in root:
            if child.tag in ("Version", "DeleteMarker"):
                hidden = child.tag == "DeleteMarker"
                entries.append(Version(_text(child, "Key"), _text(child, "VersionId"),
                                       _text(child, "IsLatest", "false") == "true", hidden,
                                       None if hidden else _text(child, "ETag", ""),
                                       None if hidden else int(_text(child, "Size", "0"))))
        more = _text(root, "IsTruncated", "false") == "true"
        return entries, ((_text(root, "NextKeyMarker"), _text(root, "NextVersionIdMarker")) if more else None)

    # uploads in parts

    def create_multipart_upload(self, bucket: str, name: str) -> str:
        reply = self.request("POST", bucket, name, [("uploads", "")], {"Content-Type": "application/octet-stream"})
        return _text(_xml(reply.body), "UploadId")

    def upload_part(self, bucket: str, name: str, upload_id: str, number: int, body: bytes) -> str:
        reply = self.request("PUT", bucket, name, [("partNumber", str(number)), ("uploadId", upload_id)], body=body)
        if "etag" not in reply.headers:
            raise S3Error(reply.status, "BadReply", "no ETag")
        return reply.headers["etag"]

    def complete_multipart_upload(self, bucket: str, name: str, upload_id: str, etags: list[str]) -> net.Reply:
        parts = "".join(f"<Part><PartNumber>{i}</PartNumber><ETag>{_escape(etag)}</ETag></Part>"
                        for i, etag in enumerate(etags, 1))
        body = f"<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>".encode("utf-8")
        reply = self.request("POST", bucket, name, [("uploadId", upload_id)], body=body)
        if _xml(reply.body).tag == "Error":  # S3 may answer 200 and still have failed
            raise error_of(reply.status, reply.body)
        return reply

    def abort_multipart_upload(self, bucket: str, name: str, upload_id: str) -> net.Reply:
        return self.request("DELETE", bucket, name, [("uploadId", upload_id)], ok=(200, 204))


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
