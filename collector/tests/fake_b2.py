"""A Backblaze B2 in memory, for the setup's tests: its own interface (the calls the setup makes) and the S3
interface (the inbox's requests), with keys limited by permissions, buckets and folder as Backblaze documents it.

Every S3 request's signature is checked against what was actually sent, so a request that's signed one way and
sent another fails here too."""

from __future__ import annotations

import base64
import datetime
import email.utils
import hashlib
import itertools
import json
import re
import urllib.parse
from dataclasses import dataclass, field

from sealdrop import net, s3

API = "api005.backblazeb2.com"
S3_HOST = "s3.eu-central-005.backblazeb2.com"
REGION = "eu-central-005"
ALL = ["listKeys", "writeKeys", "deleteKeys", "listBuckets", "listAllBucketNames", "readBuckets", "writeBuckets",
       "deleteBuckets", "readBucketRetentions", "writeBucketRetentions", "readBucketEncryption",
       "writeBucketEncryption", "listFiles", "readFiles", "shareFiles", "writeFiles", "deleteFiles",
       "readFileLegalHolds", "writeFileLegalHolds", "readFileRetentions", "writeFileRetentions", "bypassGovernance"]
_AUTH = re.compile(r"AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/s3/aws4_request, "
                   r"SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})")


@dataclass
class Key:
    id: str
    secret: str
    name: str
    capabilities: list[str]
    bucket_ids: list[str] | None = None
    prefix: str | None = None


@dataclass
class FileVersion:
    id: str
    bucket_id: str
    name: str
    action: str  # upload, hide, start
    data: bytes = b""
    parts: dict[int, bytes] = field(default_factory=dict)

    @property
    def etag(self) -> str:
        return '"' + hashlib.md5(self.data).hexdigest() + '"'


class FakeB2:
    def __init__(self):
        self.ids = itertools.count(1)
        self.master = Key("000master", "K000mastersecret", "master", list(ALL))
        self.keys: dict[str, Key] = {}
        self.tokens: dict[str, Key] = {}
        self.buckets: dict[str, dict] = {}
        self.files: list[FileVersion] = []
        self.requests: list[tuple[str, str, str]] = []
        self.date = email.utils.format_datetime(datetime.datetime.now(datetime.UTC), usegmt=True)
        # Backblaze behaviour that the setup must cope with, or must catch
        self.delete_by_version_needs_write = False
        self.extra_capability: tuple[str, str] | None = None  # (key name, capability) granted on top, wrongly
        self.ignore_if_match = False
        self.lifecycle_dropped = False
        self.interrupt_at: str | None = None  # raise KeyboardInterrupt at this S3 operation

    def _id(self, kind: str) -> str:
        return f"{kind}{next(self.ids):06d}"

    def key(self, name: str) -> Key:
        return next(k for k in self.keys.values() if k.name == name)

    def bucket_by_name(self, name: str) -> dict | None:
        return next((b for b in self.buckets.values() if b["bucketName"] == name), None)

    # --- the transport ------------------------------------------------------------------------------------------

    def __call__(self, host, port, method, target, headers, body, *, context, out=None) -> net.Reply:
        assert port == 443
        assert context is not None
        headers = {k.lower(): v for k, v in headers.items()}  # (net.exchange adds the User-Agent; test_s3 checks it)
        self.requests.append((host, method, target))
        if host in ("api.backblazeb2.com", API):
            return self._native(host, method, target, headers, body)
        assert host == S3_HOST, host
        reply = self._s3(method, target, headers, body or b"")
        if out is not None and 200 <= reply.status < 300:
            out.write(reply.body)
            reply = net.Reply(reply.status, reply.headers, b"")
        return reply

    # --- Backblaze's own interface ------------------------------------------------------------------------------

    def _json(self, status: int, value: dict) -> net.Reply:
        return net.Reply(status, {"content-type": "application/json", "date": self.date},
                         json.dumps(value).encode())

    def _error(self, status: int, code: str, message: str = "") -> net.Reply:
        return self._json(status, {"status": status, "code": code, "message": message})

    def _native(self, host, method, target, headers, body) -> net.Reply:
        name = target.removeprefix("/b2api/v4/")
        if name == "b2_authorize_account":
            assert host == "api.backblazeb2.com" and method == "GET"
            basic = headers["authorization"].removeprefix("Basic ")
            key_id, _, secret = base64.b64decode(basic).decode().partition(":")
            key = self.master if key_id == self.master.id else self.keys.get(key_id)
            if key is None or key.secret != secret:
                return self._error(401, "bad_auth_token")  # what Backblaze answers (seen 2026-11-04)
            token = self._id("token")
            self.tokens[token] = key
            allowed = {"capabilities": key.capabilities, "namePrefix": key.prefix,
                       "buckets": None if key.bucket_ids is None else [{"id": b, "name": None} for b in key.bucket_ids]}
            return self._json(200, {"accountId": "acc1", "authorizationToken": token, "apiInfo": {"storageApi": {
                "apiUrl": f"https://{API}", "s3ApiUrl": f"https://{S3_HOST}", "downloadUrl": "https://f005.example",
                "allowed": allowed, "absoluteMinimumPartSize": 5000000, "recommendedPartSize": 100000000}}})
        assert host == API and method == "POST", (host, method)
        key = self.tokens.get(headers.get("authorization"))
        if key is None:
            return self._error(401, "bad_auth_token")
        request = json.loads(body)
        handler = getattr(self, "_" + name)
        return handler(key, request)

    def _need(self, key: Key, capability: str, bucket_id: str | None = None, file_name: str | None = None) -> bool:
        if capability not in key.capabilities:
            return False
        if bucket_id is not None and key.bucket_ids is not None and bucket_id not in key.bucket_ids:
            return False
        return file_name is None or key.prefix is None or file_name.startswith(key.prefix)

    def _b2_create_bucket(self, key, r):
        if not self._need(key, "writeBuckets"):
            return self._error(401, "unauthorized")
        if self.bucket_by_name(r["bucketName"]):
            return self._error(400, "duplicate_bucket_name")
        bucket_id = self._id("bucket")
        rules = [] if self.lifecycle_dropped else [
            {**{"daysFromStartingToCancelingUnfinishedLargeFiles": None}, **rule} for rule in r["lifecycleRules"]]
        self.buckets[bucket_id] = {
            "accountId": "acc1", "bucketId": bucket_id, "bucketName": r["bucketName"], "bucketType": r["bucketType"],
            "bucketInfo": {}, "corsRules": [], "lifecycleRules": rules, "revision": 1, "options": ["s3"],
            "defaultServerSideEncryption": {"isClientAuthorizedToRead": True,
                                            "value": r["defaultServerSideEncryption"]},
            "fileLockConfiguration": {"isClientAuthorizedToRead": True,
                                      "value": {"defaultRetention": {"mode": None}, "isFileLockEnabled":
                                                r["fileLockEnabled"]}},
        }
        return self._json(200, self.buckets[bucket_id])

    def _b2_list_buckets(self, key, r):
        if not self._need(key, "listBuckets"):
            return self._error(401, "unauthorized")
        found = [b for b in self.buckets.values() if r.get("bucketName") in (None, b["bucketName"])]
        return self._json(200, {"buckets": found})

    def _b2_delete_bucket(self, key, r):
        if not self._need(key, "deleteBuckets"):
            return self._error(401, "unauthorized")
        if any(f.bucket_id == r["bucketId"] for f in self.files):
            return self._error(400, "cannot_delete_non_empty_bucket")
        return self._json(200, self.buckets.pop(r["bucketId"]))

    def _key_json(self, k: Key) -> dict:
        return {"keyName": k.name, "applicationKeyId": k.id, "capabilities": k.capabilities, "accountId": "acc1",
                "bucketIds": k.bucket_ids, "namePrefix": k.prefix, "options": ["s3"]}

    def _b2_create_key(self, key, r):
        if not self._need(key, "writeKeys"):
            return self._error(401, "unauthorized")
        assert "validDurationInSeconds" not in r and "bucketId" not in r
        new = Key(self._id("005key"), "K005" + self._id("secret") + "xyz", r["keyName"], list(r["capabilities"]),
                  r.get("bucketIds"), r.get("namePrefix"))
        if self.extra_capability and self.extra_capability[0] == new.name:
            new.capabilities.append(self.extra_capability[1])
        self.keys[new.id] = new
        return self._json(200, {**self._key_json(new), "applicationKey": new.secret})

    def _b2_list_keys(self, key, r):
        if not self._need(key, "listKeys"):
            return self._error(401, "unauthorized")
        return self._json(200, {"keys": [self._key_json(k) for k in self.keys.values()], "nextApplicationKeyId": None})

    def _b2_delete_key(self, key, r):
        if not self._need(key, "deleteKeys"):
            return self._error(401, "unauthorized")
        return self._json(200, self._key_json(self.keys.pop(r["applicationKeyId"])))

    def _version_json(self, f: FileVersion) -> dict:
        return {"fileId": f.id, "fileName": f.name, "action": f.action, "contentLength": len(f.data)}

    def _b2_list_file_versions(self, key, r):
        if not self._need(key, "listFiles", r["bucketId"]):
            return self._error(401, "unauthorized")
        found = [self._version_json(f) for f in self.files if f.bucket_id == r["bucketId"]]
        return self._json(200, {"files": found, "nextFileName": None, "nextFileId": None})

    def _b2_list_unfinished_large_files(self, key, r):
        if not self._need(key, "listFiles", r["bucketId"]):
            return self._error(401, "unauthorized")
        found = [self._version_json(f) for f in self.files if f.bucket_id == r["bucketId"] and f.action == "start"]
        return self._json(200, {"files": found, "nextFileId": None})

    def _find(self, file_id: str) -> FileVersion | None:
        return next((f for f in self.files if f.id == file_id), None)

    def _b2_cancel_large_file(self, key, r):
        f = self._find(r["fileId"])
        if f is None or f.action != "start":
            return self._error(400, "bad_request")
        if not self._need(key, "writeFiles", f.bucket_id, f.name):
            return self._error(401, "unauthorized")
        self.files.remove(f)
        return self._json(200, self._version_json(f))

    def _b2_delete_file_version(self, key, r):
        f = self._find(r["fileId"])
        if f is None or f.name != r["fileName"]:
            return self._error(400, "file_not_present")
        if not self._need(key, "deleteFiles", f.bucket_id, f.name):
            return self._error(401, "unauthorized")
        self.files.remove(f)
        return self._json(200, self._version_json(f))

    # --- the S3 interface ---------------------------------------------------------------------------------------

    def _xml(self, status: int, text: str, extra: dict | None = None) -> net.Reply:
        return net.Reply(status, {"content-type": "application/xml", **(extra or {})},
                         ('<?xml version="1.0" encoding="UTF-8"?>' + text).encode())

    def _s3_error(self, status: int, code: str, message: str = "") -> net.Reply:
        return self._xml(status, f"<Error><Code>{code}</Code><Message>{message}</Message></Error>")

    def _check_signature(self, method, path, query, headers, body) -> Key | net.Reply:
        match = _AUTH.fullmatch(headers.get("authorization", ""))
        if not match:
            return self._s3_error(400, "AuthorizationHeaderMalformed")
        key_id, day, region, signed, signature = match.groups()
        key = self.keys.get(key_id)
        if key is None:
            return self._s3_error(403, "InvalidAccessKeyId")
        names = signed.split(";")
        if not {"host", "x-amz-date", "x-amz-content-sha256"} <= set(names) or region != REGION:
            return self._s3_error(400, "AuthorizationHeaderMalformed")
        if headers["x-amz-content-sha256"] != hashlib.sha256(body).hexdigest():
            return self._s3_error(400, "XAmzContentSHA256Mismatch")
        when = datetime.datetime.strptime(headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.UTC)
        unsigned = {n: headers[n] for n in names if n not in ("host", "x-amz-date", "x-amz-content-sha256")}
        again = s3.sign(method, headers["host"], path, query, unsigned, headers["x-amz-content-sha256"],
                        s3.Credentials(key.id, key.secret), region, when)
        if again["Authorization"] != headers["authorization"] or day != headers["x-amz-date"][:8]:
            return self._s3_error(403, "SignatureDoesNotMatch")
        return key

    def _denied(self) -> net.Reply:
        return self._s3_error(403, "AccessDenied", "not entitled")

    def _s3(self, method, target, headers, body) -> net.Reply:
        raw_path, _, raw_query = target.partition("?")
        path = urllib.parse.unquote(raw_path)
        query = urllib.parse.parse_qsl(raw_query, keep_blank_values=True)
        assert all(not k.startswith("x-amz-meta") for k in headers)
        key = self._check_signature(method, path, query, headers, body)
        if isinstance(key, net.Reply):
            return key
        q = dict(query)
        bucket_name, _, name = path.lstrip("/").partition("/")
        bucket = self.bucket_by_name(bucket_name)
        if bucket is None:
            return self._s3_error(404, "NoSuchBucket")
        bid = bucket["bucketId"]
        operation = self._operation(method, name, q)
        if self.interrupt_at == operation:
            raise KeyboardInterrupt
        if not name:  # listings
            prefix = q.get("prefix", "")
            if not self._need(key, "listFiles", bid, prefix):
                return self._denied()
            return self._list_versions(bid, prefix) if "versions" in q else self._list(bid, prefix)
        if operation in ("put", "create", "part", "complete", "abort", "hide"):
            if not self._need(key, "writeFiles", bid, name):
                return self._denied()
            assert operation not in ("put", "create") or headers.get("content-type") == "application/octet-stream"
            return getattr(self, "_s3_" + operation)(bid, name, q, body)
        if operation == "get":
            if not self._need(key, "readFiles", bid, name):
                return self._denied()
            return self._s3_get(bid, name, q, headers)
        assert operation == "delete"
        if not self._need(key, "deleteFiles", bid, name) or (
                self.delete_by_version_needs_write and not self._need(key, "writeFiles", bid, name)):
            return self._denied()
        f = self._find(q["versionId"])
        if f is None or f.name != name or f.action == "start":
            return self._s3_error(400, "InvalidArgument", "bad version")
        self.files.remove(f)
        return net.Reply(204, {"x-amz-version-id": f.id}, b"")

    @staticmethod
    def _operation(method, name, q) -> str:
        if not name:
            return "list"
        if method == "PUT":
            return "part" if "partNumber" in q else "put"
        if method == "POST":
            return "create" if "uploads" in q else "complete"
        if method == "DELETE":
            return "abort" if "uploadId" in q else ("delete" if "versionId" in q else "hide")
        return "get"

    def _latest(self, bid, name) -> FileVersion | None:
        versions = [f for f in self.files if f.bucket_id == bid and f.name == name and f.action != "start"]
        return versions[-1] if versions else None

    def _s3_put(self, bid, name, q, body):
        f = FileVersion(self._id("4_z"), bid, name, "upload", body)
        self.files.append(f)
        return net.Reply(200, {"etag": f.etag, "x-amz-version-id": f.id}, b"")

    def _s3_create(self, bid, name, q, body):
        f = FileVersion(self._id("4_z"), bid, name, "start")
        self.files.append(f)
        return self._xml(200, f"<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>{name}</Key>"
                              f"<UploadId>{f.id}</UploadId></InitiateMultipartUploadResult>")

    def _s3_part(self, bid, name, q, body):
        f = self._find(q["uploadId"])
        if f is None or f.action != "start":
            return self._s3_error(404, "NoSuchUpload")
        f.parts[int(q["partNumber"])] = body
        return net.Reply(200, {"etag": '"' + hashlib.md5(body).hexdigest() + '"'}, b"")

    def _s3_complete(self, bid, name, q, body):
        f = self._find(q["uploadId"])
        if f is None or f.action != "start":
            return self._s3_error(404, "NoSuchUpload")
        listed = re.findall(r"<Part><PartNumber>(\d+)</PartNumber><ETag>([^<]+)</ETag></Part>", body.decode())
        numbers = [int(n) for n, _ in listed]
        if numbers != sorted(f.parts) or any(len(f.parts[n]) < 5_000_000 for n in numbers[:-1]):
            return self._xml(200, "<Error><Code>InvalidPart</Code><Message>parts</Message></Error>")
        f.data, f.action, f.parts = b"".join(f.parts[n] for n in numbers), "upload", {}
        return self._xml(200, f"<CompleteMultipartUploadResult><Key>{name}</Key><ETag>{f.etag}</ETag>"
                              "</CompleteMultipartUploadResult>")

    def _s3_abort(self, bid, name, q, body):
        f = self._find(q["uploadId"])
        if f is None or f.action != "start":
            return self._s3_error(404, "NoSuchUpload")
        self.files.remove(f)
        return net.Reply(204, {}, b"")

    def _s3_hide(self, bid, name, q, body):
        f = FileVersion(self._id("4_z"), bid, name, "hide")
        self.files.append(f)
        return net.Reply(204, {"x-amz-delete-marker": "true", "x-amz-version-id": f.id}, b"")

    def _s3_get(self, bid, name, q, headers):
        if "versionId" in q:
            f = self._find(q["versionId"])
            f = f if f and f.name == name and f.action == "upload" else None
        else:
            f = self._latest(bid, name)
            f = f if f and f.action == "upload" else None
        if f is None:
            return self._s3_error(404, "NoSuchKey")
        if "if-match" in headers and headers["if-match"] != f.etag and not self.ignore_if_match:
            return self._s3_error(412, "PreconditionFailed")
        if "range" in headers:
            first, _, last = headers["range"].removeprefix("bytes=").partition("-")
            data = f.data[int(first):(int(last) + 1 if last else None)]
            return net.Reply(206, {"etag": f.etag}, data)
        return net.Reply(200, {"etag": f.etag}, f.data)

    def _list(self, bid, prefix):
        names = sorted({f.name for f in self.files if f.bucket_id == bid and f.name.startswith(prefix)
                        and (latest := self._latest(bid, f.name)) and latest.action == "upload"})
        contents = "".join(f"<Contents><Key>{n}</Key><ETag>{self._latest(bid, n).etag}</ETag>"
                           f"<Size>{len(self._latest(bid, n).data)}</Size></Contents>" for n in names)
        return self._xml(200, '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                              f"<IsTruncated>false</IsTruncated>{contents}<KeyCount>{len(names)}</KeyCount>"
                              "</ListBucketResult>")

    def _list_versions(self, bid, prefix):
        entries = []
        for name in sorted({f.name for f in self.files if f.bucket_id == bid and f.name.startswith(prefix)}):
            versions = [f for f in self.files if f.bucket_id == bid and f.name == name and f.action != "start"]
            for i, f in enumerate(reversed(versions)):
                latest = "true" if i == 0 else "false"
                if f.action == "hide":
                    entries.append(f"<DeleteMarker><Key>{name}</Key><VersionId>{f.id}</VersionId>"
                                   f"<IsLatest>{latest}</IsLatest></DeleteMarker>")
                else:
                    entries.append(f"<Version><Key>{name}</Key><VersionId>{f.id}</VersionId>"
                                   f"<IsLatest>{latest}</IsLatest><ETag>{f.etag}</ETag>"
                                   f"<Size>{len(f.data)}</Size></Version>")
        return self._xml(200, '<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                              f"<IsTruncated>false</IsTruncated>{''.join(entries)}</ListVersionsResult>")
