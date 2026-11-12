"""The few calls of Backblaze B2's own interface (API v4) that the setup needs: buckets, keys, and emptying a bucket.

The S3 interface can't make keys limited to a prefix, nor read them back, so the setup uses this one; the inbox
itself is only ever used over S3 (`s3.py`)."""

from __future__ import annotations

import base64
import datetime
import email.utils
import json
import ssl
import urllib.parse

from . import net

API_URL = "https://api.backblazeb2.com"


class B2Error(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


class Account:
    """Authorized with one application key (for the setup: the master key)."""

    def __init__(self, key_id: str, key: str, *, context: ssl.SSLContext | None = None,
                 transport: net.Transport = net.exchange, api_url: str = API_URL):
        self._context = context or net.system_context()
        self._transport = transport
        self.server_time: datetime.datetime | None = None  # from the first answer's Date header
        basic = base64.b64encode(f"{key_id}:{key}".encode("utf-8")).decode("ascii")
        info = self._call(api_url, "GET", "b2_authorize_account", {"Authorization": f"Basic {basic}"}, None)
        self.account_id: str = info["accountId"]
        self._token: str = info["authorizationToken"]
        storage = info["apiInfo"]["storageApi"]
        self.api_url: str = storage["apiUrl"]
        self.s3_url: str = storage["s3ApiUrl"]
        allowed = storage.get("allowed") or {}
        self.capabilities: set[str] = set(allowed.get("capabilities") or [])

    @property
    def region(self) -> str:
        """`us-west-004` from `https://s3.us-west-004.backblazeb2.com`."""
        host = urllib.parse.urlsplit(self.s3_url).hostname or ""
        return host.split(".")[1] if host.startswith("s3.") and host.count(".") >= 2 else ""

    def _call(self, base: str, method: str, name: str, headers: dict[str, str], body: dict | None) -> dict:
        url = urllib.parse.urlsplit(base)
        data = None if body is None else json.dumps(body).encode("utf-8")
        sent = {**headers, **({"Content-Type": "application/json"} if data is not None else {})}
        reply = self._transport(url.hostname, url.port or 443, method, f"/b2api/v4/{name}", sent, data,
                                context=self._context)
        if self.server_time is None and "date" in reply.headers:
            try:
                self.server_time = email.utils.parsedate_to_datetime(reply.headers["date"])
            except (TypeError, ValueError):
                pass
        try:
            answer = json.loads(reply.body) if reply.body else {}
        except ValueError:
            answer = {}
        if reply.status != 200:
            raise B2Error(reply.status, str(answer.get("code", "?")), str(answer.get("message", "")))
        if not isinstance(answer, dict):
            raise B2Error(reply.status, "bad_reply", "not a JSON object")
        return answer

    def call(self, name: str, body: dict) -> dict:
        return self._call(self.api_url, "POST", name, {"Authorization": self._token}, body)

    # buckets

    def create_bucket(self, name: str, lifecycle_rules: list[dict]) -> dict:
        """Private, Backblaze's encryption (SSE-B2) switched on, no object lock."""
        return self.call("b2_create_bucket", {
            "accountId": self.account_id, "bucketName": name, "bucketType": "allPrivate",
            "defaultServerSideEncryption": {"mode": "SSE-B2", "algorithm": "AES256"},
            "fileLockEnabled": False, "lifecycleRules": lifecycle_rules,
        })

    def find_bucket(self, name: str) -> dict | None:
        found = self.call("b2_list_buckets", {"accountId": self.account_id, "bucketName": name})["buckets"]
        return found[0] if found else None

    def delete_bucket(self, bucket_id: str) -> None:
        self.call("b2_delete_bucket", {"accountId": self.account_id, "bucketId": bucket_id})

    # keys

    def create_key(self, name: str, capabilities: list[str], bucket_id: str, prefix: str | None) -> dict:
        """No expiry date: an expired key would silently stop the syncing. Without a prefix ("" or None) the key
        reaches the whole bucket, and `namePrefix` is left out: Backblaze answers an empty one with
        500 internal_error (seen 2026-11-11)."""
        return self.call("b2_create_key", {
            "accountId": self.account_id, "keyName": name, "capabilities": capabilities,
            "bucketIds": [bucket_id], **({"namePrefix": prefix} if prefix else {}),
        })

    def list_keys(self) -> list[dict]:
        keys, start = [], None
        while True:
            page = self.call("b2_list_keys", {"accountId": self.account_id, "maxKeyCount": 1000,
                                              **({"startApplicationKeyId": start} if start else {})})
            keys += page["keys"]
            start = page.get("nextApplicationKeyId")
            if not start:
                return keys

    def delete_key(self, key_id: str) -> None:
        self.call("b2_delete_key", {"applicationKeyId": key_id})

    # emptying a bucket (only ever the one the setup made or tested with)

    def file_versions(self, bucket_id: str) -> list[dict]:
        versions, start = [], {}
        while True:
            page = self.call("b2_list_file_versions", {"bucketId": bucket_id, "maxFileCount": 1000, **start})
            versions += page["files"]
            if not page.get("nextFileName"):
                return versions
            start = {"startFileName": page["nextFileName"], "startFileId": page.get("nextFileId")}

    def unfinished_uploads(self, bucket_id: str) -> list[dict]:
        uploads, start = [], {}
        while True:
            page = self.call("b2_list_unfinished_large_files", {"bucketId": bucket_id, "maxFileCount": 100, **start})
            uploads += page["files"]
            if not page.get("nextFileId"):
                return uploads
            start = {"startFileId": page["nextFileId"]}

    def empty_bucket(self, bucket_id: str) -> int:
        """Deletes every file version and unfinished upload; how many there were."""
        count = 0
        for upload in self.unfinished_uploads(bucket_id):
            self.call("b2_cancel_large_file", {"fileId": upload["fileId"]})
            count += 1
        for version in self.file_versions(bucket_id):
            if version.get("action") == "start":  # an unfinished upload, cancelled above
                continue
            self.call("b2_delete_file_version", {"fileName": version["fileName"], "fileId": version["fileId"]})
            count += 1
        return count
