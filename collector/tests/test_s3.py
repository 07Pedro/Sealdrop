"""The inbox's requests: Signature Version 4 against AWS's published examples, the request form of PROTOCOL.md §8,
and HTTPS against a local server."""

from __future__ import annotations

import datetime
import hashlib
import http.server
import io
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

import helpers  # noqa: F401  (paths)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sealdrop import net, s3

# AWS's examples for S3 ("Signature Calculations for the Authorization Header: Transferring Payload in a Single
# Chunk"): the documented key, bucket, time and signatures.
AWS = s3.Credentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
AWS_HOST = "examplebucket.s3.amazonaws.com"
AWS_TIME = datetime.datetime(2013, 5, 24, tzinfo=datetime.UTC)


def signature(headers: dict[str, str]) -> str:
    return headers["Authorization"].rpartition("Signature=")[2]


class SignatureV4(unittest.TestCase):
    def test_get_object(self):
        h = s3.sign("GET", AWS_HOST, "/test.txt", [], {"Range": "bytes=0-9"}, s3.EMPTY_SHA256, AWS, "us-east-1",
                    AWS_TIME)
        self.assertIn("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,", h["Authorization"])
        self.assertEqual(signature(h), "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")

    def test_put_object(self):
        body = b"Welcome to Amazon S3."
        h = s3.sign("PUT", AWS_HOST, "/test$file.text", [],
                    {"Date": "Fri, 24 May 2013 00:00:00 GMT", "x-amz-storage-class": "REDUCED_REDUNDANCY"},
                    hashlib.sha256(body).hexdigest(), AWS, "us-east-1", AWS_TIME)
        self.assertEqual(signature(h), "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")

    def test_query_without_value(self):
        h = s3.sign("GET", AWS_HOST, "/", [("lifecycle", "")], {}, s3.EMPTY_SHA256, AWS, "us-east-1", AWS_TIME)
        self.assertEqual(signature(h), "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543")

    def test_listing(self):
        # the order given doesn't matter: the canonical query is sorted
        h = s3.sign("GET", AWS_HOST, "/", [("prefix", "J"), ("max-keys", "2")], {}, s3.EMPTY_SHA256, AWS,
                    "us-east-1", AWS_TIME)
        self.assertEqual(signature(h), "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
        self.assertEqual(h["Authorization"].split(", ")[0],
                         "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request")

    def test_encoding(self):
        self.assertEqual(s3.uri_encode("a b/c~d_e.f-g+h=", keep_slash=True), "a%20b/c~d_e.f-g%2Bh%3D")
        self.assertEqual(s3.uri_encode("up/x"), "up%2Fx")
        self.assertEqual(s3.uri_encode("é"), "%C3%A9")

    def test_secret_never_in_repr(self):
        self.assertNotIn("EXAMPLEKEY", repr(AWS))
        self.assertNotIn("EXAMPLEKEY", str([AWS]))


class Recorder:
    """A transport that remembers the request and gives a set answer."""

    def __init__(self, status=200, headers=None, body=b""):
        self.reply = net.Reply(status, headers or {}, body)
        self.sent = []

    def __call__(self, host, port, method, target, headers, body, *, context, out=None):
        self.sent.append((host, port, method, target, headers, body))
        if out is not None:
            out.write(self.reply.body)
        return self.reply


def client(transport, endpoint="https://s3.eu-central-005.backblazeb2.com") -> s3.Client:
    return s3.Client(endpoint, "eu-central-005", s3.Credentials("005id", "secret"), transport=transport,
                     clock=lambda: AWS_TIME)


class Requests(unittest.TestCase):
    def test_path_style_and_signed_body(self):
        r = Recorder()
        client(r).put_object("bucket-x", "up/abc", b"data")
        host, port, method, target, headers, body = r.sent[0]
        self.assertEqual((host, port, method, target, body), ("s3.eu-central-005.backblazeb2.com", 443, "PUT",
                                                              "/bucket-x/up/abc", b"data"))
        self.assertEqual(headers["x-amz-content-sha256"], hashlib.sha256(b"data").hexdigest())
        self.assertEqual(headers["Content-Type"], "application/octet-stream")
        self.assertEqual(headers["host"], "s3.eu-central-005.backblazeb2.com")
        self.assertEqual(sorted(headers), ["Authorization", "Content-Type", "host", "x-amz-content-sha256",
                                           "x-amz-date"])  # nothing else: no metadata, no device

    def test_port_in_host(self):
        r = Recorder()
        client(r, "https://storage.example:8443").get_object("b-x", "ack/n")
        self.assertEqual(r.sent[0][:2], ("storage.example", 8443))
        self.assertEqual(r.sent[0][4]["host"], "storage.example:8443")
        self.assertIsNone(r.sent[0][5])  # no body (and so no Content-Length) on a GET

    def test_endpoints_refused(self):
        for endpoint in ("http://s3.example", "https://s3.example/path", "https://user@s3.example", "s3.example"):
            with self.assertRaises(ValueError):
                client(Recorder(), endpoint)

    def test_query_forms(self):
        r = Recorder(200, {}, b"<InitiateMultipartUploadResult><UploadId>u+1/2</UploadId>"
                              b"</InitiateMultipartUploadResult>")
        c = client(r)
        self.assertEqual(c.create_multipart_upload("b-x", "up/n"), "u+1/2")
        self.assertEqual(r.sent[0][3], "/b-x/up/n?uploads")
        r.reply = net.Reply(200, {"etag": '"e1"'}, b"")
        self.assertEqual(c.upload_part("b-x", "up/n", "u+1/2", 1, b"x"), '"e1"')
        self.assertEqual(r.sent[1][3], "/b-x/up/n?partNumber=1&uploadId=u%2B1%2F2")
        r.reply = net.Reply(200, {}, b'<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>')
        c.list_object_versions("b-x", "up/", ("up/a", "v 1"))
        self.assertEqual(r.sent[2][3], "/b-x?versions&prefix=up%2F&key-marker=up%2Fa&version-id-marker=v%201")
        r.reply = net.Reply(206, {}, b"abc")
        c.get_object("b-x", "up/n", version_id="4_z1", first=152, if_match='"e"')
        self.assertEqual((r.sent[3][3], r.sent[3][4]["Range"], r.sent[3][4]["If-Match"]),
                         ("/b-x/up/n?versionId=4_z1", "bytes=152-", '"e"'))

    def test_errors(self):
        r = Recorder(403, {}, b'<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>not entitled</Message>'
                              b"</Error>")
        with self.assertRaises(s3.S3Error) as caught:
            client(r).get_object("b-x", "up/n")
        self.assertEqual((caught.exception.status, caught.exception.code), (403, "AccessDenied"))
        r.reply = net.Reply(301, {"location": "https://elsewhere.example/"}, b"")
        with self.assertRaises(s3.S3Error) as caught:
            client(r).get_object("b-x", "up/n")
        self.assertEqual(caught.exception.status, 301)  # a redirect is an error, never followed
        self.assertEqual(len(r.sent), 2)

    def test_complete_can_fail_with_200(self):
        r = Recorder(200, {}, b"<Error><Code>InternalError</Code><Message>try again</Message></Error>")
        with self.assertRaises(s3.S3Error) as caught:
            client(r).complete_multipart_upload("b-x", "up/n", "u1", ['"a"', '"b"'])
        self.assertEqual(caught.exception.code, "InternalError")
        self.assertIn(b'<Part><PartNumber>2</PartNumber><ETag>"b"</ETag></Part>', r.sent[0][5])

    def test_listings(self):
        r = Recorder(200, {}, b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                              b"<IsTruncated>true</IsTruncated><NextContinuationToken>t/1</NextContinuationToken>"
                              b'<Contents><Key>ack/a</Key><ETag>"e"</ETag><Size>12</Size></Contents>'
                              b"</ListBucketResult>")
        entries, token = client(r).list_objects("b-x", "ack/")
        self.assertEqual((entries[0].name, entries[0].etag, entries[0].size, token), ("ack/a", '"e"', 12, "t/1"))
        self.assertEqual(r.sent[0][3], "/b-x?list-type=2&prefix=ack%2F")
        r.reply = net.Reply(200, {}, b'<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                                     b"<IsTruncated>false</IsTruncated>"
                                     b"<DeleteMarker><Key>up/a</Key><VersionId>v2</VersionId><IsLatest>true</IsLatest>"
                                     b"</DeleteMarker><Version><Key>up/a</Key><VersionId>v1</VersionId>"
                                     b'<IsLatest>false</IsLatest><ETag>"e"</ETag><Size>5</Size></Version>'
                                     b"</ListVersionsResult>")
        versions, marker = client(r).list_object_versions("b-x", "up/")
        self.assertEqual([(v.name, v.version_id, v.latest, v.hidden, v.size) for v in versions],
                         [("up/a", "v2", True, True, None), ("up/a", "v1", False, False, 5)])
        self.assertIsNone(marker)


class _Handler(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):
        _Handler.seen.append((self.path, dict(self.headers)))
        if self.path == "/moved":
            self.send_response(301)
            self.send_header("Location", "/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"x" * (3 << 20) if self.path == "/big" else b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Https(unittest.TestCase):
    """`net.exchange` against a local HTTPS server with its own certificate authority."""

    @classmethod
    def setUpClass(cls):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.UTC)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        cls.folder = tempfile.TemporaryDirectory()
        cert_file, key_file = Path(cls.folder.name, "cert.pem"), Path(cls.folder.name, "key.pem")
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_file, key_file)
        cls.server = http.server.ThreadingHTTPServer(("localhost", 0), _Handler)
        cls.server.socket = server_context.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.trusting = net.system_context()
        cls.trusting.load_verify_locations(cert_file)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.folder.cleanup()

    def get(self, path, context=None, out=None):
        return net.exchange("localhost", self.port, "GET", path, {"host": f"localhost:{self.port}"}, None,
                            context=context or self.trusting, out=out)

    def test_request(self):
        reply = self.get("/hello")
        self.assertEqual((reply.status, reply.body), (200, b"hello"))
        path, headers = _Handler.seen[-1]
        self.assertEqual(headers["User-Agent"], "sealdrop")
        self.assertEqual(headers["host"], f"localhost:{self.port}")

    def test_redirect_not_followed(self):
        reply = self.get("/moved")
        self.assertEqual((reply.status, reply.headers["location"]), (301, "/elsewhere"))
        self.assertNotIn("/elsewhere", [p for p, _ in _Handler.seen])

    def test_out(self):
        out = io.BytesIO()
        reply = self.get("/big", out=out)
        self.assertEqual((reply.body, len(out.getvalue())), (b"", 3 << 20))

    def test_unknown_certificate_refused(self):
        with self.assertRaises(net.NetError):
            self.get("/hello", context=net.system_context())

    def test_old_tls_refused(self):
        self.assertGreaterEqual(net.system_context().minimum_version, ssl.TLSVersion.TLSv1_2)


if __name__ == "__main__":
    unittest.main()
