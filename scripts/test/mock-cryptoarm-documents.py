#!/usr/bin/env python3
"""Minimal fake of the КриптоАРМ Документы API (+ КриптоАРМ Server /cms/verify) for smoke-documents tests.

Usage: mock-cryptoarm-documents.py <port> <record_dir>
Env:
  MOCK_MODE            ok | no_corp_cloud | no_cert | cloud_sign_error | attached | export_differs |
                       no_signature | download_differs |
                       verify_not_pdf | sign_invalid | two_signers | thumb_mismatch |
                       server_invalid | server_accepts_tampered
  MOCK_ADMIN_PASSWORD  password of user "admin"
  MOCK_THUMB           SHA-1 thumbprint (hex) reported for the signer certificate
Request bodies go to <record_dir>/<n>-<method>-<path>.body (path with / -> _), so tests can assert
on what the client sent; the session is a cookie "sid=<login>".
"""
import base64
import email
import hashlib
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

MODE = os.environ.get("MOCK_MODE", "ok")
THUMB = os.environ.get("MOCK_THUMB", "00" * 20)
RECORD_DIR = sys.argv[2]

users = {1: {"id": 1, "email": "admin@documents.test", "login": "admin",
             "password": os.environ.get("MOCK_ADMIN_PASSWORD", "")}}
documents = {}
signatures = {}
counter = [0]


def tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    length = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + content


OID_SIGNED_DATA = bytes.fromhex("06092a864886f70d010702")
OID_DATA = bytes.fromhex("06092a864886f70d010701")


def fake_cms(data: bytes, attached: bool) -> bytes:
    """A structurally valid CMS SignedData (DER): encapContentInfo carries eContent only if attached;
    the "signature" is an OCTET STRING with the SHA-256 of the data inside signerInfos."""
    econtent = OID_DATA + (tlv(0xA0, tlv(0x04, data)) if attached else b"")
    signer_info = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x04, hashlib.sha256(data).digest()))
    signed_data = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x31, b"") + tlv(0x30, econtent) + tlv(0x31, signer_info))
    return tlv(0x30, OID_SIGNED_DATA + tlv(0xA0, signed_data))


def cms_digest(cms: bytes) -> bytes:
    return cms[-32:]  # the OCTET STRING of the only SignerInfo is the last element


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status, payload: bytes, ctype="application/json", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def reply(self, status, obj, headers=None):
        self.send(status, json.dumps(obj, ensure_ascii=False).encode(), headers=headers)

    def error(self, status, message):
        self.reply(status, {"error": {"code": "bad_request", "message": message}})

    def user(self):
        m = re.search(r"sid=([^;]+)", self.headers.get("Cookie", ""))
        if not m:
            return None
        return next((u for u in users.values() if u["login"] == m.group(1)), None)

    def record(self, raw: bytes):
        counter[0] += 1
        name = f"{counter[0]:03d}-{self.command}-{urlparse(self.path).path.strip('/').replace('/', '_')}"
        with open(os.path.join(RECORD_DIR, name + ".body"), "wb") as f:
            f.write(raw)
        with open(os.path.join(RECORD_DIR, name + ".headers"), "w") as f:
            f.write(str(self.headers))

    def do_GET(self):
        self.handle_any(b"")

    def do_POST(self):
        self.handle_any(self.rfile.read(int(self.headers.get("Content-Length", 0))))

    def do_PUT(self):
        self.handle_any(self.rfile.read(int(self.headers.get("Content-Length", 0))))

    def handle_any(self, raw: bytes):
        self.record(raw)
        url = urlparse(self.path)
        path, query = url.path, parse_qs(url.query)
        method = self.command

        if path == "/" and method == "GET":
            return self.reply(200, {})

        if path == "/cms/verify" and method == "POST":
            body = json.loads(raw)
            cms = base64.b64decode(body["cms"])
            data = base64.b64decode(body["data"])
            valid = cms_digest(cms) == hashlib.sha256(data).digest()
            if MODE == "server_invalid" or (not valid and MODE != "server_accepts_tampered"):
                return self.reply(201, {"isValidSign": False, "isValid": False, "signs": []})
            return self.reply(201, {"isValidSign": True, "isValid": True,
                                    "signs": [{"certificate": {"thumbprint": THUMB.upper()}}]})

        if path == "/api/v1/login" and method == "POST":
            body = json.loads(raw)
            u = next((u for u in users.values() if u["login"] == body.get("username")), None)
            if not u or u["password"] != body.get("password"):
                return self.error(401, "Unauthorized")
            return self.reply(200, {"userId": u["id"]}, {"Set-Cookie": f"sid={u['login']}; Path=/"})

        u = self.user()
        if not u:
            return self.error(403, "Forbidden resource")

        if path == "/api/v1/profile":
            return self.reply(200, {
                "email": u["email"],
                "signingMethods": {"corpCloud": MODE != "no_corp_cloud"},
                "corpCloudCertAvailable": MODE != "no_cert",
                "availableSignatureLicenses": 10,
            })

        if path == "/api/v1/users" and method == "GET":
            wanted = json.loads(query.get("filter", ["{}"])[0]).get("email")
            return self.reply(200, [{k: v for k, v in x.items() if k != "password"}
                                    for x in users.values() if x["email"] == wanted])
        if path == "/api/v1/users" and method == "POST":
            body = json.loads(raw)
            new_id = max(users) + 1
            users[new_id] = {"id": new_id, "email": body["email"], "login": body["login"],
                             "password": body["password"]}
            return self.reply(201, {"id": new_id, "email": body["email"]})
        m = re.fullmatch(r"/api/v1/users/(\d+)", path)
        if m and method == "PUT":
            users[int(m.group(1))]["password"] = json.loads(raw)["password"]
            return self.reply(200, {"id": int(m.group(1))})

        if path == "/api/v1/documents/upload" and method == "POST":
            msg = email.message_from_bytes(
                b"Content-Type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + raw)
            part = next(p for p in msg.get_payload() if p.get_param("name", header="content-disposition") == "file")
            doc_id = len(documents) + 1
            documents[doc_id] = {"data": part.get_payload(decode=True), "mime": part.get_content_type()}
            return self.reply(201, {"document": {"id": doc_id, "metadata": {"mimeType": part.get_content_type()}}})

        m = re.fullmatch(r"/api/v1/documents/(\d+)/download", path)
        if m:
            data = documents[int(m.group(1))]["data"]
            return self.send(200, data + (b"x" if MODE == "download_differs" else b""), "application/octet-stream")

        m = re.fullmatch(r"/api/v1/signatures/cloud-sign/(\d+)", path)
        if m and method == "POST":
            if MODE == "cloud_sign_error":
                return self.error(400, "Не удалось получить корпоративный сертификат пользователя")
            doc_id = int(m.group(1))
            sig_id = len(signatures) + 100
            cms = fake_cms(documents[doc_id]["data"], MODE == "attached")
            signatures[sig_id] = {"documentId": doc_id, "cms": cms}
            answer = {"success": True, "signatureId": sig_id, "documentId": doc_id,
                      "signature": base64.b64encode(cms).decode()}
            if MODE == "no_signature":
                del answer["signature"]
            return self.reply(200, answer)

        m = re.fullmatch(r"/api/v1/documents/(\d+)/signature", path)
        if m and method == "POST":
            body = json.loads(raw)
            if body.get("attached") is not False:
                return self.error(400, "mock: expected attached:false")
            cms = signatures[body["signatureId"]]["cms"]
            if MODE == "export_differs":
                cms = cms[:-1] + bytes([cms[-1] ^ 1])
            return self.send(201, cms, "documents/signatures")

        m = re.fullmatch(r"/api/v1/documents/(\d+)/verify", path)
        if m and method == "POST":
            if MODE == "verify_not_pdf":
                return self.reply(201, {"ok": True})
            return self.send(201, b"%PDF-1.7\nmock report\n", "application/pdf")

        if path == "/api/v1/signatures" and method == "GET":
            doc_id = json.loads(query.get("filter", ["{}"])[0]).get("documentId")
            signer = {"certificate": {"thumbprint": "ab" * 20 if MODE == "thumb_mismatch" else THUMB,
                                      "subjectFriendlyName": "mock signer"},
                      "isCertChainValid": True}
            return self.reply(200, [
                {"id": sid, "documentId": s["documentId"],
                 "meta": {"out": base64.b64encode(s["cms"]).decode(),
                          "signValid": MODE != "sign_invalid",
                          "signers": [signer, signer] if MODE == "two_signers" else [signer]}}
                for sid, s in signatures.items() if s["documentId"] == doc_id])

        return self.error(404, f"mock: no route {method} {path}")


HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
