#!/usr/bin/env python3
"""Minimal fake of КриптоАРМ Server /cms/sign and /cms/verify for smoke-script tests.

Usage: mock-cryptoarm-server.py <port> <record_dir>
Env:
  MOCK_MODE     ok | attached | sign_error | no_cms | bad_base64 | verify_invalid |
                verify_always_valid | chain_invalid | tampered_http_error
  MOCK_API_KEY  if set, requests without a matching X-API-Key get 401
Each request body is written to <record_dir>/<endpoint>.json and headers to
<record_dir>/<endpoint>.headers so tests can assert on what the client sent.
"""
import base64
import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = os.environ.get("MOCK_MODE", "ok")
API_KEY = os.environ.get("MOCK_API_KEY", "")
RECORD_DIR = sys.argv[2]


def fake_cms(data: bytes, attached: bool) -> str:
    body = b"FAKECMS:" + hashlib.sha256(data).hexdigest().encode()
    if attached:
        body += b":" + data
    return base64.b64encode(body).decode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, obj):
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        name = self.path.strip("/").replace("/", "_")
        with open(os.path.join(RECORD_DIR, name + ".json"), "wb") as f:
            f.write(raw)
        with open(os.path.join(RECORD_DIR, name + ".headers"), "w") as f:
            f.write(str(self.headers))

        if API_KEY and self.headers.get("X-API-Key") != API_KEY:
            return self.reply(401, {"statusCode": 401, "message": "Unauthorized"})

        body = json.loads(raw)
        if self.path == "/cms/sign":
            if MODE == "sign_error":
                return self.reply(500, {"statusCode": 500, "message": "boom"})
            if MODE == "no_cms":
                return self.reply(201, {})
            if MODE == "bad_base64":
                return self.reply(201, {"cms": "%%% not base64 %%%"})
            data = base64.b64decode(body["data"])
            attached = MODE == "attached" or body.get("detached") is False
            return self.reply(201, {"cms": fake_cms(data, attached)})

        if self.path == "/cms/verify":
            data = base64.b64decode(body.get("data", ""))
            expected = b"FAKECMS:" + hashlib.sha256(data).hexdigest().encode()
            ok = base64.b64decode(body["cms"]).startswith(expected)
            if MODE == "verify_invalid":
                ok = False
            if MODE == "verify_always_valid":
                ok = True
            if MODE == "tampered_http_error" and not ok:
                return self.reply(400, {"statusCode": 400, "message": "verify failed"})
            is_valid = ok and MODE != "chain_invalid"
            return self.reply(
                201,
                {"status": 200, "message": "", "isValid": is_valid, "isValidSign": ok, "signs": []},
            )

        self.reply(404, {"statusCode": 404})


HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
