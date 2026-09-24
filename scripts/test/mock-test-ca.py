#!/usr/bin/env python3
"""Fake КриптоПро test CA (Microsoft ADCS web enrollment) for scripts/issue-test-cert.sh tests.

Usage: mock-test-ca.py <port> <record_dir> <leaf.der> <ca.der>

MOCK_MODE:
  ok      POST /certsrv/certfnsh.asp -> page linking certnew.cer?ReqID=4242&
  denied  POST /certsrv/certfnsh.asp -> ADCS "denied" page without a ReqID
The POSTed form is saved to <record_dir>/request.form. GET /certsrv/certnew.cer?ReqID=4242&Enc=bin
returns <leaf.der>; GET /CertEnroll/testgost2012(21).crt returns <ca.der>.
"""
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlparse

port, record_dir, leaf_path, ca_path = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
mode = os.environ.get("MOCK_MODE", "ok")


def read(path):
    with open(path, "rb") as f:
        return f.read()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status, body, ctype="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path == "/":
            self.send(200, b"ok")
        elif url.path == "/certsrv/certnew.cer" and query.get("ReqID") == ["4242"] and query.get("Enc") == ["bin"]:
            self.send(200, read(leaf_path), "application/pkix-cert")
        elif unquote(url.path) == "/CertEnroll/testgost2012(21).crt":
            self.send(200, read(ca_path), "application/pkix-cert")
        else:
            self.send(404, b"not found")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if urlparse(self.path).path != "/certsrv/certfnsh.asp":
            self.send(404, b"not found")
            return
        with open(os.path.join(record_dir, "request.form"), "wb") as f:
            f.write(body)
        if mode == "denied":
            page = "<html><body>Ваш запрос на сертификат был отклонен. Код ошибки 0x80094012</body></html>"
        else:
            page = (
                '<html><body><script>location="certnew.cer?ReqID=CACert&amp;Renewal=21&amp;Mode=inst&amp;Enc=b64";'
                'sPKCS7="certnew.p7b?ReqID=4242&"+getEncoding();'
                'sCert="certnew.cer?ReqID=4242&"+getEncoding();</script></body></html>'
            )
        self.send(200, page.encode("utf-8"))


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
