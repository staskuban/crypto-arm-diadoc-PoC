#!/usr/bin/env bash
# Tests for scripts/smoke-documents.sh against a fake КриптоАРМ Документы API + Server /cms/verify.
# Run: scripts/test/smoke-documents.test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
smoke="$here/../smoke-documents.sh"
mock="$here/mock-cryptoarm-documents.py"

work="$(mktemp -d)"
mock_pid=""
cleanup() {
  [ -n "$mock_pid" ] && kill "$mock_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# A real (throwaway, self-signed) DER certificate: the smoke script computes its SHA-1 thumbprint.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj '/CN=smoke-documents-test' \
  -days 1 -keyout "$work/key.pem" -outform DER -out "$work/signer.cer" 2>/dev/null
thumb="$(openssl x509 -inform DER -in "$work/signer.cer" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g' |
  tr '[:upper:]' '[:lower:]')"
admin_password="admin-secret-$RANDOM$RANDOM"
printf '%s' "$admin_password" >"$work/admin_password"
server_key="server-key-$RANDOM$RANDOM"
printf '%s\n' "$server_key" >"$work/server_key"

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
failures=0

start_mock() { # mode
  stop_mock
  rm -rf "$work/rec" && mkdir -p "$work/rec"
  MOCK_MODE="$1" MOCK_ADMIN_PASSWORD="$admin_password" MOCK_THUMB="$thumb" python3 "$mock" "$port" "$work/rec" &
  mock_pid=$!
  for _ in $(seq 1 50); do
    curl -s -o /dev/null "http://127.0.0.1:$port/" && return 0
    sleep 0.1
  done
  echo "mock server did not start" >&2
  exit 1
}

stop_mock() {
  if [ -n "$mock_pid" ]; then
    kill "$mock_pid" 2>/dev/null || true
    wait "$mock_pid" 2>/dev/null || true
    mock_pid=""
  fi
}

run_smoke() { # extra env assignments...
  env DOCUMENTS_URL="http://127.0.0.1:$port" CRYPTOARM_SERVER_URL="http://127.0.0.1:$port" \
    DOCUMENTS_ADMIN_PASSWORD_FILE="$work/admin_password" CRYPTOARM_SERVER_API_KEY_FILE="$work/server_key" \
    CERT_FILE="$work/signer.cer" SMOKE_TIMEOUT=20 "$@" "$smoke" >"$work/out" 2>&1
}

pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; sed 's/^/       /' "$work/out" 2>/dev/null || true; failures=$((failures + 1)); }

expect_success() { # name, env...
  local name="$1"; shift
  if run_smoke "$@"; then pass "$name"; else fail "$name (expected exit 0)"; fi
}

expect_failure() { # name, expected message (grep -E), env...
  local name="$1" pattern="$2"; shift 2
  if run_smoke "$@"; then
    fail "$name (expected non-zero exit)"
  elif ! grep -qE "smoke-documents: FAIL: .*($pattern)" "$work/out"; then
    fail "$name (failed for another reason, expected /$pattern/)"
  else
    pass "$name"
  fi
}

recorded() { # <method-path glob> -> first matching body file
  ls "$work/rec/"*"-$1.body" 2>/dev/null | head -n 1
}

# 1. Happy path and the request contract.
start_mock ok
expect_success "uploads, cloud-signs, exports and verifies a detached signature"
if grep -q "OK: document 1 signed by admin@documents.test" "$work/out"; then
  pass "reports the signed document and the signer"
else
  fail "no OK line"
fi
body="$(recorded POST-api_v1_documents_1_signature)"
if [ -n "$body" ] && jq -e '.attached == false and .signatureId == 100' "$body" >/dev/null; then
  pass "exports the cloud-sign signature with attached:false"
else
  fail "export request body wrong: $(cat "$body" 2>/dev/null)"
fi
body="$(recorded POST-cms_verify)"
if [ -n "$body" ] && grep -q "X-API-Key: $server_key" "${body%.body}.headers"; then
  pass "independent /cms/verify sends the КриптоАРМ Server API key"
else
  fail "/cms/verify without the API key"
fi
if grep -q "Idempotency-Key:" "$(recorded POST-api_v1_signatures_cloud-sign_1 | sed 's/\.body$/.headers/')"; then
  pass "cloud-sign carries an Idempotency-Key"
else
  fail "cloud-sign without Idempotency-Key"
fi
if grep -rqF -- "$admin_password" "$work/out"; then
  fail "the admin password is printed"
else
  pass "the admin password is not printed"
fi

# 2. Secrets are not in curl's argv (ps).
real_curl="$(command -v curl)"
mkdir -p "$work/bin"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >>"%s"\nexec "%s" "$@"\n' "$work/curl-argv" "$real_curl" >"$work/bin/curl"
chmod +x "$work/bin/curl"
start_mock ok
expect_success "runs through a curl wrapper" PATH="$work/bin:$PATH" DOCUMENTS_SIGNER_EMAIL=o2@documents.test
if [ -s "$work/curl-argv" ] && ! grep -qF -e "$admin_password" -e "$server_key" "$work/curl-argv"; then
  pass "the admin password and the server API key are not in curl's argv"
else
  fail "a secret is in curl's argv"
fi

# 3. Signing as another user: created on the first run, password reset on the next.
start_mock ok
expect_success "signs as DOCUMENTS_SIGNER_EMAIL (user created)" DOCUMENTS_SIGNER_EMAIL=o2@documents.test
grep -q "signer user o2@documents.test created" "$work/out" && grep -q "signed by o2@documents.test" "$work/out" &&
  pass "creates the signer user and signs as it" || fail "signer user not created / not used"
expect_success "signs as DOCUMENTS_SIGNER_EMAIL (existing user)" DOCUMENTS_SIGNER_EMAIL=o2@documents.test
grep -q "signer user o2@documents.test exists" "$work/out" && pass "resets the password of an existing signer user" ||
  fail "existing signer user not reused"

# 4. A given file is signed as is (УПД bytes), with its MIME type.
printf '<?xml version="1.0" encoding="windows-1251"?>\n<\xd4\xe0\xe9\xeb/>\n' >"$work/utd.xml"
start_mock ok
expect_success "signs DATA_FILE" DATA_FILE="$work/utd.xml"
body="$(recorded POST-api_v1_documents_upload)"
if LC_ALL=C grep -aq "Content-Type: application/xml" "$body" && LC_ALL=C grep -aqF "$(printf '\xd4\xe0\xe9\xeb')" "$body"; then
  pass "uploads the XML bytes unchanged as application/xml"
else
  fail "upload body wrong"
fi

# 5. Failure modes.
start_mock ok
expect_failure "fails on a wrong admin password" "login as admin: HTTP 401" \
  DOCUMENTS_ADMIN_PASSWORD_FILE="$work/server_key"
start_mock no_corp_cloud
expect_failure "fails when corpCloud is off" "SIGN_METHOD_CORP_CLOUD"
start_mock no_cert
expect_failure "fails when the user has no corporate certificate" "no corporate certificate"
start_mock download_differs
expect_failure "fails when the stored document differs from the upload" "differs from the uploaded bytes"
start_mock cloud_sign_error
expect_failure "fails on a cloud-sign error, with its message" "cloud-sign: HTTP 400.*корпоративный сертификат"
start_mock attached
expect_failure "fails when the exported signature embeds the data" "eContent present"
expect_failure "detects an attached signature for DATA_FILE too (structure, not marker)" "eContent present" \
  DATA_FILE="$work/utd.xml"
start_mock export_differs
expect_failure "fails when the export differs from the cloud-sign signature" "differs from the signature cloud-sign returned"
start_mock no_signature
expect_failure "fails when cloud-sign returns no signature" "returned no 'signature'"
start_mock verify_not_pdf
expect_failure "fails when verify returns no PDF report" "did not return a PDF"
start_mock sign_invalid
expect_failure "fails when Документы report an invalid signature" "signValid is not true"
start_mock two_signers
expect_failure "fails on more than one signer" "exactly one signer"
start_mock thumb_mismatch
expect_failure "fails when the signer is another certificate" "thumbprint .* != $thumb"
start_mock server_invalid
expect_failure "fails when КриптоАРМ Server rejects the signature" "Server /cms/verify: signature is not valid"
start_mock server_accepts_tampered
expect_failure "fails when КриптоАРМ Server accepts tampered data" "accepted tampered data"
start_mock server_invalid
expect_success "SMOKE_SKIP_SERVER_VERIFY=1 skips the independent check" SMOKE_SKIP_SERVER_VERIFY=1
stop_mock
expect_failure "fails when the stand is down" "request failed"

echo
if [ "$failures" -eq 0 ]; then
  echo "all smoke-documents tests passed"
else
  echo "$failures smoke-documents test(s) failed"
  exit 1
fi
