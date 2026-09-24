#!/usr/bin/env bash
# Tests for scripts/smoke-server.sh against a fake КриптоАРМ Server.
# Run: scripts/test/smoke-server.test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
smoke="$here/../smoke-server.sh"
mock="$here/mock-cryptoarm-server.py"

work="$(mktemp -d)"
mock_pid=""
cleanup() {
  [ -n "$mock_pid" ] && kill "$mock_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

printf 'not-a-real-certificate-%s' "$RANDOM" >"$work/test.cer"
cp "$work/test.cer" "$work/test.pfx"

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
failures=0

start_mock() { # mode [api_key]
  stop_mock
  rm -rf "$work/rec" && mkdir -p "$work/rec"
  MOCK_MODE="$1" MOCK_API_KEY="${2:-}" python3 "$mock" "$port" "$work/rec" &
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
  env CRYPTOARM_SERVER_URL="http://127.0.0.1:$port" CERT_FILE="$work/test.cer" "$@" \
    "$smoke" >"$work/out" 2>&1
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
  elif ! grep -qE "smoke: FAIL: .*($pattern)" "$work/out"; then
    fail "$name (failed for another reason, expected /$pattern/)"
  else
    pass "$name"
  fi
}

# 1. Happy path and the exact request contract.
start_mock ok
expect_success "signs and verifies against a healthy server"
cert_b64="$(base64 <"$work/test.cer" | tr -d '\n')"
if jq -e --arg c "$cert_b64" '.cert == $c and .detached == true and (has("password") | not)' \
  "$work/rec/cms_sign.json" >/dev/null; then
  pass "sign request carries only the public .cer and detached:true"
else
  fail "sign request body wrong: $(cat "$work/rec/cms_sign.json")"
fi
if [ -f "$work/rec/cms_verify.json" ] && jq -e '.data | length > 0' "$work/rec/cms_verify.json" >/dev/null; then
  pass "verify request passes the signed data (detached verification)"
else
  fail "verify request missing data"
fi

# 2. API key handling.
start_mock ok secret-key
expect_success "sends X-API-Key when CRYPTOARM_SERVER_API_KEY is set" CRYPTOARM_SERVER_API_KEY=secret-key
expect_failure "fails when the server rejects the API key" "HTTP 401" CRYPTOARM_SERVER_API_KEY=wrong

# 3. Failure modes.
start_mock attached
expect_failure "fails when the server returns an attached signature" "attached"
start_mock sign_error
expect_failure "fails when /cms/sign returns an HTTP error" "/cms/sign: HTTP 500"
start_mock verify_invalid
expect_failure "fails when /cms/verify reports an invalid signature" "signature is not valid"
start_mock verify_always_valid
expect_failure "fails when /cms/verify accepts tampered data" "accepted tampered data"
start_mock no_cms
expect_failure "fails when /cms/sign returns no cms" "returned no 'cms'"
start_mock bad_base64
expect_failure "fails when cms is not Base64" "not valid Base64"

# 3a. Chain/revocation status: informational by default, required with SMOKE_STRICT=1.
start_mock chain_invalid
expect_success "passes when only the chain is invalid (isValidSign=true, isValid=false)"
expect_failure "fails on isValid=false with SMOKE_STRICT=1" "SMOKE_STRICT" SMOKE_STRICT=1

# 3b. A server that answers tampered data with an HTTP error still rejects it.
start_mock tampered_http_error
expect_success "treats an HTTP error on tampered data as rejection"

# 4. Input validation (no request must reach the server).
start_mock ok
expect_failure "refuses a PKCS#12 container as CERT_FILE" "PKCS#12" CERT_FILE="$work/test.pfx"
if [ ! -f "$work/rec/cms_sign.json" ]; then pass "no request sent for .pfx"; else fail "request was sent for .pfx"; fi
expect_failure "fails when CERT_FILE does not exist" "certificate not found" CERT_FILE="$work/missing.cer"
stop_mock
expect_failure "fails when the server is unreachable" "request failed"

if [ "$failures" -gt 0 ]; then
  echo "$failures test(s) failed"
  exit 1
fi
echo "all smoke-server tests passed"
