#!/usr/bin/env bash
# Smoke test for a running КриптоАРМ Server:
#   1. POST /cms/sign with only the public certificate and detached:true
#      (the private key must already be installed in the container's uMy store);
#   2. check the returned CMS is detached (does not embed the signed bytes);
#   3. POST /cms/verify with the signed data -> isValidSign must be true;
#   4. POST /cms/verify with tampered data -> isValidSign must not be true.
#
# Env:
#   CRYPTOARM_SERVER_URL      default http://localhost:3037
#   CRYPTOARM_SERVER_API_KEY  sent as X-API-Key when set (AUTH_MODE=apikey)
#   CERT_FILE                 public DER certificate (.cer), default: upstream test cert
#   SMOKE_STRICT=1            also require isValid (full chain/revocation check) to be true
#   SMOKE_TIMEOUT             per-request timeout in seconds, default 120 (amd64 emulation is slow)
# Requires: bash, curl, jq, base64.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
server_url="${CRYPTOARM_SERVER_URL:-http://localhost:3037}"
cert_file="${CERT_FILE:-$repo_root/docker/cryptoarm-server/certs/cryptoarm.server.test.cer}"
api_key="${CRYPTOARM_SERVER_API_KEY:-}"

die() { echo "smoke: FAIL: $*" >&2; exit 1; }
log() { echo "smoke: $*"; }

for tool in curl jq base64; do
  command -v "$tool" >/dev/null || die "'$tool' is required"
done

case "$cert_file" in
  *.pfx | *.p12 | *.PFX | *.P12)
    die "CERT_FILE must be a public certificate, not a PKCS#12 container: $cert_file" ;;
esac
[ -f "$cert_file" ] || die "certificate not found: $cert_file (run scripts/fetch-test-certs.sh)"

b64() { base64 | tr -d '\n'; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# post <path> <json-file> [allow-4xx] -> response body on stdout; fails on other non-2xx.
# With allow-4xx a 4xx response prints {"httpStatus": <code>} instead of failing.
post() {
  local path="$1" body="$2" allow_4xx="${3:-}" status
  local -a headers=(-H 'Content-Type: application/json' -H 'Accept: application/json')
  [ -n "$api_key" ] && headers+=(-H "X-API-Key: $api_key")
  status="$(curl -sS --connect-timeout 10 --max-time "${SMOKE_TIMEOUT:-120}" -o "$tmp/resp" -w '%{http_code}' -X POST "${headers[@]}" \
    --data-binary "@$body" "$server_url$path")" || die "POST $path: request failed"
  case "$status" in
    2??) cat "$tmp/resp" ;;
    4??) [ -n "$allow_4xx" ] || die "POST $path: HTTP $status: $(head -c 500 "$tmp/resp")"
         printf '{"httpStatus": %s}' "$status" ;;
    *) die "POST $path: HTTP $status: $(head -c 500 "$tmp/resp")" ;;
  esac
}

marker="cryptoarm-smoke-$(date +%s)-$RANDOM-$RANDOM"
printf 'Smoke test payload %s\n' "$marker" >"$tmp/data"
data_b64="$(b64 <"$tmp/data")"
cert_b64="$(b64 <"$cert_file")"

log "signing $(wc -c <"$tmp/data" | tr -d ' ') bytes at $server_url with $(basename "$cert_file")"
jq -n --arg cert "$cert_b64" --arg data "$data_b64" \
  '{cert: $cert, data: $data, detached: true}' >"$tmp/sign.json"
cms="$(post /cms/sign "$tmp/sign.json" | jq -r '.cms // empty')"
[ -n "$cms" ] || die "/cms/sign returned no 'cms'"
printf '%s' "$cms" | base64 --decode >"$tmp/cms.der" 2>/dev/null || die "'cms' is not valid Base64"
log "got CMS: $(wc -c <"$tmp/cms.der" | tr -d ' ') bytes"

if grep -qF "$marker" "$tmp/cms.der"; then
  die "signature is attached (CMS contains the signed bytes); expected detached"
fi

jq -n --arg cms "$cms" --arg data "$data_b64" '{cms: $cms, data: $data}' >"$tmp/verify.json"
post /cms/verify "$tmp/verify.json" >"$tmp/verify.out"
is_valid_sign="$(jq -r '.isValidSign' "$tmp/verify.out")"
is_valid="$(jq -r '.isValid' "$tmp/verify.out")"
log "verify: isValidSign=$is_valid_sign isValid=$is_valid message=$(jq -r '.message // ""' "$tmp/verify.out")"
[ "$is_valid_sign" = "true" ] || die "/cms/verify: signature is not valid"
if [ "${SMOKE_STRICT:-0}" = "1" ] && [ "$is_valid" != "true" ]; then
  die "/cms/verify: isValid=$is_valid (SMOKE_STRICT=1)"
fi

tampered_b64="$(printf 'tampered %s\n' "$marker" | b64)"
jq -n --arg cms "$cms" --arg data "$tampered_b64" '{cms: $cms, data: $data}' >"$tmp/verify-bad.json"
# The server may answer a mismatch with 201 {isValidSign:false} or with a 4xx; both mean rejected.
post /cms/verify "$tmp/verify-bad.json" allow-4xx >"$tmp/verify-bad.out"
bad_sign="$(jq -r '.isValidSign' "$tmp/verify-bad.out")"
[ "$bad_sign" != "true" ] || die "/cms/verify accepted tampered data"
log "tampered data rejected ($(jq -c '{isValidSign, httpStatus} | with_entries(select(.value != null))' "$tmp/verify-bad.out"))"

log "OK"
