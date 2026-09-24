#!/usr/bin/env bash
# Smoke test for a running КриптоАРМ Документы stand (docker/cryptoarm-documents) that signs through
# КриптоАРМ Server with the corporate cloud signature:
#   1. POST /api/v1/login (local admin), optionally switch to DOCUMENTS_SIGNER_EMAIL (see below);
#   2. GET /api/v1/profile: signingMethods.corpCloud and corpCloudCertAvailable must be true;
#   3. POST /api/v1/documents/upload, GET /api/v1/documents/{id}/download returns the same bytes;
#   4. POST /api/v1/signatures/cloud-sign/{id} -> signatureId;
#   5. POST /api/v1/documents/{id}/signature {signatureId, attached:false} -> detached CMS
#      (no eContent in the ASN.1 structure; same bytes as cloud-sign returned);
#   6. POST /api/v1/documents/{id}/verify {signatureId} -> PDF report (the endpoint returns no JSON);
#      GET /api/v1/signatures?filter={"documentId":id} -> meta of the Документы-side verification:
#      signValid, exactly one signer, its thumbprint == SHA-1 of CERT_FILE;
#   7. independent check on КриптоАРМ Server /cms/verify with the exported CMS and the original bytes:
#      isValidSign, one signer, same thumbprint; tampered data must not verify.
#
# Env:
#   DOCUMENTS_URL                  default http://127.0.0.1:3040
#   DOCUMENTS_ADMIN_LOGIN          default admin
#   DOCUMENTS_ADMIN_PASSWORD_FILE  default docker/cryptoarm-documents/secrets/admin_password
#   DOCUMENTS_SIGNER_EMAIL         sign as this user instead of the admin: the admin creates it (login =
#                                  e-mail) or resets its password to a fresh random one (never printed),
#                                  then logs in as it. The e-mail picks the certificate (CA stub mapping).
#                                  Test stands only: it resets that user's password on every run.
#                                  Refused when it is the admin's own account (its password would be
#                                  lost: nothing saves the new one).
#   CERT_FILE                      expected signer certificate (DER .cer),
#                                  default docker/cryptoarm-server/certs/cryptoarm.server.test.cer
#   DATA_FILE                      file to sign (e.g. an УПД .xml); default: generated text payload
#   DATA_MIME                      its upload MIME type, default by extension (xml -> application/xml)
#   CRYPTOARM_SERVER_URL           default http://127.0.0.1:3037; SMOKE_SKIP_SERVER_VERIFY=1 skips step 7
#   CRYPTOARM_SERVER_API_KEY_FILE  default docker/cryptoarm-documents/secrets/sign_service_api_key
#   SMOKE_TIMEOUT                  per-request timeout in seconds, default 180 (amd64 emulation is slow)
# Secrets travel in files (curl -H @file, --data-binary @file), never in argv, and are not printed.
# Requires: bash, curl >= 7.55, jq, openssl, base64.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_url="${DOCUMENTS_URL:-http://127.0.0.1:3040}"
admin_login="${DOCUMENTS_ADMIN_LOGIN:-admin}"
admin_password_file="${DOCUMENTS_ADMIN_PASSWORD_FILE:-$repo_root/docker/cryptoarm-documents/secrets/admin_password}"
signer_email="${DOCUMENTS_SIGNER_EMAIL:-}"
cert_file="${CERT_FILE:-$repo_root/docker/cryptoarm-server/certs/cryptoarm.server.test.cer}"
server_url="${CRYPTOARM_SERVER_URL:-http://127.0.0.1:3037}"
server_key_file="${CRYPTOARM_SERVER_API_KEY_FILE:-$repo_root/docker/cryptoarm-documents/secrets/sign_service_api_key}"
timeout="${SMOKE_TIMEOUT:-180}"

die() { echo "smoke-documents: FAIL: $*" >&2; exit 1; }
log() { echo "smoke-documents: $*"; }

for tool in curl jq openssl base64; do
  command -v "$tool" >/dev/null || die "'$tool' is required"
done
[ -f "$cert_file" ] || die "certificate not found: $cert_file"
[ -f "$admin_password_file" ] || die "admin password file not found: $admin_password_file (run scripts/documents-secrets.sh)"

b64() { base64 | tr -d '\n'; }

umask 077
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# request <method> <path> <out> [curl args...] -> prints the HTTP status; the body goes to <out>.
# The session cookie jar is $tmp/jar.<who>, selected by $who.
who=admin
request() {
  local method="$1" path="$2" out="$3"
  shift 3
  curl -sS --connect-timeout 10 --max-time "$timeout" -o "$out" -w '%{http_code}' \
    -b "$tmp/jar.$who" -c "$tmp/jar.$who" -X "$method" "$@" "$base_url$path" ||
    die "$method $path: request failed"
}

# json <method> <path> <json-file> <out> -> status (mutating requests carry a fresh Idempotency-Key).
json() {
  request "$1" "$2" "$4" -H 'Content-Type: application/json' -H 'Accept: application/json' \
    -H "Idempotency-Key: $(uuidgen 2>/dev/null || openssl rand -hex 16)" --data-binary "@$3"
}

expect() { # <status> <expected> <what> <body-file>
  [ "$1" = "$2" ] || die "$3: HTTP $1 (expected $2): $(head -c 500 "$4")"
}

login() { # <login> <password-file>
  jq -n --arg u "$1" --rawfile p "$2" '{username: $u, password: ($p | rtrimstr("\n"))}' >"$tmp/login.json"
  expect "$(json POST /api/v1/login "$tmp/login.json" "$tmp/resp")" 200 "login as $1" "$tmp/resp"
  rm -f "$tmp/login.json"
}

expected_thumb="$(openssl x509 -inform DER -in "$cert_file" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g' |
  tr '[:upper:]' '[:lower:]')"
[ -n "$expected_thumb" ] || die "cannot read the SHA-1 thumbprint of $cert_file"

# 1. Log in.
log "logging in at $base_url as $admin_login"
login "$admin_login" "$admin_password_file"
cp "$tmp/resp" "$tmp/admin-login"

if [ -n "$signer_email" ]; then
  expect "$(request GET "/api/v1/users?filter=$(jq -rn --arg e "$signer_email" '{email: $e} | tojson | @uri')" \
    "$tmp/users")" 200 "user lookup" "$tmp/users"
  user_id="$(jq -r --arg e "$signer_email" '[.[] | select(.email == $e)][0].id // empty' "$tmp/users")"
  # Resetting the admin's password would lock out secrets/admin_password (and DOCUMENTS_LOGIN=admin).
  admin_id="$(jq -r '.userId // empty' "$tmp/admin-login" 2>/dev/null || true)" # local login answers {userId}
  [ -n "$admin_id" ] || die "login as $admin_login returned no userId; cannot tell the admin from $signer_email"
  [ "$user_id" != "$admin_id" ] ||
    die "DOCUMENTS_SIGNER_EMAIL=$signer_email is the admin ($admin_login, id $admin_id); its password is never reset — sign as another e-mail, or unset DOCUMENTS_SIGNER_EMAIL to sign as the admin"
  openssl rand -hex 24 >"$tmp/signer-password"
  if [ -n "$user_id" ]; then
    jq -n --rawfile p "$tmp/signer-password" '{password: ($p | rtrimstr("\n"))}' >"$tmp/user.json"
    expect "$(json PUT "/api/v1/users/$user_id" "$tmp/user.json" "$tmp/resp")" 200 "reset password of $signer_email" "$tmp/resp"
    log "signer user $signer_email exists (id $user_id), password reset"
  else
    jq -n --arg e "$signer_email" --rawfile p "$tmp/signer-password" \
      '{email: $e, login: $e, password: ($p | rtrimstr("\n"))}' >"$tmp/user.json"
    expect "$(json POST /api/v1/users "$tmp/user.json" "$tmp/resp")" 201 "create user $signer_email" "$tmp/resp"
    log "signer user $signer_email created (id $(jq -r '.id' "$tmp/resp"))"
  fi
  rm -f "$tmp/user.json"
  signer_login="$(jq -r --arg e "$signer_email" '[.[] | select(.email == $e)][0].login // $e' "$tmp/users")"
  who=signer
  login "$signer_login" "$tmp/signer-password"
fi

# 2. Profile.
expect "$(request GET /api/v1/profile "$tmp/profile")" 200 "profile" "$tmp/profile"
signer="$(jq -r '.email // "?"' "$tmp/profile")"
jq -e '.signingMethods.corpCloud == true' "$tmp/profile" >/dev/null ||
  die "signingMethods.corpCloud is not true (SIGN_METHOD_CORP_CLOUD)"
jq -e '.corpCloudCertAvailable == true' "$tmp/profile" >/dev/null ||
  die "no corporate certificate for $signer (CA stub mapping, CA_API_URI)"
licences_before="$(jq -r '.availableSignatureLicenses // "?"' "$tmp/profile")"
log "signer $signer: corpCloud on, corporate certificate available, signature licences $licences_before"

# 3. Upload.
if [ -n "${DATA_FILE:-}" ]; then
  [ -f "$DATA_FILE" ] || die "DATA_FILE not found: $DATA_FILE"
  data="$DATA_FILE"
  marker=""
else
  marker="documents-smoke-$(date +%s)-$RANDOM-$RANDOM"
  data="$tmp/smoke-$marker.txt"
  printf 'Документы smoke payload %s\n' "$marker" >"$data"
fi
case "$data" in
  *.xml | *.XML) mime="${DATA_MIME:-application/xml}" ;;
  *) mime="${DATA_MIME:-text/plain}" ;;
esac
status="$(request POST /api/v1/documents/upload "$tmp/upload" \
  -H "Idempotency-Key: $(uuidgen 2>/dev/null || openssl rand -hex 16)" -F "file=@$data;type=$mime")"
expect "$status" 201 "upload" "$tmp/upload"
doc_id="$(jq -r '.document.id // empty' "$tmp/upload")"
[ -n "$doc_id" ] || die "upload returned no document.id: $(head -c 500 "$tmp/upload")"
log "uploaded $(basename "$data") ($(wc -c <"$data" | tr -d ' ') bytes, $mime) as document $doc_id"

expect "$(request GET "/api/v1/documents/$doc_id/download" "$tmp/download")" 200 "download" "$tmp/download"
cmp -s "$data" "$tmp/download" || die "downloaded document $doc_id differs from the uploaded bytes"
log "download returns the uploaded bytes unchanged"

# 4. Cloud sign.
echo '{}' >"$tmp/empty.json"
started=$SECONDS
expect "$(json POST "/api/v1/signatures/cloud-sign/$doc_id" "$tmp/empty.json" "$tmp/cloud")" 200 "cloud-sign" "$tmp/cloud"
jq -e '.success == true' "$tmp/cloud" >/dev/null || die "cloud-sign: success is not true: $(head -c 500 "$tmp/cloud")"
sig_id="$(jq -r '.signatureId // empty' "$tmp/cloud")"
[ -n "$sig_id" ] || die "cloud-sign returned no signatureId"
log "cloud-sign: signature $sig_id in $((SECONDS - started)) s"

# 5. Export the detached signature.
jq -n --argjson s "$sig_id" '{signatureId: $s, attached: false}' >"$tmp/export.json"
status="$(json POST "/api/v1/documents/$doc_id/signature" "$tmp/export.json" "$tmp/sig.cms")"
case "$status" in 200 | 201) ;; *) die "export signature: HTTP $status: $(head -c 500 "$tmp/sig.cms")" ;; esac
[ -s "$tmp/sig.cms" ] || die "exported signature is empty"
# Detached = the encapContentInfo (first id-data OID) has no [0] eContent. Checked on the ASN.1
# structure (openssl asn1parse copes with BER and unknown GOST OIDs), so it holds for DATA_FILE too.
openssl asn1parse -inform DER -in "$tmp/sig.cms" >"$tmp/sig.asn1" 2>/dev/null ||
  die "exported signature is not parseable ASN.1 (CMS expected)"
grep -q ':pkcs7-signedData' "$tmp/sig.asn1" || die "exported signature is not a CMS SignedData"
econtent="$(awk '/:pkcs7-data/ && !found { found = 1; split($0, a, "d="); depth = a[2] + 0; next }
  found { split($0, a, "d="); if (a[2] + 0 == depth && $0 ~ /cont \[ 0 \]/) print "attached"; exit }' "$tmp/sig.asn1")"
[ -z "$econtent" ] || die "exported signature embeds the signed data (eContent present); expected detached"
if [ -n "$marker" ] && LC_ALL=C grep -aqF "$marker" "$tmp/sig.cms"; then
  die "exported signature contains the signed data; expected detached"
fi
jq -e '.signature | type == "string" and length > 0' "$tmp/cloud" >/dev/null || die "cloud-sign returned no 'signature'"
jq -r '.signature' "$tmp/cloud" | base64 --decode >"$tmp/cloud.cms" 2>/dev/null ||
  die "cloud-sign 'signature' is not valid Base64"
cmp -s "$tmp/sig.cms" "$tmp/cloud.cms" || die "exported CMS differs from the signature cloud-sign returned"
framing="DER"
[ "$(head -c 2 "$tmp/sig.cms" | od -An -tx1 | tr -d ' \n')" = 3080 ] && framing="BER (indefinite length)"
log "exported detached CMS: $(wc -c <"$tmp/sig.cms" | tr -d ' ') bytes, $framing"

# 6. Документы-side verification.
jq -n --argjson s "$sig_id" '{signatureId: $s}' >"$tmp/verify.json"
status="$(json POST "/api/v1/documents/$doc_id/verify" "$tmp/verify.json" "$tmp/report")"
case "$status" in 200 | 201) ;; *) die "verify: HTTP $status: $(head -c 500 "$tmp/report")" ;; esac
[ "$(head -c 5 "$tmp/report")" = "%PDF-" ] || die "verify did not return a PDF report: $(head -c 200 "$tmp/report")"
log "verify: PDF report, $(wc -c <"$tmp/report" | tr -d ' ') bytes"

expect "$(request GET "/api/v1/signatures?filter=$(jq -rn --argjson d "$doc_id" '{documentId: $d} | tojson | @uri')" \
  "$tmp/signatures")" 200 "signature list" "$tmp/signatures"
jq --argjson s "$sig_id" '[.[] | select(.id == $s)][0].meta // empty' "$tmp/signatures" >"$tmp/meta.json"
[ -s "$tmp/meta.json" ] || die "signature $sig_id not in the list of document $doc_id"
jq -e '.signValid == true' "$tmp/meta.json" >/dev/null ||
  die "Документы verification: signValid is not true: $(jq -c 'del(.out)' "$tmp/meta.json" | head -c 800)"
[ "$(jq '.signers | length' "$tmp/meta.json")" = 1 ] || die "Документы verification: expected exactly one signer"
thumb="$(jq -r '.signers[0].certificate.thumbprint // empty | ascii_downcase' "$tmp/meta.json")"
[ "$thumb" = "$expected_thumb" ] ||
  die "Документы verification: signer thumbprint $thumb != $expected_thumb ($(basename "$cert_file"))"
log "Документы verification: signValid, 1 signer '$(jq -r '.signers[0].certificate.subjectFriendlyName' "$tmp/meta.json")'," \
  "chain valid $(jq -r '.signers[0].isCertChainValid' "$tmp/meta.json"), thumbprint $thumb matches $(basename "$cert_file")"

# 7. Independent check on КриптоАРМ Server.
if [ "${SMOKE_SKIP_SERVER_VERIFY:-}" = 1 ]; then
  log "SMOKE_SKIP_SERVER_VERIFY=1: independent /cms/verify skipped"
else
  : >"$tmp/server-auth"
  if [ -f "$server_key_file" ]; then
    printf 'X-API-Key: %s\n' "$(tr -d '\r\n' <"$server_key_file")" >"$tmp/server-auth"
  fi
  server_verify() { # <data-file> <out> -> status
    jq -n --rawfile cms <(b64 <"$tmp/sig.cms") --rawfile data <(b64 <"$1") '{cms: $cms, data: $data}' >"$tmp/sv.json"
    curl -sS --connect-timeout 10 --max-time "$timeout" -o "$2" -w '%{http_code}' -X POST \
      -H 'Content-Type: application/json' -H "@$tmp/server-auth" --data-binary "@$tmp/sv.json" \
      "$server_url/cms/verify" || die "POST $server_url/cms/verify: request failed"
  }
  status="$(server_verify "$data" "$tmp/sv")"
  case "$status" in 2??) ;; *) die "КриптоАРМ Server /cms/verify: HTTP $status: $(head -c 500 "$tmp/sv")" ;; esac
  jq -e '.isValidSign == true' "$tmp/sv" >/dev/null ||
    die "КриптоАРМ Server /cms/verify: signature is not valid: $(head -c 800 "$tmp/sv")"
  [ "$(jq '.signs | length' "$tmp/sv")" = 1 ] || die "КриптоАРМ Server /cms/verify: expected exactly one signer"
  server_thumb="$(jq -r '.signs[0].certificate.thumbprint // empty | ascii_downcase' "$tmp/sv")"
  [ "$server_thumb" = "$expected_thumb" ] || die "КриптоАРМ Server /cms/verify: thumbprint $server_thumb != $expected_thumb"
  log "КриптоАРМ Server /cms/verify: isValidSign, isValid $(jq -r '.isValid' "$tmp/sv"), thumbprint matches"

  { cat "$data"; printf 'tampered'; } >"$tmp/tampered"
  status="$(server_verify "$tmp/tampered" "$tmp/sv-tampered")"
  if [ "${status:0:1}" = 2 ] && jq -e '.isValidSign == true' "$tmp/sv-tampered" >/dev/null; then
    die "КриптоАРМ Server /cms/verify accepted tampered data"
  fi
  log "tampered data rejected (HTTP $status)"
fi

expect "$(request GET /api/v1/profile "$tmp/profile")" 200 "profile" "$tmp/profile"
log "signature licences: $licences_before before, $(jq -r '.availableSignatureLicenses // "?"' "$tmp/profile") after"
log "OK: document $doc_id signed by $signer via cloud-sign, detached CMS verified"
