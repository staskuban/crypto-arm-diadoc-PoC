#!/usr/bin/env bash
# Tests for scripts/documents-secrets.sh and docker/cryptoarm-documents/start.sh (no Docker needed).
# Run: scripts/test/documents-stand.test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
secrets_sh="$here/../documents-secrets.sh"
start_sh="$here/../../docker/cryptoarm-documents/start.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; sed 's/^/       /' "$work/out" 2>/dev/null || true; failures=$((failures + 1)); }
mode() { stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"; }

licence="LICEN-SEKEY-$RANDOM-XXXXX"
printf '%s\n' "$licence" >"$work/licence"
printf '\n  key-one,key-two\nkey-three\n' >"$work/api_keys"

run_secrets() { # dir, extra env...
  local dir="$1"; shift
  mkdir -p "$dir"
  env DOCUMENTS_LICENSE_FILE="$work/licence" SIGN_SERVICE_API_KEYS_FILE="$work/api_keys" \
    DOCUMENTS_SECRETS_DIR="$dir" "$@" "$secrets_sh" >"$work/out" 2>&1
}

# documents-secrets.sh
if run_secrets "$work/s1"; then pass "fills an empty secrets dir"; else fail "fills an empty secrets dir"; fi
all=1
for f in license_value sign_service_api_key admin_password session_secret secret mail_link_token_secret api_key postgres_password; do
  { [ -s "$work/s1/$f" ] && [ "$(mode "$work/s1/$f")" = 600 ]; } || all=0
done
[ "$all" = 1 ] && pass "writes every secret with mode 0600" || fail "missing secret or wrong mode: $(ls -l "$work/s1")"
[ "$(cat "$work/s1/license_value")" = "$licence" ] && pass "copies the licence without the newline" || fail "licence content"
[ "$(cat "$work/s1/sign_service_api_key")" = key-one ] && pass "takes the first API key (first non-empty line, first comma field)" ||
  fail "api key: $(cat "$work/s1/sign_service_api_key")"
grep -qF -e "$licence" -e key-one -e "$(cat "$work/s1/admin_password")" "$work/out" && fail "prints a secret" ||
  pass "prints no secret values"
[ "$(cat "$work/s1/postgres_password")" != "$(cat "$work/s1/admin_password")" ] && pass "generates distinct random secrets" ||
  fail "generated secrets are equal"

cp "$work/s1/postgres_password" "$work/pg.before"
printf 'NEWLI-CENSE\n' >"$work/licence"
run_secrets "$work/s1" || true
{ cmp -s "$work/pg.before" "$work/s1/postgres_password" && [ "$(cat "$work/s1/license_value")" = "$licence" ]; } &&
  pass "keeps existing files on a re-run" || fail "re-run overwrote a file"
run_secrets "$work/s1" FORCE=1 || true
{ cmp -s "$work/pg.before" "$work/s1/postgres_password" && [ "$(cat "$work/s1/license_value")" = NEWLI-CENSE ]; } &&
  pass "FORCE=1 refreshes the copied licence but never a generated password" || fail "FORCE=1 behaviour"

run_secrets "$work/s2" DOCUMENTS_LICENSE_FILE="$work/nope" && fail "missing licence accepted" ||
  { grep -q "licence file not found" "$work/out" && pass "fails without the licence file" || fail "wrong error for a missing licence"; }
run_secrets "$work/s3" SIGN_SERVICE_API_KEYS_FILE="$work/nope" && fail "missing api_keys file accepted" ||
  { grep -q "API keys file not found" "$work/out" && pass "fails without the server API keys file" || fail "wrong error for missing api_keys"; }
run_secrets "$work/s4" SIGN_SERVICE_API_KEYS_FILE="$work/nope" SIGN_SERVICE_API_KEY_OPTIONAL=1 &&
  [ ! -e "$work/s4/sign_service_api_key" ] && [ -s "$work/s4/admin_password" ] &&
  pass "SIGN_SERVICE_API_KEY_OPTIONAL=1 skips the API key" || fail "SIGN_SERVICE_API_KEY_OPTIONAL=1"

# start.sh: secrets -> env of the command, DB_URI built, required files enforced.
cat >"$work/dump-env" <<'EOF'
#!/bin/sh
env >"$DUMP"
EOF
chmod +x "$work/dump-env"
# The image runs start.sh with Debian's /bin/sh (dash): use dash when available.
shell=/bin/sh
command -v dash >/dev/null && shell="$(command -v dash)"
echo "# start.sh under $shell"
run_start() { # secrets-dir
  env -i PATH="$PATH" SECRETS_DIR="$1" DUMP="$work/env" POSTGRES_USER=documents POSTGRES_HOST=documents-db \
    POSTGRES_DB=documents "$shell" "$start_sh" "$work/dump-env" >"$work/out" 2>&1
}
printf 'p@ss/word' >"$work/s1/postgres_password"
if command -v node >/dev/null && run_start "$work/s1"; then
  { grep -qx "LICENSE_VALUE=NEWLI-CENSE" "$work/env" && grep -qx "SIGN_SERVICE_API_KEY=key-one" "$work/env" &&
    grep -qx "ADMIN_PASSWORD=$(cat "$work/s1/admin_password")" "$work/env"; } &&
    pass "start.sh exports the secrets to the command" || fail "start.sh env: $(cut -d= -f1 "$work/env" | tr '\n' ' ')"
  grep -qx 'DB_URI=postgres://documents:p%40ss%2Fword@documents-db:5432/documents' "$work/env" &&
    ! grep -q '^POSTGRES_PASSWORD=' "$work/env" &&
    pass "start.sh builds an URL-encoded DB_URI and drops POSTGRES_PASSWORD" || fail "DB_URI: $(grep DB_URI "$work/env")"
else
  fail "start.sh with a full secrets dir (node required)"
fi
rm "$work/s1/license_value"
run_start "$work/s1" && fail "start.sh without licence" ||
  { grep -q "license_value is missing" "$work/out" && pass "start.sh fails without the licence" || fail "start.sh error"; }
: >"$work/s1/license_value"
run_start "$work/s1" && fail "start.sh with an empty licence" ||
  { grep -q "license_value is empty" "$work/out" && pass "start.sh fails on an empty licence" || fail "start.sh error"; }

echo
if [ "$failures" -eq 0 ]; then
  echo "all documents-stand tests passed"
else
  echo "$failures documents-stand test(s) failed"
  exit 1
fi
