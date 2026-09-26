#!/usr/bin/env bash
# Tests for docker/cryptoarm-server/start.sh (the КриптоАРМ Server container entrypoint) with fake
# CSP tools and temp dirs in place of the container paths.
# Run: scripts/test/cryptoarm-start.test.sh
# Under the container's shell (dash):
#   docker run --rm -v "$PWD:/repo:ro" --entrypoint bash kryptoarm-diadoc/cryptoarm-server:stand-i6 \
#     -c 'TEST_SH=dash /repo/scripts/test/cryptoarm-start.test.sh'
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
start="$here/../../docker/cryptoarm-server/start.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Fake CSP tools: each call appends "<tool> <argv...>" to $work/calls (one line per call).
mkdir -p "$work/bin"
cat >"$work/bin/fake-tool" <<'EOF'
#!/bin/sh
tool="$(basename "$0")"
printf "%s\n" "$tool $*" >>"$FAKE_CALLS"
# cpconfig -license -view prints the serial, as the real one does.
[ "$tool $*" = "cpconfig -license -view" ] && printf 'License validity:\n%s\nExpires: 94 day(s)\nLicense type: Demo.\n' "${FAKE_SERIAL:-SERIAL-0000}"
# The licence-setting calls echo the serial on stdout and stderr (worst case for the log), also
# without its dashes.
case "$tool $*" in
  "cpconfig -license -set "* | "tsputil license -s "* | "ocsputil license -s "*)
    for serial; do :; done
    echo "License $serial accepted"
    echo "serial: $(printf '%s' "$serial" | tr -d -)" >&2 ;;
esac
case "$tool $*" in
  *"${FAKE_FAIL_MATCH:-<never>}"*)
    pin=""
    while [ $# -gt 0 ]; do [ "$1" = "-pin" ] && pin="$2"; shift; done
    echo "fake $tool: error 0x80090020 (pin was '$pin')"
    exit 1 ;;
esac
EOF
chmod +x "$work/bin/fake-tool"
for t in certmgr cpconfig tsputil ocsputil; do ln -s fake-tool "$work/bin/$t"; done

# Child process: records its argv and environment.
cat >"$work/bin/child" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >"$FAKE_CHILD_ARGS"
env >"$FAKE_CHILD_ENV"
EOF
chmod +x "$work/bin/child"

failures=0
pass() { echo "ok   - $1"; }
fail() {
  echo "FAIL - $1"
  sed 's/^/       /' "$work/out" 2>/dev/null || true
  failures=$((failures + 1))
}

# Fresh container layout for every case.
reset() {
  rm -rf "$work/c" && mkdir -p "$work/c"/{store,store_default,conf,conf_default/apparmor.d,certs/root,certs/user,secrets,lic}
  echo "default" >"$work/c/store_default/config.ini"
  echo "csp config" >"$work/c/conf_default/config64.ini"
  echo "profile" >"$work/c/conf_default/apparmor.d/p"
  : >"$work/calls"
  rm -f "$work/child.args" "$work/child.env"
}

run_start() { # extra env assignments...
  env -i PATH="$work/bin:/usr/bin:/bin" \
    FAKE_CALLS="$work/calls" FAKE_CHILD_ARGS="$work/child.args" FAKE_CHILD_ENV="$work/child.env" \
    CERTMGR_BIN="$work/bin/certmgr" CPCONFIG_BIN="$work/bin/cpconfig" \
    TSPUTIL_BIN="$work/bin/tsputil" OCSPUTIL_BIN="$work/bin/ocsputil" \
    CSP_STORE_DIR="$work/c/store" CSP_STORE_DEFAULT_DIR="$work/c/store_default" \
    CSP_CONFIG_DIR="$work/c/conf" CSP_CONFIG_DEFAULT_DIR="$work/c/conf_default" \
    CERTS_DIR="$work/c/certs" SECRETS_DIR="$work/c/secrets" TRUSTED_LICENSE_DIR="$work/c/lic" \
    TRUSTED_LICENSE="" CRYPTOPRO_LICENSE="" AUTH_MODE=none \
    "$@" "${TEST_SH:-sh}" "$start" child arg1 "arg two" >"$work/out" 2>&1
}

child_ran() { [ -f "$work/child.env" ]; }
child_env() { grep -E "^$1=" "$work/child.env" | head -1 | cut -d= -f2-; }
called() { grep -qxF -- "$1" "$work/calls"; }

check() { # name, command...
  local name="$1"; shift
  if "$@"; then pass "$name"; else fail "$name"; fi
}

# 1. CSP store seeding, child exec and argv passthrough.
reset
check "starts with no secrets at all" run_start
check "execs the command with its arguments" \
  test "$(cat "$work/child.args")" = "$(printf 'arg1\narg two')"
check "seeds an empty CSP store from the image default" test -f "$work/c/store/config.ini"
reset
echo "kept" >"$work/c/store/existing"
run_start
check "does not seed a non-empty CSP store" test ! -e "$work/c/store/config.ini"
check "an empty CSP config dir is seeded even when the store is not" test -f "$work/c/conf/config64.ini"
check "warns that TRUSTED_LICENSE is empty" grep -q "TRUSTED_LICENSE is empty" "$work/out"
check "keeps TRUSTED_LICENSE / CRYPTOPRO_LICENSE defined for the server" \
  grep -qx "TRUSTED_LICENSE=" "$work/child.env"
check "CPCONFIG: no license -> trial, license state is shown" called "cpconfig -license -view"
check "CPCONFIG: no license -> -set not called" bash -c "! grep -q -- '-license -set' '$work/calls'"

# 1a. CSP configuration (/etc/opt/cprocsp): a tmpfs under read_only is seeded from the image copy
# before cpconfig runs, so `cpconfig -license -set` can write license.ini.
reset
run_start
check "seeds an empty CSP config dir from the image copy" \
  bash -c "cmp -s '$work/c/conf_default/config64.ini' '$work/c/conf/config64.ini' && test -f '$work/c/conf/apparmor.d/p'"
check "logs the CSP config seeding" grep -q "seeding empty .*conf from" "$work/out"
reset
echo "custom" >"$work/c/conf/config64.ini"
run_start
check "does not seed a non-empty CSP config dir" test "$(cat "$work/c/conf/config64.ini")" = custom
reset
rm -rf "$work/c/conf_default"
check "no image copy of the CSP config: the start continues" run_start
check "no image copy of the CSP config: nothing seeded" test -z "$(ls -A "$work/c/conf")"
check "no image copy of the CSP config: warns" grep -q "WARNING: .*conf is empty" "$work/out"
reset
chmod 0644 "$work/c/conf_default/config64.ini"
run_start
check "seeding keeps the image modes despite umask 077" \
  test "$(stat -c '%a' "$work/c/conf/config64.ini" 2>/dev/null || stat -f '%Lp' "$work/c/conf/config64.ini")" = 644

# 2. Trusted license: env (legacy), file via SECRETS_DIR, explicit *_FILE.
reset
run_start TRUSTED_LICENSE="AAAAA-BBBBB"
check "TRUSTED_LICENSE from env is written to license.lic" \
  test "$(cat "$work/c/lic/license.lic")" = "AAAAA-BBBBB"
check "license.lic has no trailing newline" test "$(wc -c <"$work/c/lic/license.lic" | tr -d ' ')" = 11
check "the server env does not carry the license value" grep -qx "TRUSTED_LICENSE=" "$work/child.env"

reset
printf 'FILE1-LICEN\n' >"$work/c/secrets/trusted_license"
run_start
check "trusted_license in SECRETS_DIR is used" test "$(cat "$work/c/lic/license.lic")" = "FILE1-LICEN"
check "no license value in any tool argv" bash -c "! grep -q FILE1 '$work/calls'"

reset
printf 'FILE2-LICEN\n' >"$work/other-lic"
printf 'FILE1-LICEN\n' >"$work/c/secrets/trusted_license"
run_start TRUSTED_LICENSE_FILE="$work/other-lic" TRUSTED_LICENSE="ENV00-LICEN"
check "TRUSTED_LICENSE_FILE wins over SECRETS_DIR and env" \
  test "$(cat "$work/c/lic/license.lic")" = "FILE2-LICEN"
check "a file overriding a non-empty env value warns" grep -q "TRUSTED_LICENSE.*ignored" "$work/out"

reset
if run_start TRUSTED_LICENSE_FILE="$work/missing"; then fail "missing *_FILE fails the start"; else pass "missing *_FILE fails the start"; fi
check "missing *_FILE names the variable" grep -q "TRUSTED_LICENSE_FILE" "$work/out"
check "missing *_FILE does not start the server" bash -c "! test -f '$work/child.env'"

# 3. КриптоПро CSP / TSP / OCSP licenses and failures.
reset
printf 'CSP-LIC\n' >"$work/c/secrets/cryptopro_license"
printf 'TSP-LIC\n' >"$work/c/secrets/cryptopro_tsp_license"
printf 'OCSP-LIC\n' >"$work/c/secrets/cryptopro_ocsp_license"
run_start
check "CSP license from file is set" called "cpconfig -license -set CSP-LIC"
check "TSP license from file is set" called "tsputil license -s TSP-LIC"
check "OCSP license from file is set" called "ocsputil license -s OCSP-LIC"
check "the server env does not carry the CSP license" grep -qx "CRYPTOPRO_LICENSE=" "$work/child.env"
check "the server env does not carry the TSP license" bash -c "! grep -q TSP-LIC '$work/child.env'"

reset
if run_start CRYPTOPRO_LICENSE="BAD" FAKE_FAIL_MATCH="-license -set"; then
  fail "a rejected CSP license fails the start"
else
  pass "a rejected CSP license fails the start"
fi
check "a rejected CSP license does not start the server" bash -c "! test -f '$work/child.env'"
check "a rejected CSP license: the tool's output is logged" grep -q "0x80090020" "$work/out"
check "a rejected CSP license: its value is not logged" bash -c "! grep -q BAD '$work/out'"

reset
printf 'CSP-LIC\r\n' >"$work/c/secrets/cryptopro_license"
printf 'TRUST-LIC\r\n' >"$work/c/secrets/trusted_license"
run_start FAKE_SERIAL="CSP-LIC"
check "CRLF in a secret file is stripped (CSP)" called "cpconfig -license -set CSP-LIC"
check "CRLF in a secret file is stripped (license.lic)" test "$(cat "$work/c/lic/license.lic")" = "TRUST-LIC"
check "the license serial printed by -view is not logged" bash -c "! grep -q CSP-LIC '$work/out'"
check "the license type is still logged" grep -q "License type: Demo" "$work/out"
check "the server env has no *_FILE / OCSP / ROOT_CERTS variables" \
  bash -c "! grep -qE '^([A-Z_]+_FILE|CRYPTOPRO_OCSP_LICENSE|ROOT_CERTS_BASE64)=' '$work/child.env'"

# 3a. The licence-setting tools may echo the serial: their output is logged redacted (R2 minor 26).
reset
printf '5050A-B0000-0CDEF-GHIJK-LMNOP\n' >"$work/c/secrets/cryptopro_license"
printf 'TSP00-11111-22222\n' >"$work/c/secrets/cryptopro_tsp_license"
printf 'OCSP0-33333-44444\n' >"$work/c/secrets/cryptopro_ocsp_license"
run_start
check "licence serials are not logged (CSP, TSP, OCSP; with or without dashes)" \
  bash -c "! grep -qE '5050A|0CDEF|TSP00|22222|OCSP0|44444' '$work/out'"
check "the licence tools' output is still logged, redacted" grep -q "License \*\*\* accepted" "$work/out"
reset
printf 'TSP00-11111-22222\n' >"$work/c/secrets/cryptopro_tsp_license"
if run_start FAKE_FAIL_MATCH="tsputil license"; then fail "a rejected TSP license fails the start"; else pass "a rejected TSP license fails the start"; fi
check "a rejected TSP license is not logged" bash -c "! grep -qE 'TSP00|22222' '$work/out'"

# 4. API keys.
reset
printf 'key-one\nkey-two\n' >"$work/c/secrets/api_keys"
run_start API_KEYS="env-key"
check "API_KEYS from file (one per line) reach the server comma-separated" \
  test "$(child_env API_KEYS)" = "key-one,key-two"
reset
run_start API_KEYS="env-key"
check "API_KEYS from env still work" test "$(child_env API_KEYS)" = "env-key"

# 4a. API_KEYS normalisation (the server itself trims and drops empty keys: dist/config.js).
reset
printf '\n key-one \r\n,, key-two,\n\n' >"$work/c/secrets/api_keys"
run_start AUTH_MODE=apikey
check "API_KEYS: keys trimmed, empty ones dropped" test "$(child_env API_KEYS)" = "key-one,key-two"
reset
run_start AUTH_MODE=apikey API_KEYS=" env-a , ,env-b "
check "API_KEYS from env: trimmed, empty ones dropped" test "$(child_env API_KEYS)" = "env-a,env-b"
reset
printf 'key one\n' >"$work/c/secrets/api_keys"
if run_start AUTH_MODE=apikey; then fail "an API key with inner whitespace fails the start"; else pass "an API key with inner whitespace fails the start"; fi
check "an API key with inner whitespace: the key is not logged" bash -c "! grep -q 'key one' '$work/out'"
check "an API key with inner whitespace: explained" grep -q "API key #1 contains whitespace" "$work/out"

# 4b. AUTH_MODE: upstream denies everything for apikey without keys and ALLOWS everything for any
# value other than none / apikey (dist/middleware/apikey.middleware.js): both stop the start.
reset
printf '\n , \n' >"$work/c/secrets/api_keys"
if run_start AUTH_MODE=apikey; then fail "AUTH_MODE=apikey without keys fails the start"; else pass "AUTH_MODE=apikey without keys fails the start"; fi
check "AUTH_MODE=apikey without keys: explained" grep -q "AUTH_MODE=apikey but no API key" "$work/out"
check "AUTH_MODE=apikey without keys: the server is not started" bash -c "! test -f '$work/child.env'"
for mode in APIKEY api-key "apikey " basic ""; do
  reset
  if run_start AUTH_MODE="$mode" API_KEYS=k1; then fail "AUTH_MODE='$mode' fails the start"; else pass "AUTH_MODE='$mode' fails the start"; fi
done
check "an unknown AUTH_MODE: explained" grep -q "AUTH_MODE must be none or apikey" "$work/out"
reset
run_start AUTH_MODE=none API_KEYS=k1
check "AUTH_MODE=none with keys: starts" child_ran
check "AUTH_MODE=none with keys: warns that the keys are ignored" grep -q "WARNING: AUTH_MODE=none.*API_KEYS.*ignored" "$work/out"
reset
run_start
check "AUTH_MODE=none without keys: starts with a warning" grep -q "WARNING: AUTH_MODE=none" "$work/out"
# Unset AUTH_MODE means no auth upstream (`?? "none"`): a stand whose .env lost the line must not
# come up open silently, so it has to be set explicitly.
reset
if run_start API_KEYS=k1 env -u AUTH_MODE; then fail "an unset AUTH_MODE fails the start"; else pass "an unset AUTH_MODE fails the start"; fi
check "an unset AUTH_MODE: explained" grep -q "AUTH_MODE is not set" "$work/out"

# 5. Root certificates.
reset
: >"$work/c/certs/root/a root.cer"
: >"$work/c/certs/root/ignored.txt"
run_start
check "root certs go to mroot" called "certmgr -install -all -store mroot -file $work/c/certs/root/a root.cer"
check "non-.cer files in certs/root are ignored" bash -c "! grep -q ignored.txt '$work/calls'"

reset
: >"$work/c/certs/root/broken.cer"
run_start FAKE_FAIL_MATCH="broken.cer"
check "a failed root cert install does not stop the start" child_ran
check "a failed root cert install is logged with certmgr's output" \
  grep -q "broken.cer.*failed" "$work/out"
check "certmgr output is in the log" grep -q "0x80090020" "$work/out"

# 6. PFX containers from files.
reset
: >"$work/c/certs/user/nopin.pfx"
: >"$work/c/secrets/org.p12"
printf 's3cr3t-pin\n' >"$work/c/secrets/org.p12.pin"
run_start
check "a PIN-less PFX from certs/user is installed without -pin" \
  called "certmgr -install -all -store uMy -file $work/c/certs/user/nopin.pfx -pfx -silent"
check "a PFX in SECRETS_DIR is installed with the PIN from <file>.pin" \
  called "certmgr -install -all -store uMy -file $work/c/secrets/org.p12 -pfx -silent -pin s3cr3t-pin"
check ".pin files are not installed as containers" bash -c "! grep -q 'file $work/c/secrets/org.p12.pin' '$work/calls'"

reset
: >"$work/c/secrets/org.pfx"
printf 's3cr3t-pin\n' >"$work/c/secrets/org.pfx.pin"
run_start FAKE_FAIL_MATCH="org.pfx"
check "a failed PFX install does not stop the start" child_ran
check "a failed PFX install is logged" grep -q "org.pfx.*failed" "$work/out"
check "the PIN is redacted from the log" bash -c "! grep -q s3cr3t-pin '$work/out'"
check "a failure count is logged" grep -q "1 certificate/key install(s) failed" "$work/out"

reset
: >"$work/c/secrets/crlf.pfx"
printf 'crlf-pin\r\n' >"$work/c/secrets/crlf.pfx.pin"
run_start
check "CRLF in a .pin file is stripped" \
  called "certmgr -install -all -store uMy -file $work/c/secrets/crlf.pfx -pfx -silent -pin crlf-pin"

reset
: >"$work/c/secrets/locked.pfx"
mkdir "$work/c/secrets/locked.pfx.pin" # unreadable as a file
run_start
check "an unreadable .pin does not stop the start" child_ran
check "an unreadable .pin is logged" grep -q "locked.pfx.pin" "$work/out"
check "a container with an unreadable .pin is not installed" bash -c "! grep -q 'locked.pfx' '$work/calls'"

# Root certificates from env.
reset
run_start ROOT_CERTS_BASE64="$(printf 'root-a' | base64),%%%"
check "ROOT_CERTS_BASE64: valid element installed into mroot" grep -q -- "-store mroot" "$work/calls"
check "ROOT_CERTS_BASE64: invalid element logged" grep -q "ROOT_CERTS_BASE64 #2 is not valid Base64" "$work/out"

# 7. Legacy CERT_PFX_BASE64 / CERT_PFX_PIN (test keys only).
reset
a="$(printf 'pfx-a' | base64)" b="$(printf 'pfx-b' | base64)"
run_start CERT_PFX_BASE64="$a,,$b" CERT_PFX_PIN="p1,p2,p3"
check "legacy: element 1 gets PIN 1" grep -qE -- "-pfx -silent -pin p1$" "$work/calls"
check "legacy: an empty element keeps the PIN index (element 3 gets PIN 3)" \
  grep -qE -- "-pfx -silent -pin p3$" "$work/calls"
check "legacy: two containers installed" test "$(grep -c -- '-pfx' "$work/calls")" = 2
check "legacy: warns that env keys are test-only" grep -q "CERT_PFX_BASE64.*test" "$work/out"
check "legacy: CERT_PFX_BASE64 is not passed to the server" bash -c "! grep -q '^CERT_PFX_BASE64=' '$work/child.env'"
check "legacy: CERT_PFX_PIN is not passed to the server" bash -c "! grep -q '^CERT_PFX_PIN=' '$work/child.env'"
reset
run_start CERT_PFX_BASE64="$a,$b" CERT_PFX_PIN="same"
check "legacy: a single PIN applies to every element" \
  test "$(grep -c -- '-pin same$' "$work/calls")" = 2
reset
run_start CERT_PFX_BASE64="$a,$b" CERT_PFX_PIN='x\cy,ab\nc'
check "legacy: backslashes in indexed PINs are kept" grep -qF -- '-pin x\cy' "$work/calls"
check "legacy: backslashes in indexed PINs are kept (2)" grep -qF -- '-pin ab\nc' "$work/calls"
reset
run_start CERT_PFX_BASE64="$a,%%%"
check "legacy: invalid Base64 element is logged" grep -q "CERT_PFX_BASE64 #2 is not valid Base64" "$work/out"

if [ "$failures" -gt 0 ]; then
  echo "$failures test(s) failed"
  exit 1
fi
echo "all cryptoarm-start tests passed"
