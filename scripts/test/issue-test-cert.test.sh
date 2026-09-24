#!/usr/bin/env bash
# Tests for scripts/issue-test-cert.sh with a fake `docker` on PATH and a fake test CA.
# Run: scripts/test/issue-test-cert.test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
issue="$here/../issue-test-cert.sh"
mock="$here/mock-test-ca.py"

work="$(mktemp -d)"
mock_pid=""
cleanup() {
  [ -n "$mock_pid" ] && kill "$mock_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
failures=0

command -v expect >/dev/null || { echo "expect is required to run the keygen script locally" >&2; exit 1; }

# Fake docker: logs every call, answers the calls issue-test-cert.sh makes. The keygen call runs the
# script's real expect program locally against a fake cryptcp.
mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case "$1" in
  inspect) echo "${FAKE_RUNNING:-true}"; exit 0 ;;
  exec) ;;
  *) echo "fake docker: unexpected command: $*" >&2; exit 99 ;;
esac
case "$*" in
  "exec -i "*" expect -f - "*) # exec -i <container> expect -f - <cryptcp> <args...>
    shift 7 # drop "exec -i <container> expect -f - <cryptcp>"
    exec expect -f - "$FAKE_CRYPTCP" "$@" ;;
esac
[ "$2" = "-i" ] && cat >/dev/null # consume stdin (certificate bytes)
case "$*" in
  *"command -v expect"*) exit "${FAKE_NO_EXPECT:-0}" ;;
  *" mkdir /tmp/"*".lock") exit "${FAKE_LOCKED:-0}" ;;
  *"-enum_cont"*)
    printf '%s\n' '\\.\HDIMAGE\other' ${FAKE_EXISTING:+"$FAKE_EXISTING"}
    exit "${FAKE_ENUM_EXIT:-0}" ;;
  *" cat /tmp/"*) cat "$FAKE_CSR" ;;
  *"-store mroot"*) exit "${FAKE_MROOT_EXIT:-0}" ;;
  *"-store uMy"*) exit "${FAKE_UMY_EXIT:-0}" ;;
esac
exit 0
EOF
# Fake cryptcp: BIO_TUI-like prompt, reads keystrokes from the pty, logs its argv one per line.
cat >"$work/bin/cryptcp" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do printf '[%s]\n' "$a"; done >"$FAKE_CRYPTCP_LOG"
[ "${FAKE_CRYPTCP_MODE:-}" = noprompt ] && exit "${FAKE_CRYPTCP_EXIT:-0}"
echo "Press keys to provide random data..."
n=0
while IFS= read -r -s -n 1 _; do
  n=$((n + 1))
  [ "${FAKE_CRYPTCP_MODE:-}" = hang ] && continue
  [ "$n" -ge 20 ] && break
done
case "${FAKE_CRYPTCP_MODE:-}" in
  signal) kill -SEGV $$ ;;
esac
echo "Request is saved in file."
exit "${FAKE_CRYPTCP_EXIT:-0}"
EOF
chmod +x "$work/bin/docker" "$work/bin/cryptcp"

# Test PKI: a CA and two leaves (with and without the ИНН ЮЛ / ОГРН attributes), AIA -> mock CA.
cat >"$work/openssl.cnf" <<'EOF'
oid_section = new_oids
[new_oids]
innle = 1.2.643.100.4
[req]
distinguished_name = dn
[dn]
EOF
aia="caIssuers;URI:http://127.0.0.1:$port/CertEnroll/testgost2012(21).crt"
ossl() { OPENSSL_CONF="$work/openssl.cnf" openssl "$@" 2>/dev/null; }
ossl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/ca.key" \
  -subj '/CN=Fake Test CA' -days 2 -outform DER -out "$work/ca.der"
sign_leaf() { # subject, output (the subject goes through `req`, which knows the innle OID)
  ossl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/leaf.key" \
    -subj "$1" -out "$work/leaf.csr"
  ossl x509 -req -in "$work/leaf.csr" -CA "$work/ca.der" -CAform DER -CAkey "$work/ca.key" -days 1 \
    -extfile <(printf 'authorityInfoAccess=%s\n' "$aia") -outform DER -out "$2"
}
sign_leaf '/CN=Fake Org/innle=2311386400/OGRN=1252300058977' "$work/leaf-full.der"
sign_leaf '/CN=Fake Org' "$work/leaf-bare.der"
ossl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/other.key" \
  -subj '/CN=Other CA' -days 2 -outform DER -out "$work/other-ca.der"
cp "$work/leaf.csr" "$work/request.pem"
openssl x509 -inform DER -in "$work/leaf-full.der" -noout -subject -nameopt oid |
  grep -qF '1.2.643.100.4=2311386400' || { echo "test setup: leaf-full.der has no ИНН ЮЛ" >&2; exit 1; }

start_mock() { # mode leaf.der [issuer.der served at the AIA URL]
  stop_mock
  rm -rf "$work/rec" && mkdir -p "$work/rec"
  MOCK_MODE="$1" python3 "$mock" "$port" "$work/rec" "$2" "${3:-$work/ca.der}" &
  mock_pid=$!
  for _ in $(seq 1 50); do
    curl -s -o /dev/null "http://127.0.0.1:$port/" && return 0
    sleep 0.1
  done
  echo "mock CA did not start" >&2
  exit 1
}

stop_mock() {
  if [ -n "$mock_pid" ]; then
    kill "$mock_pid" 2>/dev/null || true
    wait "$mock_pid" 2>/dev/null || true
    mock_pid=""
  fi
}

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
# Allowlist of trusted test-CA roots: the fake CA (and a comment / blank line, as in the real file).
printf '# test roots\n\n%s  cryptopro-test-ca-2012-21.cer\n' "$(sha256 "$work/ca.der")" >"$work/roots.sha256"

run_issue() { # extra env assignments...
  rm -rf "$work/certs" && mkdir -p "$work/certs"
  : >"$work/docker.log"
  rm -f "$work/cryptcp.log"
  env PATH="$work/bin:$PATH" FAKE_DOCKER_LOG="$work/docker.log" FAKE_CSR="$work/request.pem" \
    FAKE_CRYPTCP="$work/bin/cryptcp" FAKE_CRYPTCP_LOG="$work/cryptcp.log" KEYGEN_TIMEOUT=20 \
    TEST_CA_URL="http://127.0.0.1:$port/certsrv" CERTS_DIR="$work/certs" KEY_CONTAINER=i3-test-cont TEST_CA_ROOTS_FILE="$work/roots.sha256" "$@" \
    "$issue" >"$work/out" 2>&1
}

pass() { echo "ok   - $1"; }
fail() {
  echo "FAIL - $1"
  sed 's/^/       /' "$work/out" 2>/dev/null || true
  failures=$((failures + 1))
}
check() { # name, condition...
  local name="$1"; shift
  if "$@"; then pass "$name"; else fail "$name"; fi
}
logged() { grep -qF -- "$1" "$work/docker.log"; }
cryptcp_arg() { grep -qxF -- "[$1]" "$work/cryptcp.log"; }
pin_is_empty() { [ "$(grep -A1 -xF -- '[-pin]' "$work/cryptcp.log" | tail -1)" = "[]" ]; }
out_has() { grep -qE -- "$1" "$work/out"; }
not() { ! "$@"; }

# --- happy path ------------------------------------------------------------
start_mock ok "$work/leaf-full.der"
if run_issue ORG_NAME='ООО "Тест"'; then pass "issues and installs a certificate"; else fail "issues and installs a certificate (exit $?)"; fi
check "keeps the public .cer in CERTS_DIR" cmp -s "$work/certs/o2-platforma.test.cer" "$work/leaf-full.der"
check "stores the issuer root from AIA" cmp -s "$work/certs/root/cryptopro-test-ca-2012-21.cer" "$work/ca.der"
check "posts the PKCS#10 request as Mode=newreq" grep -q 'Mode=newreq' "$work/rec/request.form"
check "posts the request body from the container" grep -q 'CertRequest=-----BEGIN' "$work/rec/request.form"
check "generates the key inside the container" logged "exec -i kryptoarm-diadoc-cryptoarm-server expect"
check "cryptcp: GOST 2012 provider" cryptcp_arg "80"
check "cryptcp: signature key" cryptcp_arg "-sg"
check "cryptcp: empty PIN" grep -qxF -- '[-pin]' "$work/cryptcp.log"
check "cryptcp: PIN value is empty" pin_is_empty
check "cryptcp: key not exportable" not cryptcp_arg "-exprt"
check "cryptcp: key container" cryptcp_arg '\\.\HDIMAGE\i3-test-cont'
check "cryptcp: RDN quotes values and doubles inner quotes" \
  grep -qF '[CN="ООО ""Тест""",O="ООО ""Тест""",SN="Тестов",G="Тест Тестович",T="Генеральный директор",L="Краснодар",S="Краснодарский край",C=RU,1.2.643.100.4=2311386400,1.2.643.100.1=1252300058977]' "$work/cryptcp.log"
check "installs the root into mroot" logged "-store mroot"
check "binds the certificate to the key container in uMy" \
  logged '-store uMy -file /tmp/i3-test-cont.cer -cont \\.\HDIMAGE\i3-test-cont'
check "binds the signature key (the request is made with -sg)" logged "-cont \\\\.\\HDIMAGE\\i3-test-cont -at_signature"
check "keeps the key container on success" not logged "-deletekeyset"
check "takes a name lock in the container before the listing" logged "mkdir /tmp/i3-test-cont.lock"
check "releases the name lock on success" logged "rmdir /tmp/i3-test-cont.lock"
check "removes temp files in the container" logged "rm -f /tmp/i3-test-cont.req"
check "reports ИНН ЮЛ honoured" out_has '1\.2\.643\.100\.4 \(ИНН ЮЛ\) = 2311386400: honoured$'
check "reports ОГРН honoured" out_has '1\.2\.643\.100\.1 \(ОГРН\) = 1252300058977: honoured$'
check "prints the validity" out_has 'notAfter='

# --- keygen without a BIO prompt (seeded RNG) ---------------------------------
if run_issue FAKE_CRYPTCP_MODE=noprompt; then pass "succeeds when cryptcp needs no keystrokes"; else fail "succeeds when cryptcp needs no keystrokes"; fi

# --- CA dropped the attributes ---------------------------------------------
start_mock ok "$work/leaf-bare.der"
if run_issue; then pass "succeeds when the CA drops ИНН/ОГРН"; else fail "succeeds when the CA drops ИНН/ОГРН"; fi
check "reports ИНН ЮЛ missing" out_has '1\.2\.643\.100\.4 \(ИНН ЮЛ\) = 2311386400: NOT honoured'
check "reports ОГРН missing" out_has '1\.2\.643\.100\.1 \(ОГРН\) = 1252300058977: NOT honoured'

# --- CA denies ---------------------------------------------------------------
start_mock denied "$work/leaf-full.der"
if run_issue; then fail "fails when the CA denies the request"; else pass "fails when the CA denies the request"; fi
check "explains the denial" out_has 'no ReqID'
check "deletes the orphaned key container" logged '-deletekeyset -cont \\.\HDIMAGE\i3-test-cont'
check "writes no certificate" not test -e "$work/certs/o2-platforma.test.cer"

# --- AIA issuer is not the root of the certificate --------------------------
start_mock ok "$work/leaf-full.der" "$work/other-ca.der"
if run_issue; then fail "rejects an AIA issuer that did not issue the certificate"; else pass "rejects an AIA issuer that did not issue the certificate"; fi
check "does not trust the foreign issuer" not logged "-store mroot"
start_mock ok "$work/leaf-full.der" "$work/leaf-full.der"
if run_issue; then fail "rejects a non-self-signed AIA issuer"; else pass "rejects a non-self-signed AIA issuer"; fi
check "explains the non-root issuer" out_has 'not self-signed'
check "does not trust the non-root issuer" not logged "-store mroot"

# --- AIA root is not in the allowlist (fetched over plain http) ------------------
start_mock ok "$work/leaf-full.der"
printf '%s  other.cer\n' "$(sha256 "$work/other-ca.der")" >"$work/other-roots.sha256"
if run_issue TEST_CA_ROOTS_FILE="$work/other-roots.sha256"; then fail "rejects an AIA root that is not in the allowlist"; else pass "rejects an AIA root that is not in the allowlist"; fi
check "explains the unknown root and names its SHA-256" out_has "SHA-256 $(sha256 "$work/ca.der") is not in"
check "does not trust the unknown root" not logged "-store mroot"
check "deletes its own key container after an unknown root" logged '-deletekeyset -cont \\.\HDIMAGE\i3-test-cont'
if run_issue TEST_CA_ROOTS_FILE="$work/nope"; then fail "fails without the allowlist file"; else pass "fails without the allowlist file"; fi
check "does not trust a root without the allowlist" not logged "-store mroot"
check "the default allowlist pins the renewal-21 root of fetch-test-certs.sh" \
  grep -qxF '6664740262766f0428379bb6ff2340c2d8497ce1862cd4e04f6353c2e978fb03  cryptopro-test-ca-2012-21.cer' \
  "$here/../test-ca-roots.sha256"
check "fetch-test-certs.sh takes the root's hash from the same allowlist" grep -qF 'test-ca-roots.sha256' "$here/../fetch-test-certs.sh"

# --- mroot / uMy install fails ---------------------------------------------
start_mock ok "$work/leaf-full.der"
if run_issue FAKE_MROOT_EXIT=1; then fail "fails when certmgr cannot install the root"; else pass "fails when certmgr cannot install the root"; fi
check "does not bind after a failed root install" not logged "-store uMy"
check "deletes the key container after a failed root install" logged '-deletekeyset -cont \\.\HDIMAGE\i3-test-cont'
if run_issue FAKE_UMY_EXIT=1; then fail "fails when certmgr cannot bind"; else pass "fails when certmgr cannot bind"; fi
check "deletes the key container after a failed bind" logged '-deletekeyset -cont \\.\HDIMAGE\i3-test-cont'
check "writes no certificate after a failed bind" not test -e "$work/certs/o2-platforma.test.cer"

# --- key generation fails ----------------------------------------------------
start_mock ok "$work/leaf-full.der"
if run_issue FAKE_CRYPTCP_EXIT=7; then fail "fails when cryptcp fails"; else pass "fails when cryptcp fails"; fi
check "sends nothing to the CA after a failed keygen" not test -e "$work/rec/request.form"
check "deletes the key container after a failed keygen" logged '-deletekeyset -cont \\.\HDIMAGE\i3-test-cont'
if run_issue FAKE_CRYPTCP_MODE=noprompt FAKE_CRYPTCP_EXIT=5; then fail "fails when cryptcp fails before the prompt"; else pass "fails when cryptcp fails before the prompt"; fi
if run_issue FAKE_CRYPTCP_MODE=signal; then fail "fails when cryptcp is killed by a signal"; else pass "fails when cryptcp is killed by a signal"; fi
check "sends nothing to the CA after a crashed keygen" not test -e "$work/rec/request.form"
started=$SECONDS
if run_issue FAKE_CRYPTCP_MODE=hang KEYGEN_TIMEOUT=2; then fail "fails when cryptcp never finishes"; else pass "fails when cryptcp never finishes"; fi
check "gives up on a hanging keygen within the timeout" test $((SECONDS - started)) -lt 30
check "kills a leftover keygen before deleting the key" logged '/proc/[0-9]*'

# --- refusals before any key is generated -----------------------------------
refuses() { # name, env...
  local name="$1"; shift
  if run_issue "$@"; then fail "$name"; else
    if grep -qE ' (expect|-deletekeyset) ' "$work/docker.log"; then fail "$name (touched keys)"; else pass "$name"; fi
  fi
}
refuses "refuses an existing key container" FAKE_EXISTING='\\.\HDIMAGE\i3-test-cont'
check "explains the existing key container" out_has 'already exists'
# M3 (R2): a failing enumeration must not look like "no such container": the cleanup would then
# delete an existing, non-exportable key after a failed keygen.
refuses "refuses when the key containers cannot be listed" FAKE_ENUM_EXIT=1
check "explains the failed enumeration" out_has 'cannot list the key containers'
refuses "never deletes an existing key when the enumeration fails" \
  FAKE_ENUM_EXIT=1 FAKE_EXISTING='\\.\HDIMAGE\i3-test-cont' FAKE_CRYPTCP_EXIT=7
check "never runs the keygen when the enumeration fails" not logged " expect -f "
check "releases its name lock when the enumeration fails" logged "rmdir /tmp/i3-test-cont.lock"
# Two runs with the same KEY_CONTAINER: the second must not reach the keygen (its cleanup would delete
# the first run's key after cryptcp refuses the existing container).
refuses "refuses a KEY_CONTAINER another run holds" FAKE_LOCKED=1
check "explains the held name" out_has 'another issue-test-cert run'
check "does not release a lock it does not hold" not logged "rmdir /tmp/i3-test-cont.lock"
refuses "fails when the container is not running" FAKE_RUNNING=false
refuses "fails when expect is missing in the container" FAKE_NO_EXPECT=1
refuses "rejects unsafe KEY_CONTAINER" KEY_CONTAINER='bad name;rm'
check "does not call docker exec for an unsafe name" not logged "exec"
refuses "rejects a malformed ИНН" ORG_INN='1,CN=evil'
refuses "rejects a malformed ОГРН" ORG_OGRN=123
refuses "rejects an unwritable CERTS_DIR" CERTS_DIR=/dev/null/certs

stop_mock
if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "all tests passed"
