#!/usr/bin/env bash
# Issues a signer certificate from the public КриптоПро test CA (GOST R 34.10-2012, 256 bit) for a key
# that is generated INSIDE the running КриптоАРМ Server container and never leaves it:
#   1. cryptcp -createrqst in the container: new PIN-less, non-exportable key container on HDIMAGE
#      (/var/opt/cprocsp, the persistent cert_storage volume) + PKCS#10 request. The container has no
#      seeded CPSD RNG, so CSP asks for keyboard entropy (BIO_TUI); expect answers it with bytes
#      from the container's /dev/urandom.
#   2. POST the request to the CA's ADCS web enrollment (certfnsh.asp), download the certificate
#      (certnew.cer?ReqID=N&Enc=bin) and the issuer certificate from its AIA URL.
#   3. certmgr: issuer -> mroot, certificate -> uMy bound to the signature key of the key container
#      (-cont ... -at_signature; -to-container also stores the certificate in the key container).
#   4. Save only public certificates: $CERTS_DIR/$CERT_NAME.cer and $CERTS_DIR/root/<issuer>.cer.
# On any failure before step 3 completes, the new key container is deleted again.
#
# Re-run it to replace the certificate before it expires (a new key container each time; old ones
# stay installed, so certificates already in use keep working until they expire).
#
# Env (defaults in brackets):
#   CRYPTOARM_CONTAINER  [kryptoarm-diadoc-cryptoarm-server]
#   TEST_CA_URL          [http://testgost2012.cryptopro.ru/certsrv]  (https fails: its TLS chain is
#                        not in the system trust store; the AIA/CRL URLs in the certs are http anyway)
#   CERTS_DIR            [<repo>/docker/cryptoarm-server/certs]  (git-ignored *.cer)
#   CERT_NAME            [o2-platforma.test]
#   KEY_CONTAINER        [o2-platforma-test-<UTC timestamp>]  ([A-Za-z0-9._-] only; must not exist yet)
#   KEYGEN_TIMEOUT       [300]  seconds of keystroke entropy before the keygen is killed
#   TEST_CA_ROOTS_FILE   [<repo>/scripts/test-ca-roots.sha256]  SHA-256 allowlist of the issuer roots
#                        that may go into mroot (the AIA download is plain http)
#   ORG_NAME, ORG_INN, ORG_OGRN, ORG_CITY, ORG_REGION, ORG_COUNTRY,
#   SIGNER_SURNAME, SIGNER_GIVEN_NAME, SIGNER_TITLE  subject attributes, see defaults below.
#   The signer person is a placeholder on purpose.
# Requires: bash, docker, curl, openssl; expect inside the container.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container="${CRYPTOARM_CONTAINER:-kryptoarm-diadoc-cryptoarm-server}"
ca_url="${TEST_CA_URL:-http://testgost2012.cryptopro.ru/certsrv}"
certs_dir="${CERTS_DIR:-$repo_root/docker/cryptoarm-server/certs}"
cert_name="${CERT_NAME:-o2-platforma.test}"
key_container="${KEY_CONTAINER:-o2-platforma-test-$(date -u +%Y%m%d%H%M%S)}"
keygen_timeout="${KEYGEN_TIMEOUT:-300}"
roots_file="${TEST_CA_ROOTS_FILE:-$repo_root/scripts/test-ca-roots.sha256}"

org_name="${ORG_NAME:-ООО \"О2 ПЛАТФОРМА\"}"
org_inn="${ORG_INN:-2311386400}"
org_ogrn="${ORG_OGRN:-1252300058977}"
org_city="${ORG_CITY:-Краснодар}"
org_region="${ORG_REGION:-Краснодарский край}"
org_country="${ORG_COUNTRY:-RU}"
signer_surname="${SIGNER_SURNAME:-Тестов}"
signer_given="${SIGNER_GIVEN_NAME:-Тест Тестович}"
signer_title="${SIGNER_TITLE:-Генеральный директор}"

cprocsp=/opt/cprocsp/bin/amd64
fqcn="\\\\.\\HDIMAGE\\$key_container"
req_path="/tmp/$key_container.req"
cert_path="/tmp/$key_container.cer"
root_path="/tmp/$key_container-root.cer"
lock_path="/tmp/$key_container.lock"

die() { echo "issue-test-cert: FAIL: $*" >&2; exit 1; }
log() { echo "issue-test-cert: $*" >&2; }

for tool in docker curl openssl; do
  command -v "$tool" >/dev/null || die "'$tool' is required"
done
# -nameopt oid / -ext need OpenSSL 3 (macOS /usr/bin/openssl is LibreSSL).
openssl version | grep -q '^OpenSSL 3' || die "OpenSSL 3 is required, got: $(openssl version)"
[[ "$key_container" =~ ^[A-Za-z0-9._-]+$ ]] || die "KEY_CONTAINER may contain only [A-Za-z0-9._-]: $key_container"
[[ "$cert_name" =~ ^[A-Za-z0-9._-]+$ ]] || die "CERT_NAME may contain only [A-Za-z0-9._-]: $cert_name"
[[ "$org_inn" =~ ^[0-9]{10}$ ]] || die "ORG_INN must be 10 digits (ИНН ЮЛ): $org_inn"
[[ "$org_ogrn" =~ ^[0-9]{13}$ ]] || die "ORG_OGRN must be 13 digits: $org_ogrn"
[[ "$org_country" =~ ^[A-Z]{2}$ ]] || die "ORG_COUNTRY must be two capital letters: $org_country"
[[ "$keygen_timeout" =~ ^[0-9]+$ ]] || die "KEYGEN_TIMEOUT must be seconds: $keygen_timeout"
[ -f "$roots_file" ] && [ -r "$roots_file" ] || die "test-CA root allowlist not readable: $roots_file"
mkdir -p "$certs_dir/root" && [ -w "$certs_dir" ] && [ -w "$certs_dir/root" ] ||
  die "CERTS_DIR is not writable: $certs_dir"
[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = "true" ] ||
  die "container $container is not running (start the stand: docker compose up -d)"
docker exec "$container" sh -c 'command -v expect' >/dev/null 2>&1 ||
  die "expect is missing in $container (it comes with the base image registry.digtlab.ru/trusted/cryptoarm/server)"
tmp="$(mktemp -d)"
key_created=""
installed=""
locked=""
cleanup() {
  local status=$?
  if [ -n "$key_created" ] && [ -z "$installed" ]; then
    # docker exec without a TTY does not forward SIGINT: stop a still running keygen first.
    docker exec "$container" sh -c 'for p in /proc/[0-9]*; do
        pid="${p#/proc/}"; [ "$pid" = "$$" ] && continue
        case "$(tr "\0" " " <"$p/cmdline" 2>/dev/null)" in *"-cont $1 "*) kill -9 "$pid" 2>/dev/null ;; esac
      done' sh "$fqcn" >/dev/null 2>&1 || true
    log "deleting key container $fqcn (not installed)"
    docker exec "$container" "$cprocsp/csptest" -keyset -deletekeyset -cont "$fqcn" >/dev/null 2>&1 ||
      log "could not delete $fqcn; delete it by hand: csptest -keyset -deletekeyset -cont '$fqcn'"
  fi
  docker exec "$container" rm -f "$req_path" "$cert_path" "$root_path" >/dev/null 2>&1 || true
  [ -z "$locked" ] || docker exec "$container" rmdir "$lock_path" >/dev/null 2>&1 || true
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT

# Two runs with the same KEY_CONTAINER would both pass the listing below; the second one's keygen then
# fails on the existing container and its cleanup would delete the first one's key. A name lock in
# the container (its /tmp is a tmpfs, so a lock left by kill -9 is gone after a restart) prevents it.
docker exec "$container" mkdir "$lock_path" >/dev/null 2>&1 ||
  die "another issue-test-cert run holds $key_container ($lock_path in $container; remove it if no run is active)"
locked=1
# Never touch an existing key: the cleanup below deletes the container on failure. A failed listing
# must not read as "not found" (R2 M3), so its exit status is checked apart from the search.
containers="$(docker exec "$container" "$cprocsp/csptest" -keyset -enum_cont -fqcn -verifyc 2>&1)" ||
  die "cannot list the key containers in $container (csptest exit $?); not generating a key: $(tail -2 <<<"$containers" | tr -d '\r')"
if tr -d '\r' <<<"$containers" | grep -qixF "$fqcn"; then
  die "key container $fqcn already exists; choose another KEY_CONTAINER"
fi

# CertStrToName syntax: quote every value, double the quotes inside.
rdn_value() { printf '"%s"' "${1//\"/\"\"}"; }
rdn="CN=$(rdn_value "$org_name"),O=$(rdn_value "$org_name")"
rdn+=",SN=$(rdn_value "$signer_surname"),G=$(rdn_value "$signer_given"),T=$(rdn_value "$signer_title")"
rdn+=",L=$(rdn_value "$org_city"),S=$(rdn_value "$org_region"),C=$org_country"
rdn+=",1.2.643.100.4=$org_inn,1.2.643.100.1=$org_ogrn" # ИНН ЮЛ, ОГРН (NumericString)


# copy_in <local file> <container path>: public certificates only.
copy_in() { docker exec -i "$container" sh -c 'cat > "$1"' sh "$2" <"$1"; }

# --- 1. key + request inside the container ---------------------------------
log "generating key container $fqcn and a PKCS#10 request in $container"
key_created=1
# Exit codes: cryptcp's own; 2 no prompt; 3 timed out (cryptcp killed); 4 cryptcp died on a signal.
keygen_script='
set env(LC_ALL) C.UTF-8
lassign $argv cryptcp cont rdn req limit
proc finish {} {
  if {[catch wait r]} { exit 4 }
  # {pid spawn_id -1 errno ...}: OS error; {pid spawn_id 0 0 CHILDKILLED SIG msg}: killed by a signal.
  if {[lindex $r 2] != 0 || [llength $r] > 4} { exit 4 }
  exit [lindex $r 3]
}
proc abort {code} {
  catch { exec kill -9 [exp_pid] }
  catch { close }
  catch { wait }
  exit $code
}
set timeout 120
spawn $cryptcp -createrqst -rdn $rdn -provtype 80 -hashalg 1.2.643.7.1.1.2.2 -sg -ku -cont $cont \
  -pin "" -certusage "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4" $req
expect {
  "Press keys" {}
  eof { finish }
  timeout { abort 2 }
}
# BIO_TUI entropy for this TEST key only: keystrokes from /dev/urandom at random intervals until
# cryptcp exits. A production key needs a proper RNG (seeded CPSD / hardware), not this.
set rnd [open /dev/urandom rb]
set deadline [expr {[clock seconds] + $limit}]
set timeout 0
while {[clock seconds] < $deadline} {
  binary scan [read $rnd 2] cu2 b
  # send/expect fail once cryptcp has exited and its pty is closed: collect the exit status.
  if {[catch {send -- [format %c [expr {97 + [lindex $b 0] % 26}]]}]} { finish }
  after [expr {5 + [lindex $b 1] % 40}]
  if {[catch {expect eof { finish } -re .+ {} timeout {}}]} { finish }
}
set timeout 5
if {[catch {expect eof { finish } timeout { abort 3 }}]} { finish }
'
if ! printf '%s' "$keygen_script" |
  docker exec -i "$container" expect -f - "$cprocsp/cryptcp" "$fqcn" "$rdn" "$req_path" "$keygen_timeout" \
    >"$tmp/keygen.log" 2>&1; then
  tr '\r' '\n' <"$tmp/keygen.log" | grep -avE '^[a-z]*$' | tail -5 >&2
  die "key/request generation failed in the container"
fi
docker exec "$container" cat "$req_path" >"$tmp/request.pem"
grep -q 'BEGIN' "$tmp/request.pem" || die "no PKCS#10 request produced"

# --- 2. enrollment at the test CA -------------------------------------------
log "submitting the request to $ca_url"
curl -fsS --proto =http,https --connect-timeout 15 --max-time 120 -o "$tmp/submit.html" \
  --data-urlencode 'Mode=newreq' --data-urlencode "CertRequest@$tmp/request.pem" \
  --data-urlencode 'CertAttrib=' --data-urlencode 'FriendlyType=Saved-Request Certificate' \
  --data-urlencode 'TargetStoreFlags=0' --data-urlencode 'SaveCert=yes' \
  "$ca_url/certfnsh.asp" || die "POST $ca_url/certfnsh.asp failed"
req_id="$(grep -aoE 'certnew\.cer\?ReqID=[0-9]+' "$tmp/submit.html" | head -1 | cut -d= -f2 || true)"
if [ -z "$req_id" ]; then
  sed -e 's/<[^>]*>/ /g' "$tmp/submit.html" | grep -aiE 'ошиб|отклон|ожида|denied|pending|error|0x8' |
    grep -av 'Error = ' | head -5 >&2 || true
  die "the CA returned no ReqID (request denied or pending)"
fi
log "issued ReqID=$req_id"
curl -fsS --proto =http,https --connect-timeout 15 --max-time 60 -o "$tmp/cert.cer" "$ca_url/certnew.cer?ReqID=$req_id&Enc=bin" ||
  die "download of ReqID=$req_id failed"
openssl x509 -inform DER -in "$tmp/cert.cer" -noout 2>/dev/null || die "ReqID=$req_id is not a DER certificate"

aia="$(openssl x509 -inform DER -in "$tmp/cert.cer" -noout -ext authorityInfoAccess 2>/dev/null |
  sed -n 's/^ *CA Issuers - URI:\(.*\.crt\) *$/\1/p' | head -1)"
[ -n "$aia" ] || die "certificate has no CA Issuers .crt URL"
curl -fsS --proto =http,https --connect-timeout 15 --max-time 60 -o "$tmp/root.raw" "$aia" || die "download of issuer $aia failed"
openssl x509 -inform DER -in "$tmp/root.raw" -outform DER -out "$tmp/root.cer" 2>/dev/null ||
  openssl x509 -inform PEM -in "$tmp/root.raw" -outform DER -out "$tmp/root.cer" 2>/dev/null ||
  die "issuer $aia is not a certificate"
# It goes into the trusted roots and came over plain http: accept only the self-signed issuer of the
# certificate whose SHA-256 is in the allowlist. (The GOST signature itself cannot be checked here
# without a GOST provider.)
dn() { openssl x509 -inform DER -in "$1" -noout "-$2" -nameopt RFC2253 | sed "s/^$2=//"; }
[ "$(dn "$tmp/root.cer" subject)" = "$(dn "$tmp/root.cer" issuer)" ] ||
  die "issuer $aia is not self-signed (not a root): $(dn "$tmp/root.cer" subject)"
[ "$(dn "$tmp/root.cer" subject)" = "$(dn "$tmp/cert.cer" issuer)" ] ||
  die "issuer $aia ($(dn "$tmp/root.cer" subject)) is not the issuer of the certificate ($(dn "$tmp/cert.cer" issuer))"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
root_sha="$(sha256 "$tmp/root.cer")"
[[ "$root_sha" =~ ^[0-9a-f]{64}$ ]] || die "cannot hash the issuer $aia"
allowed="$(sed 's/#.*//' "$roots_file" | awk 'NF { print tolower($1) }')"
grep -qxF "$root_sha" <<<"$allowed" ||
  die "issuer $aia ($(dn "$tmp/root.cer" subject)) with SHA-256 $root_sha is not in $roots_file; check it out of band and add it there"
root_file="$(basename "$aia")"
if [[ "$root_file" =~ ^testgost2012\(([0-9]+)\)\.crt$ ]]; then
  root_file="cryptopro-test-ca-2012-${BASH_REMATCH[1]}.cer" # same name as scripts/fetch-test-certs.sh
else
  root_file="$(printf '%s' "${root_file%.*}" | tr -c 'A-Za-z0-9._-' '-').cer"
fi

# --- 3. install ----------------------------------------------------------------
log "installing issuer into mroot and the certificate into uMy (bound to $fqcn)"
copy_in "$tmp/root.cer" "$root_path"
docker exec "$container" "$cprocsp/certmgr" -inst -store mroot -file "$root_path" >"$tmp/mroot.log" 2>&1 ||
  { tail -3 "$tmp/mroot.log" >&2; die "certmgr could not install the issuer into mroot"; }
copy_in "$tmp/cert.cer" "$cert_path"
docker exec "$container" "$cprocsp/certmgr" -inst -store uMy -file "$cert_path" -cont "$fqcn" \
  -at_signature -to-container >"$tmp/umy.log" 2>&1 ||
  { tail -3 "$tmp/umy.log" >&2; die "certmgr could not bind the certificate to $fqcn"; }
installed=1

# --- 4. public certificates out --------------------------------------------
mkdir -p "$certs_dir/root"
cp "$tmp/root.cer" "$certs_dir/root/$root_file"
cp "$tmp/cert.cer" "$certs_dir/$cert_name.cer"

# --- report --------------------------------------------------------------------
subject="$(openssl x509 -inform DER -in "$tmp/cert.cer" -noout -subject -nameopt oid,sep_multiline,utf8)"
attr_report() { # oid, label, requested value
  if grep -qxF "    $1=$3" <<<"$subject"; then
    echo "  $1 ($2) = $3: honoured"
  else
    echo "  $1 ($2) = $3: NOT honoured (issued: $(grep -F "    $1=" <<<"$subject" | cut -d= -f2- || true))"
  fi
}
echo "certificate: ${certs_dir%/}/$cert_name.cer"
echo "issuer root: ${certs_dir%/}/root/$root_file"
echo "key container: $fqcn (uMy, PIN-less, non-exportable)"
openssl x509 -inform DER -in "$tmp/cert.cer" -noout -dates -fingerprint -sha1
openssl x509 -inform DER -in "$tmp/cert.cer" -noout -subject -nameopt utf8,sep_multiline
echo "requested attributes:"
attr_report 1.2.643.100.4 "ИНН ЮЛ" "$org_inn"
attr_report 1.2.643.100.1 "ОГРН" "$org_ogrn"
