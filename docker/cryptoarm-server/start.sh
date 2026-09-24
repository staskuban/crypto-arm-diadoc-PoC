#!/bin/sh
# Entrypoint of the КриптоАРМ Server container (replaces upstream's shell-form CMD; see README.md).
# Prepares CSP and licenses, installs certificates and keys, then execs the server ("$@", by default
# `node dist/main.js`), so the server receives signals directly (compose runs it under `init`).
#
# Secrets are read from files first, env second (env is the legacy path, readable via docker inspect):
#   <VAR>_FILE              explicit file; the start fails if it is not readable
#   $SECRETS_DIR/<var>      lower-case name, e.g. /run/secrets/trusted_license
#   <VAR>                   env value
# for VAR in TRUSTED_LICENSE CRYPTOPRO_LICENSE CRYPTOPRO_TSP_LICENSE CRYPTOPRO_OCSP_LICENSE API_KEYS.
# The license values are not passed on to the server process (it only needs the variables defined);
# API_KEYS is (the server reads it only from env). An api_keys file may list one key per line; keys
# are split on newlines and commas, trimmed, empty ones dropped (as the server does), and a key with
# whitespace inside stops the start. AUTH_MODE must be set explicitly to none (no auth, warned about)
# or to apikey with at least one key: upstream rejects every request for apikey without keys and lets
# every request through for any other value (e.g. APIKEY, empty) or when it is unset, so all of
# these stop the start.
#
# Key containers: *.pfx / *.p12 in $CERTS_DIR/user and $SECRETS_DIR go to uMy; a PIN is read from
# the sibling file <container>.pin. Legacy CERT_PFX_BASE64 / CERT_PFX_PIN (comma-separated, PINs by
# index or one PIN for all) still work, for test keys only. Root certificates: $CERTS_DIR/root/*.cer
# and legacy ROOT_CERTS_BASE64 go to mroot.
#
# Residual exposure: CSP / TSP / OCSP licenses and PFX PINs are passed to cpconfig / tsputil /
# ocsputil / certmgr as argv (no other input exists), visible in the container's process list for
# the duration of that call at start. The tools' output is logged with the licence value redacted.
#
# A failed certificate/key install is logged with certmgr's output (PIN redacted) and the start
# continues; a failed license setup or an unreadable *_FILE stops it.
set -eu

CERTMGR_BIN="${CERTMGR_BIN:-/opt/cprocsp/bin/amd64/certmgr}"
CPCONFIG_BIN="${CPCONFIG_BIN:-/opt/cprocsp/sbin/amd64/cpconfig}"
TSPUTIL_BIN="${TSPUTIL_BIN:-/opt/cprocsp/bin/amd64/tsputil}"
OCSPUTIL_BIN="${OCSPUTIL_BIN:-/opt/cprocsp/bin/amd64/ocsputil}"
CSP_STORE_DIR="${CSP_STORE_DIR:-/var/opt/cprocsp}"
CSP_STORE_DEFAULT_DIR="${CSP_STORE_DEFAULT_DIR:-/var/opt/cprocsp_default}"
CSP_CONFIG_DIR="${CSP_CONFIG_DIR:-/etc/opt/cprocsp}"
CSP_CONFIG_DEFAULT_DIR="${CSP_CONFIG_DEFAULT_DIR:-/etc/opt/cprocsp_default}"
CERTS_DIR="${CERTS_DIR:-/certs}"
SECRETS_DIR="${SECRETS_DIR:-/run/secrets}"
TRUSTED_LICENSE_DIR="${TRUSTED_LICENSE_DIR:-/etc/opt/Trusted/CryptoARM Server}"

umask 077 # temp files and license.lic; reset to 022 before exec

log() { echo "cryptoarm-start: $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

install_failures=0

# read_secret_file <file>: prints its content without CR and trailing newlines; fails if unreadable.
read_secret_file() {
  content="$(tr -d '\r' <"$1")" || return 1
  printf '%s' "$content"
}

# secret <VAR>: prints the value from <VAR>_FILE, $SECRETS_DIR/<var> or env (CR / trailing newlines dropped).
secret() {
  var="$1"
  lower="$(echo "$var" | tr '[:upper:]' '[:lower:]')"
  eval "file=\${${var}_FILE:-}"
  eval "env_value=\${${var}:-}"
  if [ -n "$file" ]; then
    [ -f "$file" ] && [ -r "$file" ] || die "${var}_FILE=$file is not a readable file"
  elif [ -f "$SECRETS_DIR/$lower" ]; then
    file="$SECRETS_DIR/$lower"
  fi
  if [ -n "$file" ]; then
    [ -z "$env_value" ] || log "WARNING: $var is set in env and in $file; the env value is ignored"
    read_secret_file "$file" || die "cannot read $file ($var)"
  else
    printf '%s' "$env_value"
  fi
}

# redact <text> <secret>: replaces every occurrence of <secret> (fixed string) in <text>.
redact() {
  if [ -z "$2" ]; then
    printf '%s\n' "$1"
  else
    TEXT="$1" SECRET="$2" awk 'BEGIN {
      s = ENVIRON["TEXT"]; p = ENVIRON["SECRET"]; out = ""
      while ((i = index(s, p)) > 0) { out = out substr(s, 1, i - 1) "***"; s = substr(s, i + length(p)) }
      print out s
    }'
  fi
}

# set_license <what> <value> <tool> <args...>: runs a licence tool, logs its output with <value>
# (also without its dashes) redacted, stops the start if the tool fails.
set_license() {
  what="$1" value="$2"
  shift 2
  if output="$("$@" 2>&1)"; then status=0; else status=$?; fi
  if [ -n "$output" ]; then
    redact "$(redact "$output" "$value")" "$(printf '%s' "$value" | tr -d -)" | sed 's/^/    /' >&2
  fi
  [ "$status" -eq 0 ] || die "$what (exit $status)"
}

# certmgr_install <what> <pin> <certmgr args...>: runs certmgr, logs a failure with its output.
certmgr_install() {
  what="$1" pin="$2"
  shift 2
  if output="$("$CERTMGR_BIN" "$@" 2>&1)"; then
    log "installed $what"
  else
    status=$?
    install_failures=$((install_failures + 1))
    log "ERROR: installing $what failed (certmgr exit $status):"
    redact "$output" "$pin" | sed 's/^/    /' >&2
  fi
}

install_root() { # <file> <label>
  certmgr_install "root certificate $2" "" -install -all -store mroot -file "$1"
}

install_pfx() { # <file> <pin> <label>
  if [ -n "$2" ]; then
    certmgr_install "key container $3" "$2" -install -all -store uMy -file "$1" -pfx -silent -pin "$2"
  else
    certmgr_install "key container $3" "" -install -all -store uMy -file "$1" -pfx -silent
  fi
}

# --- CSP store: a fresh bind mount gets the image's default CSP configuration.
if [ -z "$(ls -A "$CSP_STORE_DIR" 2>/dev/null)" ]; then
  log "seeding empty $CSP_STORE_DIR from $CSP_STORE_DEFAULT_DIR"
  cp -r "$CSP_STORE_DEFAULT_DIR"/. "$CSP_STORE_DIR"/
fi
# --- CSP configuration: under a read-only root filesystem it is a tmpfs (cpconfig -license -set
# writes license.ini there), filled on every start from the copy made at image build time.
if [ -z "$(ls -A "$CSP_CONFIG_DIR" 2>/dev/null)" ]; then
  if [ -d "$CSP_CONFIG_DEFAULT_DIR" ]; then
    log "seeding empty $CSP_CONFIG_DIR from $CSP_CONFIG_DEFAULT_DIR"
    cp -pR "$CSP_CONFIG_DEFAULT_DIR"/. "$CSP_CONFIG_DIR"/
  else
    log "WARNING: $CSP_CONFIG_DIR is empty and $CSP_CONFIG_DEFAULT_DIR is missing; CSP will not work (image older than the compose file?)"
  fi
fi

# --- Licenses.
csp_license="$(secret CRYPTOPRO_LICENSE)"
if [ -n "$csp_license" ]; then
  log "setting КриптоПро CSP license"
  set_license "cpconfig rejected CRYPTOPRO_LICENSE" "$csp_license" "$CPCONFIG_BIN" -license -set "$csp_license"
else
  log "no CRYPTOPRO_LICENSE: КриптоПро CSP runs on the trial license"
fi
# -view prints the license serial: log only the expiry and the type.
"$CPCONFIG_BIN" -license -view 2>&1 | grep -E '^(Expires|License type)' >&2 || true

tsp_license="$(secret CRYPTOPRO_TSP_LICENSE)"
if [ -n "$tsp_license" ]; then
  log "setting TSP license"
  set_license "tsputil rejected CRYPTOPRO_TSP_LICENSE" "$tsp_license" "$TSPUTIL_BIN" license -s "$tsp_license"
fi
ocsp_license="$(secret CRYPTOPRO_OCSP_LICENSE)"
if [ -n "$ocsp_license" ]; then
  log "setting OCSP license"
  set_license "ocsputil rejected CRYPTOPRO_OCSP_LICENSE" "$ocsp_license" "$OCSPUTIL_BIN" license -s "$ocsp_license"
fi

trusted_license="$(secret TRUSTED_LICENSE)"
if [ -n "$trusted_license" ]; then
  # Same file upstream /trusted/scripts/setup_license writes, without passing the key as argv.
  mkdir -p "$TRUSTED_LICENSE_DIR"
  printf '%s' "$trusted_license" >"$TRUSTED_LICENSE_DIR/license.lic"
  log "КриптоАРМ Server license written"
else
  log "WARNING: TRUSTED_LICENSE is empty; the server will refuse to start (\"Trusted Crypto license is invalid\")"
fi

# --- API keys and auth mode (see the header).
api_keys_raw="$(secret API_KEYS)"
if ! api_keys="$(API_KEYS_RAW="$api_keys_raw" awk 'BEGIN {
  n = split(ENVIRON["API_KEYS_RAW"], parts, /[,\r\n]/); out = ""; k = 0
  for (i = 1; i <= n; i++) {
    key = parts[i]; gsub(/^[ \t\v\f]+|[ \t\v\f]+$/, "", key)
    if (key == "") continue
    k++
    if (key ~ /[ \t\v\f]/) { print k; exit 3 }
    out = out (out == "" ? "" : ",") key
  }
  print out
}')"; then
  case "$api_keys" in
    [0-9]*) die "API key #$api_keys contains whitespace (keys are separated by newlines or commas)" ;;
    *) die "cannot parse API_KEYS" ;;
  esac
fi
unset api_keys_raw
# Upstream treats a missing AUTH_MODE as none (`?? "none"` in dist/config.js): a stand whose .env lost
# the line would come up without auth, so it must be set explicitly.
[ -n "${AUTH_MODE+set}" ] || die "AUTH_MODE is not set: set AUTH_MODE=apikey (with API keys) or AUTH_MODE=none explicitly"
case "$AUTH_MODE" in
  none)
    if [ -n "$api_keys" ]; then
      log "WARNING: AUTH_MODE=none: API_KEYS are ignored, every request is accepted without an API key"
    else
      log "WARNING: AUTH_MODE=none: every request is accepted without an API key"
    fi ;;
  apikey)
    [ -n "$api_keys" ] || die "AUTH_MODE=apikey but no API key is set (secrets/api_keys, API_KEYS_FILE or API_KEYS): the server would reject every request" ;;
  *) die "AUTH_MODE must be none or apikey, got '${AUTH_MODE}' (the server would accept every request without an API key)" ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# dash skips the EXIT trap on a signal: remove decoded legacy PFX files on INT/TERM too.
trap 'rm -rf "$work"; exit 143' INT TERM

# --- Root certificates.
if [ -d "$CERTS_DIR/root" ]; then
  find "$CERTS_DIR/root" -maxdepth 1 -type f -name '*.cer' | sort >"$work/root-list"
  while IFS= read -r f; do
    install_root "$f" "$(basename "$f")"
  done <"$work/root-list"
fi

if [ -n "${ROOT_CERTS_BASE64:-}" ]; then
  idx=0
  for cert_b64 in $(printf '%s\n' "$ROOT_CERTS_BASE64" | tr ',' ' '); do
    idx=$((idx + 1))
    if printf '%s' "$cert_b64" | base64 -d >"$work/root.cer" 2>/dev/null && [ -s "$work/root.cer" ]; then
      install_root "$work/root.cer" "ROOT_CERTS_BASE64 #$idx"
    else
      install_failures=$((install_failures + 1))
      log "ERROR: ROOT_CERTS_BASE64 #$idx is not valid Base64"
    fi
  done
fi

# --- Key containers from files.
for dir in "$CERTS_DIR/user" "$SECRETS_DIR"; do
  [ -d "$dir" ] || continue
  find "$dir" -maxdepth 1 -type f \( -name '*.pfx' -o -name '*.p12' \) | sort >"$work/pfx-list"
  while IFS= read -r f; do
    pin=""
    if [ -e "$f.pin" ]; then
      if ! pin="$(read_secret_file "$f.pin" 2>/dev/null)"; then
        install_failures=$((install_failures + 1))
        log "ERROR: cannot read $f.pin; key container $(basename "$f") not installed"
        continue
      fi
    fi
    install_pfx "$f" "$pin" "$(basename "$f")"
  done <"$work/pfx-list"
done

# --- Legacy key containers from env (test keys only: env is readable via docker inspect).
if [ -n "${CERT_PFX_BASE64:-}" ]; then
  log "WARNING: CERT_PFX_BASE64 / CERT_PFX_PIN are for test keys only; mount real keys as files (README.md)"
  n="$(printf '%s\n' "$CERT_PFX_BASE64" | tr ',' '\n' | wc -l | tr -d ' ')"
  pins="${CERT_PFX_PIN:-}"
  idx=1
  while [ "$idx" -le "$n" ]; do
    pfx_b64="$(printf '%s\n' "$CERT_PFX_BASE64" | cut -d, -f"$idx")"
    if [ -n "$pfx_b64" ]; then
      case "$pins" in
        *,*) pin="$(printf '%s\n' "$pins" | cut -d, -f"$idx")" ;;
        *) pin="$pins" ;;
      esac
      if printf '%s' "$pfx_b64" | base64 -d >"$work/cert.pfx" 2>/dev/null && [ -s "$work/cert.pfx" ]; then
        install_pfx "$work/cert.pfx" "$pin" "CERT_PFX_BASE64 #$idx"
      else
        install_failures=$((install_failures + 1))
        log "ERROR: CERT_PFX_BASE64 #$idx is not valid Base64"
      fi
      rm -f "$work/cert.pfx"
    fi
    idx=$((idx + 1))
  done
fi

if [ "$install_failures" -gt 0 ]; then
  log "WARNING: $install_failures certificate/key install(s) failed, see above; signing with them will fail"
fi

rm -rf "$work"
trap - EXIT INT TERM
umask 022

# The server only checks that the license variables are defined; keep their values out of its env.
unset CERT_PFX_BASE64 CERT_PFX_PIN ROOT_CERTS_BASE64 CRYPTOPRO_TSP_LICENSE CRYPTOPRO_OCSP_LICENSE
unset TRUSTED_LICENSE_FILE CRYPTOPRO_LICENSE_FILE CRYPTOPRO_TSP_LICENSE_FILE CRYPTOPRO_OCSP_LICENSE_FILE API_KEYS_FILE
export TRUSTED_LICENSE="" CRYPTOPRO_LICENSE="" API_KEYS="$api_keys"
exec "$@"
