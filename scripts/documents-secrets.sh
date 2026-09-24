#!/usr/bin/env bash
# Fills docker/cryptoarm-documents/secrets (git-ignored) for the КриптоАРМ Документы stand:
#   license_value          copied from DOCUMENTS_LICENSE_FILE (the Документы LICENSE_VALUE key)
#   sign_service_api_key   first key of SIGN_SERVICE_API_KEYS_FILE (the КриптоАРМ Server api_keys file:
#                          one key per line or comma-separated). REQUIRED — the shared server stand runs
#                          from another worktree, so pass that worktree's file; SIGN_SERVICE_API_KEY_OPTIONAL=1
#                          skips it for a server with AUTH_MODE=none
#   admin_password session_secret secret mail_link_token_secret api_key postgres_password
#                          random (openssl rand -hex 32)
# Existing files are kept (so the DB password and the admin password stay valid for an existing
# volume); FORCE=1 rewrites the copied ones (licence, API key), never the generated ones.
# Nothing is printed except file names.
#
# Env:
#   DOCUMENTS_LICENSE_FILE     default docker/cryptoarm-server/secrets/documents_license_value
#   SIGN_SERVICE_API_KEYS_FILE default docker/cryptoarm-server/secrets/api_keys (of THIS worktree)
#   DOCUMENTS_SECRETS_DIR      default docker/cryptoarm-documents/secrets
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
license_file="${DOCUMENTS_LICENSE_FILE:-$repo_root/docker/cryptoarm-server/secrets/documents_license_value}"
api_keys_file="${SIGN_SERVICE_API_KEYS_FILE:-$repo_root/docker/cryptoarm-server/secrets/api_keys}"
secrets_dir="${DOCUMENTS_SECRETS_DIR:-$repo_root/docker/cryptoarm-documents/secrets}"

die() { echo "documents-secrets: ERROR: $*" >&2; exit 1; }
log() { echo "documents-secrets: $*" >&2; }

command -v openssl >/dev/null || die "'openssl' is required"
[ -d "$secrets_dir" ] || die "secrets dir not found: $secrets_dir"
umask 077

# put <name> <value>: writes atomically with mode 0600.
put() {
  local tmp
  tmp="$(mktemp "$secrets_dir/.$1.XXXXXX")"
  printf '%s' "$2" >"$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$secrets_dir/$1"
  log "wrote $1"
}

# copied <name> <value>: kept unless FORCE=1.
copied() {
  if [ -s "$secrets_dir/$1" ] && [ "${FORCE:-}" != 1 ]; then
    log "kept $1"
  else
    put "$1" "$2"
  fi
}

[ -f "$license_file" ] || die "Документы licence file not found: $license_file"
license="$(tr -d '\r\n' <"$license_file")"
[ -n "$license" ] || die "Документы licence file is empty: $license_file"
copied license_value "$license"

if [ -f "$api_keys_file" ]; then
  api_key="$(tr -d '\r' <"$api_keys_file" | sed -n '/[^[:space:]]/{p;q;}' | cut -d, -f1 | tr -d '[:space:]')"
  [ -n "$api_key" ] || die "no API key in $api_keys_file"
  copied sign_service_api_key "$api_key"
elif [ "${SIGN_SERVICE_API_KEY_OPTIONAL:-}" = 1 ]; then
  log "no $api_keys_file: sign_service_api_key not written (SIGN_SERVICE_API_KEY_OPTIONAL=1, AUTH_MODE=none)"
else
  die "КриптоАРМ Server API keys file not found: $api_keys_file (set SIGN_SERVICE_API_KEYS_FILE to the api_keys of the running stand, or SIGN_SERVICE_API_KEY_OPTIONAL=1)"
fi

for name in admin_password session_secret secret mail_link_token_secret api_key postgres_password; do
  if [ -s "$secrets_dir/$name" ]; then
    log "kept $name"
  else
    put "$name" "$(openssl rand -hex 32)"
  fi
done
