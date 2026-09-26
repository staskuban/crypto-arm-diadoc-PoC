#!/bin/sh
# Entrypoint wrapper of the КриптоАРМ Документы API container (see README.md).
# The upstream image reads its settings only from env; this wrapper moves the secrets from files
# (mounted read-only at $SECRETS_DIR) into the environment of the API process, so they are not part
# of the container config (`docker inspect`). Then it execs the upstream entrypoint + command ("$@").
#
#   $SECRETS_DIR/license_value           -> LICENSE_VALUE (Документы key, REQUIRED)
#   $SECRETS_DIR/sign_service_api_key    -> SIGN_SERVICE_API_KEY (X-API-Key for КриптоАРМ Server)
#   $SECRETS_DIR/admin_password          -> ADMIN_PASSWORD (first local admin, created once)
#   $SECRETS_DIR/session_secret          -> SESSION_SECRET
#   $SECRETS_DIR/secret                  -> SECRET
#   $SECRETS_DIR/mail_link_token_secret  -> MAIL_LINK_TOKEN_SECRET (signs /api/auth/jwt tokens:
#                                           whoever knows it can act as ANY email, see README.md)
#   $SECRETS_DIR/api_key                 -> API_KEY
#   $SECRETS_DIR/postgres_password       -> DB_URI=postgres://$POSTGRES_USER:<pw>@$POSTGRES_HOST:5432/$POSTGRES_DB
#
# A missing required file stops the start; the optional ones are skipped (the image defaults apply,
# which are insecure — scripts/documents-secrets.sh generates all of them).
set -eu

SECRETS_DIR="${SECRETS_DIR:-/run/secrets}"

log() { echo "documents-start: $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# read_secret <file>: content without CR and trailing newlines.
read_secret() {
  content="$(tr -d '\r' <"$1")" || return 1
  printf '%s' "$content"
}

# load <VAR> <file> [required]
load() {
  var="$1" file="$SECRETS_DIR/$2"
  if [ -f "$file" ]; then
    value="$(read_secret "$file")" || die "cannot read $file"
    [ -n "$value" ] || die "$file is empty"
    export "$var=$value"
  elif [ "${3:-}" = required ]; then
    die "$file is missing (run scripts/documents-secrets.sh)"
  else
    log "WARNING: $file is missing; $var keeps its image default"
  fi
}

load LICENSE_VALUE license_value required
load SIGN_SERVICE_API_KEY sign_service_api_key
load ADMIN_PASSWORD admin_password required
load SESSION_SECRET session_secret required
load SECRET secret required
load MAIL_LINK_TOKEN_SECRET mail_link_token_secret required
load API_KEY api_key
load POSTGRES_PASSWORD postgres_password required

# URL-encode the password for DB_URI (generated passwords are hex, but keep it safe for any value).
pw_enc="$(node -e 'process.stdout.write(encodeURIComponent(process.env.POSTGRES_PASSWORD))')"
export DB_URI="postgres://${POSTGRES_USER}:${pw_enc}@${POSTGRES_HOST}:5432/${POSTGRES_DB}"
unset POSTGRES_PASSWORD pw_enc value

exec "$@"
