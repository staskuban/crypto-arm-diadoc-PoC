#!/bin/sh
# Upstream /trusted/scripts/setup_license exits 1 on an empty value, which aborts the
# CMD chain before CSP setup and key install. This wrapper warns instead; the server
# itself still refuses to start without a valid license.
# Usage: setup-trusted-license-optional.sh "$TRUSTED_LICENSE"

setup_bin="${TRUSTED_SETUP_LICENSE_BIN:-/trusted/scripts/setup_license}"

if [ -z "${1:-}" ]; then
  echo "WARNING: TRUSTED_LICENSE is empty; skipping КриптоАРМ Server license setup. The server will refuse to start (\"Trusted Crypto license is invalid\")." >&2
  exit 0
fi

exec "$setup_bin" "$1"
