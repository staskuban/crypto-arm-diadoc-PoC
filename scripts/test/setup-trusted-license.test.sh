#!/usr/bin/env bash
# Tests for docker/cryptoarm-server/setup-trusted-license-optional.sh.
# Run: scripts/test/setup-trusted-license.test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
wrapper="$here/../../docker/cryptoarm-server/setup-trusted-license-optional.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Fake upstream /trusted/scripts/setup_license: records its argument, exits with $FAKE_EXIT.
cat >"$work/fake_setup" <<EOF
#!/bin/sh
printf '%s' "\$1" > "$work/called_with"
exit \${FAKE_EXIT:-0}
EOF
chmod +x "$work/fake_setup"

failures=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; failures=$((failures + 1)); }

run() { TRUSTED_SETUP_LICENSE_BIN="$work/fake_setup" sh "$wrapper" "$@" 2>"$work/stderr"; }

# Empty license: skip upstream script, warn, succeed.
rm -f "$work/called_with"
if run ""; then pass "empty license exits 0"; else fail "empty license exits non-zero"; fi
if [ ! -f "$work/called_with" ]; then pass "empty license skips upstream setup"; else fail "upstream setup was called"; fi
if grep -q "TRUSTED_LICENSE is empty" "$work/stderr"; then pass "empty license logs a warning"; else fail "no warning on stderr"; fi

# No argument at all behaves like empty.
if run; then pass "missing argument exits 0"; else fail "missing argument exits non-zero"; fi

# Non-empty license: delegate to upstream and propagate its exit code.
rm -f "$work/called_with"
if run "AAAA-BBBB"; then pass "license is applied"; else fail "license apply failed"; fi
if [ "$(cat "$work/called_with" 2>/dev/null)" = "AAAA-BBBB" ]; then
  pass "upstream setup receives the license"
else
  fail "upstream setup got: $(cat "$work/called_with" 2>/dev/null)"
fi
if FAKE_EXIT=3 run "AAAA-BBBB"; then fail "upstream failure was swallowed"; else pass "upstream failure propagates"; fi

if [ "$failures" -gt 0 ]; then
  echo "$failures test(s) failed"
  exit 1
fi
echo "all setup-trusted-license tests passed"
