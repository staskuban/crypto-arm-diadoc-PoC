#!/usr/bin/env bash
# Tests for the rollout guard of the КриптоАРМ Server stand (F10, R2 M1 / D40):
# - the compose file is bound to the image built for it: its own default tag (not the old shared
#   `…:local`), never pulled, the same tag for the build-only service. So an `up` on a host that has
#   only the old image fails with "No such image" instead of recreating the server from an image that
#   cannot run under this file;
# - every documented `docker compose run … app` command passes `--no-deps`, so it never recreates the
#   shared server as a dependency.
# The compose part reads the resolved config with `docker compose config` (no daemon, no containers) and
# is skipped without the docker CLI or jq; the docs part needs only grep.
# Run: scripts/test/stand-rollout.test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$here/../.."

# The default image tag of the server compose file. Change it together with the image contract (what
# start.sh must do for this file, e.g. seed the I6 tmpfs) and the rollout in the stand README.
expected_image=kryptoarm-diadoc/cryptoarm-server:i6

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; failures=$((failures + 1)); }
check() { # name, command...
  local name="$1"
  shift
  if "$@"; then pass "$name"; else fail "$name"; fi
}
eq() { [ "$1" = "$2" ] || { echo "       expected '$2', got '$1'"; return 1; }; }

# --- Documented commands --------------------------------------------------------------------------
# no_deps_everywhere <file>: every `docker compose [-p x] [-f y] run` line names --no-deps.
no_deps_everywhere() {
  local file="$1" bad
  bad="$(grep -nE 'docker compose( +-[pf] +[^ ]+)* +run ' "$file" | grep -v -- '--no-deps' || true)"
  [ -z "$bad" ] || { echo "$bad" | sed 's/^/       /'; return 1; }
}
for f in Dockerfile .env.example docker-compose.yml CLAUDE.md; do
  check "$f: every 'docker compose run' passes --no-deps" no_deps_everywhere "$repo/$f"
done
printf '%s\n' '# docker compose -p x run --rm app send x.xml' >"$work/bad"
check "the no-deps check catches a command without it" eval '! no_deps_everywhere "$work/bad" >/dev/null'
check "CLAUDE.md: no healthy-wait promised for run --no-deps (it skips depends_on)" \
  bash -c "! grep -n -- '--no-deps app send' '$repo/CLAUDE.md' | grep -q 'waits for \`cryptoarm-server\` healthy'"

# --- Compose: image binding -----------------------------------------------------------------------
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1 || ! command -v jq >/dev/null; then
  echo "skip - compose checks: docker compose or jq not available"
else
  # The server's env_file (.env) and ./secrets are required by compose; use empty ones in a copy.
  mkdir -p "$work/server/secrets"
  cp "$repo/docker/cryptoarm-server/docker-compose.yml" "$work/server/"
  : >"$work/server/.env"
  config() { # out [VAR=value...]: resolved config as JSON with a clean environment
    local out="$1"
    shift
    env -i PATH="$PATH" HOME="$HOME" "$@" docker compose --env-file /dev/null \
      -f "$work/server/docker-compose.yml" --profile build config --format json >"$out" 2>"$work/err" ||
      { echo "docker compose config failed:"; sed 's/^/       /' "$work/err"; exit 1; }
  }
  config "$work/default.json"
  s="$work/default.json"
  q() { jq -r "$2" "$1"; }

  check "cryptoarm-server: default image is $expected_image" \
    eq "$(q "$s" '.services["cryptoarm-server"].image')" "$expected_image"
  check "cryptoarm-server: default image is not the old shared …:local (D40)" \
    bash -c "[ \"\$(jq -r '.services[\"cryptoarm-server\"].image' '$s')\" != kryptoarm-diadoc/cryptoarm-server:local ]"
  check "cryptoarm-server: never pulled (a missing image fails instead)" \
    eq "$(q "$s" '.services["cryptoarm-server"].pull_policy')" never
  check "cryptoarm-server: no build section (D8)" \
    eq "$(q "$s" '.services["cryptoarm-server"].build // "none"')" none
  check "cryptoarm-server-image: builds the same default tag" \
    eq "$(q "$s" '.services["cryptoarm-server-image"].image')" "$expected_image"
  config "$work/override.json" CRYPTOARM_SERVER_IMAGE=kryptoarm-diadoc/cryptoarm-server:throwaway
  check "CRYPTOARM_SERVER_IMAGE overrides both services (throwaway stands)" \
    eq "$(q "$work/override.json" '[.services["cryptoarm-server","cryptoarm-server-image"].image] | join(" ")')" \
    "kryptoarm-diadoc/cryptoarm-server:throwaway kryptoarm-diadoc/cryptoarm-server:throwaway"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "all stand-rollout tests passed"
else
  echo "$failures stand-rollout test(s) failed"
  exit 1
fi
