#!/usr/bin/env bash
# Tests for the container hardening in the compose files of both stands (I6) and of the app (F17):
# read-only root filesystem, tmpfs for the paths the services write, CPU/memory/PID limits, env
# overrides, capability drop, no-new-privileges, images pinned by digest (also in the root
# Dockerfile). Reads the resolved config with `docker compose config` (no daemon, no containers).
# Skipped without the docker CLI or jq.
# Run: scripts/test/stand-hardening.test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$here/../.."
server_compose="$repo/docker/cryptoarm-server/docker-compose.yml"
documents_compose="$repo/docker/cryptoarm-documents/docker-compose.yml"

if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1 || ! command -v jq >/dev/null; then
  echo "skip - docker compose or jq not available"
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; failures=$((failures + 1)); }

# config <compose file> <out> [VAR=value...]: resolved config as JSON, with a clean environment
# (no .env of a developer: --env-file /dev/null) so that the defaults are tested.
config() {
  local file="$1" out="$2"
  shift 2
  env -i PATH="$PATH" HOME="$HOME" "$@" \
    docker compose --env-file /dev/null -f "$file" config --format json >"$out" 2>"$work/err" ||
    { echo "docker compose config failed for $file:"; sed 's/^/       /' "$work/err"; exit 1; }
}

# The server's env_file (.env) is required by compose; give it an empty one in a copy of the dir.
mkdir -p "$work/server"
cp "$server_compose" "$work/server/docker-compose.yml"
cp "$repo/docker/cryptoarm-server/start.sh" "$work/server/"
: >"$work/server/.env"
mkdir -p "$work/server/secrets"
config "$work/server/docker-compose.yml" "$work/server.json"
config "$documents_compose" "$work/documents.json"
# The root compose file (service app) includes the server's: render it from a copy with the same stubs.
mkdir -p "$work/root/docker"
cp "$repo/docker-compose.yml" "$work/root/"
cp -R "$work/server" "$work/root/docker/cryptoarm-server"
config "$work/root/docker-compose.yml" "$work/root.json" COMPOSE_PROFILES=app

# q <json file> <jq filter>: prints the result (raw).
q() { jq -r "$2" "$1"; }

check() { # name, command...
  local name="$1"
  shift
  if "$@"; then pass "$name"; else fail "$name"; fi
}
eq() { [ "$1" = "$2" ] || { echo "       expected '$2', got '$1'"; return 1; }; }

# tmpfs_target <json> <service> <target>: the tmpfs mount (short `tmpfs:` or long `volumes:` syntax).
has_tmpfs() {
  local json="$1" svc="$2" target="$3"
  q "$json" ".services[\"$svc\"] | ((.tmpfs // []) | map(split(\":\")[0])) + ((.volumes // []) | map(select(.type == \"tmpfs\") | .target)) | index([\"$target\"]) != null" |
    grep -qx true || { echo "       no tmpfs at $target in $svc"; return 1; }
}

# Every service of both stands: read-only rootfs and limits.
for pair in server.json:cryptoarm-server documents.json:documents-api documents.json:documents-db documents.json:ca-stub; do
  json="$work/${pair%%:*}" svc="${pair#*:}"
  check "$svc: read_only root filesystem" eq "$(q "$json" ".services[\"$svc\"].read_only")" true
  check "$svc: CPU limit set" bash -c "[ \"\$(jq -r '.services[\"$svc\"].cpus // empty' '$json')\" != '' ]"
  check "$svc: memory limit set" bash -c "[ \"\$(jq -r '.services[\"$svc\"].mem_limit // empty' '$json')\" != '' ]"
  check "$svc: PID limit set" bash -c "[ \"\$(jq -r '.services[\"$svc\"].pids_limit // empty' '$json')\" != '' ]"
done

# КриптоАРМ Server: the paths it writes (docker diff of a running stand, see README.md).
s="$work/server.json"
for t in /tmp /var/lib/cryptoarm-server "/etc/opt/Trusted" /etc/opt/cprocsp /var/cache/fontconfig; do
  check "cryptoarm-server: tmpfs $t" has_tmpfs "$s" cryptoarm-server "$t"
done
check "cryptoarm-server: CSP store stays a bind mount" \
  eq "$(q "$s" '.services["cryptoarm-server"].volumes[] | select(.target == "/var/opt/cprocsp") | .type')" bind
check "cryptoarm-server: healthcheck fails without the seeded CSP config (old image + new compose)" \
  bash -c "jq -r '.services[\"cryptoarm-server\"].healthcheck.test | join(\" \")' '$s' | grep -q 'test -s /etc/opt/cprocsp/config64.ini &&'"
check "cryptoarm-server: default limits 2 CPUs / 2 GiB / 256 PIDs" \
  eq "$(q "$s" '.services["cryptoarm-server"] | "\(.cpus) \(.mem_limit) \(.pids_limit)"')" "2 2147483648 256"
check "cryptoarm-server: the build-only service stays unrestricted (never run)" \
  eq "$(q "$s" '.services["cryptoarm-server-image"].read_only // false')" false
config "$work/server/docker-compose.yml" "$work/server-env.json" \
  CRYPTOARM_SERVER_CPUS=1.5 CRYPTOARM_SERVER_MEMORY=3g CRYPTOARM_SERVER_PIDS=128
check "cryptoarm-server: limits overridable via env" \
  eq "$(q "$work/server-env.json" '.services["cryptoarm-server"] | "\(.cpus) \(.mem_limit) \(.pids_limit)"')" "1.5 3221225472 128"

# КриптоАРМ Документы stand.
d="$work/documents.json"
check "documents-api: tmpfs /tmp" has_tmpfs "$d" documents-api /tmp
check "documents-api: logs on a volume" \
  eq "$(q "$d" '.services["documents-api"].volumes[] | select(.target == "/logs") | .type')" volume
check "documents-api: runs node directly, no pm2 (its home would need a writable layer)" \
  eq "$(q "$d" '.services["documents-api"].command | join(" ")')" "docker-entrypoint.sh node dist/main.js"
check "documents-api: uploads stay on their volume" \
  eq "$(q "$d" '.services["documents-api"].volumes[] | select(.target == "/uploads") | .type')" volume
check "documents-db: tmpfs /run/postgresql" has_tmpfs "$d" documents-db /run/postgresql
check "documents-db: tmpfs /tmp" has_tmpfs "$d" documents-db /tmp
check "ca-stub: tmpfs /var/cache/nginx" has_tmpfs "$d" ca-stub /var/cache/nginx
check "ca-stub: tmpfs /run" has_tmpfs "$d" ca-stub /run
check "documents: default limits" \
  eq "$(q "$d" '[.services["documents-api","documents-db","ca-stub"] | "\(.cpus)/\(.mem_limit)/\(.pids_limit)"] | join(" ")')" \
  "1/1073741824/256 1/536870912/128 0.25/67108864/32"
config "$documents_compose" "$work/documents-env.json" DOCUMENTS_API_CPUS=2 DOCUMENTS_API_MEMORY=2g DOCUMENTS_API_PIDS=512
check "documents-api: limits overridable via env" \
  eq "$(q "$work/documents-env.json" '.services["documents-api"] | "\(.cpus) \(.mem_limit) \(.pids_limit)"')" "2 2147483648 512"

# F17 (R2 minor 23): capability drop, no-new-privileges and a non-root user for ca-stub and
# documents-db (both images start as root only to switch users; as the image's own user they need no
# capability), and every image pinned by digest.
for svc in documents-api ca-stub documents-db; do
  check "$svc: cap_drop ALL" eq "$(q "$d" ".services[\"$svc\"].cap_drop // [] | join(\",\")")" ALL
  check "$svc: no cap_add" eq "$(q "$d" ".services[\"$svc\"].cap_add // [] | length")" 0
  check "$svc: no-new-privileges" eq "$(q "$d" ".services[\"$svc\"].security_opt // [] | index(\"no-new-privileges:true\") != null")" true
done
check "documents-db: runs as the image's postgres user (uid of the data files and the socket tmpfs)" \
  eq "$(q "$d" '.services["documents-db"].user')" 999:999
check "ca-stub: runs as the image's nginx user" eq "$(q "$d" '.services["ca-stub"].user')" 101:101
check "ca-stub: tmpfs owned by the nginx user" \
  eq "$(q "$d" '[.services["ca-stub"].tmpfs[] | select(test("uid=101,gid=101"))] | length')" 2
for svc in documents-api documents-db ca-stub; do
  check "$svc: image pinned by digest" \
    bash -c "jq -r '.services[\"$svc\"].image' '$d' | grep -Eq '^[^@]+:[^@/]+@sha256:[0-9a-f]{64}\$'"
done

# F17 (R2 minor 24): the app service and its image.
a="$work/root.json"
check "app: read_only root filesystem" eq "$(q "$a" '.services.app.read_only')" true
check "app: tmpfs /tmp" has_tmpfs "$a" app /tmp
check "app: cap_drop ALL" eq "$(q "$a" '.services.app.cap_drop // [] | join(",")')" ALL
check "app: no cap_add" eq "$(q "$a" '.services.app.cap_add // [] | length')" 0
check "app: no-new-privileges" eq "$(q "$a" '.services.app.security_opt // [] | index("no-new-privileges:true") != null')" true
check "app: refresh-token dir stays a writable volume" \
  eq "$(q "$a" '.services.app.volumes[] | select(.target == "/var/lib/app/diadoc") | "\(.type) \(.read_only // false)"')" "volume false"
dockerfile="$repo/Dockerfile"
check "Dockerfile: two stages (the FROM checks below are not vacuous)" \
  eq "$(grep -Eic '^[[:space:]]*FROM ' "$dockerfile")" 2
check "Dockerfile: every FROM of a registry image is pinned by digest" \
  bash -c "! grep -Ei '^[[:space:]]*FROM ' '$dockerfile' | grep -Eiv '^FROM [^ ]+:[^ @]+@sha256:[0-9a-f]{64}( AS [a-z0-9_-]+)?\$' | grep ."
check "Dockerfile: no unpinned syntax frontend" \
  bash -c "! grep -Ei '^# *syntax *=' '$dockerfile' | grep -v '@sha256:[0-9a-f]\\{64\\}' | grep ."

echo
if [ "$failures" -eq 0 ]; then
  echo "all stand-hardening tests passed"
else
  echo "$failures stand-hardening test(s) failed"
  exit 1
fi
