#!/usr/bin/env bash
# Downloads the upstream КриптоАРМ Server test certificates (CRYPTO-PRO test CA)
# into docker/cryptoarm-server/certs and checks their SHA-256:
#   certs/cryptoarm.server.test.cer   public cert, sent by clients as `cert`
#   certs/root/crypto.root.test.cer   installed into mroot at container start
#   certs/user/cryptoarm.server.test.pfx  key container (no PIN), installed into uMy
# The files are git-ignored: they are test material, but keys are never committed.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
certs="$repo_root/docker/cryptoarm-server/certs"
ref="af98d55e1974b87275b7fef97a20a6c32fb6f63b"
api="https://git.digtlab.ru/api/v4/projects/trusted%2Fcryptoarm%2Fserver/repository/files"

# Download outside the repo so a failed run never leaves an un-ignored key file behind.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

fetch() { # upstream file name, destination, expected sha256
  local name="$1" dest="$2" want="$3" got
  mkdir -p "$(dirname "$dest")"
  curl -fsSL -o "$tmp/$name" "$api/certs%2F$name/raw?ref=$ref"
  got="$(sha256 "$tmp/$name")"
  if [ "$got" != "$want" ]; then
    echo "checksum mismatch for $name: got $got, want $want" >&2
    exit 1
  fi
  mv "$tmp/$name" "$dest"
  echo "fetched $name -> ${dest#"$repo_root"/}"
}

fetch cryptoarm.server.test.cer "$certs/cryptoarm.server.test.cer" \
  e86e76e9448c87cc409bb09562367db8e41709499ced623a1e3dda1f694ccc54
fetch crypto.root.test.cer "$certs/root/crypto.root.test.cer" \
  e86e76e9448c87cc409bb09562367db8e41709499ced623a1e3dda1f694ccc54
fetch cryptoarm.server.test.pfx "$certs/user/cryptoarm.server.test.pfx" \
  940667a7a2ea91c0f3aa4e50cc91c3969c0ba83b500f76e02666e02ecc59ba64
