#!/usr/bin/env bash
# Downloads the КриптоАРМ Server test certificates into docker/cryptoarm-server/certs
# and checks their SHA-256:
#   certs/cryptoarm.server.test.cer        upstream public cert, sent by clients as `cert`
#   certs/user/cryptoarm.server.test.pfx   upstream key container (no PIN), installed into uMy
#   certs/root/cryptopro-test-ca-2012-21.cer  self-signed root of its issuer, «Тестовый УЦ
#       ООО "КРИПТО-ПРО"», from the cert's AIA URL; installed into mroot. Upstream's
#       certs/crypto.root.test.cer is a copy of the leaf cert, so it is not used.
# The files are git-ignored: they are test material, but keys are never committed.
set -euo pipefail
# Owner-only by default (the .pfx is a PIN-less private key); public certificates get 0644 below.
umask 077

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

fetch() { # url, destination, expected sha256, mode
  local url="$1" dest="$2" want="$3" mode="$4" got name
  name="$(basename "$dest")"
  mkdir -p "$(dirname "$dest")"
  curl -fsSL -o "$tmp/$name" "$url"
  got="$(sha256 "$tmp/$name")"
  if [ "$got" != "$want" ]; then
    echo "checksum mismatch for $name: got $got, want $want" >&2
    exit 1
  fi
  chmod "$mode" "$tmp/$name"
  mv "$tmp/$name" "$dest"
  echo "fetched $name -> ${dest#"$repo_root"/}"
}

fetch "$api/certs%2Fcryptoarm.server.test.cer/raw?ref=$ref" "$certs/cryptoarm.server.test.cer" \
  e86e76e9448c87cc409bb09562367db8e41709499ced623a1e3dda1f694ccc54 0644
fetch "http://testgost2012.cryptopro.ru/CertEnroll/testgost2012(21).crt" \
  "$certs/root/cryptopro-test-ca-2012-21.cer" \
  6664740262766f0428379bb6ff2340c2d8497ce1862cd4e04f6353c2e978fb03 0644
fetch "$api/certs%2Fcryptoarm.server.test.pfx/raw?ref=$ref" "$certs/user/cryptoarm.server.test.pfx" \
  940667a7a2ea91c0f3aa4e50cc91c3969c0ba83b500f76e02666e02ecc59ba64 0600
