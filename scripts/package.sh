#!/usr/bin/env bash
# The agent layer as .deb and .rpm, from a release build, into dist/.
#
#   cargo build --release --locked && scripts/package.sh [deb|rpm]
#
# Needs nfpm (https://nfpm.goreleaser.com): a Go binary, one file for both formats.
# VERSION defaults to Cargo.toml's, plus ~git<rev> unless HEAD is a tag, so a
# package built from a commit sorts before the release it leads up to.
# ARCH defaults to this machine's (amd64 or arm64); AGENT_BIN to target/release/agent.
set -euo pipefail
cd "$(dirname "$0")/.."

KINDS=("${1:-deb}")
[ $# -eq 0 ] && KINDS=(deb rpm)
export AGENT_BIN="${AGENT_BIN:-target/release/agent}"
[ -x "$AGENT_BIN" ] || { echo "package: $AGENT_BIN not found; run cargo build --release --locked first" >&2; exit 1; }
command -v nfpm >/dev/null || { echo "package: nfpm not found (https://nfpm.goreleaser.com/install/)" >&2; exit 1; }

if [ -z "${VERSION:-}" ]; then
  VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
  git describe --exact-match --tags HEAD >/dev/null 2>&1 || VERSION="$VERSION~git$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
fi
case "${ARCH:-$(uname -m)}" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "package: unsupported architecture ${ARCH:-$(uname -m)}" >&2; exit 1 ;;
esac
export VERSION ARCH

mkdir -p dist/stage
install -m 0755 "$AGENT_BIN" dist/stage/agent
# The package must refuse a system whose glibc is older than the one the
# binary was built with, instead of installing something that won't start.
GLIBC_MIN="$(objdump -T "$AGENT_BIN" 2>/dev/null | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1 || true)"
if [ -z "$GLIBC_MIN" ]; then
  echo "package: couldn't read the binary's glibc requirement (objdump from binutils); assuming 2.34" >&2
  GLIBC_MIN=2.34
fi
sed "s/@GLIBC_MIN@/$GLIBC_MIN/g" packaging/nfpm.yaml > dist/nfpm.yaml
for kind in "${KINDS[@]}"; do
  nfpm package --config dist/nfpm.yaml --packager "$kind" --target dist/
done
ls -l dist/*.deb dist/*.rpm 2>/dev/null || true
