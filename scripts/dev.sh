#!/usr/bin/env bash
# Linux dev environment for non-Linux hosts (macOS, Windows).
#
#   scripts/dev.sh shell        shell as the unprivileged `dev` user, `agent` on PATH
#   scripts/dev.sh exec CMD...  run CMD as `dev` in the same environment
#   scripts/dev.sh test         build, run unit tests (root) and e2e tests (as `dev`)
#   scripts/dev.sh build        just build
#
# --privileged only lets the *container* create nested user namespaces and
# mount a fresh /proc; agentos itself runs fully unprivileged. On a real Linux
# machine skip all of this: `cargo build --release && target/release/agent doctor`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${AGENTOS_DEV_IMAGE:-rust:1.94-bookworm}"
CMD="${1:-shell}"
[ $# -gt 0 ] && shift

TTY=()
# `su -c` starts a new session with no terminal, so nothing could ask you a
# question (agentos's approvals open /dev/tty); --pty gives the dev user one.
SU_PTY=""
[ -t 0 ] && [ -t 1 ] && TTY=(-it) && SU_PTY="--pty"

# Say which checkout gets built: every checkout shares the same build cache,
# so running an old copy's dev.sh silently installs the old code.
REV="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo "no git")"
DIRTY="$(git -C "$ROOT" status --porcelain 2>/dev/null | grep -q . && echo " + uncommitted changes" || true)"
echo "agentos: building $REV$DIRTY from $ROOT" >&2

# /home/dev and /data are named volumes (ext4 inside the Docker VM) because
# overlayfs can't use the container's own overlay root as an upper dir. As a
# bonus, your home, tasks and projects survive between shells.
SETUP='set -e
id dev >/dev/null 2>&1 || useradd -M -d /home/dev -u 1000 -s /bin/bash dev
chown dev:dev /home/dev
cargo build --release --quiet
install -m 0755 /target/release/agent /usr/local/bin/agent
mkdir -p /data/tmp && chown dev:dev /data /data/tmp
[ -f /home/dev/.profile ] || { echo '"'"'export PATH="$HOME/.local/bin:$PATH"'"'"' > /home/dev/.profile; chown dev:dev /home/dev/.profile; }'

# Real Claude Code for `agent do`, installed once into the persistent home
# with the official installer. Tests never use it (they use tests/fake-claude).
CLAUDE='[ -x /home/dev/.local/bin/claude ] || { echo "installing Claude Code for the dev user (one time)..."; su - dev -c "curl -fsSL https://claude.ai/install.sh | bash" >/dev/null; }'

run() {
  docker run --rm ${TTY[@]+"${TTY[@]}"} --privileged \
    -v "$ROOT":/src \
    -v agentos-cargo:/usr/local/cargo/registry \
    -v agentos-target:/target \
    -v agentos-home:/home/dev \
    -v agentos-data:/data \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_TERM_COLOR=always \
    -w /src "$IMAGE" bash -c "$1"
}

case "$CMD" in
  build) run "cargo build --release" ;;
  test) run "$SETUP
TMPDIR=/data/tmp cargo test --release --quiet
su - dev -c 'E2E_DIR=/data/tmp bash /src/tests/e2e.sh'" ;;
  shell) run "$SETUP
$CLAUDE
echo 'agent is on PATH. Try: mkdir -p ~/app && cd ~/app && agent do \"say hello\"'
exec su - dev" ;;
  exec) run "$SETUP
$CLAUDE
su - dev $SU_PTY -c $(printf '%q' "$*")" ;;
  *) echo "usage: $0 [shell|exec CMD...|test|build]" >&2; exit 2 ;;
esac
