# The dev container plus Node and the Codex and Gemini CLIs, for scripts/verify-agents.sh:
#   docker build -f scripts/agents.Dockerfile -t agentos-agents scripts
#   AGENTOS_DEV_IMAGE=agentos-agents scripts/dev.sh exec "TMPDIR=/data/tmp bash /src/scripts/verify-agents.sh"
FROM agentos-dev
RUN set -eux; arch="$(dpkg --print-architecture)"; case "$arch" in arm64) n=arm64;; amd64) n=x64;; esac; \
    curl -fsSL "https://nodejs.org/dist/v22.12.0/node-v22.12.0-linux-$n.tar.gz" | tar -xz -C /usr/local --strip-components=1; \
    npm install -g @openai/codex @google/gemini-cli
