#!/usr/bin/env bash
# Runs the real Codex CLI and Gemini CLI under agentos with a made-up key, to
# check examples/agents/codex.toml and gemini.toml end to end. No account is
# needed: each provider answers a key it doesn't know with an error, and that
# error is the proof. The agent holds only a placeholder, so the made-up key
# the provider complains about arrived on the wire, added by agentos; and the
# journal shows the agent reached its provider and nothing else.
#
# Needs `agent`, `codex` and/or `gemini` (npm i -g @openai/codex @google/gemini-cli,
# Node 22) and internet, on this Linux machine, as a normal user. An agent that
# isn't installed is skipped. On a Mac: see scripts/agents.Dockerfile (the work
# folder has to be on a volume, not the container's own filesystem: TMPDIR=/data/tmp).
#
#   scripts/verify-agents.sh
set -uo pipefail
command -v agent >/dev/null || { echo "verify-agents: agent isn't on your PATH" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/agentos-agents.XXXXXX")"
export AGENTOS_HOME="$WORK/store" NO_COLOR=1 AGENTOS_CONFIG="$WORK/cfg/config.toml"
pass=0; fail=0; ran=0
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then printf '  \033[32m✓\033[0m %s\n' "$name"; pass=$((pass + 1)); else printf '  \033[31m✗\033[0m %s\n' "$name"; fail=$((fail + 1)); fi; }
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/cfg/agents" "$WORK/proj"
: > "$WORK/cfg/config.toml"
cp "$HERE"/../examples/agents/codex.toml "$HERE"/../examples/agents/gemini.toml "$WORK/cfg/agents/"
cd "$WORK/proj" && git init -q -b main 2>/dev/null

if command -v codex >/dev/null; then
  ran=$((ran + 1))
  echo "Codex $(codex --version 2>/dev/null)"
  out="$(CODEX_API_KEY=sk-fake-0123456789abcdef timeout 180 agent do --agent codex "say hi" 2>&1 </dev/null)"
  log="$(agent log 2>&1)"
  check "it starts in the sandbox and reaches OpenAI" grep -q 'api.openai.com:443' <<<"$log"
  check "the made-up key arrived (OpenAI complains about it by name): agentos added it on the wire" grep -q 'Incorrect API key provided: sk-fake-' <<<"$out"
  check "...the journal says a credential was added" grep -q 'credential added' <<<"$log"
  check "it reached nothing else (what it reached for stays closed, and is explained)" bash -c '! grep -E "net.connect +✓" <<<"$1" | grep -v "api.openai.com"' _ "$log"
  check "no WebSocket attempt (agentos can't carry one for a host it holds the key for)" bash -c '! grep -qi "websocket" <<<"$1"' _ "$out"
  check "the made-up key is not in the journal" bash -c '! grep -rq "sk-fake-0123456789abcdef" "$1/tasks"' _ "$AGENTOS_HOME"
else
  echo "Codex: skipped (npm i -g @openai/codex)"
fi

if command -v gemini >/dev/null; then
  ran=$((ran + 1))
  echo "Gemini CLI $(gemini --version 2>/dev/null)"
  out="$(GEMINI_API_KEY=AIza-fake-0123456789abcdef timeout 180 agent do --agent gemini "say hi" 2>&1 </dev/null)"
  log="$(agent log 2>&1)"
  check "it starts in the sandbox and reaches Google's API" grep -q 'generativelanguage.googleapis.com:443' <<<"$log"
  check "Google answers the made-up key it was sent (agentos added it on the wire)" grep -q 'API key not valid' <<<"$out"
  check "...the journal says a credential was added" grep -q 'credential added' <<<"$log"
  check "it reached nothing else" bash -c '! grep -E "net.connect +✓" <<<"$1" | grep -v "generativelanguage.googleapis.com"' _ "$log"
  check "the made-up key is not in the journal" bash -c '! grep -rq "AIza-fake-0123456789abcdef" "$1/tasks"' _ "$AGENTOS_HOME"
else
  echo "Gemini CLI: skipped (npm i -g @google/gemini-cli)"
fi

echo
echo "$pass passed, $fail failed"
[ "$ran" -gt 0 ] && [ "$fail" -eq 0 ]
