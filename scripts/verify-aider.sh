#!/usr/bin/env bash
# Runs the real Aider under agentos against a stand-in model server on this
# machine, to check examples/agents/aider-local.toml end to end: Aider starts
# in the sandbox, reaches the model server through --local (the only door it
# has), and gets an answer. Needs `agent`, `aider` (pip install aider-chat) and
# python3 on this Linux machine, as a normal user.
#
#   scripts/verify-aider.sh
#
# On a Mac: build a container with aider installed and run it with dev.sh's
# flags (see scripts/dev.sh), or run it inside `scripts/dev.sh shell` after
# `pip install --break-system-packages aider-chat`.
set -uo pipefail
for tool in agent aider python3; do command -v "$tool" >/dev/null || { echo "verify-aider: $tool isn't on your PATH" >&2; exit 2; }; done
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/agentos-aider.XXXXXX")"
export AGENTOS_HOME="$WORK/store" NO_COLOR=1 AGENTOS_CONFIG="$WORK/cfg/config.toml"
pass=0; fail=0
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then printf '  \033[32m✓\033[0m %s\n' "$name"; pass=$((pass + 1)); else printf '  \033[31m✗\033[0m %s\n' "$name"; fail=$((fail + 1)); fi; }
cleanup() { [ -n "${SERVER:-}" ] && kill "$SERVER" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
mkdir -p "$WORK/cfg/agents" "$WORK/proj"

# A stand-in for Ollama, llama.cpp or vLLM: OpenAI's chat completions, answering one thing.
cat > "$WORK/server.py" <<'PY'
import http.server, json, sys
LOG = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        open(LOG, "a").write(f"POST {self.path} stream={req.get('stream')}\n")
        if not self.path.endswith("/chat/completions"):
            return self._send(404, json.dumps({"error": "no"}))
        text = "Hello from the model on this machine."
        usage = {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19}
        if req.get("stream"):
            chunks = [{"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "m", "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None}]},
                      {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "m", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": usage}]
            return self._send(200, "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n", "text/event-stream")
        self._send(200, json.dumps({"id": "c", "object": "chat.completion", "created": 0, "model": "m", "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}], "usage": usage}))
    def do_GET(self):
        open(LOG, "a").write(f"GET {self.path}\n")
        self._send(200, json.dumps({"object": "list", "data": [{"id": "m", "object": "model"}]}))
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY
python3 "$WORK/server.py" "$WORK/requests.log" > "$WORK/port" &
SERVER=$!
for _ in $(seq 50); do [ -s "$WORK/port" ] && break; sleep 0.1; done
PORT="$(cat "$WORK/port")"

# The recipe, pointed at that server's port instead of Ollama's 11434.
sed "s/11434/$PORT/g; s#openai/llama3.2#openai/m#" "$HERE/../examples/agents/aider-local.toml" > "$WORK/cfg/agents/aider.toml"
: > "$WORK/cfg/config.toml"
cd "$WORK/proj" && git init -q -b main 2>/dev/null
echo "print('hi')" > hello.py

echo "aider $(aider --version 2>&1 | tail -1) under $(agent --version)"
out="$(timeout 180 agent do --agent aider "say hello in one sentence" 2>&1)"
code=$?
events="$(ls -td "$AGENTOS_HOME"/tasks/*/ | head -1)events.jsonl"
check "Aider runs in the sandbox and exits 0" test "$code" -eq 0
check "...and prints the model's answer" grep -q "Hello from the model on this machine" <<<"$out"
check "the model server saw its chat completion request" grep -q "POST /v1/chat/completions" "$WORK/requests.log"
check "the call went through --local, and is journaled" grep -q '"kind":"net.local".*"ok":true' "$events"
check "the only other thing Aider reached for was litellm's price list (blocked, and it carries on)" bash -c '! grep -o "\"host\":\"[^\"]*\"" "$1" | grep -v raw.githubusercontent.com | grep -q .' _ "$events"
check "its work is held for review, not applied" bash -c 'cd "$1" && agent diff | grep -q "held\|A  "' _ "$WORK/proj"
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
