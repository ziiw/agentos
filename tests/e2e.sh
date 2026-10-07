#!/usr/bin/env bash
# End-to-end tests for the agent runtime. Needs Linux with unprivileged user
# namespaces and must run as a normal user; on macOS use `scripts/dev.sh test`.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
AGENT="${AGENT:-agent}"
WORK="$(mktemp -d "${E2E_DIR:-/tmp}/agentos-e2e.XXXXXX")"
export AGENTOS_HOME="$WORK/store"
export NO_COLOR=1
PROJ="$WORK/proj"
pass=0
fail=0
skipped=0

ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  \033[31m✗\033[0m %s\n' "$1"; fail=$((fail + 1)); }
# check NAME CMD...: pass if CMD succeeds
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
section() { printf '\n\033[1m%s\033[0m\n' "$1"; }
skip() { printf '  \033[33m-\033[0m skipped: %s\n' "$1"; skipped=$((skipped + 1)); }
# Starts agentd and waits for *its* agentd.json (a previous one's may still
# be there): sets SERVE_PID, TOKEN and CONSOLE. Extra arguments: environment
# for agentd, e.g. AGENTOS_CONFIG=….
start_agentd() {
  rm -f "$AGENTOS_HOME/agentd.json"
  PORT=$((20000 + RANDOM % 10000))
  env "$@" "$AGENT" serve --listen "127.0.0.1:$PORT" >"$WORK/serve.$PORT.log" 2>&1 &
  SERVE_PID=$!
  for _ in $(seq 100); do grep -q "\"pid\": *$SERVE_PID," "$AGENTOS_HOME/agentd.json" 2>/dev/null && break; sleep 0.1; done
  TOKEN="$(sed -n 's/.*"token": *"\([0-9a-f]*\)".*/\1/p' "$AGENTOS_HOME/agentd.json")"
  CONSOLE="http://127.0.0.1:$PORT"
  SERVE_LOG="$WORK/serve.$PORT.log"
}

# Folders an agent asks for mid-task live under $HOME: with Landlock,
# that's where write access can still be added once a task runs.
ASKED="$HOME/.agentos-e2e-asked.$$"
cleanup() { chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK" "$HOME/.e2e-secret" "$ASKED"; }
trap cleanup EXIT

reset_proj() {
  rm -rf "$PROJ"
  mkdir -p "$PROJ/src" "$PROJ/old"
  printf 'fn main() {}\n' > "$PROJ/src/main.rs"
  echo keep > "$PROJ/old/a"
  echo line1 > "$PROJ/notes.txt"
}

latest_task_dir() { ls -td "$AGENTOS_HOME"/tasks/*/ | head -1; }

section "doctor"
check "agent doctor passes" "$AGENT" doctor
"$AGENT" doctor | sed 's/^/    /'

if [ "${REQUIRE_LANDLOCK:-}" = 1 ]; then
  section "landlock (required on this machine)"
  check "doctor finds Landlock" grep -Eq 'landlock +ABI v[0-9]' <<<"$("$AGENT" doctor)"
  "$AGENT" run --no-cwd -- true 2>/dev/null
  # "partially" = the kernel predates some access rights we ask for (e.g. ioctl, ABI v5)
  check "sandboxes run with Landlock enforced" grep -Eq '"landlock":"(partially )?enforced' "$(latest_task_dir)/events.jsonl"
fi

section "an agent works on a copy, not your files"
reset_proj
echo "top secret" > "$HOME/.e2e-secret"
cd "$PROJ"
"$AGENT" run --rw "$PROJ" -- sh -c '
  echo new > src/new.rs
  echo line2 >> notes.txt
  rm -r old
  test ! -e "$HOME/.e2e-secret"' 2>/dev/null
check "agent ran and could not see ungranted files in \$HOME" test $? -eq 0
check "real notes.txt untouched" test "$(cat notes.txt)" = line1
check "real old/ still there" test -f old/a
check "no src/new.rs in real tree" test ! -e src/new.rs

section "diff shows exactly what the agent did"
out="$("$AGENT" diff)"
check "added src/new.rs" grep -Eq '^  A  .*src/new.rs' <<<"$out"
check "modified notes.txt" grep -Eq '^  M  .*notes.txt +\+1 -0' <<<"$out"
check "deleted old/" grep -Eq '^  D  .*old/ +1 file' <<<"$out"
check "unified diff of notes.txt" grep -q '^+line2' <<<"$out"

section "partial commit, then rollback of the rest"
"$AGENT" commit last notes.txt >/dev/null
check "notes.txt committed" test "$(tail -1 notes.txt)" = line2
check "other changes still pending" grep -q 'src/new.rs' <<<"$("$AGENT" diff --stat)"
check "committed file no longer pending" bash -c "! '$AGENT' diff --stat | grep -Eq '^  [AMD]  .*notes.txt'"
"$AGENT" rollback >/dev/null
check "rolled back: old/ still exists" test -f old/a
check "rolled back: src/new.rs never appeared" test ! -e src/new.rs
check "task marked committed (partially)" grep -Eq 'committed' <<<"$("$AGENT" ls | sed -n 2p)"

section "replaced directories (rm -rf dir && mkdir dir)"
reset_proj
cd "$PROJ"
"$AGENT" run --rw "$PROJ" -- sh -c 'rm -rf src && mkdir src && echo x > src/other.rs' 2>/dev/null
out="$("$AGENT" diff --stat)"
check "old file shows as deleted" grep -Eq '^  D  .*src/main.rs' <<<"$out"
check "new file shows as added" grep -Eq '^  A  .*src/other.rs' <<<"$out"
"$AGENT" commit >/dev/null
check "commit applied the replacement" test "$(ls src)" = other.rs
check "nothing pending" grep -q 'no pending changes' <<<"$("$AGENT" diff)"

section "conflicts with edits made on the host meanwhile"
reset_proj
cd "$PROJ"
"$AGENT" run --rw "$PROJ" -- sh -c 'echo agent >> notes.txt' 2>/dev/null
sleep 0.05
echo host >> notes.txt
"$AGENT" commit >/dev/null 2>&1
check "commit refused" test $? -eq 1
check "host edit preserved" test "$(tail -1 notes.txt)" = host
"$AGENT" commit --force >/dev/null
check "--force overrides" test "$(tail -1 notes.txt)" = agent

section "isolation"
reset_proj
cd "$PROJ"
"$AGENT" run --ro "$PROJ" -- sh -c "echo x > '$PROJ/notes.txt'" 2>/dev/null
check "read-only grant cannot be written" test $? -ne 0
check "agent is not pid 1 but sees few processes" "$AGENT" run -- sh -c 'test $$ -eq 2'
# Routes out, whatever the interfaces are called (eth0, enp0s2, …); some
# kernels also put inert tunnel devices in every network namespace.
check "no network by default (no route out)" "$AGENT" run -- sh -c 'test "$(wc -l < /proc/net/route)" -le 1'
check "--net host shares the network" "$AGENT" run --net host -- sh -c 'test "$(wc -l < /proc/net/route)" -gt 1'
check "own hostname" "$AGENT" run -- sh -c 'case "$(cat /proc/sys/kernel/hostname)" in agent-*) ;; *) exit 1;; esac'
check "--hide masks a granted subpath" "$AGENT" run --ro "$PROJ" --hide "$PROJ/old" -- sh -c "test ! -e '$PROJ/old/a'"
check "store invisible through a read-only grant" "$AGENT" run --ro "$WORK" -- sh -c "test ! -e '$AGENTOS_HOME/tasks'"
"$AGENT" run --rw "$WORK" -- true >/dev/null 2>&1
check "store refused as a writable grant" test $? -eq 2
check "/usr is read-only" "$AGENT" run -- sh -c '! touch /usr/agentos-probe'

section "syscall filter (seccomp)"
check "seccomp is enforced" bash -c "'$AGENT' run -- true 2>/dev/null; grep -q '\"seccomp\":\"enforced\"' \"\$(ls -td '$AGENTOS_HOME'/tasks/*/ | head -1)events.jsonl\""
check "no new namespaces from inside (nested sandbox escape)" "$AGENT" run -- sh -c '! unshare -U true 2>/dev/null'
if command -v python3 >/dev/null && command -v script >/dev/null; then
  cat > "$PROJ/tiocsti.py" <<'PY'
import errno, fcntl, termios
try:
    fcntl.ioctl(0, termios.TIOCSTI, b"x")
    print("TIOCSTI allowed")
except OSError as e:
    print("TIOCSTI", errno.errorcode[e.errno])
PY
  out="$(script -qec "$AGENT run -- python3 tiocsti.py" /dev/null 2>&1)"
  check "can't type into your terminal (TIOCSTI)" grep -q 'TIOCSTI EPERM' <<<"$out"
  check "threads, fork and exec still work" "$AGENT" run -- python3 -c '
import subprocess, threading
t = threading.Thread(target=lambda: None); t.start(); t.join()
subprocess.run(["sh", "-c", "true"], check=True)'
  rm -f "$PROJ/tiocsti.py"
else
  skip "TIOCSTI and thread checks need python3 and script(1)"
fi

section "secrets stay out"
export SECRET_TOKEN=s3cr3t-value
check "env is scrubbed by default" "$AGENT" run -- sh -c 'test -z "${SECRET_TOKEN:-}"'
# (compare by length: the command line itself is journaled, so it must not contain the value)
check "--env passes it explicitly" "$AGENT" run -e SECRET_TOKEN -- sh -c 'test "${#SECRET_TOKEN}" -eq 12'
check "value never written to the journal" bash -c "! grep -rq s3cr3t-value '$AGENTOS_HOME'"
unset SECRET_TOKEN

section "network allowlist (egress proxy)"
reset_proj
cd "$PROJ"
API=https://api.anthropic.com/v1/messages
out="$("$AGENT" run --allow api.anthropic.com -- curl -sS -m 20 -o /dev/null -w 'HTTP %{http_code}' "$API" 2>&1)"
check "an allowed host is reachable through the proxy" grep -q 'HTTP 405' <<<"$out"
events="$(latest_task_dir)/events.jsonl"
check "the connection is journaled with byte counts" grep -Eq '"kind":"net.connect".*"allowed":true,"bytes_in":[1-9]' "$events"
check "banner shows the allowlist" grep -q 'net api.anthropic.com' <<<"$out"
out="$("$AGENT" run --allow api.anthropic.com -- curl -sS -m 20 https://example.com 2>&1)"
check "other hosts are refused" test $? -ne 0
check "the refusal is shown live, with the fix" grep -q 'blocked example.com:443: not in the allowlist (allow it with --allow example.com)' <<<"$out"
check "the refusal is journaled" grep -q '"kind":"net.connect".*"allowed":false.*"host":"example.com"' "$(latest_task_dir)/events.jsonl"
check "the summary counts blocked connections" grep -q '1 connection blocked' <<<"$out"
check "bypassing the proxy: no DNS" bash -c "! '$AGENT' run --allow api.anthropic.com -- curl -sS -m 5 --noproxy '*' $API"
check "bypassing the proxy: no route, even to a raw IP" bash -c "! '$AGENT' run --allow api.anthropic.com -- curl -sS -m 5 --noproxy '*' https://1.1.1.1"
check "wildcards cover subdomains" "$AGENT" run --allow '*.anthropic.com' -- curl -sS -m 20 -o /dev/null "$API"
"$AGENT" run --allow localhost:8080 -- sh -c 'NO_PROXY= no_proxy= curl -sS -m 5 https://localhost:8080' >/dev/null 2>&1
check "allowed names that resolve to local addresses are refused" grep -q '"reason":"resolves only to private or local addresses"' "$(latest_task_dir)/events.jsonl"
check "--allow with --net host is rejected" bash -c "! '$AGENT' run --net host --allow x.com -- true 2>/dev/null"

section "credential broker"
# postman-echo.com echoes back the headers and body it received, which shows
# what actually went over the wire.
export AGENTOS_E2E_TOKEN=real-secret-e2e-value
SECRET=AGENTOS_E2E_TOKEN=postman-echo.com/x-test-token
lacks() { ! grep -q -- "$1" <<<"$2"; }
out="$("$AGENT" run --secret "$SECRET" -- sh -c 'echo "token=$AGENTOS_E2E_TOKEN"' 2>&1)"
check "the agent only sees a placeholder" grep -q 'token=agentos-placeholder-agentos-e2e-token-' <<<"$out"
check "the real value is nowhere in the sandbox" lacks real-secret-e2e-value "$out"
out="$("$AGENT" run --secret "$SECRET" -- sh -c 'curl -sS -m 20 -H "x-test-token: $AGENTOS_E2E_TOKEN" https://postman-echo.com/headers' 2>&1)"
check "the proxy puts the real value in the header, on the wire" grep -Eq '"x-test-token": *"real-secret-e2e-value"' <<<"$out"
check "the agent's TLS client trusted the task CA (no cert errors)" lacks 'SSL certificate problem' "$out"
check "the injection is journaled" grep -q '"kind":"net.connect".*"brokered":true.*"injected":1' "$(latest_task_dir)/events.jsonl"
out="$("$AGENT" run --secret "$SECRET" -- sh -c 'curl -sS -m 20 -H "x-other: $AGENTOS_E2E_TOKEN" --data-raw "body=$AGENTOS_E2E_TOKEN" https://postman-echo.com/post' 2>&1)"
check "a placeholder in another header stays a placeholder" grep -Eq '"x-other": *"agentos-placeholder-' <<<"$out"
check "a placeholder in the body stays a placeholder" lacks real-secret-e2e-value "$out"
check "the value never reaches the journal" bash -c "! grep -rq real-secret-e2e-value '$AGENTOS_HOME/tasks'"
check "--secret with --net host is rejected" bash -c "! '$AGENT' run --net host --secret '$SECRET' -- true 2>/dev/null"
unset AGENTOS_E2E_TOKEN

section "configuration"
reset_proj
cd "$PROJ"
check "presets: --allow @pypi reaches PyPI" bash -c "'$AGENT' run --allow @pypi -- curl -sS -m 20 -o /dev/null -w '%{http_code}' https://pypi.org/simple/ 2>/dev/null | grep -q 200"
echo SECRET=1 > .env
printf '[network]\nallow = ["example.com"]\n[files]\nhide = [".env"]\n' > .agentos.toml
out="$("$AGENT" run -- sh -c 'curl -sS -m 10 -o /dev/null https://example.com && echo REACHED' 2>&1)"
check "an untrusted project config is ignored, with a hint" grep -q 'run `agent trust`' <<<"$out"
check "...so it grants nothing" lacks REACHED "$out"
check "agent trust shows the file and trusts it" grep -q 'trusted' <<<"$("$AGENT" trust)"
out="$("$AGENT" run -- sh -c 'curl -sS -m 20 -o /dev/null https://example.com && echo REACHED; cat .env' 2>&1)"
check "a trusted project config applies (allow)" grep -q REACHED <<<"$out"
check "a trusted project config applies (hide)" lacks 'SECRET=1' "$out"
"$AGENT" run -- sh -c 'printf "[network]\nallow = [\"example.com\", \"evil.example\"]\n" > .agentos.toml' 2>/dev/null
check "diff warns when an agent changes the project config" grep -q 'changes .agentos.toml' <<<"$("$AGENT" diff)"
"$AGENT" commit >/dev/null
out="$("$AGENT" run -- true 2>&1)"
check "after that change is committed, the config is ignored again" grep -q 'changed since you trusted it' <<<"$out"
printf '[secrets]\nGITHUB_TOKEN = "evil.example"\n' > .agentos.toml
"$AGENT" trust >/dev/null 2>&1
check "a project config can't name secrets" test $? -eq 2
printf '[files]\nro = ["%s"]\n' "$HOME" > .agentos.toml
"$AGENT" trust >/dev/null 2>&1
check "a project config can't grant paths outside the project" test $? -eq 2
rm -f .agentos.toml .env
printf '[secrets]\nAGENTOS_E2E_TOKEN = "postman-echo.com/x-test-token"\n' > "$WORK/user.toml"
out="$(AGENTOS_CONFIG="$WORK/user.toml" AGENTOS_E2E_TOKEN=from-user-config "$AGENT" run --allow example.com -- sh -c 'echo "token=$AGENTOS_E2E_TOKEN"' 2>&1)"
check "your config brokers secrets" grep -q 'token=agentos-placeholder-' <<<"$out"

section "live approvals"
reset_proj
cd "$PROJ"
GET="curl -sS -m 20 -o /dev/null -w HTTP%{http_code} https://example.com"
if command -v script >/dev/null; then
  # script(1) gives the agent a terminal and types the answer into it.
  answer() { script -qec "$AGENT run --ask -- $GET" /dev/null <<<"$1" 2>&1; }
  out="$(answer y)"
  check "you're asked while the connection waits" grep -q 'the agent wants to reach example.com' <<<"$out"
  check "[y] lets it through" grep -q HTTP200 <<<"$out"
  check "the answer is journaled" grep -q '"kind":"net.approval".*"decision":"once"' "$(latest_task_dir)/events.jsonl"
  check "the banner says it will ask" grep -q 'net asks you first' <<<"$out"
  script -qec "$AGENT run --ask -- sh -c '$GET; $GET'" /dev/null <<<"y" >/dev/null 2>&1
  check "one question per host per task" test "$(grep -c '"kind":"net.approval"' "$(latest_task_dir)/events.jsonl")" -eq 1
  check "[n] refuses it" lacks HTTP200 "$(answer n)"
  check "[a] lets it through" grep -q HTTP200 <<<"$(answer a)"
  check "...and remembers it for this project" grep -q HTTP200 <<<"$("$AGENT" run -- $GET 2>&1)"
  check "agent approvals lists it" grep -q 'example.com' <<<"$("$AGENT" approvals)"
  "$AGENT" approvals --revoke example.com >/dev/null
  check "revoking takes it back" lacks HTTP200 "$("$AGENT" run -- $GET 2>&1)"
else
  skip "terminal approvals need script(1)"
fi
out="$("$AGENT" run --ask -- $GET 2>&1 </dev/null)"
check "without a terminal nobody is asked, the host is refused" grep -q 'blocked example.com:443' <<<"$out"

section "agentd console"
start_agentd
api() { curl -sS -m 10 -H "Authorization: Bearer $TOKEN" "$@"; }
check "agent serve prints a link with a token" grep -q "#token=$TOKEN" "$SERVE_LOG"
check "the console page is served" grep -q 'agentd console' <<<"$(curl -sS -m 10 "$CONSOLE/")"
check "the API refuses calls without the token" test "$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "$CONSOLE/api/tasks")" = 401
check "it lists tasks" grep -q '"id"' <<<"$(api "$CONSOLE/api/tasks")"
reset_proj
cd "$PROJ"
"$AGENT" run --ask -- curl -sS -m 30 -o /dev/null -w 'HTTP%{http_code}' https://example.com >"$WORK/ask.out" 2>&1 </dev/null &
RUN_PID=$!
Q=""
for _ in $(seq 100); do Q="$(api "$CONSOLE/api/approvals")"; grep -q '"id"' <<<"$Q" && break; sleep 0.1; done
check "a task with no terminal asks in the console" grep -q '"target":"example.com"' <<<"$Q"
QID="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$Q")"
api -X POST -d '{"decision":"once"}' "$CONSOLE/api/approvals/$QID" >/dev/null
wait $RUN_PID
check "answering there lets the connection through" grep -q HTTP200 "$WORK/ask.out"
check "the answer is journaled" grep -q '"kind":"net.approval".*"decision":"once"' "$(latest_task_dir)/events.jsonl"
"$AGENT" run -- sh -c 'echo from-agent > console.txt' 2>/dev/null
ID="$("$AGENT" ls | sed -n 2p | cut -d' ' -f1)"
check "a task's detail shows its diff" grep -q 'console.txt' <<<"$(api "$CONSOLE/api/tasks/$ID")"
check "commit from the console" grep -q '"ok":true' <<<"$(api -X POST "$CONSOLE/api/tasks/$ID/commit")"
check "...applies the change" grep -qx from-agent console.txt
kill $SERVE_PID 2>/dev/null
wait $SERVE_PID 2>/dev/null

section "agents ask for more, mid-task (agentos MCP server)"
reset_proj
cd "$PROJ"
mkdir -p "$ASKED/docs" "$ASKED/lib" "$ASKED/nope" "$WORK/outside"
echo "the docs" > "$ASKED/docs/README"
echo "lib v1" > "$ASKED/lib/lib.txt"
echo "outside" > "$WORK/outside/file"
start_agentd
# You, in the console: yes to everything except "nope".
( for _ in $(seq 600); do
    q="$(api "$CONSOLE/api/approvals")"
    id="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$q")"
    if [ -n "$id" ]; then
      printf '%s\n' "$q" >> "$WORK/questions"
      d=once; grep -q nope <<<"$q" && d=deny
      api -X POST -d "{\"decision\":\"$d\"}" "$CONSOLE/api/approvals/$id" >/dev/null
    fi
    sleep 0.1
  done ) &
ANSWERER=$!
cat > asks.sh <<SH
mcp() { printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"\$1\",\"arguments\":\$2}}" | /run/agentos/agent mcp | tail -1; echo; }
echo "before: \$(cat $ASKED/docs/README 2>&1)"
mcp request_path_access '{"path":"$ASKED/docs","access":"read","reason":"I need the API docs"}'
echo "after: \$(cat $ASKED/docs/README 2>&1)"
touch $ASKED/docs/new 2>/dev/null && echo "docs: writable" || echo "docs: read-only"
mcp request_path_access '{"path":"$ASKED/lib","access":"write","reason":"the bug is in lib"}'
echo "lib v2" > $ASKED/lib/lib.txt && echo "wrote: \$(cat $ASKED/lib/lib.txt)"
mcp request_path_access '{"path":"$ASKED/nope","access":"read","reason":"just curious"}'
echo "nope: \$(ls $ASKED/nope 2>&1)"
mcp request_path_access '{"path":"~/.ssh","access":"read","reason":"to push"}'
mcp request_path_access '{"path":"$WORK/outside","access":"read","reason":"outside your home"}'
echo "outside: \$(cat $WORK/outside/file 2>&1)"
mcp request_path_access '{"path":"$WORK/outside","access":"write","reason":"and change it"}'
mcp request_network_access '{"host":"example.org","reason":"fetch the spec"}'
curl -sS -m 20 -o /dev/null -w 'example.org: HTTP%{http_code}\n' https://example.org
mcp sandbox_info '{}'
SH
out="$("$AGENT" run --ask --allow example.com -- sh asks.sh 2>&1 </dev/null)"
events="$(latest_task_dir)/events.jsonl"
check "a folder the task didn't have is invisible" grep -q 'before: .*No such file' <<<"$out"
check "you're asked in the console, with the agent's reason" grep -q '"kind":"read".*"reason":"I need the API docs"' "$WORK/questions"
check "once you agree, it appears at its own path" grep -q 'after: the docs' <<<"$out"
check "...read-only" grep -q 'docs: read-only' <<<"$out"
check "a writable folder, added mid-task" grep -q 'wrote: lib v2' <<<"$out"
check "...is transactional: your copy is untouched" test "$(cat "$ASKED/lib/lib.txt")" = "lib v1"
check "...and its change is held for review" grep -Eq '^  M  .*lib/lib.txt' <<<"$("$AGENT" diff --stat)"
check "what you deny stays invisible" grep -q 'nope: .*No such file' <<<"$out"
check "...and the agent is told" grep -q 'Denied: the user said no' <<<"$out"
check "credentials are refused without asking you" grep -q 'Not possible: .*holds credentials' <<<"$out"
check "...and the question never reached you" lacks '.ssh' "$(cat "$WORK/questions")"
check "folders outside your home can be added read-only" grep -q 'outside: outside' <<<"$out"
if grep -q '"landlock":"enforced' "$events" || grep -q '"landlock":"partially' "$events"; then
  check "...but with Landlock, not writable mid-task (with how to rerun)" grep -q 'Not possible: .*rerun the task with --rw' <<<"$out"
else
  check "...and without Landlock, writable too" grep -q 'Granted: you can now read and change .*outside' <<<"$out"
fi
check "a host, granted mid-task, is reachable at once" grep -q 'example.org: HTTP200' <<<"$out"
check "sandbox_info describes the sandbox" grep -q 'This is agentos task' <<<"$out"
check "requests and answers are journaled" grep -q '"kind":"agent.request".*"decision":"once"' "$events"
check "...and the grants" test "$(grep -c '"kind":"grant.added"' "$events")" -ge 3
check "...in a chain that verifies" grep -q 'chain intact' <<<"$("$AGENT" log)"
"$AGENT" commit >/dev/null 2>&1
check "commit applies changes in a folder added mid-task" test "$(cat "$ASKED/lib/lib.txt")" = "lib v2"
kill $ANSWERER 2>/dev/null; wait $ANSWERER 2>/dev/null
kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
out="$("$AGENT" run --ask -- sh -c "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"request_path_access\",\"arguments\":{\"path\":\"$ASKED/docs\",\"access\":\"read\",\"reason\":\"x\"}}}' | /run/agentos/agent mcp" 2>&1 </dev/null)"
check "with nobody to ask, the agent is told so" grep -q 'nobody can approve' <<<"$out"
check "...and so are you, and the journal" grep -q '"kind":"agent.request".*"decision":"nobody to ask"' "$(latest_task_dir)/events.jsonl"
rm -f asks.sh

section "taking back what you granted, while the task runs"
reset_proj
cd "$PROJ"
mkdir -p "$ASKED/rv" "$ASKED/signal"
echo "lent" > "$ASKED/rv/file"
rm -f "$ASKED/signal/revoked"
start_agentd
( for _ in $(seq 600); do
    id="$(api "$CONSOLE/api/approvals" | sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p')"
    [ -n "$id" ] && api -X POST -d '{"decision":"once"}' "$CONSOLE/api/approvals/$id" >/dev/null
    sleep 0.1
  done ) &
ANSWERER=$!
cat > revoke.sh <<SH
mcp() { printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"\$1\",\"arguments\":\$2}}" | /run/agentos/agent mcp | sed 's/.*"text":"\([^"]*\)".*/\1/'; echo; }
mcp request_path_access '{"path":"$ASKED/rv","access":"read","reason":"r"}' >/dev/null
echo "before: \$(cat $ASKED/rv/file 2>&1)"
mcp request_network_access '{"host":"example.org","reason":"n"}' >/dev/null
curl -sS -m 20 -o /dev/null -w 'before-net: HTTP%{http_code}\n' https://example.org
for i in \$(seq 600); do [ -e $ASKED/signal/revoked ] && break; sleep 0.1; done
echo "after: \$(cat $ASKED/rv/file 2>&1)"
curl -sS -m 20 -o /dev/null -w 'after-net: HTTP%{http_code}\n' https://example.org 2>&1
mcp request_path_access '{"path":"$ASKED/rv","access":"read","reason":"again"}'
mcp request_network_access '{"host":"example.org","reason":"again"}'
SH
"$AGENT" run --ask --ro "$ASKED/signal" -- sh revoke.sh >"$WORK/revoke.out" 2>&1 </dev/null &
RUN_PID=$!
sleep 1
TASK_DIR="$(latest_task_dir)"
ID="$(basename "$TASK_DIR")"
for _ in $(seq 300); do grep -q '"kind":"net.connect".*"host":"example.org"' "$TASK_DIR/events.jsonl" 2>/dev/null && break; sleep 0.1; done
listed="$("$AGENT" revoke)"
check "agent revoke lists what you granted while it runs" grep -q "folder  .*/rv (read)" <<<"$listed"
check "...hosts too" grep -q 'host    example.org' <<<"$listed"
check "taking back a folder, from the terminal" grep -q "took back" <<<"$("$AGENT" revoke "$ASKED/rv")"
check "taking back a host, from the console" grep -q '"ok":true' <<<"$(api -X POST -d '{"target":"example.org"}' "$CONSOLE/api/tasks/$ID/revoke")"
check "something never granted can't be taken back" bash -c '! "$@" 2>/dev/null' _ "$AGENT" revoke pypi.org
touch "$ASKED/signal/revoked"
wait $RUN_PID
out="$(cat "$WORK/revoke.out")"
check "before: the folder and host were there" grep -q 'before: lent' <<<"$out"
check "...and reachable" grep -q 'before-net: HTTP200' <<<"$out"
check "after: the folder is gone from the running sandbox" grep -q 'after: .*No such file' <<<"$out"
check "...and the host is refused" grep -q 'blocked example.org:443: you took it back from this task' <<<"$out"
check "asking again is refused, for the folder" grep -q "Not granted: the user took $ASKED/rv back" <<<"$out"
check "...and the host" grep -q 'Not granted: the user took example.org back' <<<"$out"
check "taking back is journaled" test "$(grep -c '"kind":"grant.revoked"' "$TASK_DIR/events.jsonl")" = 2
check "agent log shows it" grep -q 'you took back example.org' <<<"$("$AGENT" log "$ID")"
kill $ANSWERER 2>/dev/null; wait $ANSWERER 2>/dev/null
kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
rm -f revoke.sh

section "background tasks"
reset_proj
cd "$PROJ"
started=$(date +%s)
id="$("$AGENT" run --bg -- sh -c 'echo started; sleep 2; echo bg > bg.txt; echo done' 2>/dev/null)"
check "--bg gives the terminal back right away, with the task id" test -n "$id" -a "$(( $(date +%s) - started ))" -le 2
check "the task shows as running" grep -Eq "^$id +running" <<<"$("$AGENT" ls)"
check "agent wait waits for it (and returns its exit code)" "$AGENT" wait "$id"
check "what it printed is kept" grep -q started <<<"$("$AGENT" logs "$id")"
check "its change is held" grep -Eq '^  A  .*bg.txt' <<<"$("$AGENT" diff "$id" --stat)"
check "...and your files are untouched" test ! -e bg.txt
"$AGENT" rollback "$id" >/dev/null
id="$("$AGENT" run --bg -- sh -c 'echo x > partial.txt; sleep 60' 2>/dev/null)"
sleep 1
check "agent stop stops it" "$AGENT" stop "$id"
check "...it shows as stopped" grep -Eq "^$id +stopped" <<<"$("$AGENT" ls)"
check "...what it did so far is held" grep -q partial.txt <<<"$("$AGENT" diff "$id" --stat)"
check "...and the journal says why" grep -q '"kind":"task.stopped".*"reason":"stopped"' "$AGENTOS_HOME/tasks/$id/events.jsonl"
"$AGENT" rollback "$id" >/dev/null
started=$(date +%s)
"$AGENT" run --timeout 2s -- sleep 30 >/dev/null 2>&1
check "--timeout stops a task that runs too long" test "$(( $(date +%s) - started ))" -lt 10
check "...and it shows as timed out" grep -q 'timed out' <<<"$("$AGENT" ls | sed -n 2p)"

section "resource limits"
reset_proj
cd "$PROJ"
check "a malformed limit is rejected" bash -c "! '$AGENT' run --memory lots -- true 2>/dev/null"
if systemd-run --user --scope --quiet --collect true 2>/dev/null; then
  "$AGENT" run --memory 64M -- python3 -c 'b = bytearray(512 * 1024 * 1024)' >/dev/null 2>&1
  check "--memory stops a task that needs more" test $? -ne 0
  check "...the out-of-memory kill is journaled" grep -q '"kind":"task.oom"' "$(latest_task_dir)/events.jsonl"
  check "...and so are the limits" grep -q '"kind":"task.limits".*"memory":"64M"' "$(latest_task_dir)/events.jsonl"
  check "--pids caps processes and threads" bash -c "! '$AGENT' run --pids 30 -- python3 -c 'import threading, time; [threading.Thread(target=time.sleep, args=(2,)).start() for _ in range(100)]' >/dev/null 2>&1"
  check "a task within its limits runs normally" "$AGENT" run --memory 256M --cpus 1 --pids 100 -- python3 -c 'print(sum(range(10**6)))'
else
  out="$("$AGENT" run --memory 1G -- true 2>&1)"
  check "asking for limits where they can't be enforced fails, and says why" grep -q 'need a systemd user session' <<<"$out"
  skip "limit enforcement needs a systemd user session (the booted-VM test covers it)"
fi

section "git push outbox"
if command -v git >/dev/null; then
  # The remote is a bare repo outside the sandbox: the agent can't reach it,
  # so anything that lands there went through agentos.
  REMOTE="$WORK/remote.git"
  me() { git -c user.name=me -c user.email=me@example.com "$@"; }
  AGIT='git -c user.name=agent -c user.email=agent@example.com'
  rm -rf "$REMOTE" "$PROJ" && git init -q --bare "$REMOTE"
  mkdir -p "$PROJ" && cd "$PROJ" && git init -q -b main && git remote add origin "$REMOTE"
  echo one > a.txt && git add a.txt && me commit -qm one && git push -q origin main
  on_remote() { git --git-dir="$REMOTE" rev-parse -q --verify "$1" 2>/dev/null; }

  out="$("$AGENT" run -- sh -c "echo two > a.txt && $AGIT commit -qam two && git push -q origin HEAD:refs/heads/feature && echo PUSHED" 2>&1)"
  check "the agent's git push works inside the sandbox" grep -q PUSHED <<<"$out"
  check "...but nothing reached the remote" test -z "$(on_remote refs/heads/feature)"
  check "the push is held for review" grep -q '1 git push (origin feature)' <<<"$out"
  check "diff shows it with its commit" grep -Eq 'origin feature  [0-9a-f]{7} two' <<<"$("$AGENT" diff)"
  check "the agent's git work is one line, from the reflog" grep -Eq '^  G  .*/.git  commit: two' <<<"$("$AGENT" diff)"
  check "...not git's internal files" lacks COMMIT_EDITMSG "$("$AGENT" diff)"
  check "diff --all lists them" grep -q COMMIT_EDITMSG <<<"$("$AGENT" diff --all)"
  check "ls counts it" grep -q '↑1' <<<"$("$AGENT" ls)"
  "$AGENT" commit >/dev/null
  check "commit sends it, with your own git" test "$(on_remote refs/heads/feature)" = "$(git rev-parse HEAD)"
  check "...and applies the agent's commit locally" grep -qx two a.txt
  check "the push is journaled" grep -q '"kind":"outbox.pushed"' "$(latest_task_dir)/events.jsonl"

  "$AGENT" run -- sh -c "$AGIT commit -q --allow-empty -m three && git push -q origin HEAD:refs/heads/other" >/dev/null 2>&1
  "$AGENT" rollback >/dev/null
  check "rollback discards held pushes" test -z "$(on_remote refs/heads/other)"

  "$AGENT" run -- sh -c "$AGIT commit -q --allow-empty -m four && git push -q origin HEAD:main" >/dev/null 2>&1
  (cd "$WORK" && rm -rf other && git clone -q -b main "$REMOTE" other && cd other && me commit -q --allow-empty -m theirs && git push -q origin main)
  "$AGENT" push >/dev/null 2>&1
  check "a push the remote rejects (it moved) fails..." test $? -eq 1
  check "...and stays held" grep -q 'origin main' <<<"$("$AGENT" diff)"
  check "agent push sends without committing files (the outbox is self-contained)" "$AGENT" push --force
  check "--force overwrote the remote" test "$(git --git-dir="$REMOTE" log -1 --format=%s main)" = four
  "$AGENT" rollback >/dev/null
else
  skip "the outbox needs git"
fi

section "ignored changes (.gitignore, __pycache__)"
reset_proj
echo "build/" > "$PROJ/.gitignore"
cd "$PROJ"
"$AGENT" run -- sh -c 'mkdir -p __pycache__ build && echo x > __pycache__/m.pyc && echo y > build/out && echo "def test(): pass" > test_m.py' 2>/dev/null
out="$("$AGENT" diff --stat)"
check "diff lists the real change" grep -Eq '^  A  .*test_m.py' <<<"$out"
check "ignored changes are summarized, not listed" grep -q '+ 4 ignored changes: __pycache__/, build/' <<<"$out"
check "--all lists them" grep -Eq '^  A  .*__pycache__/m.pyc.*\(ignored\)' <<<"$("$AGENT" diff --stat --all)"
"$AGENT" commit >/dev/null
check "commit applies the real change" test -f test_m.py
check "commit leaves ignored files out" test ! -e __pycache__ -a ! -e build
check "task is closed" grep -Eq 'committed' <<<"$("$AGENT" ls | sed -n 2p)"
"$AGENT" run -- sh -c 'mkdir -p build && echo y > build/out' 2>/dev/null
"$AGENT" commit --all >/dev/null
check "commit --all includes them" test -f build/out

section "agent do (with a stand-in for Claude Code)"
mkdir -p "$WORK/tools/claude-code"
cp "$HERE/fake-claude" "$WORK/tools/claude-code/claude"
chmod +x "$WORK/tools/claude-code/claude"
export PATH="$WORK/tools/claude-code:$PATH"
AGENT_STATE="$AGENTOS_HOME/homes/claude/.claude"
mkdir -p "$HOME/.claude" && echo real > "$HOME/.claude/host-secret"
reset_proj
cd "$PROJ"
out="$("$AGENT" do add a test for greet 2>&1)"
status=$?
check "agent do succeeds" test $status -eq 0
[ $status -eq 0 ] || sed 's/^/      | /' <<<"$out"
check "agent got the task" grep -qx 'add a test for greet' "$AGENT_STATE/last-argv"
check "agent runs headless (-p)" grep -qx -- '-p' "$AGENT_STATE/last-argv"
check "agent's own permission prompts are off" grep -qx -- '--dangerously-skip-permissions' "$AGENT_STATE/last-argv"
check "agent gets agentos's MCP server" grep -q '"command":"/run/agentos/agent"' "$AGENT_STATE/last-argv"
check "...which lists its tools" grep -q '"name":"request_path_access"' "$AGENT_STATE/mcp"
check "...and answers from the sandbox" grep -q 'This is agentos task' "$AGENT_STATE/mcp"
check "agent is told it's in a sandbox" grep -q 'You are running inside an agentos sandbox' "$AGENT_STATE/last-argv"
check "progress shows tool calls" grep -Eq '⏺ Write test_greet.py' <<<"$out"
check "final answer is printed" grep -q 'Added test_greet.py' <<<"$out"
check "cost and turns are reported" grep -q '\$0.04 · 3 turns' <<<"$out"
check "non-JSON agent output passes through" grep -q 'plain line from the agent' <<<"$out"
check "current folder granted by default, real tree untouched" test ! -e test_greet.py
check "the change is held for review" grep -Eq '^  A  .*test_greet.py' <<<"$("$AGENT" diff --stat)"
events="$(latest_task_dir)/events.jsonl"
check "journal records tool calls" grep -q '"kind":"agent.tool".*"name":"Bash"' "$events"
check "journal records result and cost" grep -q '"kind":"agent.result".*"cost_usd":0.0421' "$events"
check "agent can't see your real ~/.claude" grep -qx 'host-secret: hidden' "$AGENT_STATE/observations"
check "ls shows the task by its title" grep -q 'claude: add a test for greet' <<<"$("$AGENT" ls)"
check "agent do uses the allowlist, not your network" grep -q 'net api.anthropic.com +3' <<<"$out"
check "agent gets the proxy settings" grep -qx 'proxy: set' "$AGENT_STATE/observations"
check "the final message isn't printed twice" test "$(grep -c "I'll add a test for greet" <<<"$out")" -eq 1
check "an expected block is explained, not warned about" grep -q 'mcp-proxy.anthropic.com stays closed' <<<"$out"
check "...and not counted as a problem" lacks 'connection blocked' "$out"
check "...but still journaled" grep -q '"expected":true.*"host":"mcp-proxy.anthropic.com"' "$events"
"$AGENT" rollback >/dev/null
"$AGENT" do again >/dev/null 2>&1
check "agent home persists between tasks" test "$(cat "$AGENT_STATE/runs")" = 2
ANTHROPIC_API_KEY=sk-test-0123456789 "$AGENT" do use the key >/dev/null 2>&1
check "the agent gets a placeholder, not your API key" grep -qx 'api-key: placeholder' "$AGENT_STATE/observations"
check "the key is brokered" grep -q '"secrets":\[{"env":"ANTHROPIC_API_KEY","header":"x-api-key","host":"api.anthropic.com"}\]' "$(latest_task_dir)/events.jsonl"
check "API key value never journaled" bash -c "! grep -rq sk-test-0123456789 '$AGENTOS_HOME/tasks'"
cd "$HOME"
"$AGENT" do something >/dev/null 2>&1
check "refuses to hand over all of \$HOME" test $? -eq 2
cd "$PROJ"
out="$("$AGENT" run "add a test for greet" 2>&1)"
check "a task given to agent run suggests agent do" grep -q 'agent do "add a test for greet"' <<<"$out"
"$AGENT" run -- sh -c 'echo x > made-by-run.txt' 2>/dev/null
check "agent run also grants the current folder" grep -Eq '^  A  .*made-by-run.txt' <<<"$("$AGENT" diff --stat)"

# A claude.ai login in the agent's home, as `/login` would leave it.
CREDS="$AGENT_STATE/.credentials.json"
printf '{"claudeAiOauth":{"accessToken":"sk-ant-oat01-e2e-real-access","refreshToken":"sk-ant-ort01-e2e-real-refresh","expiresAt":1}}' > "$CREDS"
out="$("$AGENT" do look at the login 2>&1)"
check "the agent's login gets sealed before it runs" grep -qx 'login: placeholder' "$AGENT_STATE/observations"
check "...it's told once" grep -q 'login is now sealed' <<<"$out"
check "the real tokens are out of the agent's home" lacks e2e-real-access "$(cat "$CREDS")"
check "...in the vault, which no sandbox sees" grep -q e2e-real-access "$AGENTOS_HOME/vault/claude.json"
check "...and never in the journal" bash -c "! grep -rq e2e-real "$AGENTOS_HOME/tasks""
check "placeholders keep the token prefix" grep -q 'sk-ant-oat01-agentosplaceholder-' "$CREDS"
check "agent vault reports it" grep -q 'claude: sealed' <<<"$("$AGENT" vault)"
"$AGENT" do --net host with the host network >/dev/null 2>&1
check "with --net host (no proxy to swap tokens) the agent gets the real login..." grep -qx 'login: real' "$AGENT_STATE/observations"
check "...and it's sealed again afterwards" grep -q agentosplaceholder "$CREDS"
"$AGENT" vault unseal >/dev/null
check "agent vault unseal puts it back" grep -q e2e-real-access "$CREDS"
"$AGENT" do after unsealing >/dev/null 2>&1
check "...and stops sealing" grep -qx 'login: real' "$AGENT_STATE/observations"
"$AGENT" vault seal >/dev/null
check "agent vault seal resumes" lacks e2e-real-access "$(cat "$CREDS")"
id="$("$AGENT" do --bg add a test in the background 2>/dev/null)"
"$AGENT" wait "$id" >/dev/null
check "agent do --bg runs the agent headless, output kept" grep -q 'Added test_greet.py' <<<"$("$AGENT" logs "$id")"
check "agent logs -f returns once the task is over" "$AGENT" logs -f "$id"
rm -rf "$HOME/.claude"

section "agents as config files"
reset_proj
cd "$PROJ"
mkdir -p "$WORK/cfg/agents" "$WORK/tools/echo-agent"
cat > "$WORK/tools/echo-agent/echo-agent" <<'SH'
#!/bin/sh
echo "echo-agent got: $*"
case "${ECHO_KEY:-}" in agentos-placeholder-*) echo "key: placeholder" ;; "") echo "key: none" ;; *) echo "key: real" ;; esac
echo done > echo.txt
SH
chmod +x "$WORK/tools/echo-agent/echo-agent"
cat > "$WORK/cfg/agents/echo.toml" <<'TOML'
run = ["echo-agent", "--task", "{task}"]
interactive = ["echo-agent", "--interactive"]
allow = ["example.com"]

[secrets]
ECHO_KEY = "example.com"
TOML
export PATH="$WORK/tools/echo-agent:$PATH"
CFG="$WORK/cfg/config.toml"
: > "$CFG"
out="$(AGENTOS_CONFIG="$CFG" ECHO_KEY=real-echo-key "$AGENT" do --agent echo fix the thing 2>&1)"
check "a file-defined agent runs headless, with the task where its file says" grep -q 'echo-agent got: --task fix the thing' <<<"$out"
check "...with its allowlist" grep -q 'net example.com' <<<"$out"
check "...its credential brokered (a placeholder inside)" grep -q 'key: placeholder' <<<"$out"
check "...and its change held for review" grep -Eq '^  A  .*echo.txt' <<<"$("$AGENT" diff --stat)"
check "agent agents lists it, with its program" grep -Eq 'echo .*echo.toml .*echo-agent' <<<"$(AGENTOS_CONFIG="$CFG" "$AGENT" agents)"
check "an unknown agent is refused, with what's available" grep -q "unknown agent 'nope' (available: claude, echo" <<<"$(AGENTOS_CONFIG="$CFG" "$AGENT" do --agent nope x 2>&1)"
echo 'agent = "echo"' > "$CFG"
check "the default agent comes from your config" grep -q 'echo-agent got' <<<"$(AGENTOS_CONFIG="$CFG" "$AGENT" do just do it 2>&1)"

section "your MCP servers, through agentos (gateway)"
if ! command -v python3 >/dev/null; then
  skip "the stand-in MCP server needs python3"
else
  reset_proj
  cd "$PROJ"
  cp "$HERE/mcp-client" ./mcp-client
  export NOTES_TOKEN=notes-token-0123456789 NOTES_FILE="$WORK/notes.txt"
  : > "$NOTES_FILE"
  cat > "$CFG" <<TOML
[mcp.notes]
command = ["python3", "$HERE/fake-mcp-server"]
env = ["NOTES_TOKEN", "NOTES_FILE"]
tools = { drop_notes = "deny" }
TOML
  start_agentd
  : > "$WORK/questions"
  # You, in the console: "Allow this call", unless the arguments say nope.
  ( for _ in $(seq 600); do
      q="$(api "$CONSOLE/api/approvals")"
      id="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$q")"
      if [ -n "$id" ]; then
        printf '%s\n' "$q" >> "$WORK/questions"
        d=call; grep -q '"reason":"{\\"text\\":\\"nope' <<<"$q" && d=deny
        api -X POST -d "{\"decision\":\"$d\"}" "$CONSOLE/api/approvals/$id" >/dev/null
      fi
      sleep 0.1
    done ) &
  ANSWERER=$!
  out="$(AGENTOS_CONFIG="$CFG" "$AGENT" run --ask -- sh -c '
    echo "token in the sandbox: ${NOTES_TOKEN:-unset}"
    python3 ./mcp-client notes tools/list \
      "tools/call:read_note:{}" \
      "tools/call:post_note:{\"text\":\"hello\"}" \
      "tools/call:post_note:{\"text\":\"nope\"}" \
      "tools/call:drop_notes:{}" \
      "sneak:post_note:{\"text\":\"sneaked\"}" \
      notes/wipe' 2>&1 </dev/null)"
  events="$(latest_task_dir)/events.jsonl"
  check "your server's credential never reaches the sandbox" grep -q 'token in the sandbox: unset' <<<"$out"
  check "...but the server, run outside, has it" grep -q "read_note: .*token: set" <<<"$out"
  check "tools your config denies aren't even listed" grep -q '^tools: read_note,post_note$' <<<"$out"
  check "read-only tools run without asking" lacks '"target":"notes.read_note"' "$(cat "$WORK/questions")"
  check "you're asked before a tool that changes things" grep -q '"target":"notes.post_note"' "$WORK/questions"
  check "...with its arguments" grep -q '"kind":"tool".*"reason":"{\\"text\\":\\"hello\\"}"' "$WORK/questions"
  check "...and once you allow it, it happens" grep -qx hello "$NOTES_FILE"
  check "what you deny doesn't happen" lacks nope "$(cat "$NOTES_FILE")"
  check "...and the agent is told" grep -q 'post_note: agentos: the user denied this call.*\[error\]' <<<"$out"
  check "tools your config denies are refused without asking" grep -q "drop_notes: agentos: the user's config doesn't allow notes.drop_notes" <<<"$out"
  check "...and a server's own methods don't get around the rules" grep -q "notes/wipe: .*isn't relayed" <<<"$out"
  check "...so the notes are still there" grep -qx hello "$NOTES_FILE"
  check "...and a tool call sent as a notification doesn't run" lacks sneaked "$(cat "$NOTES_FILE")"
  check "every call is journaled, with how it was allowed" test "$(grep -c '"kind":"mcp.call"' "$events")" = 4
  check "...including the read-only ones" grep -q '"kind":"mcp.call".*"decision":"read-only".*"tool":"read_note"' "$events"
  check "agent log shows them" grep -q 'notes.post_note {"text":"hello"} · you allowed this call · ok' <<<"$("$AGENT" log)"
  check "the credential isn't journaled" bash -c "! grep -rq notes-token-0123456789 '$AGENTOS_HOME/tasks'"
  AGENTOS_CONFIG="$CFG" "$AGENT" do use the notes >/dev/null 2>&1
  check "Claude gets your servers too, through agentos" grep -q '"notes":{[^}]*"args":\["mcp","notes"\]' "$AGENT_STATE/last-argv"
  kill $ANSWERER 2>/dev/null; wait $ANSWERER 2>/dev/null
  kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
  unset NOTES_TOKEN NOTES_FILE
  : > "$CFG"
fi

section "remote MCP servers (Streamable HTTP, OAuth sign-in)"
if ! command -v python3 >/dev/null; then
  skip "the stand-in remote MCP server needs python3"
else
  reset_proj
  cd "$PROJ"
  cp "$HERE/mcp-client" ./mcp-client
  : > "$WORK/remote.log"
  rm -f "$WORK/remote.port"
  python3 "$HERE/fake-remote-mcp" "$WORK/remote.port" "$WORK/remote.log" &
  REMOTE_PID=$!
  for _ in $(seq 50); do [ -s "$WORK/remote.port" ] && break; sleep 0.1; done
  R="http://127.0.0.1:$(cat "$WORK/remote.port")"
  cat > "$CFG" <<TOML
[mcp.tracker]
url = "$R/mcp"
taint = false
tools = { create_issue = "allow" }

[mcp.bot]
url = "$R/mcp"
token = "TRACKER_TOKEN"
TOML
  rc() { AGENTOS_CONFIG="$CFG" "$AGENT" "$@"; }
  check "agent connect lists your remote servers" grep -q "tracker .*$R/mcp  not signed in" <<<"$(rc connect)"
  out="$(rc run -- python3 ./mcp-client tracker tools/list 2>&1 </dev/null)"
  check "before you sign in, the agent is told to ask you to" grep -q 'it needs the user to sign in first: they can run `agent connect tracker`' <<<"$out"
  out="$(BROWSER="curl -sSL -o /dev/null" rc connect tracker 2>&1 </dev/null)"
  check "agent connect signs in: discovery, registration, PKCE, the browser's return" grep -q "signed in to tracker (fake-tracker)" <<<"$out"
  check "...asking for the server as the token's resource, with its scope" grep -q 'authorize ok=True' "$WORK/remote.log"
  check "...registered as agentos, with a loopback address to come back to" grep -q "registered agentos \['http://127.0.0.1:[0-9]*/callback'\]" "$WORK/remote.log"
  check "...keeping the tokens in the vault, outside every sandbox" test -f "$AGENTOS_HOME/vault/mcp-tracker.json"
  check "agent connect shows it" grep -q "tracker .*signed in at $R" <<<"$(rc connect)"
  out="$(rc run -- sh -c "python3 ./mcp-client tracker tools/list 'tools/call:whoami:{}' 'tools/call:create_issue:{\"title\":\"flaky test\"}'; curl -sS -m 5 -o /dev/null $R/mcp 2>/dev/null && echo reachable || echo unreachable" 2>&1 </dev/null)"
  events="$(latest_task_dir)/events.jsonl"
  check "the agent uses the remote server through agentos" grep -q 'whoami: signed in as alice' <<<"$out"
  check "...streamed answers too" grep -q 'create_issue: created issue 1: flaky test' <<<"$out"
  check "...while the server itself is out of the sandbox's reach" grep -q unreachable <<<"$out"
  check "a token about to expire is refreshed first" grep -q 'token grant_type=refresh_token resource=http' "$WORK/remote.log"
  check "the session ends when the agent hangs up" grep -q 'session ended' "$WORK/remote.log"
  check "calls are journaled, like a local server's" grep -q '"kind":"mcp.call".*"tool":"create_issue"' "$events"
  check "...and so is the server's URL" grep -q '"kind":"mcp.start".*"url":"http' "$events"
  check "no token in the task store's journals or logs" bash -c "! grep -rqE '(at|rt)-[0-9]+-[0-9a-f]{8}' '$AGENTOS_HOME/tasks'"
  curl -sS -X POST "$R/test/expire" >/dev/null
  out="$(rc run -- python3 ./mcp-client tracker tools/list 'tools/call:whoami:{}' 2>&1 </dev/null)"
  check "a token the server refuses is renewed, and the call goes through" grep -q 'whoami: signed in as alice' <<<"$out"
  check "...with the refresh token rotated" test "$(grep -c 'token grant_type=refresh_token' "$WORK/remote.log")" = 2
  out="$(TRACKER_TOKEN=static-secret rc run -- sh -c 'echo "token: ${TRACKER_TOKEN:-unset}"; python3 ./mcp-client bot tools/list "tools/call:whoami:{}"' 2>&1 </dev/null)"
  check "a token from your environment works too" grep -q 'whoami: signed in as bot' <<<"$out"
  check "...and stays out of the sandbox" grep -q 'token: unset' <<<"$out"
  sed -i '/^taint = false/d' "$CFG"
  out="$(rc run -- python3 ./mcp-client tracker tools/list 'tools/call:whoami:{}' 'tools/call:create_issue:{"title":"after reading"}' 2>&1 </dev/null)"
  check "a remote server's results taint the task by default: the allowed call is asked about" grep -q 'create_issue: agentos: .*nobody can be asked' <<<"$out"
  check "agent connect --forget forgets the sign-in" grep -q 'forgot your sign-in to tracker' <<<"$(rc connect tracker --forget)"
  check "...for good" test ! -e "$AGENTOS_HOME/vault/mcp-tracker.json"
  kill $REMOTE_PID 2>/dev/null; wait $REMOTE_PID 2>/dev/null
  : > "$CFG"
fi

section "your rules (policy.cedar)"
reset_proj
cd "$PROJ"
RULES="$(dirname "$CFG")/policy.cedar"
mkdir -p "$ASKED/rules-read" "$ASKED/rules-write"
echo "readable by rule" > "$ASKED/rules-read/file"
cat > "$CFG" <<TOML
[mcp.notes]
command = ["python3", "$HERE/fake-mcp-server"]
env = ["NOTES_FILE"]
TOML
cat > "$RULES" <<CEDAR
@id("read what we asked")
permit (principal, action == Action::"read", resource)
when { resource.path like "$ASKED/rules-*" };

@id("never change it")
forbid (principal, action == Action::"write", resource)
when { resource.path like "$ASKED/rules-*" };

@id("example.org for commands")
permit (principal == Agent::"command", action == Action::"connect", resource == Host::"example.org");

@id("not example.com")
forbid (principal, action == Action::"connect", resource == Host::"example.com");

@id("ok notes")
permit (principal, action == Action::"call", resource == Tool::"notes.post_note")
when { context.args has text && context.args.text == "ok" };

@id("no reading notes")
forbid (principal, action == Action::"call", resource == Tool::"notes.read_note");
CEDAR
run_rules() { AGENTOS_CONFIG="$CFG" "$AGENT" "$@"; }
check "agent policy lists your rules" grep -q 'forbid  not example.com' <<<"$(run_rules policy)"
check "agent policy check: permitted" grep -q 'permitted by “read what we asked”' <<<"$(run_rules policy check read "$ASKED/rules-read")"
check "...forbidden" grep -q 'forbidden by your rule “not example.com”' <<<"$(run_rules policy check connect example.com)"
check "...a tool call, by its arguments" grep -q 'permitted by “ok notes”' <<<"$(run_rules policy check call notes.post_note --args '{"text":"ok"}')"
check "...or no rule at all" grep -q 'no rule matches' <<<"$(run_rules policy check connect pypi.org)"
export NOTES_FILE="$WORK/rule-notes.txt"
: > "$NOTES_FILE"
cp "$HERE/mcp-client" ./mcp-client
cat > rules.sh <<SH
mcp() { printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"\$1\",\"arguments\":\$2}}" | /run/agentos/agent mcp | sed 's/.*"text":"\([^"]*\)".*/\1/'; echo; }
curl -sS -m 20 -o /dev/null -w 'example.com: HTTP%{http_code}\n' https://example.com 2>&1
curl -sS -m 20 -o /dev/null -w 'example.org: HTTP%{http_code}\n' https://example.org
mcp request_path_access '{"path":"$ASKED/rules-read","access":"read","reason":"r"}'
echo "file: \$(cat $ASKED/rules-read/file 2>&1)"
mcp request_path_access '{"path":"$ASKED/rules-write","access":"write","reason":"w"}'
python3 ./mcp-client notes tools/list "tools/call:read_note:{}" "tools/call:post_note:{\"text\":\"ok\"}" "tools/call:post_note:{\"text\":\"other\"}"
SH
out="$(run_rules run --allow example.com --allow example.net -- sh rules.sh 2>&1 </dev/null)"
events="$(latest_task_dir)/events.jsonl"
check "the task says which rules apply" grep -q 'your rules: .*policy.cedar (6 rules)' <<<"$out"
check "a forbid wins over your allowlist" grep -q 'blocked example.com:443: forbidden by your rule “not example.com”' <<<"$out"
check "...so the host is out of reach" lacks 'example.com: HTTP200' "$out"
check "a permit opens a host nobody was asked about" grep -q 'example.org: HTTP200' <<<"$out"
check "a permit grants a folder without asking" grep -q 'file: readable by rule' <<<"$out"
check "a forbid refuses a request without asking" grep -q 'Denied by the user.s rules (“never change it”)' <<<"$out"
check "a rule can allow a tool call by its arguments" grep -qx ok "$NOTES_FILE"
check "...and only that one: the rest still needs someone to ask" grep -q 'post_note: .*nobody can be asked' <<<"$out"
check "a forbid refuses even a read-only tool" grep -q 'read_note: agentos: the user.s rules forbid this call' <<<"$out"
check "rules' decisions are journaled, with the rule" grep -q '"kind":"agent.request".*"decision":"rule".*"rule":"read what we asked"' "$events"
check "...for tool calls too" grep -q '"kind":"mcp.call".*"decision":"forbidden".*"rule":"no reading notes"' "$events"
check "agent log names the rule" grep -q 'allowed by your rule “example.org for commands”' <<<"$(run_rules log)"
echo 'permit (principal, action, resource' > "$RULES"
out="$(run_rules run -- true 2>&1)"
check "a rules file that doesn't parse stops the task" grep -q 'policy.cedar' <<<"$out"
check "...rather than being skipped" test "$(run_rules run -- true >/dev/null 2>&1; echo $?)" != 0
rm -f "$RULES" rules.sh mcp-client
unset NOTES_FILE
: > "$CFG"

section "taint: a task that has read untrusted input is asked before it acts"
if ! command -v python3 >/dev/null; then
  skip "the stand-in MCP server needs python3"
else
  reset_proj
  cd "$PROJ"
  cp "$HERE/mcp-client" ./mcp-client
  export NOTES_FILE="$WORK/taint-notes.txt"
  : > "$NOTES_FILE"
  cat > "$CFG" <<TOML
[mcp.notes]
command = ["python3", "$HERE/fake-mcp-server"]
env = ["NOTES_FILE"]
taint = true
tools = { post_note = "allow" }

[taint]
trusted = ["example.org"]
TOML
  tt() { AGENTOS_CONFIG="$CFG" "$AGENT" "$@"; }
  CALLS=(tools/list 'tools/call:post_note:{"text":"before"}' 'tools/call:read_note:{}' 'tools/call:post_note:{"text":"after"}')
  out="$(tt run -- python3 ./mcp-client notes "${CALLS[@]}" 2>&1 </dev/null)"
  events="$(latest_task_dir)/events.jsonl"
  check "before it reads anything, your config's allow applies" grep -qx before "$NOTES_FILE"
  check "a read-only tool still runs" grep -q 'read_note: notes:' <<<"$out"
  check "reading a result from an outside server taints the task" grep -q '"kind":"taint.marked".*"detail":"notes","first":true,"source":"tool"' "$events"
  check "...and then the allowed tool that changes things is asked about" grep -q 'post_note: agentos: .*nobody can be asked' <<<"$out"
  check "...so it didn't happen" lacks after "$(cat "$NOTES_FILE")"
  check "the summary says what the task read" grep -q 'it read untrusted input (tool results (notes))' <<<"$out"
  check "agent log shows the taint" grep -q 'tainted: read results from notes' <<<"$("$AGENT" log)"

  # The same calls, with the server marked as trusted.
  : > "$NOTES_FILE"
  sed -i 's/^taint = true/taint = false/' "$CFG"
  out="$(tt run -- python3 ./mcp-client notes "${CALLS[@]}" 2>&1 </dev/null)"
  check "a server you say is trusted doesn't taint" lacks '"kind":"taint.marked"' "$(cat "$(latest_task_dir)/events.jsonl")"
  check "...so everything your config allows goes through" test "$(grep -c . "$NOTES_FILE")" = 2

  # Rules see taint; one that permits wins over the default.
  : > "$NOTES_FILE"
  sed -i 's/^taint = false/taint = true/' "$CFG"
  RULES="$(dirname "$CFG")/policy.cedar"
  cat > "$RULES" <<'CEDAR'
@id("notes are fine")
permit (principal, action == Action::"call", resource == Tool::"notes.post_note");
@id("clean tasks only")
permit (principal, action == Action::"read", resource) when { !context.tainted && resource.path like "/nowhere/*" };
@id("nothing after the web")
forbid (principal, action == Action::"connect", resource == Host::"example.net") when { context.tainted && context.taint.contains("web") };
CEDAR
  check "agent policy check --tainted: a rule that permits a tool still does" grep -q 'permitted by “notes are fine”' <<<"$(tt policy check call notes.post_note --tainted tool)"
  check "...rules can ask whether the task is clean" grep -q 'no rule matches' <<<"$(tt policy check read /nowhere/x --tainted file)"
  check "...and which kind of input it read" grep -q 'forbidden by your rule “nothing after the web”' <<<"$(tt policy check connect example.net --tainted web)"
  check "...a clean task isn't affected" grep -q 'no rule matches' <<<"$(tt policy check connect example.net)"
  check "an unknown kind is refused" bash -c "! AGENTOS_CONFIG='$CFG' '$AGENT' policy check connect x.org --tainted cookies 2>/dev/null"
  out="$(tt run -- python3 ./mcp-client notes "${CALLS[@]}" 2>&1 </dev/null)"
  check "a rule of yours permits the call even when tainted" test "$(grep -c . "$NOTES_FILE")" = 2

  # Web and files.
  rm -f "$RULES"
  tt run --allow example.org --allow pypi.org -- sh -c 'curl -sS -m 20 -o /dev/null https://example.org; curl -sS -m 20 -o /dev/null https://pypi.org/simple/' >/dev/null 2>&1 </dev/null
  check "hosts you trust and package registries don't taint" lacks '"kind":"taint.marked"' "$(cat "$(latest_task_dir)/events.jsonl")"
  out="$(tt run --allow example.com -- sh -c 'curl -sS -m 20 -o /dev/null https://example.com' 2>&1 </dev/null)"
  events="$(latest_task_dir)/events.jsonl"
  check "reaching any other host taints the task" grep -q '"kind":"taint.marked".*"detail":"example.com".*"source":"web"' "$events"
  check "...and the summary says so" grep -q 'it read untrusted input (web pages (example.com))' <<<"$out"
  mkdir -p "$ASKED/taint-read" && echo hi > "$ASKED/taint-read/file"
  printf '@id("read what we asked")\npermit (principal, action == Action::"read", resource) when { resource.path like "%s/taint-*" };\n' "$ASKED" > "$RULES"
  tt run -- sh -c "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"request_path_access\",\"arguments\":{\"path\":\"$ASKED/taint-read\",\"access\":\"read\",\"reason\":\"r\"}}}' | /run/agentos/agent mcp" >/dev/null 2>&1 </dev/null
  check "a folder outside the project, granted mid-task, taints it" grep -q '"kind":"taint.marked".*"source":"file"' "$(latest_task_dir)/events.jsonl"
  rm -f "$RULES"

  # A project can't decide what you trust.
  printf '[taint]\ntrusted = ["evil.example"]\n' > .agentos.toml
  check "[taint] in a project's config is refused" grep -q 'only belongs in your own config' <<<"$(tt trust 2>&1 </dev/null)"
  rm -f .agentos.toml mcp-client
  unset NOTES_FILE
  : > "$CFG"
fi

section "project rules (.agentos.cedar): they can only forbid"
reset_proj
cd "$PROJ"
cat > .agentos.cedar <<'CEDAR'
@id("not example.com")
forbid (principal, action == Action::"connect", resource == Host::"example.com");
CEDAR
GET="curl -sS -m 20 -o /dev/null -w HTTP%{http_code} https://example.com"
out="$("$AGENT" run --allow example.com -- $GET 2>&1)"
check "a project's forbid applies, without review" grep -q 'blocked example.com:443: forbidden by the project.s rule “not example.com”' <<<"$out"
check "...over your own --allow" lacks HTTP200 "$out"
check "the task names the project's rules" grep -q 'project rules: .*\.agentos\.cedar (1 rule)' <<<"$out"
check "agent policy shows them, as the project's" grep -q "this project's: forbids only" <<<"$("$AGENT" policy)"
printf '@id("mine")\npermit (principal, action == Action::"connect", resource == Host::"example.com");\n' > "$(dirname "$CFG")/policy.cedar"
check "a project's forbid beats your permit" grep -q "forbidden by the project.s rule" <<<"$(AGENTOS_CONFIG="$CFG" "$AGENT" policy check connect example.com)"
rm -f "$(dirname "$CFG")/policy.cedar"
printf 'permit (principal, action, resource);\n' >> .agentos.cedar
out="$("$AGENT" run -- true 2>&1)"
check "a project file that permits anything stops the task" grep -q 'project rules can only forbid' <<<"$out"
echo 'forbid (principal, action, resource' > .agentos.cedar
check "...and so does one that doesn't parse" test "$("$AGENT" run -- true >/dev/null 2>&1; echo $?)" != 0
cat > .agentos.cedar <<'CEDAR'
forbid (principal, action == Action::"connect", resource == Host::"example.com");
CEDAR
"$AGENT" run -- sh -c 'echo "// nothing to see" > .agentos.cedar' 2>/dev/null
check "agent diff flags an agent's change to the project's rules" grep -q 'this task changes .agentos.cedar' <<<"$("$AGENT" diff)"
check "...which didn't loosen anything in the meantime" grep -q 'forbid' .agentos.cedar
"$AGENT" rollback >/dev/null
rm -f .agentos.cedar

section "start tasks from agentd's console"
reset_proj
cd "$PROJ"
mkdir -p "$WORK/listed"
cat > "$WORK/cfg/agents/sleeper.toml" <<'TOML'
run = ["sh", "-c", "echo sleeping; sleep 60", "{task}"]
TOML
printf '[console]\nprojects = ["%s"]\n' "$WORK/listed" > "$CFG"
start_agentd AGENTOS_CONFIG="$CFG"
post() { api -X POST -d "$2" "$CONSOLE$1"; }
wait_task() { for _ in $(seq 150); do api "$CONSOLE/api/tasks/$1" | grep -q "\"live\":$2" && return; sleep 0.2; done; }
lp="$(api "$CONSOLE/api/launchpad")"
check "the console offers folders you've run agents in" grep -q "\"path\":\"$PROJ\"" <<<"$lp"
check "...and those you list in your config" grep -q "\"path\":\"$WORK/listed\"" <<<"$lp"
check "...and your agents" grep -q '"name":"sleeper"' <<<"$lp"
check "it won't start a task in any other folder" grep -q "isn't one of your projects" <<<"$(post /api/tasks "{\"project\":\"$WORK\",\"task\":\"x\"}")"
check "...or with an agent you don't have" grep -q "unknown agent" <<<"$(post /api/tasks "{\"project\":\"$PROJ\",\"task\":\"x\",\"agent\":\"nope\"}")"
check "...or a budget it can't read" grep -q '"error":"budget' <<<"$(post /api/tasks "{\"project\":\"$PROJ\",\"task\":\"x\",\"budget\":\"lots\"}")"
r="$(post /api/tasks "{\"project\":\"$PROJ\",\"task\":\"add a test for greet\",\"budget\":\"2usd\"}")"
ID="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$r")"
check "starting a task returns its id" test -n "$ID"
wait_task "$ID" false
d="$(api "$CONSOLE/api/tasks/$ID")"
check "it runs like agent do: the agent does the work" grep -q 'test_greet.py' <<<"$d"
check "...in its sandbox, held for review" test ! -e "$PROJ/test_greet.py"
check "...with what you set (budget)" grep -q '"budget":"\$2.00"' <<<"$d"
check "its output shows in the console" grep -q 'Added test_greet.py' <<<"$d"
check "the journal says it was started from the console" grep -q '"started_by":"agentd console"' "$AGENTOS_HOME/tasks/$ID/events.jsonl"
r="$(post /api/tasks "{\"project\":\"$PROJ\",\"task\":\"take a nap\",\"agent\":\"sleeper\"}")"
ID2="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$r")"
wait_task "$ID2" true
check "a running task shows what it prints, live" grep -q 'sleeping' <<<"$(api "$CONSOLE/api/tasks/$ID2")"
check "...and can be stopped from the console" grep -q '"ok":true' <<<"$(post "/api/tasks/$ID2/stop" '{}')"
check "...which it is" grep -q '"status":"stopped"' <<<"$(api "$CONSOLE/api/tasks/$ID2")"
kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
rm -f "$WORK/cfg/agents/sleeper.toml"
: > "$CFG"

section "budgets (the model gateway)"
# A stand-in model API: httpbin's /base64/… answers with whatever body the
# URL carries, so the "provider" reports exactly the usage we choose.
FAKE_API=""
for h in httpbin.org httpbingo.org; do
  if [ "$(curl -sS -m 15 "https://$h/base64/b2s=" 2>/dev/null)" = ok ]; then FAKE_API="$h"; break; fi
done
if [ -z "$FAKE_API" ]; then
  skip "budgets need httpbin.org or httpbingo.org, and neither answered"
else
  reset_proj
  cd "$PROJ"
  b64url() { base64 | tr -d '\n' | tr '+/' '-_'; }
  # $0.30 a call on Sonnet 5.5 ($2 in, $10 out per million): 100k in, 10k out.
  JSON_CALL="https://$FAKE_API/base64/$(printf '%s' '{"type":"message","model":"claude-sonnet-5-5","usage":{"input_tokens":100000,"output_tokens":10000}}' | b64url)"
  SSE_CALL="https://$FAKE_API/base64/$(printf 'event: message_start\ndata: {"type":"message_start","message":{"model":"claude-sonnet-5-5","usage":{"input_tokens":100000,"output_tokens":1}}}\n\nevent: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":10000}}\n\n' | b64url)"
  mkdir -p "$WORK/tools/model-agent"
  # Two calls, then one too many, then a retry loop that shouldn't get far.
  cat > "$WORK/tools/model-agent/model-agent" <<SH
#!/bin/sh
call() { curl -sS -m 20 "\$1"; echo; }
call "$JSON_CALL"
call "$SSE_CALL"
call "$JSON_CALL"
for i in 1 2 3 4 5 6 7 8; do call "$JSON_CALL" >/dev/null; sleep 0.2; done
echo still-running
SH
  chmod +x "$WORK/tools/model-agent/model-agent"
  cat > "$WORK/cfg/agents/metered.toml" <<TOML
run = ["model-agent"]
allow = ["$FAKE_API"]
models = [{ url = "https://$FAKE_API/base64/*", api = "anthropic" }]
TOML
  export PATH="$WORK/tools/model-agent:$PATH"
  : > "$CFG"
  out="$(AGENTOS_CONFIG="$CFG" "$AGENT" do --agent metered --budget 0.5usd spend it 2>&1)"
  events="$(latest_task_dir)/events.jsonl"
  check "the budget is shown when the task starts" grep -q 'budget \$0.50' <<<"$out"
  check "model calls are metered from the provider's own usage (JSON and streamed)" test "$(grep -c '"kind":"model.call"' "$events")" = 2
  check "the agent is told, live, when the budget is used up" grep -q 'budget used up (\$0.60 of \$0.50)' <<<"$out"
  check "the next call is answered with the API's own error, not sent" grep -q '"type":"invalid_request_error"' <<<"$out"
  check "an agent that keeps calling is stopped" grep -q '"reason":"budget"' "$events"
  check "...before it gets further" bash -c '! grep -q still-running <<<"$1"' _ "$out"
  check "the exit summary has the measured spend" grep -q '220k tokens · \$0.60' <<<"$out"
  check "agent ls shows it over budget, with its cost" grep -Eq 'over budget .*\$0\.60' <<<"$("$AGENT" ls)"
  check "agent log shows each call" grep -q 'claude-sonnet-5-5 · 100k in · 10k out · \$0.30 · total \$0.60' <<<"$("$AGENT" log)"
  check "...and its chain, costs included, verifies" grep -q 'chain intact' <<<"$("$AGENT" log)"

  # Within budget: from your config, a warning at 80%, and the task runs to the end.
  printf '[limits]\nbudget = "4usd"\n' > "$CFG"
  out="$(AGENTOS_CONFIG="$CFG" "$AGENT" do --agent metered spend less 2>&1)"
  check "a budget from your config applies" grep -q 'budget \$4.00' <<<"$out"
  check "80% of it gets a heads-up" grep -q '80% of the budget used' <<<"$out"
  check "a task within its budget runs to the end" grep -q still-running <<<"$out"
  check "...and is journaled with its totals" grep -q '"kind":"model.usage"' "$(latest_task_dir)/events.jsonl"
  check "--budget with --net host is refused" bash -c '"$@" 2>&1 | grep -q "net host bypasses"' _ "$AGENT" run --net host --budget 1usd -- true
  : > "$CFG"
fi

section "budgets across tasks (daily, weekly, monthly)"
if [ -z "$FAKE_API" ]; then
  skip "shared budgets need the stand-in model API (httpbin)"
else
  reset_proj
  cd "$PROJ"
  STORE2="$WORK/store-spend"
  cat > "$WORK/tools/model-agent/one-call" <<SH
#!/bin/sh
curl -sS -m 20 "$JSON_CALL"; echo
SH
  chmod +x "$WORK/tools/model-agent/one-call"
  cat > "$WORK/cfg/agents/onecall.toml" <<TOML
run = ["one-call"]
allow = ["$FAKE_API"]
models = [{ url = "https://$FAKE_API/base64/*", api = "anthropic" }]
TOML
  printf '[limits]\ndaily = "0.5usd"\n' > "$CFG"
  spend() { AGENTOS_HOME="$STORE2" AGENTOS_CONFIG="$CFG" "$AGENT" "$@"; }
  out="$(spend do --agent onecall first 2>&1)"
  check "a task shows where today's budget stands" grep -q 'spend: today \$0.00 of \$0.50 (all your tasks)' <<<"$out"
  out="$(spend do --agent onecall second 2>&1)"
  check "the task that uses up the day's budget is told, with when it resets" grep -q "today's budget for all your tasks is used up (\$0.60 of \$0.50); it resets at midnight" <<<"$out"
  out="$(spend do --agent onecall third 2>&1)"
  check "...and the next task doesn't start" grep -q "today's budget for all your tasks is used up" <<<"$out"
  check "...it fails, before running anything" test "$(spend do --agent onecall fourth >/dev/null 2>&1; echo $?)" = 2
  check "agent spend shows today, against your budget" grep -Eq 'today +\$0.60 · 220k of \$0.50' <<<"$(spend spend)"
  printf '[limits]\ndaily = "100usd"\n' > "$CFG"
  printf '[limits]\ndaily = "0.2usd"\n' > .agentos.toml
  spend trust >/dev/null
  out="$(spend do --agent onecall fifth 2>&1)"
  check "a project's own daily budget caps that project" grep -q "today's budget for this project (.*) is used up (\$0.60 of \$0.20)" <<<"$out"
  check "...while yours still has room" grep -Eq 'today +\$0.60 · 220k of \$100.00' <<<"$(spend spend)"
  rm -f .agentos.toml "$WORK/cfg/agents/onecall.toml"
  : > "$CFG"
fi

section "raising a budget that's used up"
if [ -z "$FAKE_API" ]; then
  skip "raising budgets needs the stand-in model API (httpbin)"
else
  reset_proj
  cd "$PROJ"
  # Three calls at $0.30: the third finds a $0.50 budget used up, and waits.
  cat > "$WORK/tools/model-agent/three-calls" <<SH
#!/bin/sh
for i in 1 2 3; do curl -sS -m 200 "$JSON_CALL"; echo; done
echo done-calling
SH
  chmod +x "$WORK/tools/model-agent/three-calls"
  for a in raiser:three-calls onecall:one-call; do
    printf 'run = ["%s"]\nallow = ["%s"]\nmodels = [{ url = "https://%s/base64/*", api = "anthropic" }]\n' "${a#*:}" "$FAKE_API" "$FAKE_API" > "$WORK/cfg/agents/${a%%:*}.toml"
  done
  : > "$CFG"
  if command -v script >/dev/null; then
    # Agents whose output agentos renders (like Claude's) ask at the terminal too.
    { cat "$WORK/cfg/agents/raiser.toml"; echo 'output = "claude-stream"'; } > "$WORK/cfg/agents/raiser-tty.toml"
    out="$(script -qec "AGENTOS_CONFIG=$CFG $AGENT do --agent raiser-tty --budget 0.5usd at the terminal" /dev/null <<<"y" 2>&1)"
    check "at the terminal, you're asked while the call waits" grep -q "this task's budget is used up (\$0.60 of \$0.50); the agent's next model call waits" <<<"$out"
    check "...[y] raises it to the first offer, and the call goes on" grep -q "this task's budget raised to \$0.90: the agent goes on" <<<"$out"
    check "...through to the provider" test "$(grep -c '"kind":"model.call"' "$(latest_task_dir)/events.jsonl")" = 3
    rm -f "$WORK/cfg/agents/raiser-tty.toml"
  else
    skip "budget questions at the terminal need script(1)"
  fi
  start_agentd
  budget_ask() { local q=""; for _ in $(seq 300); do q="$(api "$CONSOLE/api/approvals")"; grep -q '"kind":"budget"' <<<"$q" && break; sleep 0.1; done; echo "$q"; }
  qid() { sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$1"; }
  calls() { grep -c '"type":"message"' "$WORK/raise.out"; }

  AGENTOS_CONFIG="$CFG" "$AGENT" do --agent raiser --budget 0.5usd raise me >"$WORK/raise.out" 2>&1 &
  RUN_PID=$!
  Q="$(budget_ask)"
  check "a used-up budget asks you in the console, while the model call waits" grep -q "\"target\":\"this task's budget\"" <<<"$Q"
  check "...with what's spent" grep -q '"reason":"\$0.60 of \$0.50"' <<<"$Q"
  check "...and what to raise it to" grep -q '"offers":\["\$0.90","\$1.20"\]' <<<"$Q"
  api -X POST -d '{"decision":"raise","to":"$1.20"}' "$CONSOLE/api/approvals/$(qid "$Q")" >/dev/null
  wait $RUN_PID
  events="$(latest_task_dir)/events.jsonl"
  check "the agent was told it would be asked" grep -q "budget used up (\$0.60 of \$0.50): you're asked before the next model call goes" "$WORK/raise.out"
  check "raising it lets the waiting call through" test "$(calls)" = 3
  check "...and the task runs to the end" grep -q done-calling "$WORK/raise.out"
  check "the raise is journaled, with where you answered" grep -q '"kind":"budget.raised".*"by":"agentd console"' "$events"
  check "agent log shows it" grep -q "this task's budget raised to \$1.20 (from \$0.50), by you in agentd's console, when asked" <<<"$("$AGENT" log)"
  ID="$("$AGENT" ls | sed -n 2p | cut -d' ' -f1)"
  check "the task keeps the budget you raised it to" grep -q '"budget":"\$1.20"' <<<"$(api "$CONSOLE/api/tasks/$ID")"
  check "a task that ended can't be raised" grep -q "isn't running" <<<"$(api -X POST -d '{"to":"5usd"}' "$CONSOLE/api/tasks/$ID/raise")"

  AGENTOS_CONFIG="$CFG" "$AGENT" do --agent raiser --budget 0.5usd say no >"$WORK/raise.out" 2>&1 &
  RUN_PID=$!
  Q="$(budget_ask)"
  api -X POST -d '{"decision":"deny"}' "$CONSOLE/api/approvals/$(qid "$Q")" >/dev/null
  wait $RUN_PID
  check "saying no refuses the call, as before" grep -q 'invalid_request_error' "$WORK/raise.out"
  check "...and is journaled" grep -q '"kind":"budget.declined".*"why":"denied"' "$(latest_task_dir)/events.jsonl"

  AGENTOS_CONFIG="$CFG" "$AGENT" do --agent raiser --budget 0.5usd raise it elsewhere >"$WORK/raise.out" 2>&1 &
  RUN_PID=$!
  Q="$(budget_ask)"
  check "agent raise refuses less than it is" grep -q 'already \$0.50' <<<"$("$AGENT" raise 0.4usd 2>&1)"
  check "...or less than what's spent" grep -q '\$0.60 is spent already' <<<"$("$AGENT" raise 0.55usd 2>&1)"
  check "agent raise raises the running task's budget" grep -q 'budget is now \$2.00 (was \$0.50)' <<<"$("$AGENT" raise 2usd 2>&1)"
  wait $RUN_PID
  check "...and the waiting call goes on" test "$(calls)" = 3
  check "...its question gone from the console" lacks '"kind":"budget"' "$(api "$CONSOLE/api/approvals")"
  check "...journaled: by you at the terminal" grep -q '"kind":"budget.raised".*"by":"terminal"' "$(latest_task_dir)/events.jsonl"
  kill $SERVE_PID 2>/dev/null
  wait $SERVE_PID 2>/dev/null

  # Across tasks: today's budget, raised until midnight.
  SAVED_HOME="$AGENTOS_HOME"
  export AGENTOS_HOME="$WORK/store-raise"
  printf '[limits]\ndaily = "0.5usd"\n' > "$CFG"
  r3() { AGENTOS_CONFIG="$CFG" "$AGENT" "$@"; }
  r3 do --agent onecall one >/dev/null 2>&1
  r3 do --agent onecall two >/dev/null 2>&1
  out="$(r3 do --agent onecall three 2>&1)"
  check "a task that can't start says how to raise today's budget" grep -q 'agent raise 0.9usd --today' <<<"$out"
  check "...in its own unit" grep -q 'counted in dollars' <<<"$(r3 raise 2M --today 2>&1)"
  check "...and only if there's one" grep -q 'no weekly budget to raise' <<<"$(r3 raise 2usd --this-week 2>&1)"
  check "agent raise --today raises it until midnight" grep -q "today's budget for all your tasks is now \$1.00 (was \$0.50), until it resets at midnight" <<<"$(r3 raise 1usd --today 2>&1)"
  check "...so the next task starts" grep -q 'spend: today \$0.60 of \$1.00 (all your tasks; raised from \$0.50)' <<<"$(r3 do --agent onecall four 2>&1)"
  check "agent spend shows it raised" grep -Eq 'today +\$0.90 · 330k of \$1.00 \(raised from \$0.50\)' <<<"$(r3 spend)"
  start_agentd AGENTOS_CONFIG="$CFG"
  sp="$(api "$CONSOLE/api/spend")"
  check "the console shows today's spend against the budget" grep -q '"spent":"\$0.90 of \$1.00"' <<<"$sp"
  check "...that it was raised" grep -q '"raised":true' <<<"$sp"
  check "...and today's tasks by what they spent" grep -q '"title":"onecall: four","spent":"\$0.30"' <<<"$sp"
  check "raise today's budget from the console" grep -q 'is now \$3.00 (was \$1.00)' <<<"$(api -X POST -d '{"period":"daily","to":"3usd"}' "$CONSOLE/api/spend/raise")"
  check "...not below what it is" grep -q '"error":.*already \$3.00' <<<"$(api -X POST -d '{"period":"daily","to":"2usd"}' "$CONSOLE/api/spend/raise")"
  kill $SERVE_PID 2>/dev/null
  wait $SERVE_PID 2>/dev/null
  export AGENTOS_HOME="$SAVED_HOME"
  rm -f "$WORK/cfg/agents/raiser.toml" "$WORK/cfg/agents/onecall.toml"
  : > "$CFG"
fi

section "what a budget can't count is refused"
if ! curl -sS -m 10 -o /dev/null https://api.anthropic.com 2>/dev/null || ! curl -sS -m 10 -o /dev/null https://api.openai.com 2>/dev/null; then
  skip "needs api.anthropic.com and api.openai.com to answer (no key needed: the refusals happen before anything is sent)"
else
  reset_proj
  cd "$PROJ"
  # api_post BODY HOST/PATH [agent run flags…]
  api_post() { local body="$1" url="$2"; shift 2; "$AGENT" run --allow api.anthropic.com --allow api.openai.com "$@" -- curl -sS -m 20 -X POST -H content-type:application/json -d "$body" "https://$url" 2>&1; }
  out="$(api_post '{"requests":[]}' api.anthropic.com/v1/messages/batches --budget 1usd)"
  check "under a budget, a Message Batch is refused before it's sent" grep -q "Message Batches are billed when they finish, so this call can't count against the budget" <<<"$out"
  check "...in the API's own error format" grep -q '"type":"invalid_request_error"' <<<"$out"
  check "...journaled" grep -q '"kind":"model.unmeterable".*"refused":true' "$(latest_task_dir)/events.jsonl"
  check "...and agent log says why" grep -q 'api.anthropic.com/v1/messages/batches refused under a budget: Message Batches' <<<"$("$AGENT" log)"
  out="$(api_post '{"model":"gpt-5","input":"hi","background":true}' api.openai.com/v1/responses --budget 1usd)"
  check "...as is a background response" grep -q 'background responses are billed when they finish' <<<"$out"
  out="$(api_post '{"model":"gpt-5","input":"hi"}' api.openai.com/v1/responses --budget 1usd)"
  check "a response the agent waits for goes to the provider" grep -q '"error"' <<<"$out"
  check "...not stopped by agentos" lacks 'agentos:' "$out"
  export ANTHROPIC_API_KEY=sk-ant-fake
  out="$(api_post '{"requests":[]}' api.anthropic.com/v1/messages/batches --secret ANTHROPIC_API_KEY=api.anthropic.com/x-api-key)"
  unset ANTHROPIC_API_KEY
  check "without a budget it goes, and you're told it isn't counted" grep -q "Message Batches are billed when they finish: calls to api.anthropic.com/v1/messages/batches aren't counted" <<<"$out"
  check "...reaching the provider" grep -q '"error"' <<<"$out"
fi

section "exit codes and the audit journal"
"$AGENT" run -- sh -c 'exit 7' 2>/dev/null
check "agent exit code propagates" test $? -eq 7
"$AGENT" run -- no-such-command 2>/dev/null
check "missing command exits 127" test $? -eq 127
check "journal chain verifies" grep -q 'chain intact' <<<"$("$AGENT" log)"
sed -i 's/"exit_code":127/"exit_code":0/' "$(latest_task_dir)/events.jsonl"
"$AGENT" log >/dev/null
check "tampering is detected" test $? -eq 1

printf '\n%d passed, %d failed' "$pass" "$fail"
[ "$skipped" -gt 0 ] && printf ', %d sections skipped' "$skipped"
printf '\n'
[ "$fail" -eq 0 ]
