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

ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  \033[31m✗\033[0m %s\n' "$1"; fail=$((fail + 1)); }
# check NAME CMD...: pass if CMD succeeds
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
section() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() { chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK" "$HOME/.e2e-secret"; }
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
check "no network by default (only loopback)" "$AGENT" run -- sh -c '! grep -q eth0 /proc/net/dev && grep -q "lo:" /proc/net/dev'
check "--net host shares the network" "$AGENT" run --net host -- sh -c 'grep -q eth0 /proc/net/dev'
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
"$AGENT" rollback >/dev/null
"$AGENT" do again >/dev/null 2>&1
check "agent home persists between tasks" test "$(cat "$AGENT_STATE/runs")" = 2
ANTHROPIC_API_KEY=sk-test-0123456789 "$AGENT" do use the key >/dev/null 2>&1
check "API key is passed to the agent when set" grep -qx 'api-key: set' "$AGENT_STATE/observations"
check "API key value never journaled" bash -c "! grep -rq sk-test-0123456789 '$AGENTOS_HOME/tasks'"
cd "$HOME"
"$AGENT" do something >/dev/null 2>&1
check "refuses to hand over all of \$HOME" test $? -eq 2
cd "$PROJ"
out="$("$AGENT" run "add a test for greet" 2>&1)"
check "a task given to agent run suggests agent do" grep -q 'agent do "add a test for greet"' <<<"$out"
"$AGENT" run -- sh -c 'echo x > made-by-run.txt' 2>/dev/null
check "agent run also grants the current folder" grep -Eq '^  A  .*made-by-run.txt' <<<"$("$AGENT" diff --stat)"
rm -rf "$HOME/.claude"

section "exit codes and the audit journal"
"$AGENT" run -- sh -c 'exit 7' 2>/dev/null
check "agent exit code propagates" test $? -eq 7
"$AGENT" run -- no-such-command 2>/dev/null
check "missing command exits 127" test $? -eq 127
check "journal chain verifies" grep -q 'chain intact' <<<"$("$AGENT" log)"
sed -i 's/"exit_code":127/"exit_code":0/' "$(latest_task_dir)/events.jsonl"
"$AGENT" log >/dev/null
check "tampering is detected" test $? -eq 1

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
