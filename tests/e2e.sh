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
PORT=$((20000 + RANDOM % 10000))
"$AGENT" serve --listen "127.0.0.1:$PORT" >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
for _ in $(seq 50); do [ -s "$AGENTOS_HOME/agentd.json" ] && break; sleep 0.1; done
TOKEN="$(sed -n 's/.*"token": *"\([0-9a-f]*\)".*/\1/p' "$AGENTOS_HOME/agentd.json")"
CONSOLE="http://127.0.0.1:$PORT"
api() { curl -sS -m 10 -H "Authorization: Bearer $TOKEN" "$@"; }
check "agent serve prints a link with a token" grep -q "#token=$TOKEN" "$WORK/serve.log"
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
