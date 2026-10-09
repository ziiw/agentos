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
# Reads a PNG made by `agent screen` (rows filtered, then deflated): prints "WIDTH HEIGHT NONZERO-BYTES".
png_info() {
  [ -f "$WORK/png-info.py" ] || cat > "$WORK/png-info.py" <<'PY'
import struct, sys, zlib
d = open(sys.argv[1], "rb").read() if sys.argv[1] != "-" else sys.stdin.buffer.read()
assert d[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
i, idat, w, h = 8, b"", 0, 0
while i < len(d):
    n = struct.unpack(">I", d[i:i + 4])[0]
    kind, body = d[i + 4:i + 8], d[i + 8:i + 8 + n]
    assert zlib.crc32(d[i + 4:i + 8 + n]) == struct.unpack(">I", d[i + 8 + n:i + 12 + n])[0], "bad checksum"
    if kind == b"IHDR": w, h = struct.unpack(">II", body[:8])
    if kind == b"IDAT": idat += body
    i += 12 + n
raw = zlib.decompress(idat)
assert len(raw) == h * (1 + 3 * w), "wrong amount of pixels"
def paeth(a, b, c):
    pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
    return a if pa <= pb and pa <= pc else b if pb <= pc else c
stride, prev, lit = 3 * w, bytes(3 * w), 0
for y in range(h):
    kind, row = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
    if kind == 2: row = bytearray((p + q) & 255 for p, q in zip(row, prev))
    elif kind:
        for x in range(stride):
            a, b, c = (row[x - 3], prev[x], prev[x - 3]) if x >= 3 else (0, prev[x], 0)
            row[x] = (row[x] + (a if kind == 1 else (a + b) // 2 if kind == 3 else paeth(a, b, c))) & 255
    lit += sum(1 for v in row if v)
    prev = bytes(row)
print(w, h, lit)
PY
  python3 "$WORK/png-info.py" "$@"
}

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

section "secrets from a command (your keychain)"
reset_proj
cd "$PROJ"
# A stand-in for secret-tool, security or pass: prints the secret named by $1.
mkdir -p "$WORK/tools"
KC_LOG="$WORK/keychain.log"
: > "$KC_LOG"
cat > "$WORK/tools/keychain-get" <<SH
#!/bin/sh
echo "\$1" >> "$KC_LOG"
case "\$1" in
  github) echo "keychain-token-0123456789" ;;
  notes) echo "keychain-notes-0123456789" ;;
  gone) echo "no such item" >&2; exit 44 ;;
  *) exit 1 ;;
esac
SH
chmod +x "$WORK/tools/keychain-get"
KCFG="$WORK/keychain.toml"
cat > "$KCFG" <<TOML
[secrets]
AGENTOS_E2E_KC = "postman-echo.com/x-test-token"
AGENTOS_E2E_GONE = "postman-echo.com/x-gone"
[secret_commands]
AGENTOS_E2E_KC = ["$WORK/tools/keychain-get", "github"]
AGENTOS_E2E_GONE = ["$WORK/tools/keychain-get", "gone"]
TOML
ECHO_HEADERS='echo "in the sandbox: $AGENTOS_E2E_KC"; curl -sS -m 20 -H "x-test-token: $AGENTOS_E2E_KC" https://postman-echo.com/headers'
out="$(AGENTOS_CONFIG="$KCFG" "$AGENT" run --allow postman-echo.com -- sh -c "$ECHO_HEADERS" 2>&1)"
check "a secret that isn't in your environment comes from its command" grep -Eq '"x-test-token": *"keychain-token-0123456789"' <<<"$out"
check "...while the sandbox only has a placeholder" grep -q 'in the sandbox: agentos-placeholder-agentos-e2e-kc-' <<<"$out"
check "...and the value never reaches the journal or the task store" bash -c "! grep -rq keychain-token-0123456789 '$AGENTOS_HOME'"
check "a command that fails is a warning, and the task goes on" grep -q 'AGENTOS_E2E_GONE: keychain-get exited 44: no such item; going on without it' <<<"$out"
n="$(wc -l < "$KC_LOG")"
out="$(AGENTOS_CONFIG="$KCFG" AGENTOS_E2E_KC=from-env "$AGENT" run --allow postman-echo.com -- sh -c "$ECHO_HEADERS" 2>&1)"
check "your environment wins over the command" grep -Eq '"x-test-token": *"from-env"' <<<"$out"
check "...which isn't even run" bash -c '! tail -n +$(($1 + 1)) "$2" | grep -qx github' _ "$n" "$KC_LOG"
n="$(wc -l < "$KC_LOG")"
AGENTOS_CONFIG="$KCFG" "$AGENT" run -- true >/dev/null 2>&1
check "a task that can't use the network doesn't run your commands" test "$(wc -l < "$KC_LOG")" = "$n"
out="$(AGENTOS_CONFIG="$KCFG" "$AGENT" run --secret AGENTOS_E2E_KC=postman-echo.com/x-test-token -- sh -c "$ECHO_HEADERS" 2>&1)"
check "--secret NAME=HOST takes it from there too" grep -Eq '"x-test-token": *"keychain-token-0123456789"' <<<"$out"
out="$(AGENTOS_CONFIG="$KCFG" "$AGENT" run --secret AGENTOS_E2E_GONE=postman-echo.com -- true 2>&1)"
check "...and an explicit --secret that has no value is an error" grep -q 'AGENTOS_E2E_GONE is not set in your environment (or by a \[secret_commands\] entry)' <<<"$out"
printf '[secret_commands]\nGITHUB_TOKEN = ["sh", "-c", "echo hi"]\n' > .agentos.toml
"$AGENT" trust >/dev/null 2>&1
check "a project can't make agentos run a program for a secret" test $? -eq 2
rm -f .agentos.toml
if command -v python3 >/dev/null; then
  cp "$HERE/mcp-client" ./mcp-client
  export NOTES_FILE="$WORK/kc-notes.txt"
  : > "$NOTES_FILE"
  cat > "$KCFG" <<TOML
[secret_commands]
NOTES_TOKEN = ["$WORK/tools/keychain-get", "notes"]
[mcp.notes]
command = ["python3", "$HERE/fake-mcp-server"]
env = ["NOTES_TOKEN", "NOTES_FILE"]
TOML
  out="$(env -u NOTES_TOKEN AGENTOS_CONFIG="$KCFG" "$AGENT" run -- sh -c 'python3 ./mcp-client notes tools/list "tools/call:read_note:{}"' 2>&1 </dev/null)"
  check "an MCP server's variable can come from a command, too" grep -q "read_note: .*token: set" <<<"$out"
  unset NOTES_FILE
else
  skip "the stand-in MCP server needs python3"
fi

section "a server on your machine (--local)"
reset_proj
cd "$PROJ"
if command -v python3 >/dev/null; then
  # Stand-in model servers on this machine's loopback: each prints its port and answers GETs.
  cat > "$WORK/local-server.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"{sys.argv[1]} served {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY
  start_local() {  # NAME → LOCAL_PID, LOCAL_PORT
    python3 "$WORK/local-server.py" "$1" > "$WORK/local.port" &
    LOCAL_PID=$!
    for _ in $(seq 50); do [ -s "$WORK/local.port" ] && break; sleep 0.1; done
    LOCAL_PORT="$(cat "$WORK/local.port")"
    : > "$WORK/local.port"
  }
  start_local models;  MODELS=$LOCAL_PORT; MODELS_PID=$LOCAL_PID
  start_local secrets; OTHER=$LOCAL_PORT;  OTHER_PID=$LOCAL_PID
  GETM="curl -sS -m 10 http://127.0.0.1:$MODELS/v1/models"
  out="$("$AGENT" run --local "$MODELS" -- $GETM 2>&1)"
  check "--local PORT: the agent reaches a server on your loopback, at the same port" grep -q 'models served /v1/models' <<<"$out"
  check "...which the banner says" grep -q "your machine's 127.0.0.1:$MODELS (--local)" <<<"$out"
  check "...and the journal records" grep -Eq "\"kind\":\"net.local\".*\"bytes_in\":[1-9].*\"ok\":true,\"port\":$MODELS" "$(latest_task_dir)/events.jsonl"
  check "...which agent log shows" grep -q "✓ 127.0.0.1:$MODELS (your machine) · ↑" <<<"$("$AGENT" log)"
  check "other ports on your loopback stay out of reach" bash -c '! "$@" 2>/dev/null' _ "$AGENT" run --local "$MODELS" -- curl -sS -m 5 "http://127.0.0.1:$OTHER/"
  check "without --local nothing of your loopback is reachable" bash -c '! "$@" 2>/dev/null' _ "$AGENT" run -- $GETM
  check "the server is reachable with an allowlist too" grep -q 'models served' <<<"$("$AGENT" run --allow example.com --local "$MODELS" -- $GETM 2>&1)"
  printf '[network]\nlocal = [%s]\n' "$MODELS" > "$WORK/local.toml"
  check "[network] local in your config does the same" grep -q 'models served' <<<"$(AGENTOS_CONFIG="$WORK/local.toml" "$AGENT" run -- $GETM 2>&1)"
  printf '[network]\nlocal = [%s]\n' "$OTHER" > .agentos.toml
  "$AGENT" trust >/dev/null 2>&1
  check "a project can't hand its agents your services" test $? -eq 2
  rm -f .agentos.toml
  check "--local with --net host is rejected" bash -c '"$@" 2>&1 | grep -q "already shares yours"' _ "$AGENT" run --net host --local "$MODELS" -- true
  kill "$MODELS_PID" "$OTHER_PID" 2>/dev/null; wait "$MODELS_PID" "$OTHER_PID" 2>/dev/null
  out="$("$AGENT" run --local "$MODELS" -- sh -c "$GETM; echo; $GETM" 2>&1)"
  check "a server that isn't running is explained, once" test "$(grep -c "nothing is listening on 127.0.0.1:$MODELS on this machine" <<<"$out")" -eq 1
  check "...and each try is journaled" grep -q '"kind":"net.local".*"ok":false' "$(latest_task_dir)/events.jsonl"
else
  skip "the local server tests need python3"
fi

section "a screen of its own (--display)"
reset_proj
cd "$PROJ"
if command -v Xvfb >/dev/null && command -v xmessage >/dev/null && command -v xwininfo >/dev/null && command -v python3 >/dev/null; then
  DRAW='echo "display=$DISPLAY auth=$XAUTHORITY"; xdpyinfo | grep dimensions; ls /tmp/.X11-unix; (xmessage -geometry +10+10 "hello from the agent" &); sleep 2; echo "windows=$(xwininfo -root -children | grep -c xmessage)"'
  out="$("$AGENT" run --display -- sh -c "$DRAW" 2>&1)"
  events="$(latest_task_dir)/events.jsonl"
  TASK="$(basename "$(latest_task_dir)")"
  check "--display: the agent has a screen of its own to draw on" grep -q 'display=:0 auth=/run/agentos/xauth' <<<"$out"
  check "...of the default size" grep -q 'dimensions: *1280x800 pixels' <<<"$out"
  check "...which it can draw on" grep -q '^windows=[1-9]' <<<"$out"
  check "...the only display it can see" test "$(grep -c '^X' <<<"$out")" -eq 1
  check "the banner and journal say so" grep -q 'a screen of its own: 1280x800' <<<"$out"
  check "...and journal that it ended with a picture" grep -q '"kind":"display.ended".*"screenshot":true' "$events"
  check "the screen ends with the task" bash -c '! pgrep -x Xvfb >/dev/null'
  "$AGENT" screen -o "$WORK/shot.png" >/dev/null 2>&1
  info="$(png_info "$WORK/shot.png" 2>&1)"
  check "agent screen saves the last picture as a PNG of the right size" grep -Eq '^1280 800 ' <<<"$info"
  check "...with what the agent drew in it" test "$(cut -d' ' -f3 <<<"$info")" -gt 10000
  check "agent screen -o - writes it to a pipe" grep -Eq '^1280 800 ' <<<"$("$AGENT" screen "$TASK" -o - | png_info - 2>&1)"
  if command -v script >/dev/null; then
    check "...and not to a terminal" grep -q 'not for your terminal' <<<"$(script -qec "$AGENT screen -o -" /dev/null 2>&1)"
  fi
  out="$("$AGENT" run --display-size 800x600 -- sh -c 'xdpyinfo | grep dimensions' 2>&1)"
  check "--display-size sets it (and implies --display)" grep -q 'dimensions: *800x600' <<<"$out"
  check "a bad size is refused" grep -q 'a screen is between' <<<"$("$AGENT" run --display-size 10x10 -- true 2>&1)"
  "$AGENT" run -- true >/dev/null 2>&1
  check "a task without a screen says so" grep -q 'has no screen' <<<"$("$AGENT" screen 2>&1)"
  AGENT_BIN="$(command -v "$AGENT")"
  check "without Xvfb, --display says what to install" grep -q 'needs Xvfb' <<<"$(PATH=/nonexistent "$AGENT_BIN" run --display -- true 2>&1)"
  # While it runs, too.
  id="$("$AGENT" run --bg --display -- sh -c '(xmessage -geometry +10+10 "still here" &); sleep 12' 2>/dev/null | tail -1)"
  nonzero=0
  for _ in $(seq 40); do
    "$AGENT" screen "$id" -o "$WORK/live.png" >/dev/null 2>&1 && nonzero="$(png_info "$WORK/live.png" 2>/dev/null | cut -d' ' -f3)"
    [ "${nonzero:-0}" -gt 10000 ] && break
    sleep 0.25
  done
  check "agent screen shows a running task's screen as it is" test "${nonzero:-0}" -gt 10000
  "$AGENT" stop "$id" >/dev/null 2>&1; "$AGENT" wait "$id" >/dev/null 2>&1
  check "...and stopping the task ends its screen too" bash -c '! pgrep -x Xvfb >/dev/null'
  "$AGENT" rollback >/dev/null 2>&1
else
  skip "screens need Xvfb, xmessage and xwininfo (Debian, Ubuntu: apt install xvfb x11-utils)"
fi

section "the console shows a screen, and lets you act on it"
reset_proj
cd "$PROJ"
if command -v Xvfb >/dev/null && command -v xev >/dev/null && command -v stdbuf >/dev/null && command -v xdotool >/dev/null && command -v python3 >/dev/null; then
  start_agentd
  as() { local t="$1"; shift; curl -sS -m 10 -H "Authorization: Bearer $t" "$@"; }
  # How much of a picture isn't black (0 when it can't be fetched).
  drawn() { as "$1" "$CONSOLE/api/tasks/$2/screen.png${3:-}" 2>/dev/null | png_info - 2>/dev/null | cut -d' ' -f3; }
  tok() { sed -n 's/.*#token=\([0-9a-f]*\).*/\1/p'; }
  WATCHER="$("$AGENT" users add vera --role viewer | tok)"
  HELPER="$("$AGENT" users add alex --role approver | tok)"
  # xev shows what the window is sent: the output of a background task is kept in its folder.
  id="$("$AGENT" run --bg --display -- sh -c '(stdbuf -oL xev -geometry 300x200+0+0 -event button -event keyboard &); sleep 40' 2>/dev/null | tail -1)"
  n=0
  for _ in $(seq 60); do n="$(drawn "$TOKEN" "$id")"; [ "${n:-0}" -gt 10000 ] && break; sleep 0.25; done
  check "the console serves a running task's screen as a PNG" test "${n:-0}" -gt 10000
  check "...also scaled down, for a phone" test "$(as "$TOKEN" "$CONSOLE/api/tasks/$id/screen.png?w=320" | png_info - | cut -d' ' -f1)" -eq 320
  check "...to a viewer too" test "$(drawn "$WATCHER" "$id")" -gt 10000
  check "the task says it has a screen" grep -q '"screen":{"width":1280,"height":800,"live":true}' <<<"$(as "$TOKEN" "$CONSOLE/api/tasks/$id")"
  "$AGENT" run -- true >/dev/null 2>&1
  check "a task without one says nothing of the kind" grep -q '"screen":null' <<<"$(as "$TOKEN" "$CONSOLE/api/tasks" | tr -d ' ')"
  check "the page offers to act on it" grep -q 'Act on it' <<<"$(curl -sS -m 10 "$CONSOLE/")"
  OUT="$AGENTOS_HOME/tasks/$id/output.log"
  check "a viewer can't act on the screen" test "$(as "$WATCHER" -o /dev/null -w '%{http_code}' -X POST -d '{"kind":"key","key":"Return"}' "$CONSOLE/api/tasks/$id/input")" = 403
  check "a bad key name is refused" grep -q 'a key is a name like' <<<"$(as "$HELPER" -X POST -d '{"kind":"key","key":"Return; rm -rf"}' "$CONSOLE/api/tasks/$id/input")"
  check "a click outside the screen is refused" grep -q 'outside the 1280x800 screen' <<<"$(as "$HELPER" -X POST -d '{"kind":"click","x":5000,"y":5}' "$CONSOLE/api/tasks/$id/input")"
  waits() { for _ in $(seq 40); do grep -q "$1" "$OUT" 2>/dev/null && return 0; sleep 0.25; done; return 1; }
  check "an approver clicks in the window: the program is sent a ButtonPress" bash -c 'curl -sS -m 10 -H "Authorization: Bearer $1" -X POST -d "{\"kind\":\"click\",\"x\":100,\"y\":100}" "$2/api/tasks/$3/input" | grep -q "\"ok\":true"' _ "$HELPER" "$CONSOLE" "$id"
  check "...and the click arrives" waits ButtonPress
  as "$HELPER" -X POST -d '{"kind":"key","key":"Return"}' "$CONSOLE/api/tasks/$id/input" >/dev/null
  check "pressing Return arrives as that key" waits 'keysym 0xff0d, Return'
  as "$HELPER" -X POST -d '{"kind":"type","text":"q"}' "$CONSOLE/api/tasks/$id/input" >/dev/null
  check "typing arrives as the typed key" waits 'keysym 0x71, q'
  check "what was done at the screen is journaled, by whom" grep -q '"kind":"display.input".*"by":"alex"' "$AGENTOS_HOME/tasks/$id/events.jsonl"
  as "$HELPER" -X POST -d '{"kind":"type","text":"s3cret-typed-text"}' "$CONSOLE/api/tasks/$id/input" >/dev/null
  check "...but never what was typed" bash -c "! grep -q s3cret-typed-text '$AGENTOS_HOME/tasks/$id/events.jsonl'"
  "$AGENT" stop "$id" >/dev/null 2>&1; "$AGENT" wait "$id" >/dev/null 2>&1
  check "after the task, its last picture is still served" test "$(drawn "$TOKEN" "$id")" -gt 10000
  check "...and acting on it isn't possible any more" grep -q 'has no screen up' <<<"$(as "$TOKEN" -X POST -d '{"kind":"key","key":"Return"}' "$CONSOLE/api/tasks/$id/input")"
  kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
  rm -f "$AGENTOS_HOME/users.json"
  "$AGENT" rollback >/dev/null 2>&1
else
  skip "the console's screen needs Xvfb, xev, stdbuf and xdotool (Debian, Ubuntu: apt install xvfb x11-utils xdotool)"
fi

section "a corporate proxy (upstream)"
reset_proj
cd "$PROJ"
if command -v python3 >/dev/null; then
  # A stand-in corporate proxy: logs each CONNECT, optionally wants a login,
  # and tunnels to the real host. Prints its port.
  cat > "$WORK/upstream-proxy.py" <<'PY'
import base64, socket, sys, threading
log = open(sys.argv[1], "a", buffering=1)
want = sys.argv[2] if len(sys.argv) > 2 else None
def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        try: b.shutdown(socket.SHUT_WR)
        except OSError: pass
def handle(c):
    head = b""
    while b"\r\n\r\n" not in head:
        d = c.recv(4096)
        if not d:
            return
        head += d
    first, *lines = head.decode().split("\r\n")
    hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines if ":" in l}
    method, target, _ = first.split(" ", 2)
    log.write(f"{method} {target} auth={'yes' if 'proxy-authorization' in hdrs else 'no'}\n")
    if want and hdrs.get("proxy-authorization") != "Basic " + base64.b64encode(want.encode()).decode():
        c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
        c.close()
        return
    if "refuse" in sys.argv[3:]:
        c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        c.close()
        return
    host, port = target.rsplit(":", 1)
    try:
        u = socket.create_connection((host, int(port)), timeout=10)
    except OSError:
        c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        c.close()
        return
    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    t = threading.Thread(target=pipe, args=(c, u), daemon=True)
    t.start()
    pipe(u, c)
    t.join(5)
    c.close()
    u.close()
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(16)
print(srv.getsockname()[1], flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
  start_upstream() {  # LOG [USER:PASSWORD [refuse]]  → UP_PORT
    : > "$1"
    python3 "$WORK/upstream-proxy.py" "$@" > "$WORK/upstream.port" &
    UP_PID=$!
    for _ in $(seq 50); do [ -s "$WORK/upstream.port" ] && break; sleep 0.1; done
    UP_PORT="$(cat "$WORK/upstream.port")"
    : > "$WORK/upstream.port"
  }
  GETX="curl -sS -m 20 -o /dev/null -w HTTP%{http_code} https://example.com"

  start_upstream "$WORK/up1.log"
  out="$(HTTPS_PROXY=http://127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "HTTPS_PROXY: an allowed host is reached through your proxy" grep -q HTTP200 <<<"$out"
  check "...which saw the CONNECT" grep -q '^CONNECT example.com:443 auth=no' "$WORK/up1.log"
  check "...and the banner and journal say so" grep -q "through your proxy 127.0.0.1:$UP_PORT" <<<"$out"
  check "...with the hop on the connection" grep -q "\"via\":\"127.0.0.1:$UP_PORT\"" "$(latest_task_dir)/events.jsonl"
  check "...which agent log shows" grep -q "example.com:443 .* via 127.0.0.1:$UP_PORT" <<<"$("$AGENT" log)"
  inside="$(HTTPS_PROXY=http://127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- env 2>/dev/null)"
  check "the sandbox has a proxy variable of its own" grep -q '^HTTPS_PROXY=http://127.0.0.1:' <<<"$inside"
  check "...never yours" bash -c '! grep -q "$1" <<<"$2"' _ "$UP_PORT" "$inside"
  before="$(wc -l < "$WORK/up1.log")"
  HTTPS_PROXY=http://127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- curl -sS -m 20 https://example.org >/dev/null 2>&1
  check "other hosts are still refused before they reach it" test "$(wc -l < "$WORK/up1.log")" = "$before"
  out="$(NO_PROXY=example.com HTTPS_PROXY=http://127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "NO_PROXY: hosts it lists are reached directly" grep -q HTTP200 <<<"$out"
  check "...without asking your proxy" test "$(wc -l < "$WORK/up1.log")" = "$before"
  printf '[network]\nproxy = "http://127.0.0.1:%s"\nno_proxy = ["example.org"]\n' "$UP_PORT" > "$WORK/proxy.toml"
  out="$(AGENTOS_CONFIG="$WORK/proxy.toml" "$AGENT" run --allow example.com --allow example.org -- sh -c "$GETX; ${GETX%example.com}example.org" 2>&1)"
  check "[network] proxy in your config does the same" test "$(grep -o HTTP200 <<<"$out" | wc -l)" -eq 2
  check "...for the hosts its no_proxy list doesn't name" grep -q '^CONNECT example.com:443' "$WORK/up1.log"
  check "...and not for those it does" bash -c '! grep -q example.org "$1"' _ "$WORK/up1.log"
  out="$(HTTPS_PROXY=http://127.0.0.1:9 AGENTOS_CONFIG="$WORK/proxy.toml" "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "your config's proxy wins over the environment's" grep -q HTTP200 <<<"$out"
  printf '[network]\nproxy = ""\n' > "$WORK/direct.toml"
  out="$(HTTPS_PROXY=http://127.0.0.1:9 AGENTOS_CONFIG="$WORK/direct.toml" "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "proxy = \"\" connects directly, whatever the environment says" grep -q HTTP200 <<<"$out"
  out="$(HTTPS_PROXY=ftp://127.0.0.1:21 "$AGENT" run --allow example.com -- true 2>&1)"
  check "a proxy it can't use is an error, not a silent bypass" grep -q "ftp:// proxies aren't supported" <<<"$out"
  check "...which a task without the network never hits" env HTTPS_PROXY=ftp://127.0.0.1:21 "$AGENT" run -- true
  printf '[network]\nproxy = "http://127.0.0.1:%s"\n' "$UP_PORT" > .agentos.toml
  "$AGENT" trust >/dev/null 2>&1
  check "a project can't choose where your traffic goes" test $? -eq 2
  rm -f .agentos.toml
  out="$(HTTPS_PROXY=http://127.0.0.1:$UP_PORT AGENTOS_E2E_TOKEN=proxied-secret-value "$AGENT" run --secret AGENTOS_E2E_TOKEN=postman-echo.com/x-test-token -- sh -c 'curl -sS -m 20 -H "x-test-token: $AGENTOS_E2E_TOKEN" https://postman-echo.com/headers' 2>&1)"
  check "brokered credentials work through it too" grep -Eq '"x-test-token": *"proxied-secret-value"' <<<"$out"
  check "...with the CONNECT to the broker's host" grep -q '^CONNECT postman-echo.com:443' "$WORK/up1.log"
  kill "$UP_PID" 2>/dev/null; wait "$UP_PID" 2>/dev/null

  start_upstream "$WORK/up2.log" 'alice:s3cret-proxy-pw'
  out="$(HTTPS_PROXY=http://alice:s3cret-proxy-pw@127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "a proxy that wants a login gets it from the address" grep -q HTTP200 <<<"$out"
  check "...as Proxy-Authorization" grep -q '^CONNECT example.com:443 auth=yes' "$WORK/up2.log"
  check "...never shown in the banner" bash -c '! grep -q s3cret-proxy-pw <<<"$1"' _ "$out"
  check "...nor written to the journal or the task store" bash -c "! grep -rq s3cret-proxy-pw '$AGENTOS_HOME'"
  out="$(HTTPS_PROXY=http://alice:wrong@127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "a wrong password is refused, and the agent is told why" grep -q 'wants a login (407)' <<<"$out"
  kill "$UP_PID" 2>/dev/null; wait "$UP_PID" 2>/dev/null

  start_upstream "$WORK/up3.log" "" refuse
  out="$(HTTPS_PROXY=http://127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "a proxy that refuses is explained" grep -q 'upstream proxy 127.0.0.1:[0-9]* refused: HTTP/1.1 403 Forbidden' <<<"$out"
  check "...and the refusal is journaled" grep -q '"allowed":false.*"reason":"the upstream proxy' "$(latest_task_dir)/events.jsonl"
  kill "$UP_PID" 2>/dev/null; wait "$UP_PID" 2>/dev/null
  out="$(HTTPS_PROXY=http://127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "a proxy that is down is explained" grep -q "can't reach the upstream proxy" <<<"$out"
  # A SOCKS5 proxy (an `ssh -D` tunnel, say): the name goes to it, and it connects.
  cat > "$WORK/socks-proxy.py" <<'PY'
import socket, struct, sys, threading
log = open(sys.argv[1], "a", buffering=1)
login = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
def recv(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise EOFError
        b += d
    return b
def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        try: b.shutdown(socket.SHUT_WR)
        except OSError: pass
def handle(c):
    try:
        _, n = recv(c, 2)
        methods = recv(c, n)
        if login:
            if 2 not in methods:
                c.sendall(b"\x05\xff"); return
            c.sendall(b"\x05\x02")
            _, ul = recv(c, 2); user = recv(c, ul); pl = recv(c, 1)[0]; pw = recv(c, pl)
            if f"{user.decode()}:{pw.decode()}" != login:
                c.sendall(b"\x01\x01"); return
            c.sendall(b"\x01\x00")
        else:
            c.sendall(b"\x05\x00")
        _, _, _, atyp = recv(c, 4)
        if atyp == 3:
            host = recv(c, recv(c, 1)[0]).decode()
        elif atyp == 1:
            host = socket.inet_ntoa(recv(c, 4))
        else:
            c.sendall(b"\x05\x08\x00\x01" + bytes(6)); return
        port = struct.unpack(">H", recv(c, 2))[0]
        log.write(f"SOCKS {host}:{port} atyp={atyp}\n")
        try:
            u = socket.create_connection((host, port), timeout=10)
        except OSError:
            c.sendall(b"\x05\x05\x00\x01" + bytes(6)); return
        c.sendall(b"\x05\x00\x00\x01" + bytes(4) + struct.pack(">H", 0))
        t = threading.Thread(target=pipe, args=(c, u), daemon=True)
        t.start(); pipe(u, c); t.join(5); u.close()
    except EOFError:
        pass
    finally:
        c.close()
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(16)
print(srv.getsockname()[1], flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
  start_socks() {  # LOG [USER:PASSWORD] → UP_PORT, UP_PID
    : > "$1"
    python3 "$WORK/socks-proxy.py" "$@" > "$WORK/upstream.port" &
    UP_PID=$!
    for _ in $(seq 50); do [ -s "$WORK/upstream.port" ] && break; sleep 0.1; done
    UP_PORT="$(cat "$WORK/upstream.port")"
    : > "$WORK/upstream.port"
  }
  start_socks "$WORK/socks1.log"
  out="$(HTTPS_PROXY=socks5://127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "socks5://: an allowed host is reached through the SOCKS proxy" grep -q HTTP200 <<<"$out"
  check "...which was asked for the name, not an address" grep -q '^SOCKS example.com:443 atyp=3' "$WORK/socks1.log"
  check "...and the journal says which proxy" grep -q "\"via\":\"127.0.0.1:$UP_PORT\"" "$(latest_task_dir)/events.jsonl"
  out="$(ALL_PROXY=socks5://127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "ALL_PROXY works too" grep -q HTTP200 <<<"$out"
  kill "$UP_PID" 2>/dev/null; wait "$UP_PID" 2>/dev/null
  start_socks "$WORK/socks2.log" 'alice:s3cret-socks-pw'
  out="$(HTTPS_PROXY=socks5://alice:s3cret-socks-pw@127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "a SOCKS proxy that wants a login gets it from the address" grep -q HTTP200 <<<"$out"
  check "...which never reaches the banner, journal or store" bash -c "! grep -rq s3cret-socks-pw '$AGENTOS_HOME'"
  out="$(HTTPS_PROXY=socks5://alice:wrong@127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "a wrong password is explained" grep -q 'refused that login' <<<"$out"
  out="$(HTTPS_PROXY=socks5://127.0.0.1:$UP_PORT "$AGENT" run --allow example.com -- $GETX 2>&1)"
  check "no login at all is explained too" grep -q 'accepts no login method we have' <<<"$out"
  kill "$UP_PID" 2>/dev/null; wait "$UP_PID" 2>/dev/null
else
  skip "the corporate proxy tests need python3"
fi

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

section "team access to agentd (users and roles)"
reset_proj
cd "$PROJ"
check "agent users starts empty" grep -q 'nobody besides you' <<<"$("$AGENT" users)"
tok() { sed -n 's/.*#token=\([0-9a-f]*\).*/\1/p'; }
VIEW="$("$AGENT" users add vera --role viewer | tok)"
APPR="$("$AGENT" users add alex --role approver | tok)"
ADMN="$("$AGENT" users add dana --role admin | tok)"
out="$("$AGENT" users)"
check "agent users lists them with what their roles may do" grep -Eq 'alex +approver +also answers questions' <<<"$out"
check "a name that's yours is refused" bash -c '! "$@" 2>/dev/null' _ "$AGENT" users add you
check "...and so is a second token for one person" bash -c '! "$@" 2>/dev/null' _ "$AGENT" users add vera
check "only hashes are kept" bash -c "! grep -q '$VIEW' '$AGENTOS_HOME/users.json'"
start_agentd
as() { local t="$1"; shift; curl -sS -m 10 -H "Authorization: Bearer $t" "$@"; }
code() { local t="$1"; shift; curl -sS -m 10 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $t" "$@"; }
check "yours is the owner's" grep -q '"name":"you","role":"admin","owner":true' <<<"$(as "$TOKEN" "$CONSOLE/api/whoami")"
check "a person's token says who they are" grep -q '"name":"vera","role":"viewer","owner":false' <<<"$(as "$VIEW" "$CONSOLE/api/whoami")"
check "a viewer reads tasks" test "$(code "$VIEW" "$CONSOLE/api/tasks")" = 200
check "...but can't answer questions" test "$(code "$VIEW" -X POST -d '{"decision":"deny"}' "$CONSOLE/api/approvals/0000")" = 403
check "...or stop a task" test "$(code "$VIEW" -X POST "$CONSOLE/api/tasks/0000/stop")" = 403
check "...or start one" test "$(code "$VIEW" -X POST -d '{}' "$CONSOLE/api/tasks")" = 403
check "an approver can't start tasks or commit either" test "$(code "$APPR" -X POST -d '{}' "$CONSOLE/api/tasks")$(code "$APPR" -X POST "$CONSOLE/api/tasks/0000/commit")" = 403403
check "a token nobody has is refused" test "$(code deadbeefdeadbeefdeadbeefdeadbeef "$CONSOLE/api/tasks")" = 401
check "the 403 says what it needs" grep -q 'vera is a viewer: that needs an approver' <<<"$(as "$VIEW" -X POST -d '{"decision":"deny"}' "$CONSOLE/api/approvals/0000")"
"$AGENT" run --ask -- curl -sS -m 30 -o /dev/null -w 'HTTP%{http_code}' https://example.com >"$WORK/team.out" 2>&1 </dev/null &
RUN_PID=$!
Q=""
for _ in $(seq 100); do Q="$(as "$VIEW" "$CONSOLE/api/approvals")"; grep -q '"id"' <<<"$Q" && break; sleep 0.1; done
check "a viewer sees the question" grep -q '"target":"example.com"' <<<"$Q"
QID="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$Q")"
check "an approver answers it" grep -q '"ok":true' <<<"$(as "$APPR" -X POST -d '{"decision":"once"}' "$CONSOLE/api/approvals/$QID")"
wait $RUN_PID
check "...and the connection goes through" grep -q HTTP200 "$WORK/team.out"
check "the task's journal says who answered" grep -q '"kind":"console.action".*"action":"answered example.com".*"by":"alex"\|"kind":"console.action".*"by":"alex".*"action":"answered example.com"' "$(latest_task_dir)/events.jsonl"
"$AGENT" run -- sh -c 'echo from-team > team.txt' 2>/dev/null
ID="$("$AGENT" ls | sed -n 2p | cut -d' ' -f1)"
check "an admin commits from the console" grep -q '"ok":true' <<<"$(as "$ADMN" -X POST "$CONSOLE/api/tasks/$ID/commit")"
check "...and the journal says who" grep -q '"by":"dana".*"role":"admin"\|"action":"commit".*"by":"dana"' "$AGENTOS_HOME/tasks/$ID/events.jsonl"
check "...and the journal still verifies" grep -q 'chain intact' <<<"$("$AGENT" log "$ID")"
"$AGENT" users remove vera >/dev/null
check "a removed token stops working" test "$(code "$VIEW" "$CONSOLE/api/tasks")" = 401
check "...the others don't" test "$(code "$APPR" "$CONSOLE/api/tasks")" = 200

# A token can be limited to projects: it sees their tasks, and nothing else is even there.
mkdir -p "$WORK/proj2"
( cd "$WORK/proj2" && "$AGENT" run -- sh -c 'echo two > two.txt' >/dev/null 2>&1 )
ID2="$("$AGENT" ls | sed -n 2p | cut -d' ' -f1)"
out="$("$AGENT" users add pia --role admin --project "$PROJ")"
PIA="$(tok <<<"$out")"
check "agent users add says what the token is limited to" grep -q "only the tasks that ran in $PROJ" <<<"$out"
check "agent users lists the limit" grep -Eq "pia +admin .*only $PROJ" <<<"$("$AGENT" users)"
check "a project that isn't a folder is refused" bash -c '! "$@" 2>/dev/null' _ "$AGENT" users add rex --role admin --project "$WORK/nonexistent"
check "whoami says what a token is limited to" grep -q "\"projects\":\[\"$PROJ\"\]" <<<"$(as "$PIA" "$CONSOLE/api/whoami")"
check "a limited token sees its project's tasks" grep -q "\"id\":\"$ID\"" <<<"$(as "$PIA" "$CONSOLE/api/tasks")"
check "...and not another project's" bash -c '! grep -q "$1" <<<"$2"' _ "$ID2" "$(as "$PIA" "$CONSOLE/api/tasks")"
check "...which you still see" grep -q "\"id\":\"$ID2\"" <<<"$(as "$TOKEN" "$CONSOLE/api/tasks")"
other="$(as "$PIA" "$CONSOLE/api/tasks/$ID2" | sed "s/$ID2/ID/")"
bogus="$(as "$PIA" "$CONSOLE/api/tasks/ffffffff" | sed "s/ffffffff/ID/")"
check "another project's task looks like one that doesn't exist" test "$other" = "$bogus"
check "...whatever is done to it" test "$(code "$PIA" -X POST "$CONSOLE/api/tasks/$ID2/commit")" = 400
check "...so nothing of it was committed" test ! -f "$WORK/proj2/two.txt"
check "...and not by the start of its id either" grep -q "no task matching" <<<"$(as "$PIA" "$CONSOLE/api/tasks/${ID2:0:4}")"
check "a limited token can't start a task elsewhere" test "$(code "$PIA" -X POST -d "{\"project\":\"$WORK/proj2\",\"task\":\"x\"}" "$CONSOLE/api/tasks")" = 403
check "...and the 403 says where it may" grep -q "pia's token is limited to $PROJ" <<<"$(as "$PIA" -X POST -d "{\"project\":\"$WORK/proj2\",\"task\":\"x\"}" "$CONSOLE/api/tasks")"
check "...a path with .. doesn't get around it" test "$(code "$PIA" -X POST -d "{\"project\":\"$PROJ/../proj2\",\"task\":\"x\"}" "$CONSOLE/api/tasks")" = 403
check "budgets across tasks aren't for a limited token" test "$(code "$PIA" "$CONSOLE/api/spend")" = 403
check "the new-task form offers a limited token its projects only" bash -c '! grep -q proj2 <<<"$1"' _ "$(as "$PIA" "$CONSOLE/api/launchpad")"
check "...yours offers both" grep -q "$WORK/proj2" <<<"$(as "$TOKEN" "$CONSOLE/api/launchpad")"
( cd "$WORK/proj2" && exec "$AGENT" run --ask -- curl -sS -m 30 -o /dev/null -w 'HTTP%{http_code}' https://example.com ) >"$WORK/scoped.out" 2>&1 </dev/null &
SCOPED_PID=$!
Q=""
for _ in $(seq 100); do Q="$(as "$TOKEN" "$CONSOLE/api/approvals")"; grep -q '"id"' <<<"$Q" && break; sleep 0.1; done
QID2="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$Q")"
check "a question from another project reaches you" test -n "$QID2"
check "...but not a limited token" bash -c '! grep -q "\"id\"" <<<"$1"' _ "$(as "$PIA" "$CONSOLE/api/approvals")"
check "...which can't answer it either" grep -q "no such question" <<<"$(as "$PIA" -X POST -d '{"decision":"once"}' "$CONSOLE/api/approvals/$QID2")"
as "$TOKEN" -X POST -d '{"decision":"once"}' "$CONSOLE/api/approvals/$QID2" >/dev/null
wait $SCOPED_PID
check "...and the task went on waiting for you" grep -q HTTP200 "$WORK/scoped.out"
check "a limited token reads its own project's task in full" grep -q "\"id\":\"$ID\".*\"diff\"" <<<"$(as "$PIA" "$CONSOLE/api/tasks/$ID")"
kill $SERVE_PID 2>/dev/null
wait $SERVE_PID 2>/dev/null
rm -f "$AGENTOS_HOME/users.json"

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
# (If this ever fails in CI, say what was asked: it failed once on an arm runner, unexplained.)
if grep -q -- '.ssh' "$WORK/questions" 2>/dev/null; then echo "    questions seen: $(head -c 1500 "$WORK/questions")"; fi
check "...and the question never reached you" lacks '.ssh' "$(cat "$WORK/questions" 2>/dev/null)"
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

section "agent packages (an agent, and what it asks for)"
reset_proj
cd "$PROJ"
PKGCFG="$WORK/pkgcfg/config.toml"
mkdir -p "$WORK/pkgcfg"
: > "$PKGCFG"
export AGENTOS_PACKAGES="$WORK/packages"
pk() { AGENTOS_CONFIG="$PKGCFG" "$AGENT" "$@"; }
SRC="$WORK/pkg-src"
mkdir -p "$SRC/bin"
echo 'readable by the package' > "$WORK/pkg-reads"
cat > "$SRC/bin/run" <<'SH'
#!/bin/sh
echo "pkg-agent got: $*"
echo "mode: ${E2E_PKG_MODE:-unset}"
case "${E2E_PKG_KEY:-}" in agentos-placeholder-*) echo "key: placeholder" ;; "") echo "key: none" ;; *) echo "key: real" ;; esac
echo "reads: $(cat "$E2E_PKG_READS" 2>/dev/null || echo cannot)"
if echo x > "$(dirname "$0")/tamper" 2>/dev/null; then echo "tamper: wrote"; else echo "tamper: read-only"; fi
echo done > pkg-ran.txt
SH
chmod +x "$SRC/bin/run"
echo 'a stand-in agent that ships its own program' > "$SRC/README"
cat > "$SRC/agentos-package.toml" <<TOML
[package]
name = "e2e-pkg"
version = "0.1.0"
description = "A stand-in agent that ships its own program"

[agent]
run = ["{pkg}/bin/run", "{task}"]
allow = ["example.com"]
local = [47999]
ro = ["$WORK/pkg-reads"]

[agent.secrets]
E2E_PKG_KEY = "postman-echo.com/x-test-token"

[agent.env]
E2E_PKG_MODE = "test"
E2E_PKG_READS = "$WORK/pkg-reads"
TOML
out="$(pk install "$SRC" </dev/null 2>&1)"
check "install shows what the package asks for: hosts" grep -q 'network      example.com' <<<"$out"
check "...secrets" grep -q 'secret       E2E_PKG_KEY → postman-echo.com/x-test-token' <<<"$out"
check "...your machine" grep -q 'your machine 127.0.0.1:47999' <<<"$out"
check "...what it reads" grep -q "reads        $WORK/pkg-reads (read-only)" <<<"$out"
check "...and with no terminal to answer at, installs nothing" test ! -e "$WORK/packages/e2e-pkg"
digest="$(sed -n 's/^  digest  \([0-9a-f]*\) .*/\1/p' <<<"$out")"
check "--digest refuses a package that isn't the one you read" grep -q "isn't the one you meant" <<<"$(pk install "$SRC" --yes --digest 00000000 2>&1)"
check "...and --yes with its digest installs it" grep -q 'installed to' <<<"$(pk install "$SRC" --yes --digest "$digest" 2>&1)"
check "agent packages lists it, intact" grep -Eq 'e2e-pkg +0.1.0 .*intact' <<<"$(pk packages)"
check "agent agents lists the agent it wrote" grep -q 'e2e-pkg' <<<"$(pk agents)"
out="$(E2E_PKG_KEY=real-pkg-key pk do --agent e2e-pkg hello world 2>&1)"
check "agent do --agent runs the package's own program" grep -q 'pkg-agent got: hello world' <<<"$out"
check "...with the environment it declared" grep -q 'mode: test' <<<"$out"
check "...its secret as a placeholder" grep -q 'key: placeholder' <<<"$out"
check "...the file it asked to read" grep -q 'reads: readable by the package' <<<"$out"
check "...and its own files read-only" grep -q 'tamper: read-only' <<<"$out"
echo '# edited on the host' >> "$WORK/packages/e2e-pkg/bin/run"
out="$(pk do --agent e2e-pkg again 2>&1)"
check "a package changed since you installed it won't run" grep -q 'package e2e-pkg changed since you installed it (bin/run changed)' <<<"$out"
check "...and agent packages says what" grep -q 'CHANGED: bin/run changed' <<<"$(pk packages)"
check "...and fails" bash -c '! "$@" >/dev/null' _ env AGENTOS_CONFIG="$PKGCFG" "$AGENT" packages
pk install "$SRC" --yes >/dev/null 2>&1
check "installing it again puts it right" grep -q 'pkg-agent got: again' <<<"$(pk do --agent e2e-pkg again 2>&1)"
sed -i 's/"example.com"/"example.com", "evil.example"/' "$WORK/pkgcfg/agents/e2e-pkg.toml"
out="$(pk do --agent e2e-pkg widened 2>&1)"
check "an agent file edited to ask for more won't run either" grep -q 'e2e-pkg.toml changed since you installed package e2e-pkg' <<<"$out"
pk install "$SRC" --yes >/dev/null 2>&1
sed -i 's/version = "0.1.0"/version = "0.2.0"/; s/allow = \["example.com"\]/allow = ["example.com", "pypi.org"]/' "$SRC/agentos-package.toml"
out="$(pk install "$SRC" --yes 2>&1)"
check "an upgrade shows what it asks for now, against what you approved" grep -q 'installed now: e2e-pkg 0.1.0' <<<"$out"
check "...the new host" grep -q '+ network      example.com, pypi.org' <<<"$out"
check "...and the one it replaced" grep -q -- '- network      example.com$' <<<"$out"
ln -s /etc/passwd "$SRC/link"
check "a package with a symlink is refused" grep -q "symlinks aren't allowed" <<<"$(pk install "$SRC" --yes 2>&1)"
rm "$SRC/link"
mkdir -p "$WORK/pkgcfg/agents"
printf 'run = ["true"]\n' > "$WORK/pkgcfg/agents/mine.toml"
sed 's/name = "e2e-pkg"/name = "mine"/' "$SRC/agentos-package.toml" > "$SRC/other.toml"
mv "$SRC/other.toml" "$SRC/agentos-package.toml"
check "a package can't replace an agent file of yours" grep -q 'an agent file of yours with that name' <<<"$(pk install "$SRC" --yes 2>&1)"
sed -i 's/name = "mine"/name = "claude"/' "$SRC/agentos-package.toml"
check "...nor take the built-in agent's name" grep -q 'claude is built in' <<<"$(pk install "$SRC" --yes 2>&1)"
check "agent uninstall removes the package and its agent" grep -q 'removed package e2e-pkg' <<<"$(pk uninstall e2e-pkg 2>&1)"
check "...the files" test ! -e "$WORK/packages/e2e-pkg"
check "...and the agent file" test ! -e "$WORK/pkgcfg/agents/e2e-pkg.toml"
check "...but not an agent file of yours" test -f "$WORK/pkgcfg/agents/mine.toml"
check "uninstalling what isn't installed says so" grep -q 'no package named e2e-pkg' <<<"$(pk uninstall e2e-pkg 2>&1)"
out="$(pk install "$HERE/../examples/packages/echo-agent" --yes 2>&1)"
check "the example package installs" grep -q 'installed to' <<<"$out"
out="$(pk do --agent echo-agent hello there 2>&1)"
check "...and runs in a sandbox, its own files read-only" bash -c 'grep -q "echo-agent was asked: hello there" <<<"$1" && grep -q "  yes" <<<"$1"' _ "$out"
pk uninstall echo-agent >/dev/null 2>&1
unset AGENTOS_PACKAGES

section "a registry of agent packages"
reset_proj
cd "$PROJ"
if command -v python3 >/dev/null && command -v tar >/dev/null; then
  REG="$WORK/registry"
  mkdir -p "$REG" "$WORK/reg-src/e2e-reg/bin" "$WORK/regcfg"
  cat > "$WORK/reg-src/e2e-reg/bin/run" <<'SH'
#!/bin/sh
echo "registry agent got: $*"
SH
  chmod +x "$WORK/reg-src/e2e-reg/bin/run"
  cat > "$WORK/reg-src/e2e-reg/agentos-package.toml" <<'TOML'
[package]
name = "e2e-reg"
version = "0.1.0"
description = "A package that comes from a registry"

[agent]
run = ["{pkg}/bin/run", "{task}"]
allow = ["example.com"]
TOML
  tar czf "$REG/e2e-reg-0.1.0.tar.gz" -C "$WORK/reg-src" e2e-reg
  GOODSHA="$(sha256sum "$REG/e2e-reg-0.1.0.tar.gz" | cut -d' ' -f1)"
  python3 - "$REG" "$WORK/reg-src/e2e-reg" <<'PY'
import io, os, sys, tarfile
reg, src = sys.argv[1:3]
def add_tree(t):
    for name in ("agentos-package.toml", "bin/run"):
        t.add(os.path.join(src, name), arcname=name)
with tarfile.open(os.path.join(reg, "traversal.tar.gz"), "w:gz") as t:
    add_tree(t)
    info = tarfile.TarInfo("../escape.txt"); info.size = 1
    t.addfile(info, io.BytesIO(b"x"))
with tarfile.open(os.path.join(reg, "linked.tar.gz"), "w:gz") as t:
    add_tree(t)
    link = tarfile.TarInfo("passwd"); link.type = tarfile.SYMTYPE; link.linkname = "/etc/passwd"
    t.addfile(link)
PY
  sha() { sha256sum "$REG/$1" | cut -d' ' -f1; }
  cat > "$REG/index.json" <<JSON
{ "packages": {
  "e2e-reg":   { "version": "0.1.0", "description": "A package that comes from a registry", "url": "e2e-reg-0.1.0.tar.gz", "sha256": "$GOODSHA" },
  "forged":    { "version": "0.1.0", "description": "Not the tarball it names", "url": "e2e-reg-0.1.0.tar.gz", "sha256": "$(printf 0%.0s $(seq 64))" },
  "traversal": { "version": "0.1.0", "description": "Reaches outside its folder", "url": "traversal.tar.gz", "sha256": "$(sha traversal.tar.gz)" },
  "linked":    { "version": "0.1.0", "description": "Carries a symlink", "url": "linked.tar.gz", "sha256": "$(sha linked.tar.gz)" },
  "lying":     { "version": "0.1.0", "description": "Vouches for another package", "url": "e2e-reg-0.1.0.tar.gz", "sha256": "$GOODSHA", "digest": "00000000000000000000" }
} }
JSON
  RPORT=$((20000 + RANDOM % 10000))
  python3 -m http.server "$RPORT" --bind 127.0.0.1 --directory "$REG" >/dev/null 2>&1 &
  REG_PID=$!
  for _ in $(seq 50); do curl -sf -m 2 "http://127.0.0.1:$RPORT/index.json" >/dev/null 2>&1 && break; sleep 0.1; done
  RCFG="$WORK/regcfg/config.toml"
  printf '[registry]\nurl = "http://127.0.0.1:%s/index.json"\n' "$RPORT" > "$RCFG"
  export AGENTOS_PACKAGES="$WORK/regpackages"
  rg() { AGENTOS_CONFIG="$RCFG" "$AGENT" "$@"; }
  out="$(rg search 2>&1)"
  check "agent search lists what your registry has" grep -Eq 'e2e-reg +0.1.0 +A package that comes from a registry' <<<"$out"
  check "...or what matches" test "$(rg search symlink 2>&1 | wc -l)" -eq 1
  out="$(rg install e2e-reg </dev/null 2>&1)"
  check "agent install NAME says where it came from, and what it asks for" grep -q "from http://127.0.0.1:$RPORT/e2e-reg-0.1.0.tar.gz" <<<"$out"
  check "...and installs nothing without your yes" test ! -e "$WORK/regpackages/e2e-reg"
  check "--yes installs it" grep -q 'installed to' <<<"$(rg install e2e-reg --yes 2>&1)"
  check "...and it runs" grep -q 'registry agent got: hello' <<<"$(rg do --agent e2e-reg hello 2>&1)"
  check "...and leaves nothing of the download behind" test -z "$(ls -A "$WORK/regpackages" | grep '^.fetch')"
  check "a tarball that isn't the one the index names is refused" grep -q "isn't the tarball the index names" <<<"$(rg install forged --yes 2>&1)"
  check "...a tarball reaching outside its folder" grep -q "couldn't unpack" <<<"$(rg install traversal --yes 2>&1)"
  check "...and nothing of it was written outside" test ! -e "$WORK/regpackages/files/../escape.txt" -a ! -e "$WORK/regpackages/escape.txt"
  check "...a tarball with a symlink" grep -q "symlinks aren't allowed" <<<"$(rg install linked --yes 2>&1)"
  check "...a package whose digest isn't what the index vouches for" grep -q "the registry's index says this package's digest is 00000000000000000000" <<<"$(rg install lying --yes 2>&1)"
  check "a name in neither place is explained" grep -q "isn't a folder here or in your registry" <<<"$(rg install nonesuch --yes 2>&1)"
  check "without a registry, so is the hint" grep -q 'you have no registry' <<<"$(AGENTOS_CONFIG="$WORK/regcfg/none.toml" "$AGENT" install e2e-reg --yes 2>&1)"
  printf '[registry]\nurl = "http://agents.example.com/index.json"\n' > "$WORK/regcfg/plain.toml"
  check "a registry has to be https (or this machine)" grep -q 'a registry is an https' <<<"$(AGENTOS_CONFIG="$WORK/regcfg/plain.toml" "$AGENT" search 2>&1)"
  printf '[registry]\nurl = "https://agents.example.com/index.json"\n' > .agentos.toml
  "$AGENT" trust >/dev/null 2>&1
  check "a project can't choose where your agents come from" test $? -eq 2
  rm -f .agentos.toml
  # A signed index: the publisher's key in your config, and the index has to carry its signature.
  PUB="$("$AGENT" registry keygen "$WORK/publisher.key" | sed -n 's/^  public key  \([0-9a-f]*\)$/\1/p')"
  check "a publisher makes a signing key" test -n "$PUB"
  check "agent registry sign writes index.json.sig next to the index" grep -q 'signed' <<<"$("$AGENT" registry sign "$REG/index.json" --key "$WORK/publisher.key")"
  printf '[registry]\nurl = "http://127.0.0.1:%s/index.json"\nkey = "%s"\n' "$RPORT" "$PUB" > "$WORK/regcfg/signed.toml"
  rs() { AGENTOS_CONFIG="$WORK/regcfg/signed.toml" "$AGENT" "$@"; }
  check "with the publisher's key, a signed index is read" grep -q 'e2e-reg' <<<"$(rs search 2>&1)"
  check "...and its packages install" grep -q 'installed to' <<<"$(rs install e2e-reg --yes 2>&1)"
  cp "$REG/index.json" "$WORK/index.good"
  sed -i 's/A package that comes from a registry/A package that was edited/' "$REG/index.json"
  check "an index edited after signing is refused, unread" grep -q "its signature isn't the key's: nothing was read" <<<"$(rs search 2>&1)"
  cp "$WORK/index.good" "$REG/index.json"
  mv "$REG/index.json.sig" "$WORK/index.sig.bak"
  check "an index without its signature is refused" grep -q 'must be signed by the key in your config' <<<"$(rs search 2>&1)"
  mv "$WORK/index.sig.bak" "$REG/index.json.sig"
  OTHER="$("$AGENT" registry keygen "$WORK/other.key" | sed -n 's/^  public key  \([0-9a-f]*\)$/\1/p')"
  printf '[registry]\nurl = "http://127.0.0.1:%s/index.json"\nkey = "%s"\n' "$RPORT" "$OTHER" > "$WORK/regcfg/other.toml"
  check "another publisher's key refuses it" grep -q "its signature isn't the key's" <<<"$(AGENTOS_CONFIG="$WORK/regcfg/other.toml" "$AGENT" search 2>&1)"
  check "keygen never overwrites a key" bash -c '! "$@" 2>/dev/null' _ "$AGENT" registry keygen "$WORK/publisher.key"
  printf '[registry]\nurl = "http://127.0.0.1:%s/index.json"\nkey = "abc"\n' "$RPORT" > "$WORK/regcfg/badkey.toml"
  check "a key that isn't a key is a config error" grep -q 'expected an Ed25519 public key' <<<"$(AGENTOS_CONFIG="$WORK/regcfg/badkey.toml" "$AGENT" search 2>&1)"
  # Changing keys: the publisher signs with the old and the new one, and readers move when they like.
  out="$("$AGENT" registry keygen "$WORK/new.key")"
  NEW="$(sed -n 's/^  public key  \([0-9a-f]*\)$/\1/p' <<<"$out")"
  NEWID="$(sed -n 's/^  key id      \([0-9a-f]*\)$/\1/p' <<<"$out")"
  check "keygen names a key by a short id" test "${#NEWID}" -eq 16
  out="$("$AGENT" registry sign "$REG/index.json" --key "$WORK/publisher.key" --key "$WORK/new.key")"
  check "a publisher can sign with two keys at once" test "$(wc -l < "$REG/index.json.sig")" -eq 2
  check "...and is told which" grep -q "key $NEWID" <<<"$out"
  printf '[registry]\nurl = "http://127.0.0.1:%s/index.json"\nkey = "%s"\n' "$RPORT" "$NEW" > "$WORK/regcfg/new.toml"
  printf '[registry]\nurl = "http://127.0.0.1:%s/index.json"\nkey = ["%s", "%s"]\n' "$RPORT" "$OTHER" "$NEW" > "$WORK/regcfg/list.toml"
  printf '[registry]\nurl = "http://127.0.0.1:%s/index.json"\nkey = []\n' "$RPORT" > "$WORK/regcfg/empty.toml"
  rn() { AGENTOS_CONFIG="$WORK/regcfg/$1.toml" "$AGENT" search 2>&1; }
  check "a reader with the old key still accepts it" grep -q 'e2e-reg' <<<"$(rs search 2>&1)"
  check "...and one who has moved to the new key" grep -q 'e2e-reg' <<<"$(rn new)"
  check "...and search says which key signed it" grep -q "the index is signed by key $NEWID" <<<"$(rn new)"
  check "a list of keys accepts any one of them" grep -q "signed by key $NEWID" <<<"$(rn list)"
  "$AGENT" registry sign "$REG/index.json" --key "$WORK/new.key" >/dev/null
  check "once the old key stops signing, a reader who hasn't moved is refused" grep -q "its signature isn't the key's: nothing was read" <<<"$(rs search 2>&1)"
  check "...while one who lists both reads it" grep -q "signed by key $NEWID" <<<"$(rn list)"
  printf '[registry]\nurl = "http://127.0.0.1:%s/index.json"\nkey = ["%s", "%s"]\n' "$RPORT" "$OTHER" "$PUB" > "$WORK/regcfg/neither.toml"
  check "a list without the signer's key refuses it" grep -q "none of the keys in your config signed it" <<<"$(rn neither)"
  check "an empty list of keys is a config error, not no protection" grep -q "nobody's signature is needed" <<<"$(rn empty)"
  "$AGENT" registry sign "$REG/index.json" --key "$WORK/publisher.key" >/dev/null
  # The publisher's side: pack a package, serve the folder, install it by name.
  cp -r "$HERE/../examples/packages/echo-agent" "$WORK/pack-src"
  PUBDIR="$WORK/published"
  out="$("$AGENT" registry pack "$WORK/pack-src" -o "$PUBDIR" 2>&1)"
  check "agent registry pack makes a tarball and an index entry" test -f "$PUBDIR/echo-agent-0.1.0.tar.gz" -a -f "$PUBDIR/index.json"
  PACKED="$(sed -n 's/^  digest  \([0-9a-f]*\)$/\1/p' <<<"$out")"
  check "...with the package's digest, which agent install shows too" grep -q "digest  ${PACKED:0:16}" <<<"$("$AGENT" install "$WORK/pack-src" </dev/null 2>&1)"
  check "...and the program is executable in the tarball, under the package's name" bash -c 'tar tvzf "$1" | grep -Eq "^-rwxr-xr-x .*echo-agent/bin/run$"' _ "$PUBDIR/echo-agent-0.1.0.tar.gz"
  first="$(sha256sum "$PUBDIR/echo-agent-0.1.0.tar.gz" | cut -d' ' -f1)"
  sleep 1; touch "$WORK/pack-src/bin/run" "$WORK/pack-src/agentos-package.toml"
  "$AGENT" registry pack "$WORK/pack-src" -o "$PUBDIR" >/dev/null 2>&1
  check "the same files make the same tarball" test "$(sha256sum "$PUBDIR/echo-agent-0.1.0.tar.gz" | cut -d' ' -f1)" = "$first"
  printf '# edited\n' >> "$WORK/pack-src/bin/run"
  "$AGENT" registry pack "$WORK/pack-src" -o "$PUBDIR" >/dev/null 2>&1
  check "...and other files, another" test "$(sha256sum "$PUBDIR/echo-agent-0.1.0.tar.gz" | cut -d' ' -f1)" != "$first"
  PPORT=$((20000 + RANDOM % 10000))
  python3 -m http.server "$PPORT" --bind 127.0.0.1 --directory "$PUBDIR" >/dev/null 2>&1 &
  PUB_PID=$!
  for _ in $(seq 50); do curl -sf -m 2 "http://127.0.0.1:$PPORT/index.json" >/dev/null 2>&1 && break; sleep 0.1; done
  printf '[registry]\nurl = "http://127.0.0.1:%s/index.json"\n' "$PPORT" > "$WORK/regcfg/pub.toml"
  out="$(AGENTOS_CONFIG="$WORK/regcfg/pub.toml" "$AGENT" install echo-agent --yes 2>&1)"
  check "a package packed here installs by name from wherever the folder is served" grep -q 'installed to' <<<"$out"
  check "...and runs" grep -q 'echo-agent was asked: from the registry' <<<"$(AGENTOS_CONFIG="$WORK/regcfg/pub.toml" "$AGENT" do --agent echo-agent from the registry 2>&1)"
  kill "$PUB_PID" 2>/dev/null; wait "$PUB_PID" 2>/dev/null
  unset AGENTOS_PACKAGES
  kill "$REG_PID" 2>/dev/null; wait "$REG_PID" 2>/dev/null
else
  skip "the registry tests need python3 and tar"
fi

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

section "services on your machine (D-Bus as MCP servers)"
BUS_PID=
if command -v python3 >/dev/null && command -v busctl >/dev/null && command -v dbus-daemon >/dev/null; then
  # A bus of its own, so nothing here touches yours.
  mkdir -p "$WORK/dbus"
  dbus-daemon --session --address="unix:path=$WORK/dbus/bus" --nofork --nopidfile >/dev/null 2>&1 &
  BUS_PID=$!
  for _ in $(seq 50); do [ -S "$WORK/dbus/bus" ] && break; sleep 0.1; done
fi
if [ ! -S "$WORK/dbus/bus" ]; then
  skip "D-Bus tools need python3, busctl (systemd) and a dbus-daemon that starts"
else
  reset_proj
  cd "$PROJ"
  cp "$HERE/mcp-client" ./mcp-client
  DCFG="$WORK/dbuscfg/config.toml"
  mkdir -p "$(dirname "$DCFG")"
  write_dcfg() { cat > "$DCFG" <<TOML
[mcp.bus]
dbus = "session"
services = ["org.freedesktop.DBus", "org.example.*"]
$1
TOML
  }
  bb() { DBUS_SESSION_BUS_ADDRESS="unix:path=$WORK/dbus/bus" AGENTOS_CONFIG="$DCFG" "$AGENT" "$@"; }
  write_dcfg 'tools = { dbus_call = "allow" }'
  D='"service":"org.freedesktop.DBus","path":"/org/freedesktop/DBus"'
  I='"interface":"org.freedesktop.DBus"'
  CALLS=(
    tools/list
    'tools/call:dbus_services:{}'
    "tools/call:dbus_introspect:{$D}"
    "tools/call:dbus_get:{$D,$I,\"property\":\"Features\"}"
    "tools/call:dbus_call:{$D,$I,\"method\":\"NameHasOwner\",\"args\":[\"org.freedesktop.DBus\"]}"
    "tools/call:dbus_call:{$D,$I,\"method\":\"NameHasOwner\",\"args\":[\"--user\"]}"
    "tools/call:dbus_call:{$D,$I,\"method\":\"UpdateActivationEnvironment\",\"args\":[{\"E2E_VAR\":\"a b\"}]}"
    "tools/call:dbus_call:{$D,$I,\"method\":\"GetNameOwner\",\"args\":[5]}"
    'tools/call:dbus_call:{"service":"org.freedesktop.secrets","path":"/","interface":"org.freedesktop.Secret.Service","method":"OpenSession"}'
  )
  out="$(bb run -- python3 ./mcp-client bus "${CALLS[@]}" 2>&1 </dev/null)"
  events="$(latest_task_dir)/events.jsonl"
  check "the bus's tools are listed" grep -q '^tools: dbus_services,dbus_introspect,dbus_get,dbus_call$' <<<"$out"
  check "services lists the ones you named that are there, and only those" grep -q 'dbus_services: {"bus":"session","allowed":\["org.freedesktop.DBus","org.example.\*"\],"services":\[{"name":"org.freedesktop.DBus","running":true}\]}' <<<"$out"
  check "an object's methods come with their types" grep -q 'method NameHasOwner(s) -> b' <<<"$out"
  check "a property is read" grep -q 'dbus_get: {"type":"as","data":\[.*"HeaderFiltering"' <<<"$out"
  check "a method is called with its arguments as JSON" grep -q 'dbus_call: {"type":"b","data":\[true\]}' <<<"$out"
  check "...a value that looks like an option is only a value" grep -q 'dbus_call: {"type":"b","data":\[false\]}' <<<"$out"
  check "...a dict goes through" grep -q 'dbus_call: (it returned nothing)' <<<"$out"
  check "...the wrong type is explained before anything is sent" grep -q 'dbus_call: args\[0\]: expected a string (type s), got 5 \[error\]' <<<"$out"
  check "a service you didn't list is out of reach" grep -q "isn't a service this server may use. It can reach: org.freedesktop.DBus, org.example.\* \[error\]" <<<"$out"
  check "reads are journaled as read-only" grep -q '"kind":"mcp.call".*"decision":"read-only".*"server":"bus","tool":"dbus_get"' "$events"
  check "calls are journaled as allowed, with their arguments" grep -q '"kind":"mcp.call".*NameHasOwner.*"decision":"allowed".*"server":"bus","tool":"dbus_call"' "$events"
  out="$(bb run -- sh -c "echo \"bus address in the sandbox: \${DBUS_SESSION_BUS_ADDRESS:-unset}\"; DBUS_SESSION_BUS_ADDRESS=unix:path=$WORK/dbus/bus busctl --user --no-pager list >/dev/null 2>&1 && echo 'the bus itself: reached' || echo 'the bus itself: unreachable'" 2>&1 </dev/null)"
  check "the sandbox isn't told where your bus is" grep -q 'bus address in the sandbox: unset' <<<"$out"
  check "...and can't reach it" grep -q 'the bus itself: unreachable' <<<"$out"

  # One method of a service can be forbidden, whatever the config allows.
  cat > "$(dirname "$DCFG")/policy.cedar" <<'CEDAR'
@id("no activation environment")
forbid (principal, action == Action::"call", resource == Tool::"bus.dbus_call")
when { context.args has method && context.args.method == "UpdateActivationEnvironment" };
CEDAR
  out="$(bb run -- python3 ./mcp-client bus tools/list "tools/call:dbus_call:{$D,$I,\"method\":\"UpdateActivationEnvironment\",\"args\":[{\"E2E_VAR\":\"x\"}]}" "tools/call:dbus_call:{$D,$I,\"method\":\"NameHasOwner\",\"args\":[\"org.freedesktop.DBus\"]}" 2>&1 </dev/null)"
  check "a rule can forbid one method of a service" grep -q 'rules forbid this call' <<<"$out"
  check "...and the rest still works" grep -q 'dbus_call: {"type":"b","data":\[true\]}' <<<"$out"
  check "...which the journal says" grep -q '"decision":"forbidden".*"rule":"no activation environment"' "$(latest_task_dir)/events.jsonl"
  rm -f "$(dirname "$DCFG")/policy.cedar"

  # A call can wait for your review, like any tool's.
  write_dcfg 'hold = true'
  out="$(bb run -- python3 ./mcp-client bus tools/list "tools/call:dbus_call:{$D,$I,\"method\":\"UpdateActivationEnvironment\",\"args\":[{\"E2E_HELD\":\"1\"}]}" "tools/call:dbus_get:{$D,$I,\"property\":\"Features\"}" 2>&1 </dev/null)"
  check "a call can be held for review" grep -q 'dbus_call: Queued, not done yet: bus.dbus_call is held' <<<"$out"
  check "...while reads still run" grep -q 'dbus_get: {"type":"as"' <<<"$out"
  check "agent diff lists it with its arguments" grep -q 'bus.dbus_call .*UpdateActivationEnvironment' <<<"$(bb diff 2>&1)"
  check "agent commit makes the call, through the same bridge" grep -q 'ran bus.dbus_call: (it returned nothing)' <<<"$(bb commit 2>&1)"

  # A bus is a lot of power: a list of services is not optional.
  printf '[mcp.bus]\ndbus = "session"\n' > "$DCFG"
  check "a bus without a list of services is refused" grep -q 'name the services it may reach' <<<"$(bb run -- true 2>&1)"
  kill "$BUS_PID" 2>/dev/null; wait "$BUS_PID" 2>/dev/null
  rm -f mcp-client
  : > "$DCFG"
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

section "held tool calls: the outbox for tools, released when you commit"
if ! command -v python3 >/dev/null; then
  skip "the stand-in MCP server needs python3"
else
  reset_proj
  cd "$PROJ"
  cp "$HERE/mcp-client" ./mcp-client
  export NOTES_FILE="$WORK/held-notes.txt"
  : > "$NOTES_FILE"
  write_cfg() { cat > "$CFG" <<TOML
[mcp.notes]
command = ["python3", "$HERE/fake-mcp-server"]
env = ["NOTES_FILE"]
$1
TOML
  }
  write_cfg 'tools = { post_note = "hold" }'
  hh() { AGENTOS_CONFIG="$CFG" "$AGENT" "$@"; }
  CALLS=(tools/list 'tools/call:post_note:{"text":"one"}' 'tools/call:read_note:{}' 'tools/call:post_note:{"text":"two"}')
  out="$(hh run -- python3 ./mcp-client notes "${CALLS[@]}" 2>&1 </dev/null)"
  events="$(latest_task_dir)/events.jsonl"
  check "a held call isn't run: the agent is told it's queued" grep -q 'post_note: Queued, not done yet: notes.post_note is held for the user to review' <<<"$out"
  check "...it has NOT happened" test ! -s "$NOTES_FILE"
  check "read-only tools still run live" grep -q 'read_note: notes:' <<<"$out"
  check "the summary lists what is held" grep -q '2 tool calls (notes.post_note, notes.post_note) held for review' <<<"$out"
  check "each is journaled as held" test "$(grep -c '"decision":"held"' "$events")" = 2
  d="$(hh diff 2>&1)"
  check "agent diff shows them with their arguments" grep -q 'held tool calls' <<<"$d"
  check "...in order" grep -q 'notes.post_note  {"text":"one"}' <<<"$d"
  check "agent ls marks the task" grep -q '⏸2' <<<"$(hh ls)"
  out="$(hh commit 2>&1)"
  check "agent commit runs them, from outside the sandbox" grep -q 'ran notes.post_note: posted' <<<"$out"
  check "...in the order they were made" test "$(tr '\n' ',' < "$NOTES_FILE")" = "one,two,"
  check "...and the task is done" grep -q 'committed' <<<"$(hh ls)"
  check "each run is journaled with its result" test "$(grep -c '"kind":"outbox.called"' "$(latest_task_dir)/events.jsonl")" = 2

  # Rolling back drops them.
  : > "$NOTES_FILE"
  hh run -- python3 ./mcp-client notes tools/list 'tools/call:post_note:{"text":"never"}' >/dev/null 2>&1 </dev/null
  out="$(hh rollback 2>&1)"
  check "agent rollback drops held calls" grep -q '1 held tool call' <<<"$out"
  check "...and they never run" test ! -s "$NOTES_FILE"
  check "...it's journaled which" grep -q '"calls":\[{"arguments":"{\\"text\\":\\"never\\"}","call":"notes.post_note"' "$(latest_task_dir)/events.jsonl"

  # A server can hold all its tools that change things.
  write_cfg 'hold = true'
  out="$(hh run -- python3 ./mcp-client notes tools/list 'tools/call:post_note:{"text":"x"}' 'tools/call:drop_notes:{}' 'tools/call:read_note:{}' 2>&1 </dev/null)"
  check "hold = true holds every tool that isn't read-only" grep -q '2 tool calls (notes.post_note, notes.drop_notes) held for review' <<<"$out"
  check "...and read-only ones still run" grep -q 'read_note: notes:' <<<"$out"
  hh rollback >/dev/null 2>&1

  # Held, a tainted task isn't asked: nothing goes out until you look.
  write_cfg $'taint = true\ntools = { post_note = "allow", drop_notes = "hold" }'
  out="$(hh run -- python3 ./mcp-client notes tools/list 'tools/call:read_note:{}' 'tools/call:drop_notes:{}' 'tools/call:post_note:{"text":"y"}' 2>&1 </dev/null)"
  check "a tainted task's held call is held, not asked about" grep -q 'drop_notes: Queued, not done yet' <<<"$out"
  check "...while its allowed one is asked about, as before" grep -q 'post_note: agentos: .*nobody can be asked' <<<"$out"
  hh rollback >/dev/null 2>&1

  # A call that fails when released stays held.
  write_cfg 'tools = { post_note = "hold" }'
  hh run -- python3 ./mcp-client notes tools/list 'tools/call:post_note:{"text":"later"}' >/dev/null 2>&1 </dev/null
  cat > "$CFG" <<TOML
[mcp.notes]
command = ["no-such-server-0xdead"]
TOML
  out="$(hh commit 2>&1)"
  check "a call that can't run says so" grep -q '✗ tool call.*notes.post_note' <<<"$out"
  check "...and stays held, with the way to retry" grep -q '1 tool call still held. Once you.ve sorted it out: .agent push' <<<"$out"
  check "...commit exits non-zero" test "$(hh commit >/dev/null 2>&1; echo $?)" != 0
  write_cfg 'tools = { post_note = "hold" }'
  out="$(hh push 2>&1)"
  check "agent push runs what's still held" grep -q 'ran notes.post_note' <<<"$out"
  check "...once" grep -qx later "$NOTES_FILE"

  # [h] when you're asked.
  write_cfg ''
  start_agentd
  ( for _ in $(seq 600); do
      q="$(api "$CONSOLE/api/approvals")"
      id="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$q")"
      [ -n "$id" ] && api -X POST -d '{"decision":"hold"}' "$CONSOLE/api/approvals/$id" >/dev/null
      sleep 0.1
    done ) &
  ANSWERER=$!
  : > "$NOTES_FILE"
  out="$(hh run --ask -- python3 ./mcp-client notes tools/list 'tools/call:post_note:{"text":"asked"}' 2>&1 </dev/null)"
  kill $ANSWERER 2>/dev/null; wait $ANSWERER 2>/dev/null
  kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
  check "answering [h] when asked holds the call" grep -q 'post_note: Queued, not done yet' <<<"$out"
  check "...journaled as your choice" grep -q '"decision":"held by you"' "$(latest_task_dir)/events.jsonl"
  check "...and nothing happened yet" test ! -s "$NOTES_FILE"
  hh commit >/dev/null 2>&1
  check "...until you commit" grep -qx asked "$NOTES_FILE"
  rm -f mcp-client
  unset NOTES_FILE
  : > "$CFG"
fi

section "held API requests (the outbox for HTTP)"
reset_proj
cd "$PROJ"
# postman-echo.com answers a POST with what it received: a 200 means the request got there.
HCFG="$WORK/hold.toml"
printf '[secrets]\nAGENTOS_E2E_HOLD = "postman-echo.com/x-test-token"\n' > "$HCFG"
hh2() { AGENTOS_CONFIG="$HCFG" AGENTOS_E2E_HOLD=held-secret-value "$AGENT" "$@"; }
POSTX='curl -sS -m 20 -X POST -H "x-test-token: $AGENTOS_E2E_HOLD" -d "hello=held" https://postman-echo.com/post'
out="$(hh2 run --hold postman-echo.com -- sh -c "$POSTX; echo; curl -sS -m 20 'https://postman-echo.com/get?read=1'" 2>&1)"
events="$(latest_task_dir)/events.jsonl"
HELD_TASK="$(basename "$(latest_task_dir)")"
check "--hold: a write to the host is answered with a 202 that says it was held" grep -q "was held for the user's review and has not been sent" <<<"$out"
check "...while a read of the same host goes through" grep -q '"read": *"1"' <<<"$out"
check "...the task says so at the start" grep -q 'writes to postman-echo.com wait for your review (--hold)' <<<"$out"
check "...and when it happens" grep -q 'held POST postman-echo.com/post until you commit' <<<"$out"
check "...and in the exit summary" grep -q '1 API request (POST postman-echo.com/post)' <<<"$out"
check "the journal records it" grep -q '"kind":"outbox.held_request".*"request":"POST postman-echo.com/post"' "$events"
check "...and the connection that carried it relayed nothing" grep -q '"kind":"net.connect".*"requests":0' "$events"
d="$("$AGENT" diff)"
check "agent diff lists the held request" grep -q 'held API requests (sent by `agent commit`' <<<"$d"
check "...with its method and URL" grep -q 'POST postman-echo.com/post' <<<"$d"
check "...and a preview of the body" grep -q 'hello=held' <<<"$d"
start_agentd AGENTOS_CONFIG="$HCFG"
check "the console counts held calls and requests with the task" grep -q '"calls":1' <<<"$(curl -sS -m 10 -H "Authorization: Bearer $TOKEN" "$CONSOLE/api/tasks/$HELD_TASK")"
kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
check "the credential is nowhere in the task store" bash -c "! grep -rq held-secret-value '$AGENTOS_HOME'"
out="$("$AGENT" commit 2>&1)"
check "a commit without the credential's value can't send it" grep -q 'AGENTOS_E2E_HOLD isn.t set in your environment' <<<"$out"
check "...so it stays held" grep -q 'POST postman-echo.com/post' <<<"$("$AGENT" diff)"
out="$(hh2 commit 2>&1)"
check "agent commit sends it, with the credential put back" grep -Eq 'sent POST postman-echo.com/post → 200' <<<"$out"
check "...and it is no longer held" test -z "$(ls "$AGENTOS_HOME/tasks/$HELD_TASK/held-calls" 2>/dev/null)"
check "...journaled as called" grep -q '"kind":"outbox.called".*"server":"http"' "$AGENTOS_HOME/tasks/$HELD_TASK/events.jsonl"
check "...and the credential still isn't in the store" bash -c "! grep -rq held-secret-value '$AGENTOS_HOME'"
hh2 run --hold postman-echo.com -- sh -c "$POSTX" >/dev/null 2>&1
out="$("$AGENT" rollback 2>&1)"
check "agent rollback drops a held request" grep -q '1 held API request' <<<"$out"
printf '[network]\nhold = ["postman-echo.com"]\n[secrets]\nAGENTOS_E2E_HOLD = "postman-echo.com/x-test-token"\n' > "$HCFG"
out="$(hh2 run -- sh -c "$POSTX" 2>&1)"
check "[network] hold in your config does the same, for tasks with a network" grep -q "has not been sent" <<<"$out"
hh2 rollback >/dev/null 2>&1
check "--hold wants a host name, not a pattern" grep -q "isn't a host name" <<<"$("$AGENT" run --hold '*.example.com' -- true 2>&1)"
check "--hold with --net host is rejected" grep -q 'contradict' <<<"$("$AGENT" run --net host --hold example.com -- true 2>&1)"
printf '[network]\nhold = ["example.com"]\n' > .agentos.toml
"$AGENT" trust >/dev/null 2>&1
check "a project may ask for holds too (it only restricts)" test $? -eq 0
rm -f .agentos.toml

section "rules that release what a task left held"
reset_proj
cd "$PROJ"
RELDIR="$WORK/rel"
mkdir -p "$RELDIR"
printf '[secrets]\nAGENTOS_E2E_HOLD = "postman-echo.com/x-test-token"\n' > "$RELDIR/config.toml"
cat > "$RELDIR/policy.cedar" <<'CEDAR'
@id("posts to the echo may go")
permit (principal, action == Action::"release", resource)
when { resource has method && resource.method == "POST" && resource.host == "postman-echo.com" && resource.path == "/post" };
CEDAR
rl() { AGENTOS_CONFIG="$RELDIR/config.toml" AGENTOS_E2E_HOLD=held-secret-value "$AGENT" "$@"; }
out="$(rl run --hold postman-echo.com -- sh -c 'curl -sS -m 20 -X POST -H "x-test-token: $AGENTOS_E2E_HOLD" -d a=1 https://postman-echo.com/post >/dev/null; curl -sS -m 20 -X PUT -d b=2 https://postman-echo.com/put >/dev/null' 2>&1)"
check "a held request your rules permit is sent when the task ends" grep -q 'released by your rules: POST postman-echo.com/post' <<<"$out"
check "...and the line says which rule" grep -q 'posts to the echo may go' <<<"$out"
check "...with its credential put back (the echo took it)" grep -Eq 'sent POST postman-echo.com/post → 200' <<<"$out"
check "what no rule permits stays held" grep -q '1 API request (PUT postman-echo.com/put)' <<<"$out"
check "...and only that is left to review" test "$(grep -c '^  ⏸' <<<"$(rl diff)")" -eq 1
check "the journal records the release and the rule" grep -q '"kind":"outbox.released".*"rule":"posts to the echo may go"' "$(latest_task_dir)/events.jsonl"
rl rollback >/dev/null 2>&1
check "agent policy check release asks the same question" grep -q 'permitted by .*posts to the echo may go' <<<"$(rl policy check release POST:postman-echo.com/post)"
check "...and a method no rule names stays undecided" grep -q 'no rule' <<<"$(rl policy check release PUT:postman-echo.com/put)"
cat >> "$RELDIR/policy.cedar" <<'CEDAR'
@id("never the echo")
forbid (principal, action == Action::"release", resource)
when { resource has host && resource.host == "postman-echo.com" };
CEDAR
check "a forbid beats the permit" grep -q 'forbidden by your rule .*never the echo' <<<"$(rl policy check release POST:postman-echo.com/post)"
out="$(rl run --hold postman-echo.com -- sh -c 'curl -sS -m 20 -X POST -d a=1 https://postman-echo.com/post >/dev/null' 2>&1)"
check "...so that request waits" grep -q '1 API request (POST postman-echo.com/post)' <<<"$out"
rl rollback >/dev/null 2>&1
if command -v git >/dev/null; then
  REMOTE2="$WORK/rel-remote.git"
  me2() { git -c user.name=me -c user.email=me@example.com "$@"; }
  AGIT2='git -c user.name=agent -c user.email=agent@example.com'
  rm -rf "$REMOTE2" "$PROJ" && git init -q --bare "$REMOTE2"
  mkdir -p "$PROJ" && cd "$PROJ" && git init -q -b main && git remote add origin "$REMOTE2"
  echo one > a.txt && git add a.txt && me2 commit -qm one && git push -q origin main
  MAIN_BEFORE="$(git --git-dir="$REMOTE2" rev-parse main)"
  cat > "$RELDIR/policy.cedar" <<'CEDAR'
@id("agent branches may go")
permit (principal, action == Action::"release", resource)
when { resource has branch && resource.remote == "origin" && resource.branch like "agent/*" };
@id("never main")
forbid (principal, action == Action::"release", resource)
when { resource has branch && resource.branch == "main" };
CEDAR
  out="$(rl run -- sh -c "$AGIT2 commit -q --allow-empty -m a1 && git push -q origin HEAD:refs/heads/agent/fix && git push -q origin HEAD:refs/heads/feature && git push -q origin HEAD:refs/heads/main" 2>&1)"
  check "a held push your rules permit is sent when the task ends" test -n "$(git --git-dir="$REMOTE2" rev-parse -q --verify refs/heads/agent/fix)"
  check "...and says so" grep -q 'released by your rules: origin agent/fix' <<<"$out"
  check "the pushes no rule permits wait" test -z "$(git --git-dir="$REMOTE2" rev-parse -q --verify refs/heads/feature)"
  check "...and so does the one a forbid names" test "$(git --git-dir="$REMOTE2" rev-parse main)" = "$MAIN_BEFORE"
  check "...both still held for review" grep -q '2 git pushes (origin feature, origin main)' <<<"$out"
  rl rollback >/dev/null 2>&1
else
  skip "releasing pushes needs git"
fi
rm -f "$RELDIR/policy.cedar"

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

section "agents that live for days (schedules in agentd)"
reset_proj
cd "$PROJ"
SAVED_HOME="$AGENTOS_HOME"
export AGENTOS_HOME="$WORK/store-sched"
mkdir -p "$AGENTOS_HOME" "$WORK/sched/agents"
cat > "$WORK/sched/agents/sched-agent.toml" <<'TOML'
run = ["sh", "-c", "echo scheduled: $1", "sh", "{task}"]
TOML
sched_config() {  # NAME EVERY
  printf '[console]\nprojects = ["%s"]\n\n[schedule.%s]\nevery = "%s"\nproject = "%s"\ntask = "triage the issues"\nagent = "sched-agent"\nbudget = "1usd"\ntimeout = "5m"\n' "$PROJ" "$1" "$2" "$PROJ" > "$WORK/sched/config.toml"
}
tasks_started() { ls -d "$AGENTOS_HOME"/tasks/*/ 2>/dev/null | wc -l; }
sc() { AGENTOS_CONFIG="$WORK/sched/config.toml" "$AGENT" "$@"; }
tok() { sed -n 's/.*#token=\([0-9a-f]*\).*/\1/p'; }
# A schedule that came due while agentd was off: one run when it's back, not a catch-up of every missed one.
sched_config overdue 1h
printf '{"overdue":{"first_seen_ms":1000,"last_start_ms":2000,"last_task":null,"runs":4,"skipped":0,"last_error":null}}' > "$AGENTOS_HOME/schedules.json"
check "agent schedules says it's due, and that nothing starts without agentd" bash -c 'out="$(AGENTOS_CONFIG="$1" "$2" schedules 2>&1)"; grep -q "as soon as agentd can" <<<"$out" && grep -q "agentd isn.t running" <<<"$out"' _ "$WORK/sched/config.toml" "$AGENT"
start_agentd AGENTOS_CONFIG="$WORK/sched/config.toml" AGENTOS_MIN_SCHEDULE=1s
api() { curl -sS -m 10 -H "Authorization: Bearer $TOKEN" "$@"; }
for _ in $(seq 60); do [ "$(tasks_started)" -ge 1 ] && break; sleep 0.5; done
check "a schedule that came due while agentd was off runs when it's back" test "$(tasks_started)" -ge 1
sleep 8
check "...once" test "$(tasks_started)" -eq 1
FIRST="$(ls -td "$AGENTOS_HOME"/tasks/*/ | head -1)"
check "the task says which schedule started it" grep -q '"started_by":"agentd schedule overdue"' "${FIRST}events.jsonl"
check "...with the agent, task and budget the schedule names" grep -q 'sched-agent: triage the issues' <<<"$("$AGENT" ls)"
check "agent schedules shows its runs, and the task" grep -Eq "overdue +every 1h .*task $(basename "$FIRST").*5 runs" <<<"$(sc schedules 2>&1)"
check "the console lists it" grep -q '"name":"overdue".*"runs":5' <<<"$(api "$CONSOLE/api/schedules")"
check "Run now starts another, ahead of time" grep -Eq '"id":"[0-9a-f]{8}"' <<<"$(api -X POST -d '{}' "$CONSOLE/api/schedules/overdue/run")"
check "...and a name that isn't there is refused" grep -q 'no \[schedule.nope\]' <<<"$(api -X POST -d '{}' "$CONSOLE/api/schedules/nope/run")"
for _ in $(seq 20); do [ "$(tasks_started)" -ge 2 ] && break; sleep 0.5; done
check "the console's Run now made a second task" test "$(tasks_started)" -eq 2
check "a viewer can't start one" bash -c 'tk="$("$1" users add vera --role viewer | sed -n "s/.*#token=\([0-9a-f]*\).*/\1/p")"; test "$(curl -sS -m 10 -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $tk" -X POST -d "{}" "$2/api/schedules/overdue/run")" = 403' _ "$AGENT" "$CONSOLE"
OTHERP="$WORK/other-proj"; mkdir -p "$OTHERP"
LIM="$("$AGENT" users add lim --role admin --project "$OTHERP" | tok)"
INN="$("$AGENT" users add inn --role admin --project "$PROJ" | tok)"
sas() { local t="$1"; shift; curl -sS -m 10 -H "Authorization: Bearer $t" "$@"; }
check "a token limited to another project sees none of this one's schedules" grep -q '^\[\]$' <<<"$(sas "$LIM" "$CONSOLE/api/schedules")"
check "...one limited to this project sees them" grep -q '"name":"overdue"' <<<"$(sas "$INN" "$CONSOLE/api/schedules")"
check "...and the other can't run it: it looks like it isn't there" grep -q 'no \[schedule.overdue\]' <<<"$(sas "$LIM" -X POST -d '{}' "$CONSOLE/api/schedules/overdue/run")"
check "...but this project's token can" grep -Eq '"id":"[0-9a-f]{8}"' <<<"$(sas "$INN" -X POST -d '{}' "$CONSOLE/api/schedules/overdue/run")"
kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
before="$(tasks_started)"
start_agentd AGENTOS_CONFIG="$WORK/sched/config.toml" AGENTOS_MIN_SCHEDULE=1s
sleep 8
check "restarted, agentd remembers: nothing runs that isn't due" test "$(tasks_started)" -eq "$before"
kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
# On a timer.
rm -rf "$AGENTOS_HOME/tasks" "$AGENTOS_HOME/schedules.json" "$AGENTOS_HOME/users.json"
sched_config ticking 5s
start_agentd AGENTOS_CONFIG="$WORK/sched/config.toml" AGENTOS_MIN_SCHEDULE=1s
for _ in $(seq 80); do [ "$(tasks_started)" -ge 2 ] && break; sleep 0.5; done
check "a schedule every few seconds keeps starting its task" test "$(tasks_started)" -ge 2
kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
out="$(printf '[schedule.too-often]\nevery = "10s"\nproject = "%s"\ntask = "x"\n' "$PROJ" > "$WORK/sched/fast.toml"; AGENTOS_CONFIG="$WORK/sched/fast.toml" "$AGENT" schedules 2>&1)"
check "a schedule can't be faster than a minute (unless you say otherwise)" grep -q 'not more often than every 1m' <<<"$out"
printf '[schedule.sneaky]\nevery = "1h"\nproject = "%s"\ntask = "x"\n' "$PROJ" > .agentos.toml
"$AGENT" trust >/dev/null 2>&1
check "a project can't start tasks on its own" test $? -eq 2
rm -f .agentos.toml
export AGENTOS_HOME="$SAVED_HOME"

section "events wake an agent (hooks in agentd)"
reset_proj
cd "$PROJ"
SAVED_HOME="$AGENTOS_HOME"
export AGENTOS_HOME="$WORK/store-hooks"
mkdir -p "$AGENTOS_HOME" "$WORK/hooks/agents"
cat > "$WORK/hooks/agents/sched-agent.toml" <<'TOML'
run = ["sh", "-c", "echo task-was: $1", "sh", "{task}"]
TOML
printf '[console]\nprojects = ["%s"]\n\n[hook.ci]\nproject = "%s"\ntask = "CI failed. The event: {event}"\ntoken = "AGENTOS_E2E_HOOK_TOKEN"\nagent = "sched-agent"\nbudget = "1usd"\nmin_interval = "4s"\n' "$PROJ" "$PROJ" > "$WORK/hooks/config.toml"
cat > "$WORK/hooks/policy.cedar" <<'CEDAR'
@id("nothing consequential once an event started it")
forbid (principal, action == Action::"call", resource)
when { context.taint.contains("event") && resource.name like "delete*" };
CEDAR
hc() { AGENTOS_CONFIG="$WORK/hooks/config.toml" "$AGENT" "$@"; }
start_agentd AGENTOS_CONFIG="$WORK/hooks/config.toml" AGENTOS_E2E_HOOK_TOKEN=hook-secret-123
code() { curl -sS -m 10 -o "$WORK/hook.out" -w '%{http_code}' "$@"; }
HOOK="$CONSOLE/api/hooks/ci"
check "an event without the hook's token is refused" test "$(code -X POST -d x "$HOOK")" = 401
check "...with a wrong one" test "$(code -X POST -H 'Authorization: Bearer nope' -d x "$HOOK")" = 401
check "...with agentd's own token: that opens the console, not hooks" test "$(code -X POST -H "Authorization: Bearer $TOKEN" -d x "$HOOK")" = 401
check "...to a hook that isn't there, the same" test "$(code -X POST -H 'Authorization: Bearer hook-secret-123' -d x "$CONSOLE/api/hooks/nope")" = 401
check "the hook's token opens nothing else" test "$(code -H 'Authorization: Bearer hook-secret-123' "$CONSOLE/api/tasks")" = 401
check "agent hooks lists it, and says its token is set" bash -c 'out="$(AGENTOS_E2E_HOOK_TOKEN=x AGENTOS_CONFIG="$1" "$2" hooks 2>&1)"; grep -q "ci .*POST http.*/api/hooks/ci" <<<"$out" && grep -q "AGENTOS_E2E_HOOK_TOKEN is set" <<<"$out"' _ "$WORK/hooks/config.toml" "$AGENT"
check "an event with the token starts the task" test "$(code -X POST -H 'Authorization: Bearer hook-secret-123' -d '{"build":"red"}' "$HOOK")" = 202
ID="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' "$WORK/hook.out")"
for _ in $(seq 60); do grep -q task-was "$AGENTOS_HOME/tasks/$ID/output.log" 2>/dev/null && break; sleep 0.5; done
check "...with the event's words in it" grep -q 'task-was: CI failed. The event: {"build":"red"}' "$AGENTOS_HOME/tasks/$ID/output.log"
check "...and the journal says which hook" grep -q '"started_by":"agentd hook ci"' "$AGENTOS_HOME/tasks/$ID/events.jsonl"
check "what came in is untrusted: the task started tainted by it" grep -q '"kind":"taint.marked".*"detail":"hook ci".*"source":"event"\|"kind":"taint.marked".*"source":"event"' "$AGENTOS_HOME/tasks/$ID/events.jsonl"
check "...which shows in the journal as read" grep -q 'the event that started it (hook ci)\|event' <<<"$("$AGENT" log "$ID" 2>&1)"
check "an event straight after is refused: too soon" test "$(code -X POST -H 'Authorization: Bearer hook-secret-123' -d again "$HOOK")" = 429
sleep 4
check "later, one with X-Gitlab-Token works" test "$(code -X POST -H 'X-Gitlab-Token: hook-secret-123' -d "$(printf 'a\033[2Jb')" "$HOOK")" = 202
ID2="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' "$WORK/hook.out")"
for _ in $(seq 60); do grep -q task-was "$AGENTOS_HOME/tasks/$ID2/output.log" 2>/dev/null && break; sleep 0.5; done
check "...and control characters in the event don't reach the agent" bash -c '! grep -q "$(printf "\033")" "$1"' _ "$AGENTOS_HOME/tasks/$ID2/output.log"
sleep 4
check "X-Agentos-Token works too, and a long event is cut" test "$(code -X POST -H 'X-Agentos-Token: hook-secret-123' --data-binary "$(head -c 20000 /dev/zero | tr '\0' 'x')" "$HOOK")" = 202
ID3="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' "$WORK/hook.out")"
for _ in $(seq 60); do grep -q task-was "$AGENTOS_HOME/tasks/$ID3/output.log" 2>/dev/null && break; sleep 0.5; done
check "...to a size an agent can be handed" test "$(awk '/^task-was:/ { print length($0) }' "$AGENTOS_HOME/tasks/$ID3/output.log" | head -1)" -lt 8200
check "the hook's token is nowhere in the store" bash -c "! grep -rq hook-secret-123 '$AGENTOS_HOME'"
check "agent hooks counts what happened" grep -Eq '3 runs.*last: task' <<<"$(hc hooks 2>&1)"
check "...and what was refused" grep -q 'refused' <<<"$(hc hooks 2>&1)"
kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
cp "$WORK/hooks/policy.cedar" "$WORK/hooks/policy.cedar.keep"
check "your rules can see that an event started the task" grep -q 'forbidden by your rule .*nothing consequential' <<<"$(hc policy check call tracker.delete_issue --tainted event 2>&1)"
check "...and --tainted takes event" bash -c '! AGENTOS_CONFIG="$1" "$2" policy check call tracker.delete_issue --tainted cookies >/dev/null 2>&1' _ "$WORK/hooks/config.toml" "$AGENT"
printf '[hook.sneaky]\nproject = "%s"\ntask = "x"\ntoken = "T"\n' "$PROJ" > .agentos.toml
"$AGENT" trust >/dev/null 2>&1
check "a project can't open a door into agentd" test $? -eq 2
rm -f .agentos.toml
printf '[hook.bad]\nproject = "%s"\ntask = "x"\ntoken = "not a variable name"\n' "$PROJ" > "$WORK/hooks/bad.toml"
check "a token has to name a variable" grep -q 'token:' <<<"$(AGENTOS_CONFIG="$WORK/hooks/bad.toml" "$AGENT" hooks 2>&1)"
export AGENTOS_HOME="$SAVED_HOME"

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

section "receipts (a signed journal head, and a witness)"
reset_proj
cd "$PROJ"
"$AGENT" run -- true >/dev/null 2>&1
T="$(latest_task_dir)"
check "a finished task has a signed receipt" test -f "${T}receipt.json"
check "...which the journal records" grep -q '"kind":"receipt.signed"' "${T}events.jsonl"
check "agent log shows it" grep -q 'signed receipt · key' <<<"$("$AGENT" log)"
check "...and the chain with it still verifies" grep -q 'chain intact' <<<"$("$AGENT" log)"
out="$("$AGENT" attest --verify "${T}receipt.json" --journal "${T}events.jsonl" 2>&1)"
check "agent attest --verify checks the signature" grep -q "✓ signed by key .* (this machine's)" <<<"$out"
check "...and that the journal still holds that history" grep -q 'the journal holds that history (1 events since)' <<<"$out"
KEY="$("$AGENT" attest --public | cut -d' ' -f1)"
check "--trust accepts the key it is" grep -q 'that is the key you trust' <<<"$("$AGENT" attest --verify "${T}receipt.json" --trust "$KEY")"
check "...and refuses another" bash -c '! "$@" >/dev/null' _ "$AGENT" attest --verify "${T}receipt.json" --trust 0123456789abcdef
sed 's/"events": [0-9]*/"events": 999/' "${T}receipt.json" > "$WORK/forged.json"
check "a receipt edited afterwards fails" grep -q "the signature doesn't match" <<<"$("$AGENT" attest --verify "$WORK/forged.json")"
cp "${T}events.jsonl" "$WORK/events.good"
sed -i 's/"exit_code":0/"exit_code":9/' "${T}events.jsonl"
out="$("$AGENT" attest --verify "${T}receipt.json" --journal "${T}events.jsonl" 2>&1)"
check "a journal edited afterwards fails the check" grep -q 'the journal is broken' <<<"$out"
cp "$WORK/events.good" "${T}events.jsonl"
out="$("$AGENT" attest)"
check "agent attest signs the journal as it stands now, receipt event and all" grep -q "\"events\": $(wc -l < "${T}events.jsonl")," <<<"$out"
if command -v python3 >/dev/null; then
  cat > "$WORK/witness.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        open(sys.argv[1], "ab").write(self.rfile.read(n) + b"\n")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *a):
        pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY
  : > "$WORK/witnessed.jsonl"
  python3 "$WORK/witness.py" "$WORK/witnessed.jsonl" > "$WORK/witness.port" &
  WITNESS_PID=$!
  for _ in $(seq 50); do [ -s "$WORK/witness.port" ] && break; sleep 0.1; done
  WPORT="$(cat "$WORK/witness.port")"
  printf '[journal]\nwitness = "http://127.0.0.1:%s/receipts"\n' "$WPORT" > "$WORK/witness.toml"
  AGENTOS_CONFIG="$WORK/witness.toml" "$AGENT" run -- true >/dev/null 2>&1
  T="$(latest_task_dir)"
  check "[journal] witness: the signed receipt is posted when a task ends" test "$(wc -l < "$WORK/witnessed.jsonl")" -eq 1
  check "...and the journal says the witness took it" grep -q '"witness":{"status":200,"url":"http://127.0.0.1:' "${T}events.jsonl"
  head -1 "$WORK/witnessed.jsonl" > "$WORK/witnessed.receipt"
  check "what the witness holds verifies against the journal" grep -q 'the journal holds that history' <<<"$("$AGENT" attest --verify "$WORK/witnessed.receipt" --journal "${T}events.jsonl")"
  AGENTOS_CONFIG="$WORK/witness.toml" "$AGENT" attest "$(basename "$T")" >/dev/null 2>&1
  check "agent attest posts to it too" test "$(wc -l < "$WORK/witnessed.jsonl")" -eq 2
  kill "$WITNESS_PID" 2>/dev/null; wait "$WITNESS_PID" 2>/dev/null
  out="$(AGENTOS_CONFIG="$WORK/witness.toml" "$AGENT" run -- true 2>&1)"
  check "a witness that can't be reached is a warning, not a failure" grep -q "couldn't reach the witness" <<<"$out"
  check "...and the receipt is signed all the same" grep -q '"kind":"receipt.signed"' "$(latest_task_dir)/events.jsonl"
else
  skip "the witness tests need python3"
fi
printf '[journal]\nwitness = "http://witness.example.com/receipts"\n' > "$WORK/badwitness.toml"
check "a witness has to be https (or this machine)" grep -q 'a witness is an https' <<<"$(AGENTOS_CONFIG="$WORK/badwitness.toml" "$AGENT" run -- true 2>&1)"
printf '[journal]\nwitness = "https://witness.example.com/receipts"\n' > .agentos.toml
"$AGENT" trust >/dev/null 2>&1
check "a project can't choose who hears about your tasks" test $? -eq 2
rm -f .agentos.toml

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
