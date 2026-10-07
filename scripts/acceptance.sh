#!/usr/bin/env bash
# Acceptance run of the golden path with the real Claude Code:
#
#   cd ~/app && agent do "add a test for greet" && agent diff && agent commit
#
# It needs a Claude login (or ANTHROPIC_API_KEY) and your judgement, so a
# human runs it, once per milestone:
#
#   scripts/dev.sh exec 'bash /src/scripts/acceptance.sh'    # macOS, in the dev container
#   bash scripts/acceptance.sh                                # on Linux
set -uo pipefail

APP="${APP:-$HOME/acceptance-app}"
failed=0
step() { printf '\n\033[1;36m▸ %s\033[0m\n' "$1"; }
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; failed=1; }
ask()  { read -rp "  $1 [y/N] " answer; if [[ $answer == [yY]* ]]; then pass "$1"; else fail "$1"; fi; }

echo "testing $(agent --version)"
REMOTE="$APP.remote.git"
rm -rf "$APP" "$REMOTE" && mkdir -p "$APP" && cd "$APP" || exit 1
cat > greet.py <<'EOF'
def greet(name):
    return "hello " + name
EOF
# A git repo with a remote, to check that the agent's pushes wait for you.
git init -q --bare "$REMOTE"
git init -q -b main && git remote add origin "$REMOTE"
git add greet.py && git -c user.name=you -c user.email=you@example.com commit -qm "greet" && git push -q origin main

step "1. The agent is logged in"
probe() { agent do "Reply with exactly the word READY. Do nothing else." 2>&1; }
out="$(probe)"
if grep -q "Not logged in" <<<"$out"; then
  echo "  Not yet. Opening an interactive session: finish the setup, type /login,"
  echo "  then quit with Ctrl-D twice. This is the only time you'll need to."
  agent do
  out="$(probe)"
fi
if grep -q READY <<<"$out"; then pass "agent answers"; else fail "agent answers"; echo "$out"; exit 1; fi
if agent vault | grep -q 'claude: sealed'; then
  pass "your login is sealed: the agent only holds placeholders, and it still works"
elif agent vault | grep -q 'not logged in'; then
  pass "(API key login: brokered as a placeholder)"
else
  fail "your login is sealed ($(agent vault))"
fi

step "2. agent do \"add a test for greet\""
agent do "add a pytest test file for greet() in greet.py. Don't modify greet.py. Then commit it with git (author: Agent <agent@example.com>) and push it to a new branch named test-greet on origin."
code=$?
if [ $code -eq 0 ]; then pass "agent finished (exit 0)"; else fail "agent finished (exit $code)"; fi
if compgen -G "test_*.py" >/dev/null || compgen -G "tests/*" >/dev/null; then
  fail "your real folder is untouched until you commit"
else
  pass "your real folder is untouched until you commit"
fi
if agent log --json | grep -q '"kind":"agent.tool"'; then pass "tool calls were journaled"; else fail "tool calls were journaled"; fi
# What the gateway measured on the wire, next to what Claude says it spent.
costs="$(agent log --json | python3 -c '
import json, sys
gw = cl = None
for line in sys.stdin:
    e = json.loads(line)
    if e["kind"] == "model.usage": gw = e["data"]["totals"]["cost_usd"]
    if e["kind"] == "agent.result": cl = e["data"].get("cost_usd")
print(gw if gw is not None else "", cl if cl is not None else "")')"
read -r gateway claude <<<"$costs"
if [ -n "$gateway" ]; then
  pass "the gateway measured the agent's model calls (\$$gateway)"
  if [ -n "$claude" ] && python3 -c "import sys; g, c = float(sys.argv[1]), float(sys.argv[2]); sys.exit(0 if c > 0 and 0.7 <= g / c <= 1.3 else 1)" "$gateway" "$claude"; then
    pass "...within 30% of what Claude reports (\$$claude)"
  else
    fail "...within 30% of what Claude reports (\$${claude:-none}): the price table may be off"
  fi
else
  fail "the gateway measured the agent's model calls"
fi

if git --git-dir="$REMOTE" rev-parse -q --verify refs/heads/test-greet >/dev/null; then
  fail "the agent's push is held, not sent"
else
  pass "the agent's push is held, not sent"
fi

step "3. Review"
agent diff
if agent diff --stat | grep -Eq '^  A  .*test.*\.py'; then pass "diff shows a new test file"; else fail "diff shows a new test file"; fi
ask "Does the diff look like what you asked for?"

step "4. Commit"
agent commit
if compgen -G "test*.py" >/dev/null || compgen -G "tests/*.py" >/dev/null; then pass "the test is now in your folder"; else fail "the test is now in your folder"; fi

if git --git-dir="$REMOTE" rev-parse -q --verify refs/heads/test-greet >/dev/null; then
  pass "commit sent the held push to the remote"
else
  fail "commit sent the held push to the remote"
fi

step "5. Audit"
agent log | tail -12
if agent log >/dev/null; then pass "journal chain intact"; else fail "journal chain intact"; fi

step "6. A budget stops a task"
# Claude's first call alone (its system prompt) costs more than a cent, so
# the call after it is refused. Costs one or two model calls.
out="$(agent do --budget 0.01usd "Count from 1 to 5, running a separate echo command for each number." 2>&1)"
echo "$out" | tail -6
if grep -q 'budget used up' <<<"$out"; then pass "you're told when the budget is used up"; else fail "you're told when the budget is used up"; fi
if agent log --json | grep -q '"kind":"model.refused"'; then pass "the next model call was refused, not sent"; else fail "the next model call was refused, not sent"; fi
if agent ls | sed -n 2p | grep -q 'over budget'; then pass "agent ls shows the task over budget"; else fail "agent ls shows the task over budget"; fi
agent rollback >/dev/null

step "7. The agent asks for a folder it doesn't have"
NOTES="$APP.notes"
WORD="pelican-$RANDOM"
rm -rf "$NOTES" && mkdir -p "$NOTES" && echo "The magic word is $WORD." > "$NOTES/word.txt"
echo "  Claude will ask to read $NOTES: answer y when agentos asks."
agent do "Read $NOTES/word.txt and reply with only the magic word in it. This sandbox doesn't show that folder yet: ask for it." 2>&1 | tee "$NOTES.out"
out="$(cat "$NOTES.out")"
if agent log --json | grep -q '"kind":"agent.request"'; then pass "Claude asked, through agentos's MCP server"; else fail "Claude asked, through agentos's MCP server"; fi
if agent log --json | grep -q '"kind":"agent.request".*"decision":"nobody to ask"'; then
  echo "  (nobody could be asked: no terminal. Run this from an interactive terminal, or with agent serve running.)"
fi
if agent log --json | grep -q '"kind":"grant.added"'; then pass "the folder was added to the running sandbox"; else fail "the folder was added to the running sandbox"; fi
if grep -q "$WORD" <<<"$out"; then pass "...and Claude could read it"; else fail "...and Claude could read it"; fi
agent rollback >/dev/null
rm -rf "$NOTES" "$NOTES.out"

echo
if [ $failed -eq 0 ]; then
  printf '\033[1;32mACCEPTED\033[0m: the golden path works end to end.\n'
else
  printf '\033[1;31mNOT ACCEPTED\033[0m: see the ✗ lines above.\n'
fi
exit $failed
