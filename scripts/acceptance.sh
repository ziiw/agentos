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
rm -rf "$APP" && mkdir -p "$APP" && cd "$APP" || exit 1
cat > greet.py <<'EOF'
def greet(name):
    return "hello " + name
EOF

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

step "2. agent do \"add a test for greet\""
agent do "add a pytest test file for greet() in greet.py. Don't modify greet.py."
code=$?
if [ $code -eq 0 ]; then pass "agent finished (exit 0)"; else fail "agent finished (exit $code)"; fi
if compgen -G "test_*.py" >/dev/null || compgen -G "tests/*" >/dev/null; then
  fail "your real folder is untouched until you commit"
else
  pass "your real folder is untouched until you commit"
fi
if agent log --json | grep -q '"kind":"agent.tool"'; then pass "tool calls were journaled"; else fail "tool calls were journaled"; fi

step "3. Review"
agent diff
if agent diff --stat | grep -Eq '^  A  .*test.*\.py'; then pass "diff shows a new test file"; else fail "diff shows a new test file"; fi
ask "Does the diff look like what you asked for?"

step "4. Commit"
agent commit
if compgen -G "test*.py" >/dev/null || compgen -G "tests/*.py" >/dev/null; then pass "the test is now in your folder"; else fail "the test is now in your folder"; fi

step "5. Audit"
agent log | tail -12
if agent log >/dev/null; then pass "journal chain intact"; else fail "journal chain intact"; fi

echo
if [ $failed -eq 0 ]; then
  printf '\033[1;32mACCEPTED\033[0m: the golden path works end to end.\n'
else
  printf '\033[1;31mNOT ACCEPTED\033[0m: see the ✗ lines above.\n'
fi
exit $failed
