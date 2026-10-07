# A tour of agentos, to do yourself

About 90 minutes, in ten stops. Each stop says what to type, what you should see, and what to judge. Keep a scratch file open and write down every moment you hesitated, were confused, or wished it did something else. That list is worth more than any pass or fail.

Stops 1 to 3 need no accounts. Stops 4 to 7 need a Claude login. Stop 8 needs nothing new. Stop 9 needs an OpenAI or Gemini key and is optional. Stop 10 is for a remote MCP server you actually use.

## 0. Get a Linux shell with `agent` in it

On a Mac, use the dev container (Docker must be running). First time takes a few minutes to build:

```bash
cd ~/Documents/Projects/agentos
scripts/dev.sh shell
```

You're now the unprivileged `dev` user, `agent` is on your PATH, the repo is at `/src`, and your home and tasks survive between shells. On a Linux machine, build and install instead (see the README) and ignore `/src`.

```bash
agent doctor
```

Every line should be green. If one isn't, stop here and note it. Nothing later works without it.

Make a practice project with a git remote, so held pushes have somewhere to go:

```bash
mkdir -p ~/app && cd ~/app
printf 'def greet(name):\n    return "hello " + name\n' > greet.py
git init -q -b main && git add . && git -c user.name=you -c user.email=you@example.com commit -qm greet
git init -q --bare ~/app.remote.git && git remote add origin ~/app.remote.git && git push -q origin main
```

## 1. The sandbox, with no agent involved

`agent run` puts any command in the same box an agent gets. You're the "agent" here.

```bash
agent run -- sh -c 'echo changed > greet.py; echo new > extra.txt; ls ~/.ssh; ls /home; curl -m 5 https://example.com'
```

Judge: it ran, but `~/.ssh` isn't there, and the network call failed (loopback only by default). Now check your real files:

```bash
cat greet.py ; ls          # untouched
agent ls                   # one task, with pending changes
agent diff                 # what the "agent" did
```

Take it back, then do it again and keep it this time:

```bash
agent rollback
agent run -- sh -c 'echo "# a comment" >> greet.py'
agent diff && agent commit
cat greet.py               # now it's there
```

Try the conflict rule. Make the task change a file, change the same file yourself, then commit:

```bash
agent run -- sh -c 'echo agent >> greet.py'
echo me >> greet.py
agent commit               # refused: nothing applied, it tells you which file
agent rollback
```

Judge: is the diff readable? Did the commit/rollback vocabulary make sense without reading docs?

## 2. The journal

```bash
agent log
```

It lists what the last task did and ends with "chain intact". Prove it notices tampering:

```bash
f="$(ls -td ~/.local/share/agentos/tasks/*/ | head -1)events.jsonl"
cp "$f" /tmp/events.bak
sed -i 's/"exit_code":0/"exit_code":9/' "$f"
agent log; echo "exit=$?"   # should complain, exit 1
cp /tmp/events.bak "$f"
```

Judge: the message tells you which event broke. (This catches edits; it does not stop someone who rewrites the whole chain. That's on the roadmap.)

## 3. The network is an allowlist

```bash
agent run --allow example.org -- sh -c 'curl -sS -m 10 -o /dev/null -w "org: %{http_code}\n" https://example.org; curl -sS -m 10 https://example.com'
```

Judge: org works, com is refused live, with the exact flag that would allow it. Then:

```bash
agent log | grep -i -E 'connect|blocked'
```

Every connection is in the journal, allowed or not.

## 4. The real agent (Claude Code)

Log in once. This opens Claude's own interface; finish setup, type `/login`, then quit with Ctrl-D twice:

```bash
cd ~/app && agent do
agent vault               # "claude: sealed": the agent holds placeholders, not your token
```

Now a task:

```bash
agent do "add a pytest test file for greet() in greet.py. Don't modify greet.py. Commit it with git (author Agent <agent@example.com>) and push it to a new branch test-greet on origin."
```

While it runs, watch the live lines. Then:

```bash
ls                                  # your folder: no test file yet
git --git-dir ~/app.remote.git branch   # no test-greet yet: the push is held
agent diff
```

`agent diff` should show the new test file and a "held git pushes" section. Then:

```bash
agent commit
git --git-dir ~/app.remote.git branch   # test-greet is there now
agent log | tail -20                    # tool calls, model calls, cost
```

Judge: does the exit summary tell you what to do next? Was the cost it printed believable? (`scripts/acceptance.sh` automates the comparison with Claude's own figure.)

## 5. The agent asks for what it doesn't have

```bash
mkdir -p ~/notes && echo "The magic word is pelican." > ~/notes/word.txt
agent do "Read ~/notes/word.txt and reply with only the magic word in it. This sandbox doesn't show that folder: ask for it."
```

agentos should ask you at the terminal, with Claude's reason. Answer `y`. Then:

```bash
agent log | grep -i -E 'request|grant'
agent rollback
```

Run it again and, while it works, take the folder back from another terminal (`scripts/dev.sh exec` opens a second shell, or use tmux):

```bash
agent revoke              # lists what the running task was given
agent revoke ~/notes
```

Judge: the question was clear about what, and why. Taking it back worked while the task ran.

## 6. Budgets

```bash
agent do --budget 0.01usd "Count from 1 to 5, running a separate echo command for each number."
```

Claude's very first call costs more than a cent, so the next call waits and you're asked whether to raise the budget. Answer `n` once and see the refusal. Run it again and answer `y` to see it go on. Then:

```bash
agent spend
agent ls                  # the task shows "over budget" with its cost
agent rollback
```

Judge: were you ever surprised by money? Did you understand what "raise" would cost?

## 7. Your rules (Cedar)

Rules answer, in advance, the questions agentos would ask you.

```bash
mkdir -p ~/.config/agentos
cat > ~/.config/agentos/policy.cedar <<'EOF'
@id("notes are readable")
permit (principal, action == Action::"read", resource)
when { resource.path like "/home/dev/notes*" };

@id("never example.com")
forbid (principal, action == Action::"connect", resource == Host::"example.com");
EOF
agent policy
agent policy check read /home/dev/notes
agent policy check connect example.com
```

Repeat stop 5. This time nothing should ask you, and the journal names the rule that answered. Then break the file on purpose (delete the last `;`) and run any task: it must refuse to start rather than skip your rules. Fix it, and remove the file when you're done.

## 8. MCP tools: ask, allow, deny, hold, and taint

This uses a stand-in "notes" server shipped in `tests/`, so you need no account. It runs outside the sandbox with a credential the agent never sees.

```bash
export NOTES_FILE=$HOME/server-notes.txt NOTES_TOKEN=secret-token-123 ; : > $NOTES_FILE
cat > ~/.config/agentos/config.toml <<'EOF'
[mcp.notes]
command = ["python3", "/src/tests/fake-mcp-server"]
env = ["NOTES_FILE", "NOTES_TOKEN"]
tools = { drop_notes = "deny" }
EOF
cd ~/app
agent do "Use the notes server: read the notes, then post a note saying hello."
```

You should be asked before `post_note` (it changes things), with its arguments. Reading ran without a question. Answer `y`. Check `cat $NOTES_FILE`, and `agent log | grep notes`. Confirm the agent never saw the token: ask it, `agent do "print the NOTES_TOKEN environment variable"`.

**Hold instead of approving one by one.** Change the tools line to `tools = { post_note = "hold", drop_notes = "deny" }` and repeat. Nothing is asked. The agent is told the call is queued.

```bash
cat $NOTES_FILE            # still empty
agent diff                 # "held tool calls", with the arguments
agent commit               # runs it now, from outside the sandbox
cat $NOTES_FILE
```

Run once more and `agent rollback` instead: the call never happens.

**Taint.** Change the server to `taint = true` (and `post_note = "allow"`). Ask for the same task. Now `read_note` taints the task, so `post_note` is asked about even though you allowed it, and the prompt says why. Check:

```bash
agent log | grep -i taint
agent policy check call notes.post_note --tainted tool
```

Judge, honestly: is "tainted tasks get asked" the right default, or is it noise? Which of your own servers would you mark `taint = true`? Which tools would you `hold`?

## 9. Another agent (optional, needs a key)

```bash
agent agents
cp /src/examples/agents/gemini.toml ~/.config/agentos/agents/   # or codex.toml
export GEMINI_API_KEY=...        # or OPENAI_API_KEY for codex
cd ~/app && agent do --agent gemini --budget 1usd "add a docstring to greet()"
```

These recipes have never been run end to end. Expect to learn something: a host that needs allowing, a flag that changed, a login mode that bypasses the key. Write down exactly what failed. Check `agent log` for the metered cost, and whether it's priced (add a `[prices]` entry if it counts at the highest rate).

## 10. A real remote MCP server (optional)

Add one you use, for example:

```toml
[mcp.linear]
url = "https://mcp.linear.app/mcp"
```

```bash
agent connect linear          # prints a link; open it on your Mac and approve
agent connect                 # shows signed in
agent do "list my open issues"
```

Over Docker the browser's return address won't reach the container: paste the final address back when asked. This is the least tested path in the project, so every rough edge here matters. Then check that remote results taint the task (stop 8), and that `agent connect linear --forget` really forgets.

## Wrap-up

Delete what you made, and write the friction list:

```bash
agent rollback 2>/dev/null; rm -rf ~/app ~/app.remote.git ~/notes ~/server-notes.txt
rm -f ~/.config/agentos/policy.cedar ~/.config/agentos/config.toml
```

For each moment on your list, say which kind it was: *I didn't understand*, *it asked too much*, *it asked too little*, *it broke*, or *it can't do what I need*. The roadmap should follow that list, not the other way round.
