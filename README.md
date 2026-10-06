# agentos

**Run AI agents with full autonomy, and undo anything.**

```console
$ cd ~/app
$ agent do "add a test for greet"
agent ▸ task 7c1e04a2  claude: add a test for greet  rw ~/app  ro ~/.local/share/claude/versions  net api.anthropic.com +3
  I'll add a test for greet.
  ⏺ Read greet.py
  ⏺ Write test_greet.py
  ⏺ Bash python3 -m pytest -q

Added test_greet.py with two tests for greet().
agent ▸ task 7c1e04a2 exited 0 in 38.4s · 61.2k tokens · $0.04 · 6 turns · 1 change held for review (+1 ~0 -0)
        agent diff     7c1e04a2  review
        agent commit   7c1e04a2  apply to your files
        agent rollback 7c1e04a2  discard

$ agent diff          # exactly what it did
$ agent commit        # keep it (or: agent commit last src/, agent rollback)
$ agent log           # what happened, verifiably
```

Every agent task is a *transaction*:

- the agent sees **only what you grant**: by default the current folder. No `~/.ssh`, no other projects, no environment secrets. Network access is an **allowlist**: Claude reaches Anthropic's API and nothing else, and every connection is logged.
- its writes land in an **overlay, not your files**: when it finishes you `diff`, then `commit` or `rollback`, all of it or per path. That's why the agent runs with its own permission prompts off: nothing it does is final until you say so.
- everything, including each tool call and each model call with what it cost, is recorded in a **hash-chained journal** the agent can't reach. Give a task a **budget** (`--budget 2usd`) and it can't spend more.

No root, no daemon, no containers to build: plain Linux kernel features (user namespaces, overlayfs, Landlock). `agent run -- CMD` does the same for any command.

This is Phase 0 of an agent-native OS. See [docs/DESIGN.md](docs/DESIGN.md) for the full design and roadmap.

## Install

**As a whole OS:** [image/](image/README.md) is agentos as a Linux distribution. It's a Fedora bootc image with the runtime built in, atomic updates and rollbacks, bootable as a VM or on hardware. CI builds it and runs the end-to-end suite inside it.

**On an existing Linux machine:**

Linux, kernel 5.11+, Rust 1.85+:

```bash
cargo build --release && sudo install -m 0755 target/release/agent /usr/local/bin/agent
```

```bash
agent doctor
```

**Ubuntu 23.10+** blocks unprivileged user namespaces through AppArmor. Allow them for `agent` only:

```bash
sudo tee /etc/apparmor.d/agentos <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile agentos /usr/local/bin/agent flags=(unconfined) {
  userns,
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/agentos
```

**macOS / Windows**: develop and try it in a Linux container with Docker:

```bash
scripts/dev.sh test
```

```bash
scripts/dev.sh shell
```

## Commands

| | |
|---|---|
| `agent do [-i] [GRANTS] "TASK"` | Give TASK to an AI agent (Claude Code), working on the current folder |
| `agent do` | Open an interactive agent session (also how you log it in) |
| `agent run [GRANTS] [--net none\|host] -- CMD…` | Run any command as a sandboxed task |
| `agent ls` | List tasks and their pending changes |
| `agent logs [TASK] [-f]` / `wait` / `stop` | Follow, wait for, or stop a (background) task |
| `agent diff [TASK] [PATH…] [--stat]` | Show what a task changed |
| `agent commit [TASK] [PATH…] [--force] [--no-push]` | Apply changes to your files (all, or under PATHs) and send held git pushes |
| `agent push [TASK] [--force]` | Send only the held git pushes |
| `agent rollback [TASK] [PATH…]` | Discard changes (all, or under PATHs) |
| `agent log [TASK] [--json]` | Show the journal and verify its hash chain |
| `agent doctor` | Check this machine |
| `agent trust [FILE]` | Show a project's `.agentos.toml` and apply it from now on |
| `agent vault [status\|seal\|unseal]` | Your agent's sealed login |
| `agent agents` | Agents you can use with `agent do --agent NAME` |
| `agent serve [--listen ADDR] [--notify URL]` | agentd: web console for tasks and approvals |
| `agent approvals [--revoke HOST]` | List hosts you approved "always", or forget one for this project |

`GRANTS` are `--rw DIR`, `--ro PATH`, `--hide PATH`, `-e NAME[=VAL]`, `--no-cwd`, `--allow HOST`, `--secret NAME=HOST[/HEADER]` and `--ask`/`--no-ask`. For `diff`, `commit`, `rollback` and `log`, `TASK` is an id prefix or `last`, and defaults to the latest task. To pass paths for the latest task, write `agent commit last src/`.

## What the agent sees

| Path | Inside the sandbox |
|---|---|
| `/usr`, `/etc`, `/opt`, `/lib*`, `/bin`, `/sys` | read-only |
| the current folder | read-write, transactional (unless `--no-cwd`; never `$HOME` itself, `/` or system dirs) |
| `--rw` dirs | read-write, transactional |
| `--ro` paths | read-only |
| `--hide` paths | empty |
| `$HOME` with `agent do` | the agent's **own** persistent home (`$AGENTOS_HOME/homes/<agent>`): its login, settings and history. Your real home is never visible. |
| `$HOME` with `agent run` | empty and private, discarded at exit |
| `/tmp`, `/var/tmp`, `/run`, `/dev/shm` | private, discarded at exit |
| `/proc` | its own pid namespace only |
| `/dev` | `null zero full random urandom tty`, a private `pts` |
| network | `agent run`: loopback only by default. `agent do`: the agent's allowlist. `--allow HOST` adds hosts (and switches `agent run` to an allowlist); `--net host` shares your network. |
| environment | `PATH TERM LANG LC_* TZ USER SHELL EDITOR…`, `HOME`, `AGENTOS_TASK`, and only what you pass with `-e` |
| the task store | never visible, even through a grant |
| syscalls | no new namespaces, mounts, bpf, io_uring, keyrings, kernel modules, or typing into your terminal (seccomp) |

Conflicts: if a file changed on your side while the agent worked on its copy, `commit` refuses, tells you which files, and applies nothing. `--force` takes the agent's version.

Ignored changes: files matching the folder's `.gitignore`, or generated files like `__pycache__/` and `*.pyc`, are summarized in one line by `diff` and left out by `commit`. `diff --all` and `commit --all` include them, as does naming them: `agent commit last build/`.

## Network

With an allowlist, the agent has no network at all, not even DNS. Its only way out is an HTTPS proxy outside the sandbox, reached through a socket passed into it:

```
agent ──HTTPS_PROXY──▶ 127.0.0.1 (inside) ──▶ socket ══╪══▶ proxy (outside) ──▶ allowed host
```

The proxy accepts `CONNECT` to allowlisted hosts only, refuses hosts that resolve to private or local addresses, and journals every attempt with byte counts. Refused connections show up live, with the flag that would allow them:

```console
agent: blocked pypi.org:443: not in the allowlist (allow it with --allow pypi.org)
```

When an agent reaches for a host that isn't allowed, and there's a terminal to ask at, agentos asks you while the connection waits:

```console
agent ▸ the agent wants to reach pypi.org · [y] this task · [a] always, in ~/app · [N] deny ›
```

`y` allows it for this task. `a` remembers it for this project (in the task store, out of agents' reach; `agent approvals` lists them, `--revoke HOST` forgets one). Anything else, or no answer within 2 minutes, refuses it. Headless `agent do` asks by default (`--no-ask` to refuse instead); `agent run --ask` opts in, e.g. `agent run --ask -- npm install`. Nobody is asked in CI, pipes, or while Claude's own full-screen interface has the terminal. Every answer is journaled.

Some hosts an agent reaches for stay closed on purpose. Claude, when logged in with a claude.ai account, tries `mcp-proxy.anthropic.com` for its remote MCP connectors, which can reach your other accounts. agentos explains that once per task, journals it, and doesn't count it as a problem.

`agent log` lists every connection: `✓ api.anthropic.com:443 · ↑1.9 kB ↓4.8 kB · 228ms`.

## Git pushes wait in an outbox

When the agent commits, its git work shows up in `agent diff` as one line, taken from git's reflog (`G  ~/app/.git  commit: Add a test for greet`), rather than as files inside `.git`. `--all` lists those files.

In a git repository with remotes, the agent's `git push` works, but nothing leaves your machine. Each remote gets an outbox inside the task, and git in the sandbox is configured to push there. The push shows up with the rest of the changes:

```console
$ agent diff
  M  ~/app/a.txt  +1 -1

  held git pushes (sent by `agent commit` or `agent push`)
  ↑  origin feature  3f2a9c1 Add a test for greet · 1 new commit
```

`agent commit` applies the files, then sends the pushes from **your** git, outside the sandbox, with your usual SSH keys or credential helper. The agent never needs push rights. `agent push` sends only the pushes, `agent commit --no-push` only the files, and `agent rollback` drops both. If the remote moved in the meantime, git rejects the push as usual, and it stays held until you sort it out (`agent push --force` overwrites).

## Background tasks

```bash
agent do --bg "upgrade the dependencies and fix what breaks"
agent do --bg --timeout 30m "find and fix the flaky test"
```

`--bg` gives you the terminal back and prints the task id. The task keeps what it prints (`agent logs -f`). Its questions go to agentd's console, since there's no terminal to ask at; without agentd running, hosts outside the allowlist are refused. `agent wait` blocks until a task ends and exits with its code. `agent stop` ends it early. `--timeout` stops a task that runs too long. Either way, what it did up to that point is held for review like any other task. A task whose terminal closes is stopped the same way.

## Resource limits

```bash
agent do --bg --memory 4G --cpus 2 --pids 1024 "run the full test suite and fix failures"
```

The kernel enforces them (cgroup v2). The task runs inside a transient systemd scope that carries the limits (`systemd-run --user --scope`). That needs a systemd user session: a normal login has one, the agentos distro does, a container usually doesn't. `agent doctor` tells you. Asking for limits where they can't be enforced is an error, not a silent no-op. Defaults for every task can go in your config (`[limits]`). A task that runs out of memory gets killed by the kernel, and the journal says so.

## Budgets

```bash
agent do --budget 2usd "migrate the tests to pytest"
agent do --budget 1M "summarize the codebase"        # tokens
```

The gateway in the egress proxy reads the token counts the provider puts in each response, so the agent can't under-report them. Every model call is in the journal with its model, tokens and price. The task's total is in the exit summary, in `agent ls`, and live in the console.

At 80% of the budget you get a heads-up. Once it's used up, further model calls are answered with an error in the API's own format instead of reaching the provider: the agent stops on it, and its work so far is held for review like any other task. An agent that keeps calling anyway is stopped. The call that crosses the budget completes, since its cost is only known once it's done, so a task can end slightly over.

- **Dollars are at list prices.** Claude's are built in, including cache reads and writes, fast mode and web searches. With a claude.ai login, that's what the same calls would cost on the API: a measure of use, not your bill. For other models, add prices to your config (`[prices]`). Until you do, an unknown model counts at the highest Claude rate, so the budget errs on the safe side and the total shows as an upper bound (`≤ $1.20`).
- **Tokens count everything the model processed**: input, output, cache reads and writes.
- **Metered APIs:** Anthropic's Messages API, OpenAI's Responses and Chat Completions, and whatever an agent file lists under `models`. Calls are measured whenever the broker relays them, as with Claude's login or a brokered key, even without a budget.
- A default for every task goes in your config: `[limits] budget = "5usd"`.

## agentd: the console

```bash
agent serve
```

This starts agentd and prints a link like `http://127.0.0.1:7777/#token=…`. The page lists your tasks, shows each one's diff, held pushes and journal, and has **Commit / Push / Roll back** buttons that run the same commands as the terminal. Running tasks show what they're doing right now. Questions from agents appear at the top with **Allow for this task / Always / Deny**, alongside the terminal prompt; the first answer wins. Tasks with no terminal to ask at, like Claude's full-screen interface or background runs, ask there too.

- `--listen 0.0.0.0:7777` to reach it from your phone, ideally over a private network such as Tailscale. Every API call needs the token.
- `--notify https://ntfy.sh/<your-topic>` sends a push notification for each new question (host and task title only), and when a task finishes, with what it left for review.

## Configuration

Two optional files, in TOML:

```toml
[network]
allow = ["@pypi", "api.github.com"]   # presets: @pypi @npm @crates @github @go

[files]
hide = [".env"]
ro = ["~/.cargo"]

[secrets]                             # your file only
GITHUB_TOKEN = "api.github.com"       # header defaults to authorization (Bearer)

[limits]                              # defaults for every task
memory = "8G"
cpus = 4
budget = "5usd"                       # model calls: dollars, or tokens ("2M")

[prices]                              # your file only; USD per million tokens
"gpt-*" = { input = 1.25, output = 10 }   # example figures: use your provider's
```

- **`~/.config/agentos/config.toml` is yours.** It applies to every task. Only this file may define `[secrets]` and `[prices]`; they're brokered whenever the variable is set in your environment and the task uses the allowlist network.
- **`.agentos.toml` in a project** (the current directory or a parent, below `$HOME`) can allow hosts, and hide or grant read-only paths *inside the project*. It comes with the repo, so agentos ignores it until you've read it and run `agent trust`, and again after any change. That includes a change an agent made and you committed: `agent diff` flags it. Without this, an agent could widen its own permissions for the next run, and a cloned repo could send your tokens anywhere.

With an allowlist from either file, `agent run` uses the proxied network instead of none.

## Credentials

The agent never holds your real API key. With `ANTHROPIC_API_KEY` set, `agent do` gives Claude a placeholder instead. The proxy terminates Claude's connections to `api.anthropic.com` with a certificate from a CA created for this task only and trusted only inside its sandbox. It replaces the placeholder in the `x-api-key` header with your key, then forwards over normal, verified TLS. The CA's private key never leaves the `agent` process.

Only that header, only on that host. A placeholder pasted into a request body, another header, or a request to another host stays a placeholder. Otherwise an agent could have the real key echoed back to it, or put it in front of the model.

**Logins too.** If you logged Claude in with a claude.ai account (`agent do`, then `/login`), the tokens in its home are **sealed**. The real ones move to a vault in the task store, and the agent's file keeps look-alike placeholders (`sk-ant-oat01-agentosplaceholder-…`). On API calls, the proxy swaps the access-token placeholder in `Authorization`. On Anthropic's token endpoint it works both ways: the placeholder refresh token goes out as the real one, and fresh tokens come back as new placeholders. So even a `/login` inside the sandbox never hands the agent a real token. `agent vault` shows the state, and `agent vault unseal` puts the real tokens back and stops sealing, if you ever need it. With `--net host` there's no proxy to swap tokens, so the login is unsealed for that task and sealed again afterwards.

Any command can use it:

```bash
agent run --secret GITHUB_TOKEN=api.github.com -- my-script
```

The script sees a placeholder in `$GITHUB_TOKEN`, and the proxy adds `Authorization: Bearer <your token>` on requests to `api.github.com`. Inside the sandbox, Node and Bun (`NODE_EXTRA_CA_CERTS`), and curl, Python, git and OpenSSL (`SSL_CERT_FILE` and friends) trust the task CA automatically.

## Agents

`agent do` uses Claude Code ([install it](https://claude.ai/install.sh) as usual). agentos finds the installation and grants it read-only. Claude then runs in its own home, so it needs one login of its own:

```bash
agent do
```

Then type `/login` and quit (Ctrl-D twice). Or `export ANTHROPIC_API_KEY=…`, which is passed through when set.

Headless runs (`agent do "TASK"`) stream progress and journal every tool call, the result and the cost. `agent do -i "TASK"` opens Claude's own interface instead, so you can watch and steer.

**Other agents** are defined in a file each, `~/.config/agentos/agents/NAME.toml`:

```toml
run = ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "{task}"]   # headless
interactive = ["codex"]                    # agent do --agent codex, with no task
allow = ["api.openai.com"]                 # hosts it needs

[secrets]                                  # brokered: the agent only sees placeholders
OPENAI_API_KEY = "api.openai.com"
```

An agent calling a model API other than Anthropic's or OpenAI's can list it before the first `[section]`, so its calls are metered and count against budgets: `models = [{ url = "https://openrouter.ai/api/v1/chat/completions", api = "openai" }]` (`api` is `anthropic` or `openai`; a trailing `*` in the URL matches any path under it).

`agent do --agent codex "…"` runs it like Claude: same sandbox, transactions, outbox, allowlist and broker, and its own persistent home. `agent agents` lists what you have, and `agent = "codex"` in your config makes it the default. [examples/agents/](examples/agents) has starting points for Codex, Gemini CLI and Aider. They're untested sketches, so check their flags.

To check the whole path with your real login, run `scripts/acceptance.sh`: `scripts/dev.sh exec 'bash /src/scripts/acceptance.sh'` on macOS.

## Limits (honest list)

- **An allowlist limits where data can go, not what is sent there.** The agent can put anything it read into its requests to allowed hosts. Keep secrets out of granted folders (`--hide .env`).
- **The proxy speaks HTTPS (`CONNECT`) only.** Plain HTTP, other protocols, and chaining to a corporate upstream proxy aren't supported yet.
- **Brokered hosts speak HTTP/1.1 through the proxy**, one request at a time per connection. Clients that require HTTP/2 or WebSockets to those hosts won't work. With a budget, that includes model APIs.
- **Budgets meter what they can read.** A Chat Completions stream without `stream_options.include_usage` reports no usage, so it isn't counted (you get a warning). The batch APIs are billed later and aren't metered. US-only inference (`inference_geo`, 1.1×) is priced at the standard rate.
- **The agent's home persists between tasks.** That's what keeps its login, but a misbehaving task could leave something there for the next one. Nothing outside the sandbox runs from it.
- **The syscall filter is a denylist** (seccomp): it blocks typing into your terminal (TIOCSTI), new namespaces, mounts, kernel modules, bpf, io_uring, keyrings and userfaultfd. Kernel bugs reachable through the remaining syscalls are out of scope until the microVM tier.
- **Only your own uid is mapped.** Files in a writable grant owned by another user (e.g. root-owned build output) can be read but not modified.
- **Writable grants must be directories**, and their paths can't contain `,` `:` or `\`.
- **Conflict detection uses mtimes.** If you *delete* a file on the host that the agent modified, commit recreates it without warning.
- **Only the top-level `.gitignore` of a grant is read**, not nested ones.
- **The outbox covers remotes that exist when the task starts.** A remote the agent adds itself has no outbox, and pushing to it fails for lack of network. Deleting a remote branch isn't held yet either.
- **`agent trust` records what you saw, not what you understood.** Read the file it prints.
- **The journal is tamper-evident against the agent, not against you.** Anchoring its head (TPM, remote witness) is a later phase.
- **Landlock is best-effort.** It's used when the kernel has it (`agent doctor` tells you). Namespaces do the isolation either way.
- **Grants are mounted at their canonical path.** If `~/app` is a symlink, the agent sees the real path.

## Layout

```
src/sandbox.rs   namespaces, root assembly, Landlock, exec
src/changes.rs   reading/committing/rolling back overlay transactions
src/journal.rs   hash-chained event log
src/store.rs     on-disk task store
src/doctor.rs    environment checks
src/profiles.rs  agent profiles (Claude Code) and their output
src/proxy.rs     egress proxy and allowlist
src/broker.rs    credential broker (per-task CA, HTTP/1.1 relay)
src/gateway.rs   model gateway: usage metering, prices, budgets
src/main.rs      CLI          src/render.rs   output
tests/e2e.sh     end-to-end tests (run as a normal user), with tests/fake-claude
scripts/acceptance.sh   the golden path with real Claude, for a human to run
.github/workflows/ci.yml   unit + e2e tests on real Ubuntu 24.04 (x86_64, arm64), Landlock required
```
