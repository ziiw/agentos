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
agent ▸ task 7c1e04a2 exited 0 in 38.4s · $0.04 · 6 turns · 1 change held for review (+1 ~0 -0)
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
- everything, including each tool call and what it cost, is recorded in a **hash-chained journal** the agent can't reach.

No root, no daemon, no containers to build: plain Linux kernel features (user namespaces, overlayfs, Landlock). `agent run -- CMD` does the same for any command.

This is Phase 0 of an agent-native OS. See [docs/DESIGN.md](docs/DESIGN.md) for the full design and roadmap.

## Install

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
| `agent diff [TASK] [PATH…] [--stat]` | Show what a task changed |
| `agent commit [TASK] [PATH…] [--force]` | Apply changes to your files (all, or under PATHs) |
| `agent rollback [TASK] [PATH…]` | Discard changes (all, or under PATHs) |
| `agent log [TASK] [--json]` | Show the journal and verify its hash chain |
| `agent doctor` | Check this machine |

`GRANTS` are `--rw DIR`, `--ro PATH`, `--hide PATH`, `-e NAME[=VAL]` and `--no-cwd`. For `diff`, `commit`, `rollback` and `log`, `TASK` is an id prefix or `last`, and defaults to the latest task. To pass paths for the latest task, write `agent commit last src/`.

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

`agent log` lists every connection: `✓ api.anthropic.com:443 · ↑1.9 kB ↓4.8 kB · 228ms`.

## Agents

`agent do` uses Claude Code ([install it](https://claude.ai/install.sh) as usual). agentos finds the installation and grants it read-only. Claude then runs in its own home, so it needs one login of its own:

```bash
agent do
```

Then type `/login` and quit (Ctrl-D twice). Or `export ANTHROPIC_API_KEY=…`, which is passed through when set.

Headless runs (`agent do "TASK"`) stream progress and journal every tool call, the result and the cost. `agent do -i "TASK"` opens Claude's own interface instead, so you can watch and steer.

To check the whole path with your real login, run `scripts/acceptance.sh`: `scripts/dev.sh exec 'bash /src/scripts/acceptance.sh'` on macOS.

## Limits (honest list)

- **An allowlist limits where data can go, not what is sent there.** The agent can put anything it read into its requests to allowed hosts. Keep secrets out of granted folders (`--hide .env`).
- **The proxy speaks HTTPS (`CONNECT`) only.** Plain HTTP, other protocols, and chaining to a corporate upstream proxy aren't supported yet.
- **Credentials are visible to the agent**: the API key it's given, or its login in its own home. The credential broker fixes this.
- **The agent's home persists between tasks.** That's what keeps its login, but a misbehaving task could leave something there for the next one. Nothing outside the sandbox runs from it.
- **The syscall filter is a denylist** (seccomp): it blocks typing into your terminal (TIOCSTI), new namespaces, mounts, kernel modules, bpf, io_uring, keyrings and userfaultfd. Kernel bugs reachable through the remaining syscalls are out of scope until the microVM tier.
- **Only your own uid is mapped.** Files in a writable grant owned by another user (e.g. root-owned build output) can be read but not modified.
- **Writable grants must be directories**, and their paths can't contain `,` `:` or `\`.
- **Conflict detection uses mtimes.** If you *delete* a file on the host that the agent modified, commit recreates it without warning.
- **Only the top-level `.gitignore` of a grant is read**, not nested ones.
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
src/main.rs      CLI          src/render.rs   output
tests/e2e.sh     end-to-end tests (run as a normal user), with tests/fake-claude
scripts/acceptance.sh   the golden path with real Claude, for a human to run
.github/workflows/ci.yml   unit + e2e tests on real Ubuntu 24.04 (x86_64, arm64), Landlock required
```
