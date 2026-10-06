# agentos

**Run AI agents with full autonomy, and undo anything.**

```console
$ cd ~/app
$ agent do "add a test for greet"
agent ▸ task 7c1e04a2  claude: add a test for greet  rw ~/app  ro ~/.local/share/claude/versions  net host
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

- the agent sees **only what you grant**: by default the current folder. No `~/.ssh`, no other projects, no environment secrets, no network unless the agent needs it.
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
| network | loopback only (`--net none`, default) or the host's (`--net host`) |
| environment | `PATH TERM LANG LC_* TZ USER SHELL EDITOR…`, `HOME`, `AGENTOS_TASK`, and only what you pass with `-e` |
| the task store | never visible, even through a grant |

Conflicts: if a file changed on your side while the agent worked on its copy, `commit` refuses, tells you which files, and applies nothing. `--force` takes the agent's version.

## Agents

`agent do` uses Claude Code ([install it](https://claude.ai/install.sh) as usual). agentos finds the installation and grants it read-only. Claude then runs in its own home, so it needs one login of its own:

```bash
agent do
```

Then type `/login` and quit (Ctrl-D twice). Or `export ANTHROPIC_API_KEY=…`, which is passed through when set.

Headless runs (`agent do "TASK"`) stream progress and journal every tool call, the result and the cost. `agent do -i "TASK"` opens Claude's own interface instead, so you can watch and steer.

To check the whole path with your real login, run `scripts/acceptance.sh`: `scripts/dev.sh exec 'bash /src/scripts/acceptance.sh'` on macOS.

## Limits of Phase 0 (honest list)

- **Network is all or nothing.** `agent do` gives Claude your network (`net host`) because it needs the API. The next milestone replaces that with an egress proxy that only lets through the hosts the agent needs.
- **Credentials are visible to the agent**: the API key it's given, or its login in its own home. The credential broker fixes this.
- **The agent's home persists between tasks.** That's what keeps its login, but a misbehaving task could leave something there for the next one. Nothing outside the sandbox runs from it.
- **No seccomp filter yet.** In particular, on kernels before 6.2 (or with `dev.tty.legacy_tiocsti=1`), a process sharing your terminal can inject keystrokes into it.
- **Only your own uid is mapped.** Files in a writable grant owned by another user (e.g. root-owned build output) can be read but not modified.
- **Writable grants must be directories**, and their paths can't contain `,` `:` or `\`.
- **Conflict detection uses mtimes.** If you *delete* a file on the host that the agent modified, commit recreates it without warning.
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
src/main.rs      CLI          src/render.rs   output
tests/e2e.sh     end-to-end tests (run as a normal user), with tests/fake-claude
scripts/acceptance.sh   the golden path with real Claude, for a human to run
```
