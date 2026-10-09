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

This is Phase 0 of an agent-native OS. See [docs/DESIGN.md](DESIGN.md) for the full design and roadmap.

## Install

**As a whole OS:** [image/](../image/README.md) is agentos as a Linux distribution. It's a Fedora bootc image with the runtime built in, atomic updates and rollbacks, bootable as a VM or on hardware. CI builds it and runs the end-to-end suite inside it.

**As a package** (Linux, kernel 5.11+): CI builds a `.deb` and an `.rpm` on every push (Actions → ci → the `packages-…` artifacts), or `scripts/package.sh` makes them from a release build (it needs [nfpm](https://nfpm.goreleaser.com)):

```bash
sudo apt install ./agentos_*.deb
sudo dnf install ./agentos-*.rpm
```

They install `agent`, agentd as a user service (`systemctl --user enable --now agentd`) and these docs under `/usr/share/doc/agentos`. On Ubuntu 23.10+ the package also loads the AppArmor profile below for `/usr/bin/agent`, and removes it with the package. They don't pull in anything to run a particular agent: Claude Code and the others come as they usually do. They require at least the glibc the binary was built against (CI builds on Ubuntu 24.04, so that's its glibc), and refuse to install on older systems; CI installs them on Ubuntu 24.04 and Fedora 42.

**On an existing Linux machine, from source:**

Linux, kernel 5.11+, Rust 1.85+:

```bash
cargo build --release && sudo install -m 0755 target/release/agent /usr/local/bin/agent
```

```bash
agent doctor
```

**Ubuntu 23.10+** blocks unprivileged user namespaces through AppArmor (the package takes care of this). Allow them for `agent` only:

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

While working on one thing, `scripts/dev.sh e2e 'a corporate proxy' 'configuration'` builds and runs only the end-to-end sections from the first name up to (not including) the second.

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
| `agent push [TASK] [--force]` | Send only what's held: git pushes and tool calls |
| `agent rollback [TASK] [PATH…]` | Discard changes (all, or under PATHs) |
| `agent log [TASK] [--json]` | Show the journal and verify its hash chain |
| `agent doctor` | Check this machine |
| `agent trust [FILE]` | Show a project's `.agentos.toml` and apply it from now on |
| `agent vault [status\|seal\|unseal]` | Your agent's sealed login |
| `agent screen [TASK] [-o FILE]` | Save a PNG of a task's screen (a task started with `--display`), now or as it ended |
| `agent attest [TASK]` / `--verify FILE [--journal FILE] [--trust KEY]` / `--public` | Sign a task's journal head (a receipt), check a receipt, show this machine's receipt key |
| `agent agents` | Agents you can use with `agent do --agent NAME` |
| `agent install DIR\|NAME [--yes] [--digest HEX]` / `uninstall NAME` / `packages` / `search [TEXT]` | Agent packages: install one (from a folder, or by name from your registry) after reading what it asks for, remove it, list them and whether they're intact, search your registry |
| `agent serve [--listen ADDR] [--notify URL]` | agentd: web console for tasks and approvals |
| `agent schedules` / `agent hooks` | The tasks agentd starts on a timer, and when each runs next; the hooks that start one when an event arrives |
| `agent users [add NAME --role ROLE \| remove NAME]` | Who else may use agentd's console (viewer, approver, admin), with their own tokens |
| `agent approvals [--revoke HOST]` | List hosts you approved "always", or forget one for this project |
| `agent revoke [TARGET] [--task ID]` | Take back a folder or host you granted while a task runs |
| `agent connect [NAME] [--forget]` | Sign in to one of your remote MCP servers, or list them |
| `agent spend` | What agents spent today, this week and this month, against your budgets |
| `agent raise AMOUNT [--task ID \| --today \| --this-week \| --this-month [--project]]` | Raise a budget that's used up: a running task's, or one across tasks until it resets |

`GRANTS` are `--rw DIR`, `--ro PATH`, `--hide PATH`, `-e NAME[=VAL]`, `--no-cwd`, `--allow HOST`, `--hold HOST`, `--local PORT`, `--display`/`--display-size WxH`, `--secret NAME=HOST[/HEADER]` and `--ask`/`--no-ask`. For `diff`, `commit`, `rollback` and `log`, `TASK` is an id prefix or `last`, and defaults to the latest task. To pass paths for the latest task, write `agent commit last src/`.

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

**Behind a corporate proxy**, the allowlist still decides, and allowed connections go out through your proxy instead of straight to the host. agentos uses the proxy your shell has (`HTTPS_PROXY`, or `ALL_PROXY`, minus `NO_PROXY`), or the one in your config:

```toml
[network]
proxy = "http://user:password@proxy.corp.example:3128"   # "" = connect directly, whatever your environment says
no_proxy = ["*.corp.example", "10.0.0.0/8"]               # reached directly
```

The proxy is reached by agentos itself, outside the sandbox: the agent never sees its address or password, and it can't ask for another. Only your own config can set it, never a project's. Each connection records the hop (`via proxy.corp.example:3128`), and a proxy that says no (a login is needed, the host is blocked) is explained to the agent and in the journal. It's an `http://` proxy (the usual `CONNECT` kind) or a `socks5://` one (an `ssh -D` tunnel, say; the host name is handed to the proxy to resolve, and `user:password@` works for both); `https://` proxies aren't supported, and one that isn't usable is an error, not a silent direct connection. A host name your machine can't resolve is left to the proxy to resolve; one it resolves only to private addresses is still refused.

**A model server on your machine.** Local models (Ollama, llama.cpp, vLLM) listen on your loopback, which the sandbox can't see. Give an agent one port and it reaches that server at the same address it would use anywhere else, `127.0.0.1:PORT`, with no proxy settings:

```bash
agent do --local 11434 --agent aider "…"       # or: [network] local = [11434] in your config
```

Only that port: the rest of your loopback (databases, dev servers, anything else) stays out of reach, and a project's `.agentos.toml` can't hand out your services. Each connection is journaled (`✓ 127.0.0.1:11434 (your machine) · ↑2.1 kB ↓48 kB`), and a server that isn't running is explained once. Everything the server's own API lets a client do, the agent can do (Ollama's can pull and delete models, say), and calls to it aren't metered or counted against budgets: local models cost no dollars.

## A screen of its own

For an agent that drives a graphical program (a browser, a desktop app), give the task a virtual screen:

```bash
agent do --display "open the settings page and screenshot it"     # or --display-size 1920x1080
agent screen                                                       # a PNG of what's on it now, or as the task left it
```

agentd's console shows the screen live too, and lets you take over the mouse and keyboard (see below).

The task gets a private X display. Xvfb (`apt install xvfb`, `dnf install xorg-x11-server-Xvfb`) runs outside the sandbox, started by agentos; the sandbox gets that one socket and a cookie, as `DISPLAY=:0`, and sees no other display of your machine. The server listens on neither the network nor an abstract socket, and shared memory isn't offered to clients (the sandbox has its own IPC namespace; they fall back to the plain protocol). The screen's framebuffer is a file in the task, so `agent screen` shows what's on it without going through the agent, while it runs, and the latest picture that had anything on it is kept when the task ends. `agent screen -o -` writes the PNG to a pipe. An agent file or a package can ask for a screen with `display = true` (and `display_size`).

Browsers and other programs that build their own sandbox out of namespaces can't inside agentos's (new namespaces are denied): run them with their sandbox off, the way you would in a container. Wayland-only programs and GPU access aren't covered.

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

## The agent can ask

An agent that needs more than it was given asks you, instead of failing or working around the sandbox:

```console
agent ▸ the agent asks to change ~/code/shared-lib (held for your review)
  its reason: “the failing test is caused by a bug in parse() there”
  [y] this task · [N] deny (or answer in agentd) › y
agent ▸ now read-write: ~/code/shared-lib
```

Every sandbox has agentos's own MCP server, and Claude gets it automatically, along with a word about where it runs. Its tools:

- `sandbox_info`: what the agent has (folders, hosts, budget, held pushes);
- `request_path_access`: a folder or file, to read or to change, with a reason;
- `request_network_access`: a host, with a reason.

You're asked at the terminal or in the console, with the agent's reason. Say yes and it's there at once, at its own path: agentos mounts it into the running sandbox. A folder you make writable is transactional like the rest: its changes are held, `agent diff` shows them and `agent commit` applies them.

Some things are never offered, and the agent is told so without bothering you: your credentials (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.claude`, …), your whole home, agentos's own task store and config, and anything hidden from the task. With Landlock, a folder outside your home can only be added read-only, since its write rules are fixed when a task starts. Every request, its reason and your answer are in the journal.

**And you can take it back** while the task runs, from another terminal or from the task's card in the console (**Take back**):

```bash
agent revoke                      # what you granted the running task
agent revoke ~/code/shared-lib    # unmounted from the sandbox, at once
agent revoke pypi.org             # refused from now on; open connections closed
```

The agent is refused if it asks again, even if one of your rules would allow it. A writable folder's changes stay held for review: taking back access doesn't throw away the work. It's all in the journal.

Other agents can use the same server: point their MCP configuration at `/run/agentos/agent`, with the argument `mcp`.

## Your MCP servers, through agentos

Declare an MCP server in your config, and agentos runs it for each task, outside the sandbox, with your credentials:

```toml
[mcp.github]
command = ["github-mcp-server", "stdio"]
env = ["GITHUB_PERSONAL_ACCESS_TOKEN"]     # from your environment, to the server only
tools = { delete_file = "deny", create_issue = "allow" }
```

Claude gets it automatically, as `github`; other agents reach it inside the sandbox with `/run/agentos/agent mcp github`. The agent never sees the token, and every tool call goes through agentos:

- tools the server marks read-only run directly;
- any other tool asks you first, showing the call's arguments: allow this call, allow it for the rest of the task, always in this project, or deny;
- `tools` sets a tool to `allow`, `ask`, `hold` or `deny` (see below); denied tools aren't even listed to the agent;
- every call is journaled: the tool, its arguments, how it was allowed, and whether it failed.

**Hold calls for review, instead of approving them one by one.** A call that changes things but whose result the agent doesn't need (create an issue, post a message) can be *held*: `tools = { create_issue = "hold" }`, or `hold = true` on a server to hold all its tools that aren't read-only, or `[h]` when you're asked. The agent is told it's queued and that it hasn't happened. Nothing runs, and a tainted task isn't asked either. `agent diff` lists the held calls with their arguments, next to the files and git pushes; `agent commit` runs them in order, from outside the sandbox with your credentials, and `agent rollback` drops them. A call that fails stays held (`agent push` retries). Hold only tools whose result the agent can do without: it can't see what a held call returns.

Only your own config can declare servers: a project's `.agentos.toml` can't make agentos run anything on your machine. A server runs as you, with your access; agentos governs the calls the agent makes, not what the server can reach.

**Remote servers** too. agentos connects to them itself, outside the sandbox, so the sandbox can't reach them and never holds their token. Their tools go through the same questions and journal:

```toml
[mcp.linear]
url = "https://mcp.linear.app/mcp"

[mcp.github]
url = "https://api.githubcopilot.com/mcp/"
token = "GITHUB_TOKEN"                     # a bearer token from your environment
```

A server that wants you to sign in (OAuth) gets it once, from your terminal:

```bash
agent connect linear      # opens your browser; you approve; done
agent connect             # your remote servers, and whether you're signed in
```

agentos finds where to sign in from the server itself, registers there as a client, and has you approve in your browser, which comes back to agentos on a loopback address. Over SSH, open the printed link anywhere and paste back the address your browser ends up on. The tokens are kept in the task store's vault, which no sandbox can see. They're refreshed when they expire, or when the server refuses them. `agent connect NAME --forget` forgets them.

## API writes wait in the outbox too

```bash
agent do --hold api.github.com "triage the open issues"     # or: [network] hold = ["api.github.com"]
```

`--hold HOST` lets the agent reach HOST, but its **writes** (POST, PUT, PATCH, DELETE) don't leave your machine. Each is answered with a `202` that says it was queued, and held in the task like git pushes and held tool calls: `agent diff` lists it with its URL and a preview of its body, `agent commit` (or `agent push`) sends it from outside the sandbox, in order, and `agent rollback` drops it. Reads (GET, HEAD, OPTIONS) go through as usual.

```console
$ agent diff
  held API requests (sent by `agent commit` or `agent push`, with your credentials)
  ⏸  POST api.github.com/repos/acme/app/issues/12/comments  {"body":"Looks like a duplicate of #9","bytes":38}
$ agent commit
  ↑ sent POST api.github.com/repos/acme/app/issues/12/comments → 201
```

A credential the agent holds only as a placeholder (`--secret`, `[secrets]`) is never stored with the request. It's added when the request is sent, from your environment or your `[secret_commands]`; if it isn't available then, the request stays held.

- **Exact host names.** agentos reads the method by terminating the TLS connection with the task's CA, so a wildcard has no certificate to match. Model APIs and logins aren't held.
- **The agent can't see the result.** A client waiting for the id of the thing it created gets a `202` with no resource. Hold hosts whose writes don't need an answer (post a comment, file an issue). Some APIs use POST to read (GraphQL, search): don't hold those, or the agent can't read.
- **A request that fails stays held**: any answer other than 2xx, no network, a missing credential. `agent push` tries again. Redirects aren't followed. A body over 1 MiB is refused, not held.
- A project's `.agentos.toml` may ask for holds too: it only restricts.

## Rules: answers you've already given

Everything agentos would ask you about (a host, a folder, a tool call) can be answered in advance, in `~/.config/agentos/policy.cedar`, next to your config. The rules are [Cedar](https://www.cedarpolicy.com) policies, the language behind AWS Verified Permissions, evaluated by deterministic code:

```cedar
@id("read code")
permit (principal, action == Action::"read", resource)
when { resource.path like "~/code/*" };

@id("no paste sites")
forbid (principal, action == Action::"connect", resource)
when { resource.name like "*paste*" };

@id("issues in our repo")
permit (principal, action == Action::"call", resource == Tool::"github.create_issue")
when { context.args has repo && context.args.repo == "agentos" };
```

- **A `forbid` that matches refuses**, and wins over everything: your allowlist, an agent's defaults, a read-only tool.
- **A `permit` that matches allows without asking.**
- **When nothing matches, you're asked**, as before.
- Rules work without a terminal: background tasks and `--no-ask` tasks follow them too.

What a rule sees:

| | |
|---|---|
| principal | `Agent::"claude"` (the agent's name; `Agent::"command"` for `agent run`) |
| actions | `Action::"connect"`, `"read"` and `"write"` (folders asked for mid-task), `"call"` (your MCP servers' tools), `"release"` (what a finished task left held: see below) |
| resources | `Host::"pypi.org"` {name, port}, `Path::"/home/you/code/lib"` {path}, `Tool::"github.create_issue"` {server, name} |
| context | `agent`, `task`, `project`, `reason` (the agent's own words, when it asked), `args` (a tool call's arguments), `tainted` and `taint` (see Taint, below) |

**A project can ship rules too**, in `.agentos.cedar` at its root, for anyone who runs agents there:

```cedar
@id("never production")
forbid (principal, action == Action::"connect", resource)
when { resource.name like "*.prod.example.com" };
```

Project rules can only forbid, so they apply without review, and they beat your own `permit` and `--allow`. A project file with a `permit` in it, or one that doesn't parse, stops the task: a protection the project asked for is never silently dropped. An agent can't loosen them for itself: rules are read when the task starts, and `agent diff` flags any change it makes to the file.

`"~/…"` in a string means your home. `agent policy` lists your rules and the project's, and `agent policy check read ~/code/lib` (or `connect pypi.org`, or `call github.create_issue --args '{"repo":"x"}'`) tells you what they'd say. Every decision a rule makes is journaled with the rule's name. A rules file that doesn't parse stops tasks rather than being skipped, and agents can never be granted it.

## Rules can release what a task left held

Held git pushes, tool calls and API requests wait for your `agent commit`. For tasks nobody is watching (`--bg`, started from your phone), your rules can say which of them may leave on their own, when the task ends, with the `release` action:

```cedar
@id("our own branches")
permit (principal, action == Action::"release", resource)
when { resource has branch && resource.remote == "origin" && resource.branch like "agent/*" };

@id("comments on our repo")
permit (principal, action == Action::"release", resource)
when { resource has method && resource.method == "POST" && resource.host == "api.github.com"
       && resource.path like "/repos/acme/app/issues/*/comments" };

@id("clean tasks may file issues")
permit (principal, action == Action::"release", resource == Tool::"github.create_issue")
when { !context.tainted && context.args.repo == "app" };

@id("never main")
forbid (principal, action == Action::"release", resource)
when { resource has branch && resource.branch == "main" };
```

| | |
|---|---|
| resources | `Push::"origin agent/fix"` {remote, branch, refname}, `Request::"POST api.github.com/repos/…"` {method, host, path}, `Tool::"github.create_issue"` {server, name} (with `context.args`) |
| context | the same as for the other actions, including `tainted` |

What a permit matches is sent when the task ends, from outside the sandbox with your credentials, exactly as `agent commit` would send it: the exit summary says `released by your rules: …` and the journal has an `outbox.released` event with the rule's name. A `forbid` beats a `permit`, and what no rule permits stays held for review. Only your own rules can release; a project's can only forbid. The task's file changes are never released this way. `agent policy check release git:origin/agent/fix` (or `POST:api.github.com/repos/acme/app/issues/1/comments`, or `github.create_issue --args '{…}'`) tells you what your rules would do.

## Taint: what it read changes what it may do

An agent can be steered by any text it reads: a web page, an issue, a file it was never meant to trust. So agentos tracks whether a task has read something like that, and treats a task that has differently. A task is **tainted** once it:

- reaches a host that isn't one of its own model APIs, a host of a credential you gave it, a package registry (PyPI, npm, crates.io, Go), or one you list under `[taint] trusted = ["git.corp.example", "*.docs.example"]` in your config (never a project's);
- is started by an event (a hook, see Schedules): it begins tainted;
- reads a result from an MCP server that reaches outside your machine: every remote server (`url = …`), and a local one only if you say `taint = true` (`taint = false` trusts a remote one);
- is allowed, mid-task, to read a folder outside its project.

Taint stays for the rest of the task. From then on, **a tool call that isn't read-only is asked about every time**, with what the task read shown in the question, even if your config says `allow` or you answered "always" before. Read-only tools still run. Only a rule of yours that permits the call lets it through silently, and your rules can see the taint:

```cedar
@id("no uploads once it has read the web")
forbid (principal, action == Action::"call", resource)
when { context.taint.contains("web") && resource.name like "upload*" };

@id("clean tasks may file issues")
permit (principal, action == Action::"call", resource == Tool::"github.create_issue")
when { !context.tainted };
```

`agent policy check call github.create_issue --tainted web` (or `event`, `tool`, `file`) asks what they'd say. The journal records each source (`taint.marked`), and the summary at the end of a tainted task says what it read, so you review its diff and held pushes with that in mind. A server's own `readOnlyHint` is still believed; it's the server's word, so give `taint = true` only to servers you'd believe it from.

## Receipts: the journal's head, signed

The journal is tamper-evident against the agent, which can't reach it. Against *you*, or whoever has your machine, a whole chain can be rewritten and still verify. A **receipt** closes part of that gap. When a task ends, agentos signs its journal's head (the hash that commits to every event) with this machine's key and keeps the receipt with the task (`receipt.json`). Anyone holding it can later check that a journal they're shown still contains the history it vouches for:

```console
$ agent attest --verify receipt.json --journal events.jsonl
✓ signed by key 3f2a9c1e84b07d21 · task 7c1e04a2 · journal head 9ab4f10c77d2 (212 events) · 2026-10-09T16:02:11Z
✓ that is the key you trust                     (with --trust 3f2a9c1e)
✓ the journal holds that history (4 events since)
```

- **The key** is an Ed25519 key made on first use in the task store, which no sandbox can see. `agent attest --public` shows its id and public key. A receipt names its key but can't say whose it is: compare it with the one you trust (`--trust KEY`).
- **A witness** makes the receipt outlive your machine. With `[journal] witness = "https://witness.example/receipts"` in your config, every finished task's signed receipt is posted there (a JSON POST; https, or this machine for testing). Rewriting a task's history later then means rewriting the witness's copy too. A witness that can't be reached is a warning.
- `agent attest [TASK]` signs a task's journal as it stands now (after you've committed, say) and prints the receipt; it's posted to the witness too.
- Not yet: keeping the key in a TPM, so even root on your machine can't sign for it.

## Budgets

```bash
agent do --budget 2usd "migrate the tests to pytest"
agent do --budget 1M "summarize the codebase"        # tokens
```

The gateway in the egress proxy reads the token counts the provider puts in each response, so the agent can't under-report them. Every model call is in the journal with its model, tokens and price. The task's total is in the exit summary, in `agent ls`, and live in the console.

At 80% of the budget you get a heads-up. Once it's used up, **the agent's next model call waits while you're asked** whether to raise it, at the terminal or in agentd's console (and on your phone with `--notify`):

```
agent ▸ this task's budget is used up ($2.07 of $2.00); the agent's next model call waits
  [y] raise it to $3.11 · or type an amount, e.g. 4.14usd · [N] no, let it stop ›
```

Raise it, and the call goes through as if nothing happened. Say no, or don't answer within two minutes, and the call is answered with an error in the API's own format instead of reaching the provider: the agent stops on it, and its work so far is held for review like any other task. A "no" holds for the rest of the task, and an agent that keeps calling anyway is stopped. With nobody to ask (no terminal, no agentd, or `--no-ask`), calls are refused right away. The call that crosses the budget completes, since its cost is only known once it's done, so a task can end slightly over.

You can also raise a running task's budget before it runs out: `agent raise 5usd` (the latest running task, or `--task ID`), or **Raise budget** on its card in the console. Every raise is journaled with where you made it.

- **Dollars are at list prices.** Claude's are built in, including cache reads and writes, fast mode and web searches. With a claude.ai login, that's what the same calls would cost on the API: a measure of use, not your bill. For other models, add prices to your config (`[prices]`). Until you do, an unknown model counts at the highest Claude rate, so the budget errs on the safe side and the total shows as an upper bound (`≤ $1.20`).
- **Tokens count everything the model processed**: input, output, cache reads and writes.
- **Metered APIs:** Anthropic's Messages API, OpenAI's Responses, Chat Completions and embeddings, and whatever an agent file lists under `models`. Calls are measured whenever the broker relays them, as with Claude's login or a brokered key, even without a budget. Embedding models have no built-in price: add yours under `[prices]`, or they count at the highest rate.
- **What can't be metered is refused under a budget.** Some paid calls report no cost when they're made: Anthropic's Message Batches, OpenAI's batches, background responses (`"background": true`), fine-tuning, images, audio, video, Assistants runs and Realtime sessions. Under a budget (a task's, or one across tasks), agentos answers them with an error in the API's own format, before anything is sent; without one, they go through and you're told they aren't counted.
- **Near the end of a budget, model calls go one at a time.** From 80%, a call waits for the one before it to finish and be counted, so calls made in parallel (subagents, say) can't overshoot the budget together.
- A default for every task goes in your config: `[limits] budget = "5usd"`.

**Across tasks**, too, so many small tasks can't add up to a large bill:

```toml
[limits]
daily = "20usd"        # all your tasks, per day (your local time)
weekly = "80usd"
monthly = "150usd"
```

In your config they cover all your tasks; in a project's `.agentos.toml`, that project's (both apply). Every metered call goes into a ledger in the task store that all tasks share, so budgets hold across tasks running at the same time. Once one is used up, running tasks ask you as with a task budget, and new tasks don't start: the message says which budget, when it resets, and how to raise it until then. `agent spend` shows today, this week and this month, for everything and for the current project. A new ledger starts with the last 40 days of finished tasks.

Raising one lasts until it resets, so your config stays your standing policy:

```bash
agent raise 30usd --today              # all your tasks, until midnight
agent raise 60usd --this-month --project   # this project's, until the 1st
```

## agentd: the console

```bash
agent serve
```

This starts agentd and prints a link like `http://127.0.0.1:7777/#token=…`. The page lists your tasks, shows each one's diff, held pushes and journal, and has **Commit / Push / Roll back** buttons that run the same commands as the terminal. Running tasks show what they're doing right now.

**Start tasks from there too**, from your laptop or your phone: **New task**, pick a project, describe the task, optionally choose the agent, a budget and when to stop it. It runs exactly like `agent do --bg` in that folder: same sandbox, rules and journal (which notes it was started from the console). Its output streams into its card, and **Stop** ends it, with what it did so far held for review. Tasks can only be started in your projects: folders you've run agents in, plus those you list in your config:

```toml
[console]
projects = ["~/code/app", "~/code/site"]
```

Questions from agents appear at the top with **Allow for this task / Always / Deny**, alongside the terminal prompt; the first answer wins. Tasks with no terminal to ask at, like Claude's full-screen interface or background runs, ask there too. A task whose budget runs out asks there with **Raise to … / Let it stop**.

**Spend is in the header**: today's, against your daily budget if you have one. Click it for this week and this month, where each budget across tasks stands, and today's tasks by cost. A budget that's used up shows at the top, with buttons to raise it until it resets.

- **A team can share it.** agentd's own token is yours and does everything. `agent users add alex --role approver` makes another, shown once (only a hash is kept), as a link to give them:

  | role | may |
  |---|---|
  | `viewer` | read tasks, diffs, journals and what agents are asking, and watch a task's screen |
  | `approver` | also answer questions, stop tasks, take back what an agent was given, act on a task's screen |
  | `admin` | also start tasks, commit, push, roll back and raise budgets |

  What a named person does to a task (an answer, a commit, a stop) is written into that task's journal under their name (`console.action`), and a task they start says who started it. `agent users` lists them, `agent users remove NAME` takes a token back at once. Put agentd on a private network (`--listen 0.0.0.0:7777` over Tailscale, say), not the open internet: it's a plain-HTTP console and the token is a bearer token. A viewer sees every task's diff and journal, so give that role the way you'd give read access to the repositories.
- **A task with a screen** (`--display`) shows it in its card, refreshed every second, scaled to fit. **Act on it** hands you the mouse and keyboard: click on the picture and type, and your input goes to the task's screen as a person's would (through `xdotool`, which must be installed on the machine running agentd). It's for stepping in when an agent is stuck on a dialog; every click, key and typed run is journaled with your name, never the text you typed. A viewer can watch; acting needs an approver or you. Once the task has ended the card shows its last picture.
- `--listen 0.0.0.0:7777` to reach it from your phone, ideally over a private network such as Tailscale. Every API call needs the token.
- `--notify https://ntfy.sh/<your-topic>` sends a push notification for each new question (host and task title only, or which budget ran out), and when a task finishes, with what it left for review.

## Agents that live for days: schedules

An agent task is a transaction, so it ends. Work that goes on for days is a sequence of tasks that start themselves: agentd, the long-lived part, starts them on a timer.

```toml
[schedule.triage]                      # your config only
every = "24h"                          # a duration, at least a minute
project = "~/code/app"                 # one of the folders agentd may start tasks in (see [console] projects)
task = "Look at the open issues and write a summary in TRIAGE.md"
budget = "2usd"                        # a task nobody is watching deserves a budget
timeout = "30m"
# agent = "claude"
```

```bash
agent serve                            # agentd; or keep it running: systemctl --user enable --now agentd
agent schedules                        # what runs when
```

Each run is a task like any other, started as from the console (its journal says `agentd schedule triage`): its own sandbox, its changes and held pushes waiting for your review, its budget. A run never starts while the last one is still going. The first run comes one interval after agentd first sees the schedule, and agentd remembers when each last ran (in the task store), so it carries on across restarts, logouts and reboots: a run that came due while agentd was off happens once, when it's back. To keep agentd up with nobody logged in, `loginctl enable-linger $USER`. The console lists schedules with their next run and a **Run now** button (admins only).

**Events wake an agent too.** A hook is an address that starts a task when something is sent to it: a CI failure, an alert, a message.

```toml
[hook.ci-failed]                       # your config only
project = "~/code/app"
task = "CI failed. Find out why and fix it. The event: {event}"
token = "CI_HOOK_TOKEN"                # a variable (or a [secret_commands] entry) holding the hook's secret
budget = "2usd"
min_interval = "5m"                    # events closer together than this are refused (default 1m)
```

```bash
curl -X POST -H "Authorization: Bearer $CI_HOOK_TOKEN" --data @failure.json http://agentd-host:7777/api/hooks/ci-failed
agent hooks                            # the hooks, their addresses and use
```

The token (also accepted as `X-Agentos-Token` or `X-Gitlab-Token`, for senders that can only set a header) opens that hook and nothing else of agentd, and agentd's own token doesn't open hooks. The event's words go where `{event}` is (cleaned of control characters and cut to 8,000 characters), or after the task if you leave it out. **What came in is untrusted**, so the task starts *tainted* (`event`): it is asked before every tool call that isn't read-only, and your rules see `context.taint.contains("event")`. A hook never starts a second run while the last one is going, or sooner than `min_interval` (429 and 409 say so). Put agentd behind something private (Tailscale, a reverse proxy that checks the sender): anyone who can reach it and holds the token can start the task.

Rules, budgets and your questions all apply as they do to any task. With nobody at a terminal, a task's questions go to the console or are refused: give a scheduled task rules (`policy.cedar`) for what it should be allowed to do, and `release` rules for what may leave without you. Schedules are in your config only: a project can't make agentd run anything.

## Configuration

Two optional files, in TOML:

```toml
[network]
allow = ["@pypi", "api.github.com"]   # presets: @pypi @npm @crates @github @go
proxy = "http://proxy.corp:3128"      # your file only: see Network (default: HTTPS_PROXY)
local = [11434]                       # your file only: ports on your loopback agents may reach
hold = ["api.github.com"]             # reachable, but writes wait for your review (see API writes)

[files]
hide = [".env"]
ro = ["~/.cargo"]

[secrets]                             # your file only
GITHUB_TOKEN = "api.github.com"       # header defaults to authorization (Bearer)

[secret_commands]                     # your file only: where a key comes from when it isn't in your environment
GITHUB_TOKEN = ["pass", "show", "github"]

[limits]                              # defaults for every task
memory = "8G"
cpus = 4
budget = "5usd"                       # model calls: dollars, or tokens ("2M")

[mcp.github]                          # your file only: an MCP server, run outside the sandbox
command = ["github-mcp-server", "stdio"]
env = ["GITHUB_PERSONAL_ACCESS_TOKEN"]

[prices]                              # your file only; USD per million tokens
"gpt-*" = { input = 1.25, output = 10 }   # example figures: use your provider's

[schedule.triage]                     # your file only: agentd starts this on a timer
every = "24h"
project = "~/code/app"
task = "Summarize the open issues"

[hook.ci-failed]                      # your file only: POST /api/hooks/ci-failed starts this
project = "~/code/app"
task = "CI failed. The event: {event}"
token = "CI_HOOK_TOKEN"

[journal]                             # your file only: finished tasks' signed receipts go here
witness = "https://witness.example/receipts"

[registry]                            # your file only: where `agent install NAME` looks
url = "https://agents.example.com/index.json"
key = "…"                             # optional: the publisher's key, which must have signed the index
```

- **`~/.config/agentos/config.toml` is yours.** It applies to every task. Only this file may define `[secrets]`, `[mcp]` and `[prices]`; they're brokered whenever the variable has a value (in your environment, or from its `[secret_commands]` entry) and the task uses the allowlist network.
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

**Keys from your keychain.** A key doesn't have to live in your environment. Name a command that prints it, in your own config, and agentos runs it when a task needs the key and your environment doesn't have it:

```toml
[secret_commands]
ANTHROPIC_API_KEY = ["secret-tool", "lookup", "service", "anthropic"]      # GNOME Keyring, KWallet
GITHUB_TOKEN = ["pass", "show", "github"]                                  # pass
OPENAI_API_KEY = ["op", "read", "op://Private/OpenAI/credential"]          # 1Password
```

The command runs as you, outside any sandbox, with your environment. What it prints (minus the final newline) is the value, and it goes where the variable's value would have gone: to the broker for a `[secrets]` entry, `--secret`, an agent's own secrets (`ANTHROPIC_API_KEY` for Claude), or an MCP server's `env` and `token`. A variable set in your environment wins, and the command isn't run. Tasks that can't use the network don't run it. A command that fails, prints nothing or takes more than 30 seconds is a warning, and the task goes on without that key. The warning has the command's first line of error, never its output. Only your own config can have `[secret_commands]`: a project's can't make agentos run a program.

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
local = [11434]                            # ports on your loopback it uses (--local)
ro = ["~/.gitconfig"]                      # files and folders it reads, read-only
display = true                             # a virtual screen of its own (display_size = "1920x1080")

[secrets]                                  # brokered: the agent only sees placeholders
OPENAI_API_KEY = "api.openai.com"          # (the value: your environment, or [secret_commands])
```

An agent calling a model API other than Anthropic's or OpenAI's can list it before the first `[section]`, so its calls are metered and count against budgets: `models = [{ url = "https://openrouter.ai/api/v1/chat/completions", api = "openai" }]` (`api` is `anthropic`, `openai` or `gemini`; Gemini, Anthropic's and OpenAI's own APIs are built in; a trailing `*` in the URL matches any path under it).

`agent do --agent codex "…"` runs it like Claude: same sandbox, transactions, outbox, allowlist and broker, and its own persistent home. `agent agents` lists what you have, and `agent = "codex"` in your config makes it the default. [examples/agents/](../examples/agents) has starting points for Codex, Gemini CLI and Aider. **Aider has been run end to end** (0.86.2, with a model server on your machine through `local`: `aider-local.toml`, and `scripts/verify-aider.sh` runs the real Aider against a stand-in server to check it again); its Anthropic variant uses the same broker as Claude Code but hasn't been run with a real key. Codex and Gemini's flags are checked against their `--help`, but neither has been run end to end under agentos yet.

**Agent packages** are agents that come with what they run, and say what they need. A package is a folder with an `agentos-package.toml`:

```toml
[package]
name = "local-aider"
version = "0.1.0"
description = "Aider, with a model on this machine"

[agent]                                  # an agent file, as above
run = ["{pkg}/bin/run", "{task}"]        # {pkg}: where the package is installed
allow = ["pypi.org"]
local = [11434]                          # a server on your machine (--local)
ro = ["~/.gitconfig"]                    # files and folders it reads

[agent.secrets]
OPENAI_API_KEY = "api.openai.com"
```

```console
$ agent install ./local-aider
agent ▸ package local-aider 0.1.0: Aider, with a model on this machine
  digest  3f2a9c1e84b07d21 (4 files, 12.3 kB)
  it gets:
    runs         {pkg}/bin/run {task}
    network      pypi.org
    secret       OPENAI_API_KEY → api.openai.com (a placeholder in the sandbox; …)
    your machine 127.0.0.1:11434 (a server on your machine)
agent ▸ install local-aider 0.1.0? [y/N] y
✓ installed to ~/.local/share/agentos-packages/local-aider
$ agent do --agent local-aider "…"
```

[examples/packages/](../examples/packages) has one to try. `[agent]` *is* the agent file `agent install` writes, so the list you read is exactly what is enforced; there is no separate declaration to drift from it. The files are copied to a folder the agent can only read, their hashes are recorded, and **before every run** agentos checks that neither the files nor the agent file have changed since you approved them. A package that asks for more later (an upgrade) shows the difference first (`+`/`-` against what you installed). Without a terminal, install needs `--yes`; `--digest HEX` makes sure it's the package you read. `agent packages` lists what's installed and whether it's intact; `agent uninstall NAME` removes a package and the agent file it wrote. A package can't contain symlinks, can't take the name of a built-in agent, and can't replace an agent file you wrote yourself.

**A registry** is a static `index.json` anyone can host (GitHub Pages, S3, your intranet). Point your config at one, and install by name:

```toml
[registry]                                        # your config only
url = "https://agents.example.com/index.json"
```

```json
{ "packages": { "local-aider": {
    "version": "0.1.0",
    "description": "Aider, with a model on this machine",
    "url": "local-aider-0.1.0.tar.gz",
    "sha256": "…the tarball's…" } } }
```

```bash
agent search aider            # what the registry has
agent install local-aider     # fetch, unpack, then the same review as above
```

The tarball (32 MB at most) is checked against the `sha256` the index gives, unpacked into a folder of its own, and reviewed like any package: you read what it asks for and answer. An index entry may also give the package's `digest`, and then the package must match it. Symlinks, hard links and members that reach outside the folder are refused. The index is as trustworthy as the host you fetch it from: what the hash and the review protect is that the tarball is the one that index named, and that nothing is installed that you haven't read. A registry has to be https (or this machine, for testing), and only your own config can name one.

**Signed indexes.** To not depend on the host alone, give the publisher's key:

```toml
[registry]
url = "https://agents.example.com/index.json"
key = "9a1f…64 hex characters…"           # the publisher's Ed25519 public key
```

agentos then also fetches `index.json.sig` and refuses an index that key didn't sign, before reading a word of it; the index's hashes then vouch for the tarballs. A publisher makes a key once, and signs each version of the index:

```bash
agent registry pack ./my-agent -o site/      # site/my-agent-0.1.0.tar.gz, and its entry in site/index.json
agent registry keygen publisher.key          # prints the public key to hand out; keep the file private
agent registry sign site/index.json --key publisher.key     # writes site/index.json.sig next to it
```

`pack` reviews the package like `install` does and makes the same tarball for the same files (sorted, no dates or owners), so you can check what you publish; the index entry carries the tarball's hash and the package's digest. Putting `site/` on a web server is your step; agentos only makes the files.

To check the whole path with your real login, run `scripts/acceptance.sh`: `scripts/dev.sh exec 'bash /src/scripts/acceptance.sh'` on macOS.

## Limits (honest list)

- **An allowlist limits where data can go, not what is sent there.** The agent can put anything it read into its requests to allowed hosts. Keep secrets out of granted folders (`--hide .env`).
- **The proxy speaks HTTPS (`CONNECT`) only.** Plain HTTP and other protocols aren't supported. A corporate upstream proxy has to be `http://` or `socks5://`.
- **Brokered hosts speak HTTP/1.1 through the proxy**, one request at a time per connection. Clients that require HTTP/2 or WebSockets to those hosts won't work. With a budget, that includes model APIs.
- **Rules can't loosen the hard limits.** Credentials in your home, the task store and your config are never offered, whatever a `permit` says, and folders outside your home stay read-only mid-task when Landlock is on.
- **The agent writes its own reasons.** An agent steered by something it read can write a convincing one. Judge the request, not the prose.
- **Taking a folder back unmounts it, but files a process already has open there stay open**, and a shell already inside it keeps its working directory.
- **An MCP server marks its own tools read-only**, and agentos trusts that hint since the server is yours. If you don't, set the tool to `ask`.
- **Remote MCP servers speak Streamable HTTP.** The older HTTP+SSE transport isn't supported, and messages a server sends outside an answer (on its own stream) aren't relayed yet. Signing in needs a server whose authorization server lets clients register themselves, as MCP recommends; for others, use a token from your environment.
- **Budgets meter what they can read.** A Chat Completions stream without `stream_options.include_usage` reports no usage, so it isn't counted (you get a warning). Paid calls no response reports (batches and the others under Budgets) are refused under a budget only on Anthropic's and OpenAI's own hosts, from a list: an endpoint added after it isn't known. Model calls go one at a time only from 80% of a budget, so calls started in parallel just before that can still overshoot together. US-only inference (`inference_geo`, 1.1×) is priced at the standard rate.
- **The agent's home persists between tasks.** That's what keeps its login, but a misbehaving task could leave something there for the next one. Nothing outside the sandbox runs from it.
- **The syscall filter is a denylist** (seccomp): it blocks typing into your terminal (TIOCSTI), new namespaces, mounts, kernel modules, bpf, io_uring, keyrings and userfaultfd. Kernel bugs reachable through the remaining syscalls are out of scope until the microVM tier.
- **Only your own uid is mapped.** Files in a writable grant owned by another user (e.g. root-owned build output) can be read but not modified.
- **Writable grants must be directories**, and their paths can't contain `,` `:` or `\`.
- **Conflict detection uses mtimes.** If you *delete* a file on the host that the agent modified, commit recreates it without warning.
- **Only the top-level `.gitignore` of a grant is read**, not nested ones.
- **The outbox covers remotes that exist when the task starts.** A remote the agent adds itself has no outbox, and pushing to it fails for lack of network. Deleting a remote branch isn't held yet either.
- **`agent trust` records what you saw, not what you understood.** Read the file it prints.
- **The journal is tamper-evident against the agent, not against you.** Receipts and a witness (above) anchor its head somewhere you can't rewrite after the fact, if you run one; keeping the signing key in a TPM is a later step.
- **Landlock is best-effort.** It's used when the kernel has it (`agent doctor` tells you). Namespaces do the isolation either way.
- **Grants are mounted at their canonical path.** If `~/app` is a symlink, the agent sees the real path.

## Layout

```
src/sandbox.rs   namespaces, root assembly, Landlock, exec
src/changes.rs   reading/committing/rolling back overlay transactions
src/journal.rs   hash-chained event log
src/attest.rs    receipts: the journal head, signed; the witness
src/users.rs     people besides you for agentd's console: tokens and roles
src/schedule.rs  tasks agentd starts on a timer, and what it remembers of them
src/display.rs   a task's virtual screen: Xvfb, its cookie, screenshots (XWD to PNG)
src/store.rs     on-disk task store
src/doctor.rs    environment checks
src/profiles.rs  agent profiles (Claude Code) and their output
src/proxy.rs     egress proxy and allowlist
src/broker.rs    credential broker (per-task CA, HTTP/1.1 relay)
src/gateway.rs   model gateway: usage metering, prices, budgets
src/control.rs   the agent's requests from inside (control socket), and what may be granted
src/mcp.rs       `agent mcp`: agentos's MCP server for agents, and the gateway to yours
src/oauth.rs     signing in to remote MCP servers (`agent connect`), token refresh
src/policy.rs    your rules (Cedar): answers given in advance
src/packages.rs  agent packages: review, install, check before every run
src/registry.rs  a registry of them: index.json (signed, if you like), tarballs checked by hash
src/taint.rs     whether a task has read untrusted input
src/held.rs      held tool calls and API requests (the outbox for tools and APIs)
src/main.rs      entry point and dispatch; the rest of the CLI, one file per concern:
  src/cli.rs           arguments            src/plan.rs     `do`/`run`: arguments and config into a plan
  src/task.rs          running a task       src/owner.rs    your side of a running task (give back, raise)
  src/agent_control.rs the agent's requests src/review.rs   diff, commit, push, rollback, log
  src/admin.rs         approvals, rules, spend, connect, doctor
src/render.rs    output       src/web.rs   agentd's console
tests/e2e.sh     end-to-end tests (run as a normal user), with tests/fake-claude
scripts/acceptance.sh   the golden path with real Claude, for a human to run
scripts/package.sh      .deb and .rpm (nfpm), from packaging/: the unit, the AppArmor profile, install scripts
.github/workflows/ci.yml   unit + e2e tests on real Ubuntu 24.04 (x86_64, arm64), Landlock required
```
