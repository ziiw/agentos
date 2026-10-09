# agentos: design

## Thesis

Today's operating systems assume a human is the actor and programs are tools. Agents break that:
- they act on their own,
- any text they read can steer them (prompt injection),
- they make mistakes at machine speed.

Today the choice is to approve every action (permission fatigue) or turn on "YOLO mode". An agent-native OS makes full autonomy safe by default:

> **Every agent task is a transaction.** It runs with only the permissions it was granted. Every local change is snapshotted for review. Every action that reaches the outside world goes through an outbox. The human decides what gets committed.

And one hard rule: **models propose, the OS decides.** No LLM inside the security core. Every policy decision is deterministic code.

## Principles and their Linux mechanisms

| Principle | Meaning | Mechanism | Status |
|---|---|---|---|
| Agents have their own identity | Each task is its own principal, not "runs as you" | user namespaces, per-task ids, cgroups | ◐ namespaces |
| Explicit grants, no inherited access | The agent gets *this folder* and *this API with these scopes*, nothing else | mount namespaces, Landlock, seccomp | ● filesystem + syscalls; per-host network; grants grow mid-task when the agent asks and you agree (M16) |
| Local changes are reversible | A task ends as a diff you merge or throw away | overlayfs upper dirs, read-only base | ● |
| Network is an allowlist | No direct network, not even DNS; an egress proxy outside the sandbox lets through allowed hosts only and journals every connection | private netns + unix-socket proxy | ● |
| External actions wait in an outbox | Pushes, emails, API writes are held until policy or a human releases them | per-remote bare repos + your git; the egress proxy for HTTP | ● git pushes (M8), MCP tool calls that don't need an answer (M27) and API writes to hosts you hold (M34); what your rules permit is released without you when the task ends (M38) |
| Secrets never reach the model | The agent sees placeholders; real credentials are added at the proxy | credential broker, vault, keystore/TPM | ● API keys and OAuth logins brokered; keys from your environment or from a command of yours (your keychain, a password manager) (M29) |
| Taint tracking | Once a session reads untrusted input, its risky actions need approval | policy engine (Cedar) | ◐ (M26) a task is tainted by web hosts, outside-machine tool results and outside folders; tainted tasks are asked before every non-read-only tool call, and rules see `context.tainted`. Not yet: held pushes and uploads don't change, and taint isn't per-file |
| Flight recorder | Every action logged in a tamper-evident, replayable record | hash-chained journal, eBPF | ◐ journal: tool calls, connections, every model call with its measured cost; the head is signed into a receipt, optionally posted to a witness (M35); not yet: a TPM-held key, eBPF |
| Tokens are a budgeted resource | $/token/time budgets per task | model gateway | ● per-task $ or token budgets, metered on the wire (M15); time via --timeout |
| Interfaces built for agents | System services exposed as typed tools | MCP gateway, D-Bus bridge, AT-SPI | ◐ agentos's own MCP server in every sandbox: sandbox_info, request_path_access, request_network_access (M16); your MCP servers through a gateway (M17) |
| Agents can live for days | Sleep, wake on events, survive reboots | systemd units, CRIU | ◐ tasks that start themselves on a timer, remembered across restarts and reboots (M43); not yet: waking on events, resuming one task's context |

● done ◐ partial ○ planned

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Human surfaces    CLI (agent run/diff/commit) · approval UI  │
│                   (desktop + phone) · live session viewer    │
├──────────────────────────────────────────────────────────────┤
│ Agents (BYO)      Claude Code, Agent SDK apps, any CLI;      │
│                   works with any model or framework          │
├──────────────────────────────────────────────────────────────┤
│ Agent interface   MCP gateway · event bus · searchable index │
├──────────────────────────────────────────────────────────────┤
│ agentd            identity · permissions · policy ·          │
│                   transactions · outbox · credential broker ·│
│                   egress proxy · budgets · journal           │
├──────────────────────────────────────────────────────────────┤
│ Isolation tiers   process sandbox (ns + Landlock + seccomp)  │
│                   → microVM (Firecracker / Cloud Hypervisor) │
├──────────────────────────────────────────────────────────────┤
│ Base OS           read-only image, atomic A/B updates        │
│                   (bootc), measured boot                     │
├──────────────────────────────────────────────────────────────┤
│ Kernel            upstream LTS Linux, config only            │
└──────────────────────────────────────────────────────────────┘
```

**The distro is how this ships, not what it is.** The runtime has to be compelling on stock Ubuntu/Fedora first. The image (Phase 2) then bakes it in and guarantees the kernel features it relies on.

## Phase 0: what exists now

A single unprivileged binary, `agent`. Process tree for `agent run`:

```
supervisor (host)       validates grants, writes the journal, survives Ctrl-C
 └─ A                   unshare(user, mount, pid, ipc, uts[, net]); map own uid/gid
     └─ B  (pid 1)      tmpfs root ← ro system binds, private /dev /proc /tmp $HOME,
                        grants (overlay for rw), hide/mask; pivot_root; Landlock
         └─ C           exec the agent with a scrubbed environment
```

- **Transactions.** Each `--rw` grant is `overlay(lower=real dir, upper=store/tasks/<id>/layers/<n>/upper)`. The upper dir is the changeset: files are additions/modifications, `0:0` char devices are deletions, and `user.overlay.opaque` dirs replaced their lower dir. `commit` applies entries and retires them from the upper dir, so what remains is exactly what is pending. That makes partial commit and rollback natural, including for replaced directories (see `changes.rs` tests).
- **Journal.** `events.jsonl`. Each event is `sha256(prev_hash ‖ canonical_json(event))`. Written only by the supervisor, outside the sandbox, and the store is masked from every sandbox.
- **Tests.** Unit tests for the transaction engine and journal, plus `tests/e2e.sh` (80 checks covering isolation, transactions, conflicts, env scrubbing, the network allowlist and attempts to bypass it, ignored files, `agent do`, exit codes and tamper detection).

## Threat model (Phase 0)

**In scope.** An agent that is buggy, over-eager or steered by injected content, running as your uid. It must not:
- read ungranted files,
- modify anything except through a transaction,
- see your environment secrets,
- see other processes,
- reach the network under `--net none`,
- alter the record of what it did.

**Out of scope for now.** Kernel exploits (the microVM tier addresses those). Exfiltration under `--net host`, or to an allowed host (an allowlist limits destinations, not content). Abuse of secrets you pass explicitly. A malicious *user* rewriting the journal.

## Roadmap

| Phase | Deliverable | Proof it works |
|---|---|---|
| **0. Transactions** ✅ | Sandbox, overlay transactions, diff/commit/rollback, journal, doctor | An agent's risky change, reviewed and half rolled back |
| **1. The layer** ◐ | `agentd` + the items below, shipped as .deb/.rpm "agent layer for Linux" (M30) ✅; next: a signed apt/dnf repository | Outside developers use it daily |
| **2. The distro** ◐ | bootc image with agentos and agentd built in (M11) ✅; disks for clouds and VMs, with cloud-init (M31) ✅; next: the microVM tier (designed [below](#the-microvm-tier-design)), a published image to follow with `bootc upgrade` (pushing it to a registry is the owner's call, so CI doesn't) | Teams run agent fleets on it |
| **3. Desktop** ◐ | A separate display per agent: a virtual X screen each, watched with `agent screen` (M40 ✅), live in agentd's console where you can take over the mouse and keyboard (M41 ✅; next: Wayland, a desktop shell); local model service (agents reach the model server on your machine, M32 ✅) | Early adopters use it as their daily machine |
| **4. Ecosystem** ◐ | Agent packages that declare the permissions they need (M33 ✅), a registry (M37 ✅, signed indexes M39 ✅, `agent registry pack` M42 ✅; next: key rotation), remote attestation: signed journal heads and a witness (M35 ✅; next: a TPM-held key, verifying a whole machine's state) | Other developers build on it |

### The golden path (the Phase 1 target)

```bash
cd ~/app && agent do "add a test for greet" && agent diff && agent commit
```

It's done when:
- a real agent does the work in the sandbox, on the current folder, with no flags;
- it can reach its API and nothing else;
- it can't read outside the folder except its own installation;
- its credentials never appear in the journal;
- the journal records the task, every tool call and connection, and the result;
- all of this holds on macOS (dev container), real Ubuntu 24.04, and CI.

It's verified at three levels:
1. `tests/e2e.sh` with a stand-in agent (deterministic, every change), plus an attack suite;
2. CI on real kernels;
3. `scripts/acceptance.sh` with the real agent and a human, once per milestone.

| Milestone | Status |
|---|---|
| M1: `agent do`, current folder granted by default, hint for tasks passed to `agent run` | ✅ |
| M2: Claude Code profile, per-agent persistent home, streamed progress, tool calls and cost journaled | ✅ accepted with real Claude (2026-10-06) |
| M3: egress proxy with an allowlist, replacing `net host`; ignored files left out of commits | ✅ automated; real Claude verified through the proxy (free 401 check); human acceptance pending |
| M4: CI on ubuntu-24.04 (x86_64 + arm64): Landlock enforced, AppArmor path | ✅ green on GitHub Actions |
| M5: credential broker: the agent holds a placeholder, the proxy adds the real key on the wire | ✅ CI green; real Claude Code verified (13/13 requests injected, free 401 check) |
| M6: configuration: host presets, your config + project config with `agent trust`, expected denials | ✅ CI green |
| M7: live approvals: unlisted hosts are asked about at the terminal while the connection waits; "always" remembered per project | ✅ CI green |
| M8: git push outbox: pushes held per remote, replayed from your own git on commit | ✅ CI green |
| M9: login brokering: OAuth tokens sealed in a vault; placeholders in the sandbox; token endpoint rewritten both ways | ✅ CI green; real Claude verified with fake tokens (API + refresh paths) |
| M10: agentd console: tasks, diffs, commit/push/rollback and approvals in a browser; first answer wins; push notifications | ✅ CI green + checked in a browser |
| M12: background tasks: --bg, logs/wait/stop, --timeout; agentd shows live progress and notifies on completion | ✅ CI green |
| M13: resource limits: --memory/--cpus/--pids via transient systemd scopes (cgroup v2); OOM kills journaled | ✅ enforced and tested on Ubuntu CI (x86_64, arm64) and in the booted distro |
| M14: agents as config files: any agent CLI via `agents/NAME.toml` (commands, allowlist, brokered secrets, output); `agent agents`; default agent | ✅ CI green (stand-in agents); the real Aider run end to end with a local model (`scripts/verify-aider.sh`); Codex/Gemini examples untested |
| M15: model gateway: every model call metered from the provider's own usage (Anthropic Messages, OpenAI Responses/Chat Completions, custom endpoints), priced, journaled; per-task $ or token budgets, refused in the API's own format once used up | ✅ CI green (stand-in API); real Claude: in scripts/acceptance.sh |
| M16: agents ask: an MCP server in every sandbox (`agent mcp`, over a control socket) to see the sandbox and request folders or hosts with a reason; you answer at the terminal or in the console; granted folders are mounted into the running sandbox (open_tree + setns + move_mount from the namespace parent, which keeps a host view), writable ones as new overlay layers | ✅ CI green; real Claude Code connects to the server; asking for itself: in scripts/acceptance.sh |
| M17: MCP gateway: your servers (`[mcp.NAME]`, your config only) run by agentos outside the sandbox with your credentials; the agent reaches them through `agent mcp NAME`; read-only tools run, others ask you (this call / this task / always), per-tool policy, denied tools hidden, non-standard methods not relayed, every call journaled | ✅ CI green (stand-in server) |
| M18: rules: Cedar policies (`policy.cedar`) answer what agentos would ask you: connect, read, write, call (with the call's arguments as context); forbid beats everything including the allowlist, permit allows without asking, otherwise you're asked; `agent policy` lists and checks; a broken file stops tasks | ✅ CI green |
| M19: start tasks from agentd: a New task form (project, task, agent, budget, stop after) runs `agent do --bg` in one of your projects (folders you've used, or `[console] projects`); live output and Stop in the task's card; the journal records who started it | ✅ CI green |
| M20: project rules: `.agentos.cedar` at a project's root, forbids only, applied without review on top of yours (a project forbid beats your permit); a permit or a parse error stops the task; `agent diff` flags edits to it | ✅ CI green |
| M21: budgets across tasks: `[limits] daily/weekly/monthly` (yours: all tasks; a project's: that project); a spend ledger in the task store shared by every task (incremental reads, a file per month, seeded from the last 40 days); used up → model calls refused, new tasks don't start, the message says when it resets; `agent spend` | ✅ CI green |
| M22: taking grants back mid-task: `agent revoke` (or Take back in the console) unmounts a folder from the running sandbox or removes a host (closing its open connections); asking again is refused, rules included; held changes stay; journaled. Through a per-task owner socket the sandbox never sees | ✅ CI green |
| M23: raising a budget that's used up: the next model call waits while you're asked (terminal or console: raise to …, or let it stop) instead of being refused outright; `agent raise` for a running task's budget (owner socket) or one across tasks until it resets (raises in the ledger, the highest wins, so answering twice can't add up); spend in the console's header, a spend panel, used-up budgets with raise buttons | ✅ CI green |
| M24: budgets without loopholes: paid calls no response reports (Anthropic's and OpenAI's batches, background responses, fine-tuning, images, audio, video, Assistants runs, Realtime) are refused under a budget, before anything is sent, and noted otherwise; OpenAI Responses bodies are read ahead under a budget to spot `background`; embeddings are metered; from 80% of a budget, model calls go one at a time so parallel calls can't overshoot it together | ✅ CI green |
| M25: remote MCP servers natively: `[mcp.NAME] url = …` (Streamable HTTP: a POST per message, JSON or SSE answers, session and protocol-version headers, the session ended on hang-up), reached by the supervisor so the sandbox can't reach the server or hold its token; `token = "ENV"`, or `agent connect NAME` (OAuth 2.1 per MCP: discovery from the 401, RFC 9728 and 8414 metadata, dynamic client registration, PKCE, `resource`, a loopback redirect or a pasted one), tokens in the vault, refreshed before expiry or on a 401, one refresh at a time across tasks | ✅ |
| M26: taint tracking: a task is tainted once it reaches a host that isn't its own model API, a brokered credential's host, a package registry or in `[taint] trusted`; reads a result from an MCP server outside your machine (remote ones by default, `taint = …` per server); or is granted a folder outside its project. From then on, tool calls that aren't read-only are asked about every time whatever config or "always" said (only your own `permit` skips it), with what it read shown; rules see `context.tainted` / `context.taint`; `policy check --tainted`; `taint.marked` in the journal; a warning in the exit summary | ✅ |
| M27: held tool calls: `hold` per tool, per server (`hold = true`) or \[h] when asked queues a call in the task instead of running it; the agent is told it's queued, `agent diff` lists them with arguments, `agent commit`/`push` run them in order from outside the sandbox (stdio or remote server, your credentials), `agent rollback` drops them, a failed one stays held; held calls aren't asked about when tainted | ✅ |
| M28: corporate proxies: allowed connections can go out through your proxy (`HTTPS_PROXY`/`NO_PROXY`, or `[network] proxy` in your config only) instead of straight to the host, `CONNECT` with its login from the address, reached outside the sandbox so the agent never sees it; the hop is journaled, a proxy that says no is explained; hosts only the proxy can resolve work, ones resolving to private addresses are still refused; a CONNECT target with odd characters is refused before it's journaled or shown | ✅ |
| M29: keys from your keychain: `[secret_commands]` (your config only) names a command that prints a key when your environment doesn't have it (`secret-tool`, `pass`, `op read`…); used for `[secrets]`, `--secret`, an agent's own keys and MCP servers' `env` and `token`; run only when a task can use it, as you and outside the sandbox, 30-second limit; a failure is a warning that never includes the output | ✅ |
| M30: the layer as packages: `.deb` and `.rpm` (one nfpm file, `scripts/package.sh`) with `agent`, agentd as a systemd user unit (shared with the image), the docs, and on Ubuntu 23.10+ an install script that loads the AppArmor profile for `/usr/bin/agent` and takes it out with the package; CI builds them on x86_64 and arm64, installs the .deb on the Ubuntu 24.04 runner (the profile has to work: `agent doctor`, a sandboxed command), the .rpm on Fedora 42, removes both, and keeps them as artifacts | ✅ built and installed in clean Ubuntu 24.04 and Fedora 42 containers; CI job `package` |
| M31: images for clouds: cloud-init in the image (a cloud's users and SSH keys applied at first boot), the disk workflow builds qcow2, raw, ami (a raw disk to import), vmdk and an installer ISO (only the qcow2 is booted in CI), and the image README says how a machine follows an image and updates itself | ✅ the image builds with `bootc container lint` and cloud-init enabled; the other disk types are built, not tried |
| M32: a model server on your machine: `--local PORT` (or `[network] local = [PORT]` in your config only) gives a task one port of your loopback, at the same port on its own: a forwarder inside the sandbox, a socket out to the supervisor, and a relay to 127.0.0.1:PORT. Ollama, llama.cpp and vLLM work at their usual addresses with no proxy settings; the rest of your loopback stays out of reach; each connection is journaled, a server that isn't running is explained; not metered | ✅ |
| M33: agent packages: a folder with `agentos-package.toml` whose `[agent]` is an agent file (now also `local` and `ro`); `agent install` shows exactly what it gets (hosts, brokered secrets, ports on your machine, files read, environment, metered APIs), asks, copies the files where agents can only read them, records their hashes and the written agent file's; `agent do` checks both against what you approved before every run; an upgrade shows `+`/`-` against the installed version; `--digest` pins the package you read; no symlinks, no built-in names, no replacing your own agent files; `agent packages`, `agent uninstall` | ✅ |
| M34: API writes wait in the outbox: `--hold HOST` (or `[network] hold`, in your config or a project's, since it only restricts) lets a task reach a host but queues its writes (POST, PUT, PATCH, DELETE) in the task, answered with a 202; the broker terminates TLS for the host to read the method; a brokered credential's header is left blank in the queue and filled in from your environment or `[secret_commands]` when `agent commit`/`push` sends the request (nothing followed, 2xx or it stays held); `agent diff` shows URL and body preview, `agent rollback` drops it; model APIs and logins aren't held; bodies over 1 MiB are refused | ✅ |
| M35: receipts: when a task ends, its journal's head is signed with this machine's Ed25519 key (made on first use in the task store) into `receipt.json`; `agent attest --verify` checks the signature and, with `--journal`, that a journal still holds the history the receipt vouches for (a rewritten chain is caught even when it verifies); `--trust KEY`; `[journal] witness` (your config only; https, or this machine) gets every receipt, and `agent attest` re-issues one; an unreachable witness is a warning | ✅ |
| M36: a team on one agentd: `agent users add NAME --role viewer\|approver\|admin` makes a token (shown once, kept hashed in the store) with less than yours; the API checks the role on every call (reading for viewers; answering, stopping and taking back for approvers; starting, commit, push, rollback and budgets for admins; 403 says what's needed); what a named person does to a task is journaled under their name (`console.action`), and tasks they start say who started them; `agent users remove` revokes at once | ✅ API and CLI; the console page doesn't show who you are yet |
| M37: a registry of agent packages: `[registry] url` (your config only; https, or this machine) names a static `index.json`; `agent search` lists it and `agent install NAME` fetches the tarball (32 MB at most), checks it against the index's sha256 (and the package's digest, if the index gives one), unpacks it in a folder of its own with symlinks, hard links and `..` refused, then puts it through the same review as a package from disk; the download is removed afterwards | ✅ |
| M38: rules that release: a Cedar `release` action (resources `Push`, `Request`, `Tool`; yours only) decides, when a task ends, which held pushes, tool calls and API requests are sent without you, with the same credentials and code as `agent commit`; a forbid wins, the rest stays held; `outbox.released` in the journal names the rule; `agent policy check release …` | ✅ |
| M39: signed registry indexes: `[registry] key` (the publisher's Ed25519 public key, in your config) makes agentos fetch `index.json.sig` as well and refuse an index that key didn't sign, unread; `agent registry keygen` and `agent registry sign` are the publisher's side | ✅ |
| M40: a screen of its own: `--display` (or `display = true` in an agent file or package) starts a private Xvfb outside the sandbox, with no network and no abstract socket, a cookie for the one client, shared memory off; the sandbox gets its socket as display :0 and nothing else of your displays; the framebuffer is a file in the task, so `agent screen` (PNG, now or as it ended; `-o -` for a pipe) shows it without the agent, and the latest picture with anything on it is kept at the end; `agent doctor` says whether Xvfb is there | ✅ with Xvfb installed (CI installs it) |
| M41: watching and taking over a screen from agentd: a task's card shows its screen, live (`GET /api/tasks/ID/screen.png`, `?w=` to scale; viewers may), and **Act on it** sends clicks, keys and typed text to the running task's display with xdotool (approvers and you); every input is journaled with who did it, never the typed text; the last picture is served after the task ends | ✅ |
| M42: the publisher's side of a registry: `agent registry pack DIR -o SITE` reviews a package, makes `NAME-VERSION.tar.gz` (sorted, no dates or owners: the same files make the same bytes) and adds its entry, with the tarball's sha256 and the package's digest, to `SITE/index.json`; with `keygen` and `sign` that's everything a static registry needs; nothing is uploaded anywhere | ✅ |
| M43: schedules: `[schedule.NAME]` (your config only: every, project, task, agent, budget, timeout) makes agentd start the task on a timer, each run a task of its own that says `agentd schedule NAME` in its journal; never while the last run is still going; what agentd remembers (`schedules.json` in the store) means a restart or a reboot carries on: a run that came due meanwhile happens once; `agent schedules`, the console's list with **Run now** (admins) | ✅ |
| M11: the distro: Fedora bootc image with agentos built in, e2e run inside it in CI, qcow2 on demand | ✅ e2e green inside the image; the qcow2 boots in QEMU (own kernel 6.19) and passes the whole e2e suite (179/179, Landlock and limits enforced) |

### Phase 1 backlog, in order

1. **Profiles and configuration.** Claude Code is built in (`src/profiles.rs`). ✅ Config files: `~/.config/agentos/config.toml` and trust-on-review `.agentos.toml` (M6). ✅ Agents as files (M14). ✅ Token and dollar budgets (M15). ✅ Aider verified end to end against a model on your machine (`scripts/verify-aider.sh`). Next: verified recipes for Codex and Gemini CLI.
2. **Egress proxy.** ✅ Done without veth or root: the sandbox has only loopback, and a forwarder inside relays to the proxy through a unix socket. ✅ Presets (`--allow @pypi`, M6). ✅ Upstream corporate proxies, `http://` and `socks5://` (M28). Next: plain HTTP, and `https://` upstream proxies.
3. **Credential broker.** ✅ Per-task CA, TLS termination for brokered hosts only, placeholder → real value in one header. ✅ OAuth logins (M9): tokens sealed in a vault, the token endpoint rewritten both ways so even `/login` in the sandbox yields placeholders. ✅ Keys from your keychain or a password manager instead of the environment (M29). Next: sealing them in the agentos vault itself (TPM-backed).
4. **Effects outbox.** ✅ `git push` (M8): each remote gets a bare outbox repo in the task, git in the sandbox pushes there (`GIT_CONFIG_*`), `agent commit` replays from your own git. ✅ HTTP writes to APIs (M34). ✅ Policy auto-release (M38): your rules send what they permit when a task ends. Next: writes to hosts the proxy only tunnels.
5. **seccomp profile.** ✅ Denylist: TIOCSTI/TIOCLINUX, namespace creation (unshare, setns, clone flags; clone3 → ENOSYS), mount APIs, modules, kexec, bpf, perf, io_uring, keyrings, userfaultfd. Next: an allowlist profile per agent.
6. **cgroups.** ✅ CPU, memory and pid limits through a systemd transient scope (M13).
   **Budgets across tasks.** ✅ (M21) Per day, week or month, for all your tasks or one project's, against a ledger every task writes to. ✅ Raised for the rest of the period, from the terminal or the console (M23).
   **Model gateway.** ✅ (M15) Model calls go through the broker's TLS termination (for credentialed hosts, and for model APIs when there's a budget), so the gateway reads the usage the provider reports in each response, JSON or streamed, without trusting the agent. Calls are priced (built-in Claude list prices, `[prices]` for the rest; an unknown model counts at the highest rate), journaled, and counted against the task's budget. Once it's used up, the next model call waits while you're asked whether to raise it (M23): the request is held before anything goes upstream, and if the provider drops the idle connection meanwhile, the agent's client retries on a new one. Refused (you said no, nobody answered in 2 minutes, or there's nobody to ask), it gets a 400 in the API's own error format, which agents don't retry; one that keeps calling is stopped after 5 refusals. ✅ What can't be metered (batches, background responses, and other paid calls no response reports) is refused under a budget, and calls go one at a time near its end (M24). ✅ The Gemini API too (generateContent, streamed or not; batches, Imagen and Veo refused under a budget).
7. **agentd + API.** ✅ `agent serve` (M10): token-protected web console and JSON API; approvals reach you away from the terminal, with optional push notifications. ✅ Agents request folders and hosts mid-task, with a reason, and you answer at the terminal or in the console (M16). ✅ Your rules in Cedar answer in advance (M18). ✅ Tasks start from agentd's console too, with live output and Stop (M19). ✅ Projects ship rules that can only forbid (M20). ✅ What you grant mid-task can be taken back (M22). ✅ A team on one agentd: tokens with roles, and who did what in the journal (M36). Next: sign-in with your identity provider (OIDC) instead of tokens, per-project roles.
8. **MCP gateway.** System services exposed as typed tools, governed by the same policy. ✅ The first server: agentos itself (M16). ✅ Your servers, run outside the sandbox with your credentials, every call journaled and governed (M17). ✅ Remote (HTTP) servers natively, with their OAuth sign-in kept in the vault (M25). ✅ Policy on a call's arguments: rules see `context.args`, so "only this repo" is a rule (M18), for running a call and for releasing a held one (M38). Next: system services (D-Bus) as servers.

## The microVM tier (design)

The process sandbox shares the host's kernel, so a kernel bug reachable through the syscalls it still allows is out of scope (see the threat model). For agents you trust less, or machines shared by a team, the answer is a VM boundary under the same task model. Nothing here is built yet; this is the plan, shaped by what already exists.

**The seam.** `sandbox::run(spec, …)` is the one place a task's isolation starts. It becomes one of two implementations of the same contract, chosen with `agent do --isolation vm` (or `[isolation]` in your config): the process sandbox as today, or a microVM. Everything outside it is untouched, because it already lives on the host side of sockets: the journal and receipts, the credential broker and its CA, the model gateway and budgets, the egress proxy and allowlist, the outbox and held calls, rules, taint, `agent diff`/`commit`/`rollback`.

**The guest.** Cloud Hypervisor or Firecracker (small Rust VMMs, KVM only, a minimal device model), the distro's own kernel with a trimmed config, and an initramfs that holds one program: `agent` itself, as the guest's init, running the same `sandbox_init` steps it runs in a namespace today (root assembly, Landlock, seccomp, exec), so the in-guest sandbox still applies to a compromised agent that reaches its root.

**Grants.** Read-only grants go in over virtiofs. A writable grant stays an overlay: lower is the virtiofs read-only view of your folder, upper is a directory in the task store shared read-write. The host reads the changeset from the upper directory exactly as `changes.rs` does now, so transactions, conflict detection, partial commit and rollback don't change, and the agent still can't write your files.

**No network device at all.** The sockets that carry the proxy, the control channel, the owner channel and `--local` ports today (unix sockets mounted into the sandbox) become vsock ports. The guest forwarders already speak "connect to a socket, pump bytes"; they connect to vsock instead. On the host the VMM maps a guest vsock port to a unix socket path, so `proxy::serve`, `control::serve` and `serve_local` bind and accept as they do now. A guest with no NIC cannot reach anything but those doors.

**Limits and startup.** `--memory` and `--cpus` become the VM's memory and vCPUs (enforced by the VMM and KVM, no systemd scope needed). Boot is a fraction of a second with a stripped guest; restoring from a snapshot of a booted-and-idle guest is the later optimisation. The agent's home and the task store's masking are unchanged: the guest sees only what the VMM was given.

**What it doesn't change, or add.** GPU and device passthrough are out. Nested virtualisation matters in CI and on cloud VMs: GitHub's Ubuntu runners and bare-metal or nested-capable instances have `/dev/kvm`; Docker Desktop on a Mac does not, so the e2e suite keeps running the process tier there.

**In order.** (1) Put `sandbox::run` behind an `Isolation` trait with the process sandbox as its first implementation, no behaviour change. (2) A guest image and init: reuse the bootc image's kernel, build the initramfs from `agent`. (3) vsock transport for the existing socket doors, tested against the process tier with the same e2e checks. (4) virtiofs grants and the shared upper directory. (5) `agent doctor` checks `/dev/kvm`; CI runs the suite under `--isolation vm` on a KVM runner. (6) Snapshots.

## Open decisions

- **First user.** Developers running coding/ops agents (current bet) vs fleets on servers vs consumer desktop.
- **Base image for Phase 2.** Fedora/CentOS bootc (current bet) vs NixOS.
- **License.** Apache-2.0 placeholder. Decide before the first public release.
