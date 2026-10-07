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
| External actions wait in an outbox | Pushes, emails, API writes are held until policy or a human releases them | per-remote bare repos + your git; egress proxy for HTTP later | ◐ git pushes (M8) |
| Secrets never reach the model | The agent sees placeholders; real credentials are added at the proxy | credential broker, vault, keystore/TPM | ● API keys and OAuth logins brokered; keys from the environment, not yet the OS keychain |
| Taint tracking | Once a session reads untrusted input, its risky actions need approval | policy engine (Cedar) | ◐ the engine: your Cedar rules answer every question agentos asks (M18); taint as context next |
| Flight recorder | Every action logged in a tamper-evident, replayable record | hash-chained journal, eBPF | ◐ journal: tool calls, connections, every model call with its measured cost |
| Tokens are a budgeted resource | $/token/time budgets per task | model gateway | ● per-task $ or token budgets, metered on the wire (M15); time via --timeout |
| Interfaces built for agents | System services exposed as typed tools | MCP gateway, D-Bus bridge, AT-SPI | ◐ agentos's own MCP server in every sandbox: sandbox_info, request_path_access, request_network_access (M16); your MCP servers through a gateway (M17) |
| Agents can live for days | Sleep, wake on events, survive reboots | systemd units, CRIU | ○ Phase 3 |

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
| **1. The layer** | `agentd` + the items below, shipped as .deb/.rpm "agent layer for Linux" | Outside developers use it daily |
| **2. The distro** ◐ | bootc image with agentos and agentd built in (M11) ✅; next: microVM tier, cloud images, published updates | Teams run agent fleets on it |
| **3. Desktop** | Wayland session with a separate display per agent (watch, take over), local model service | Early adopters use it as their daily machine |
| **4. Ecosystem** | Agent packages that declare the permissions they need, registry, remote attestation | Other developers build on it |

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
| M14: agents as config files: any agent CLI via `agents/NAME.toml` (commands, allowlist, brokered secrets, output); `agent agents`; default agent | ✅ CI green (stand-in agents); Codex/Gemini/Aider examples untested |
| M15: model gateway: every model call metered from the provider's own usage (Anthropic Messages, OpenAI Responses/Chat Completions, custom endpoints), priced, journaled; per-task $ or token budgets, refused in the API's own format once used up | ✅ CI green (stand-in API); real Claude: in scripts/acceptance.sh |
| M16: agents ask: an MCP server in every sandbox (`agent mcp`, over a control socket) to see the sandbox and request folders or hosts with a reason; you answer at the terminal or in the console; granted folders are mounted into the running sandbox (open_tree + setns + move_mount from the namespace parent, which keeps a host view), writable ones as new overlay layers | ✅ CI green; real Claude Code connects to the server; asking for itself: in scripts/acceptance.sh |
| M17: MCP gateway: your servers (`[mcp.NAME]`, your config only) run by agentos outside the sandbox with your credentials; the agent reaches them through `agent mcp NAME`; read-only tools run, others ask you (this call / this task / always), per-tool policy, denied tools hidden, non-standard methods not relayed, every call journaled | ✅ CI green (stand-in server) |
| M18: rules: Cedar policies (`policy.cedar`) answer what agentos would ask you: connect, read, write, call (with the call's arguments as context); forbid beats everything including the allowlist, permit allows without asking, otherwise you're asked; `agent policy` lists and checks; a broken file stops tasks | ✅ CI green |
| M19: start tasks from agentd: a New task form (project, task, agent, budget, stop after) runs `agent do --bg` in one of your projects (folders you've used, or `[console] projects`); live output and Stop in the task's card; the journal records who started it | ✅ CI green |
| M20: project rules: `.agentos.cedar` at a project's root, forbids only, applied without review on top of yours (a project forbid beats your permit); a permit or a parse error stops the task; `agent diff` flags edits to it | ✅ CI green |
| M21: budgets across tasks: `[limits] daily/weekly/monthly` (yours: all tasks; a project's: that project); a spend ledger in the task store shared by every task (incremental reads, a file per month, seeded from the last 40 days); used up → model calls refused, new tasks don't start, the message says when it resets; `agent spend` | ✅ CI green |
| M22: taking grants back mid-task: `agent revoke` (or Take back in the console) unmounts a folder from the running sandbox or removes a host (closing its open connections); asking again is refused, rules included; held changes stay; journaled. Through a per-task owner socket the sandbox never sees | ✅ CI green |
| M23: raising a budget that's used up: the next model call waits while you're asked (terminal or console: raise to …, or let it stop) instead of being refused outright; `agent raise` for a running task's budget (owner socket) or one across tasks until it resets (raises in the ledger, the highest wins, so answering twice can't add up); spend in the console's header, a spend panel, used-up budgets with raise buttons | ✅ |
| M11: the distro: Fedora bootc image with agentos built in, e2e run inside it in CI, qcow2 on demand | ✅ e2e green inside the image; the qcow2 boots in QEMU (own kernel 6.19) and passes the whole e2e suite (179/179, Landlock and limits enforced) |

### Phase 1 backlog, in order

1. **Profiles and configuration.** Claude Code is built in (`src/profiles.rs`). ✅ Config files: `~/.config/agentos/config.toml` and trust-on-review `.agentos.toml` (M6). ✅ Agents as files (M14). ✅ Token and dollar budgets (M15). Next: verified recipes for Codex, Gemini CLI and Aider.
2. **Egress proxy.** ✅ Done without veth or root: the sandbox has only loopback, and a forwarder inside relays to the proxy through a unix socket. Next: presets (`--allow @pypi`), upstream corporate proxies.
3. **Credential broker.** ✅ Per-task CA, TLS termination for brokered hosts only, placeholder → real value in one header. ✅ OAuth logins (M9): tokens sealed in a vault, the token endpoint rewritten both ways so even `/login` in the sandbox yields placeholders. Next: keys from the OS keychain instead of the environment.
4. **Effects outbox.** ✅ `git push` (M8): each remote gets a bare outbox repo in the task, git in the sandbox pushes there (`GIT_CONFIG_*`), `agent commit` replays from your own git. Next: HTTP writes to APIs, policy auto-release.
5. **seccomp profile.** ✅ Denylist: TIOCSTI/TIOCLINUX, namespace creation (unshare, setns, clone flags; clone3 → ENOSYS), mount APIs, modules, kexec, bpf, perf, io_uring, keyrings, userfaultfd. Next: an allowlist profile per agent.
6. **cgroups.** ✅ CPU, memory and pid limits through a systemd transient scope (M13).
   **Budgets across tasks.** ✅ (M21) Per day, week or month, for all your tasks or one project's, against a ledger every task writes to. ✅ Raised for the rest of the period, from the terminal or the console (M23).
   **Model gateway.** ✅ (M15) Model calls go through the broker's TLS termination (for credentialed hosts, and for model APIs when there's a budget), so the gateway reads the usage the provider reports in each response, JSON or streamed, without trusting the agent. Calls are priced (built-in Claude list prices, `[prices]` for the rest; an unknown model counts at the highest rate), journaled, and counted against the task's budget. Once it's used up, the next model call waits while you're asked whether to raise it (M23): the request is held before anything goes upstream, and if the provider drops the idle connection meanwhile, the agent's client retries on a new one. Refused (you said no, nobody answered in 2 minutes, or there's nobody to ask), it gets a 400 in the API's own error format, which agents don't retry; one that keeps calling is stopped after 5 refusals. Next: the Gemini API, and refusing the batch APIs under a budget (they're billed later and not metered).
7. **agentd + API.** ✅ `agent serve` (M10): token-protected web console and JSON API; approvals reach you away from the terminal, with optional push notifications. ✅ Agents request folders and hosts mid-task, with a reason, and you answer at the terminal or in the console (M16). ✅ Your rules in Cedar answer in advance (M18). ✅ Tasks start from agentd's console too, with live output and Stop (M19). ✅ Projects ship rules that can only forbid (M20). ✅ What you grant mid-task can be taken back (M22). Next: accounts for teams.
8. **MCP gateway.** System services exposed as typed tools, governed by the same policy. ✅ The first server: agentos itself (M16). ✅ Your servers, run outside the sandbox with your credentials, every call journaled and governed (M17). Next: remote (HTTP) servers natively, with their OAuth tokens in the vault; policy on arguments (e.g. only this repo); system services (D-Bus) as servers.

## Open decisions

- **First user.** Developers running coding/ops agents (current bet) vs fleets on servers vs consumer desktop.
- **Base image for Phase 2.** Fedora/CentOS bootc (current bet) vs NixOS.
- **License.** Apache-2.0 placeholder. Decide before the first public release.
