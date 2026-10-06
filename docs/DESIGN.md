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
| Explicit grants, no inherited access | The agent gets *this folder* and *this API with these scopes*, nothing else | mount namespaces, Landlock, seccomp | ● filesystem + syscalls; per-host network |
| Local changes are reversible | A task ends as a diff you merge or throw away | overlayfs upper dirs, read-only base | ● |
| Network is an allowlist | No direct network, not even DNS; an egress proxy outside the sandbox lets through allowed hosts only and journals every connection | private netns + unix-socket proxy | ● |
| External actions wait in an outbox | Pushes, emails, API writes are held until policy or a human releases them | egress proxy + effects broker | ○ Phase 1 |
| Secrets never reach the model | The agent sees placeholders; real credentials are added at the proxy | credential broker, keystore/TPM | ● API keys brokered (header-only, per-host); logins not yet |
| Taint tracking | Once a session reads untrusted input, its risky actions need approval | policy engine (Cedar) | ○ Phase 1 |
| Flight recorder | Every action logged in a tamper-evident, replayable record | hash-chained journal, eBPF | ◐ journal: tool calls, connections, cost |
| Tokens are a budgeted resource | $/token/time budgets per task | model gateway | ○ Phase 1 |
| Interfaces built for agents | System services exposed as typed tools | MCP gateway, D-Bus bridge, AT-SPI | ○ Phase 1 |
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
| **2. The distro** | bootc image with agentd built in, microVM tier, cloud images, headless agent host | Teams run agent fleets on it |
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
| M7: live approvals: unlisted hosts are asked about at the terminal while the connection waits; "always" remembered per project | ✅ automated (pseudo-terminal tests) |

### Phase 1 backlog, in order

1. **Profiles and configuration.** Claude Code is built in (`src/profiles.rs`). ✅ Config files: `~/.config/agentos/config.toml` and trust-on-review `.agentos.toml` (M6). Next: agent profiles as files, verified recipes for Codex and Aider, budgets.
2. **Egress proxy.** ✅ Done without veth or root: the sandbox has only loopback, and a forwarder inside relays to the proxy through a unix socket. Next: presets (`--allow @pypi`), upstream corporate proxies.
3. **Credential broker.** ✅ Per-task CA, TLS termination for brokered hosts only, placeholder → real value in one header. Next: OAuth logins (keep refresh tokens outside), keys from the OS keychain instead of the environment.
4. **Effects outbox.** `git push`, mail and API writes are held as pending effects next to the file diff. `agent commit` releases them, or policy auto-releases low-risk ones.
5. **seccomp profile.** ✅ Denylist: TIOCSTI/TIOCLINUX, namespace creation (unshare, setns, clone flags; clone3 → ENOSYS), mount APIs, modules, kexec, bpf, perf, io_uring, keyrings, userfaultfd. Next: an allowlist profile per agent.
6. **cgroups.** CPU, memory and pid limits through a systemd transient scope. Token/$ budgets through the model gateway.
7. **agentd + API.** ◐ Approvals exist at the terminal (M7); the daemon makes them reachable from elsewhere. Long-running daemon. Agents can request extra permissions mid-task, and an approval UI (terminal, desktop notification, phone) answers. Policy in Cedar.
8. **MCP gateway.** System services exposed as typed tools, governed by the same policy.

## Open decisions

- **First user.** Developers running coding/ops agents (current bet) vs fleets on servers vs consumer desktop.
- **Base image for Phase 2.** Fedora/CentOS bootc (current bet) vs NixOS.
- **License.** Apache-2.0 placeholder. Decide before the first public release.
