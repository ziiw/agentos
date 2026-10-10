> 👋 This is a side project made for fun

> I want to build a computer for agents.
> For now it looks closely to a "Sandbox code exec"
> If you look in details, it's quite different

> The core is a custom made agent harness that wraps, agents.
> Then all the good things a sandbox should have
> And finally the `diff`, `commit`, `rollback`
> You should try this it's quite fun

# agentos

Run AI agents with full autonomy, and undo anything.

```console
$ cd ~/app
$ agent do "add a test for greet"
$ agent diff        # exactly what it did
$ agent commit      # keep it (or: agent rollback)
```

Every agent task is a transaction:

- The agent sees only what you grant. By default that's the current folder, and the network is an allowlist.
- Its writes land in an overlay, not your files. You review, then commit or roll back.
- Everything is recorded in a hash-chained journal the agent can't reach. Budgets cap what it can spend.

No root, no daemon, no containers: just Linux user namespaces, overlayfs and Landlock.

## Install

Linux, kernel 5.11+. As a package (CI builds a `.deb` and an `.rpm` on every push, under Actions → ci; `scripts/package.sh` makes them locally):

```bash
sudo apt install ./agentos_*.deb     # Ubuntu, Debian: also sets up the AppArmor profile Ubuntu 23.10+ needs
sudo dnf install ./agentos-*.rpm     # Fedora, RHEL
agent doctor
```

Or from source, with Rust 1.85+:

```bash
cargo build --release && sudo install -m 0755 target/release/agent /usr/local/bin/agent
agent doctor
```

On macOS or Windows, use Docker: `scripts/dev.sh shell`.

## Docs

- [Tour](docs/TOUR.md): a hands-on walkthrough
- [Reference](docs/REFERENCE.md): commands, network, budgets, rules, configuration, limits
- [Design](docs/DESIGN.md): the full design and roadmap
- [OS image](image/README.md): agentos as a bootable Linux distribution
