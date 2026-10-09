//! Command-line arguments.

use crate::*;

#[derive(Parser)]
#[command(
    name = "agent",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("AGENTOS_REV"), ")"),
    about = "Run AI agents as transactions: sandboxed, reversible, audited.",
    after_help = "Examples:
  agent do \"add a test for greet\"   give a task to Claude Code, working on this folder
  agent do                          open an interactive Claude Code session
  agent run -- make test            run any command as a sandboxed task
  agent diff                        see what the last task changed
  agent commit / agent rollback     keep it or throw it away"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Give a task to an AI agent, working on the current folder
    Do(DoArgs),
    /// Run any command as a sandboxed task
    Run(RunArgs),
    /// List tasks
    Ls,
    /// Show what a task changed
    Diff {
        /// Task id or prefix (default: the latest task)
        task: Option<String>,
        /// Only show changes under these paths
        paths: Vec<PathBuf>,
        /// Only list changed paths, no contents
        #[arg(long)]
        stat: bool,
        /// Also show ignored changes (.gitignore, __pycache__, …)
        #[arg(long)]
        all: bool,
    },
    /// Apply a task's changes to your files (all of them, or only those under PATHs)
    Commit {
        /// Task id or prefix (`last` for the latest)
        task: Option<String>,
        paths: Vec<PathBuf>,
        /// Commit even if the files changed on your side while the agent ran
        #[arg(long)]
        force: bool,
        /// Include ignored changes (.gitignore, __pycache__, …)
        #[arg(long)]
        all: bool,
        /// Apply the file changes but keep the agent's git pushes held
        #[arg(long)]
        no_push: bool,
    },
    /// Send a task's held git pushes, with your own git and credentials
    Push {
        /// Task id or prefix (default: the latest task)
        task: Option<String>,
        /// Overwrite the remote even if it moved since (git push --force)
        #[arg(long)]
        force: bool,
    },
    /// Discard a task's changes (all of them, or only those under PATHs)
    #[command(alias = "discard")]
    Rollback {
        /// Task id or prefix (`last` for the latest)
        task: Option<String>,
        paths: Vec<PathBuf>,
    },
    /// Show what a task printed (background tasks)
    Logs {
        /// Task id or prefix (default: the latest task)
        task: Option<String>,
        /// Keep printing until the task ends
        #[arg(short, long)]
        follow: bool,
    },
    /// Wait for a task to end; exits with its exit code
    Wait {
        /// Task id or prefix (default: the latest task)
        task: Option<String>,
    },
    /// Stop a running task (its changes stay held for review)
    Stop {
        /// Task id or prefix (default: the latest task)
        task: Option<String>,
    },
    /// Show a task's audit journal and verify its hash chain
    Log {
        /// Task id or prefix (default: the latest task)
        task: Option<String>,
        /// Print raw JSON events
        #[arg(long)]
        json: bool,
    },
    /// Check whether this machine can run agent sandboxes
    Doctor,
    /// Your agent's sealed login: status, seal (move tokens to the vault) or
    /// unseal (put them back and stop sealing)
    Vault {
        #[arg(value_parser = ["status", "seal", "unseal"], default_value = "status")]
        action: String,
        /// Which agent
        #[arg(long, default_value = "claude")]
        agent: String,
    },
    /// People besides you who can use agentd's console, with a token and a
    /// role each (viewer, approver or admin); with no subcommand, list them
    Users {
        #[command(subcommand)]
        command: Option<UsersCommand>,
    },
    /// Run agentd: a web console for tasks and approvals (phone-friendly)
    Serve {
        /// Address to listen on; 0.0.0.0:PORT to reach it from other devices
        #[arg(long, default_value = "127.0.0.1:7777")]
        listen: String,
        /// Ping this URL on each new question (e.g. https://ntfy.sh/your-topic)
        #[arg(long, value_name = "URL")]
        notify: Option<String>,
    },
    /// List hosts you approved "always", or revoke one for this project
    Approvals {
        /// Forget this host (as listed) for the current project
        #[arg(long, value_name = "HOST")]
        revoke: Option<String>,
    },
    /// List the agents you can use with `agent do --agent NAME`
    Agents,
    /// The tasks agentd starts on a timer ([schedule.NAME] in your config), and
    /// when each next runs
    Schedules,
    /// The hooks that start a task when an event is sent to agentd ([hook.NAME]
    /// in your config)
    Hooks,
    /// Save a picture of a task's screen (it needs --display)
    Screen {
        /// Task id or prefix (default: the latest task)
        task: Option<String>,
        /// Where to write the PNG (default: screen-ID.png here; `-` for standard output)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Sign where a task's journal stands (a receipt), or check a receipt
    Attest {
        /// Task id or prefix (default: the latest task)
        task: Option<String>,
        /// Check this receipt instead (a file made by `agent attest`)
        #[arg(long, value_name = "FILE")]
        verify: Option<PathBuf>,
        /// With --verify: also check that this journal (an events.jsonl) holds the history the receipt vouches for
        #[arg(long, value_name = "FILE", requires = "verify")]
        journal: Option<PathBuf>,
        /// With --verify: the key you expect (its id, or a prefix of at least 8)
        #[arg(long, value_name = "KEY", requires = "verify")]
        trust: Option<String>,
        /// Show this machine's receipt key
        #[arg(long, conflicts_with_all = ["verify", "task"])]
        public: bool,
    },
    /// Install an agent package after showing what it asks for: from a
    /// folder, or by name from your registry
    Install {
        /// A folder with an agentos-package.toml, or a package in your registry ([registry] in your config)
        dir: PathBuf,
        /// Install without asking (once you've read what it asks for)
        #[arg(long)]
        yes: bool,
        /// Only install a package with this digest (a prefix of at least 8 is enough)
        #[arg(long, value_name = "HEX")]
        digest: Option<String>,
    },
    /// For whoever publishes a registry: make a signing key, sign an index
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// The packages in your registry, matching TEXT if you give some
    Search { text: Option<String> },
    /// Remove an installed agent package
    Uninstall {
        /// The package, as `agent packages` lists it
        name: String,
    },
    /// List the installed agent packages, and whether they're as you approved them
    Packages,
    /// Review a project's .agentos.toml and let agentos apply it
    Trust {
        /// The file (default: the nearest .agentos.toml from here)
        path: Option<PathBuf>,
    },
    /// Take back a folder or host you granted while a task runs (with no
    /// TARGET: list them)
    Revoke {
        /// A folder (path) or a host, as listed
        target: Option<String>,
        /// The task (default: the latest running one)
        #[arg(long)]
        task: Option<String>,
    },
    /// What agents spent on model calls: today, this week, this month, in
    /// all and in this project, against your budgets
    Spend,
    /// Raise a budget that's used up (or nearly): a running task's own, or
    /// today's, this week's or this month's across tasks, until it resets
    Raise {
        /// The new budget: dollars (5usd, $5) or tokens (2M), as it's counted
        amount: Budget,
        /// The running task (default: the latest running one)
        #[arg(long, conflicts_with_all = ["today", "this_week", "this_month"])]
        task: Option<String>,
        /// Today's budget across your tasks, until midnight
        #[arg(long, conflicts_with_all = ["this_week", "this_month"])]
        today: bool,
        /// This week's, until Monday
        #[arg(long, conflicts_with = "this_month")]
        this_week: bool,
        /// This month's, until the 1st
        #[arg(long)]
        this_month: bool,
        /// With --today, --this-week or --this-month: this project's budget
        /// (from its .agentos.toml), not the one for all your tasks
        #[arg(long)]
        project: bool,
    },
    /// Your rules for what agents may do without asking (policy.cedar):
    /// list them, or check what they say about a request
    Policy {
        #[command(subcommand)]
        command: Option<PolicyCommand>,
    },
    /// Sign in to one of your remote MCP servers (OAuth), so agents can use
    /// it through agentos without ever holding the token; with no NAME, list
    /// your remote servers
    Connect {
        /// The server, as named under [mcp.NAME] in your config
        name: Option<String>,
        /// Forget the sign-in instead
        #[arg(long)]
        forget: bool,
    },
    /// MCP server for agents, run inside their sandbox: agentos's own, or
    /// the gateway to one of yours
    #[command(hide = true)]
    Mcp { server: Option<String> },
}

#[derive(Subcommand)]
pub(crate) enum RegistryCommand {
    /// Make a publisher's signing key (a new file, private to you) and print its public half
    Keygen { file: PathBuf },
    /// Pack a package folder for a registry: NAME-VERSION.tar.gz and its entry in index.json
    Pack {
        /// A folder with an agentos-package.toml
        dir: PathBuf,
        /// Where the tarball and index.json go (default: the current folder)
        #[arg(short, long, value_name = "DIR", default_value = ".")]
        output: PathBuf,
    },
    /// Sign an index.json: writes index.json.sig next to it
    Sign {
        index: PathBuf,
        /// The key `agent registry keygen` made
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum UsersCommand {
    /// Give someone a token (shown once)
    Add {
        /// Lowercase letters, digits, - and _
        name: String,
        /// viewer: reads. approver: also answers questions, stops tasks. admin: everything
        #[arg(long, default_value = "viewer", value_parser = ["viewer", "approver", "admin"])]
        role: String,
    },
    /// Take their token back
    Remove { name: String },
}

#[derive(Subcommand)]
pub(crate) enum PolicyCommand {
    /// What your rules say about one request
    Check {
        /// connect, read, write or call
        action: String,
        /// HOST[:PORT], a path, or SERVER.TOOL
        target: String,
        /// A tool call's arguments, as JSON
        #[arg(long, value_name = "JSON")]
        args: Option<String>,
        /// The agent asking
        #[arg(long, default_value = "claude")]
        agent: String,
        /// Pretend the task has read untrusted input of this kind (web, tool, file or event; repeatable)
        #[arg(long, value_name = "KIND")]
        tainted: Vec<String>,
    },
}

#[derive(Args)]
pub(crate) struct GrantArgs {
    /// Grant read-write access to a directory. Writes are held in the task's
    /// transaction until you commit them. The current directory is granted
    /// this way by default.
    #[arg(long = "rw", value_name = "DIR")]
    pub(crate) rw: Vec<PathBuf>,
    /// Grant read-only access to a file or directory
    #[arg(long = "ro", value_name = "PATH")]
    pub(crate) ro: Vec<PathBuf>,
    /// Hide a path a grant would otherwise expose (e.g. --hide .env)
    #[arg(long, value_name = "PATH")]
    pub(crate) hide: Vec<PathBuf>,
    /// Pass an environment variable: NAME copies it from your shell, NAME=VALUE sets it.
    /// Values never reach the audit log.
    #[arg(long = "env", short = 'e', value_name = "NAME[=VALUE]")]
    pub(crate) env: Vec<String>,
    /// Don't grant the current directory
    #[arg(long)]
    pub(crate) no_cwd: bool,
    /// Let the agent reach this host through the egress proxy (HOST,
    /// *.DOMAIN or HOST:PORT; port 443 by default). Nothing else is reachable.
    #[arg(long, value_name = "HOST")]
    pub(crate) allow: Vec<String>,
    /// Let the agent reach this host, but hold its writes (POST, PUT, PATCH,
    /// DELETE) for your review: answered with a 202 and sent, with the
    /// credential --secret would add, when you commit. Exact host names.
    #[arg(long, value_name = "HOST")]
    pub(crate) hold: Vec<String>,
    /// Give the task a screen of its own: a private virtual display (Xvfb)
    /// the agent's graphical programs draw on. `agent screen` shows it.
    #[arg(long)]
    pub(crate) display: bool,
    /// The screen's size, WIDTHxHEIGHT (default 1280x800); implies --display
    #[arg(long, value_name = "WxH")]
    pub(crate) display_size: Option<String>,
    /// Let the agent reach a server on this machine's loopback, at the same
    /// port on its own (--local 11434 for a local model server like Ollama).
    /// Only that port; the rest of your loopback stays out of reach.
    #[arg(long, value_name = "PORT")]
    pub(crate) local: Vec<u16>,
    /// Broker a credential: the agent sees a placeholder in $NAME, and the
    /// proxy puts the real value (from your environment) into HEADER of
    /// requests to HOST, and nowhere else. HEADER defaults to authorization.
    #[arg(long, value_name = "NAME=HOST[/HEADER]")]
    pub(crate) secret: Vec<String>,
    /// Ask in the terminal when the agent reaches for a host that isn't
    /// allowed (default for headless `agent do`)
    #[arg(long, conflicts_with = "no_ask")]
    pub(crate) ask: bool,
    /// Never ask: hosts that aren't allowed are refused
    #[arg(long)]
    pub(crate) no_ask: bool,
}

#[derive(Args)]
pub(crate) struct Mode {
    /// Run in the background and give the terminal back; follow with
    /// `agent logs -f`, answer questions in agentd (`agent serve`)
    #[arg(long)]
    pub(crate) bg: bool,
    /// Stop the task after this long (e.g. 90s, 30m, 2h)
    #[arg(long, value_name = "DURATION", value_parser = humantime::parse_duration)]
    pub(crate) timeout: Option<Duration>,
    /// Memory limit for the task, e.g. 4G (needs a systemd user session)
    #[arg(long, value_name = "SIZE")]
    pub(crate) memory: Option<String>,
    /// CPU limit, in CPUs (e.g. 2 or 0.5)
    #[arg(long, value_name = "N")]
    pub(crate) cpus: Option<f32>,
    /// Limit on processes and threads
    #[arg(long, value_name = "N")]
    pub(crate) pids: Option<u32>,
    /// Budget for model calls: dollars (2usd, $2) or tokens (500k, 2M).
    /// Measured on the wire; once it's used up, you're asked whether to
    /// raise it, else model calls are refused. Calls it can't measure
    /// (batches, background responses) are refused under a budget.
    #[arg(long, value_name = "AMOUNT")]
    pub(crate) budget: Option<Budget>,
}

impl Mode {
    /// Re-runs this command inside a systemd scope carrying the resource
    /// limits (flags over config), unless that's already done. Returns only
    /// when there are no limits to apply (or none can be, from config).
    pub(crate) fn apply_limits(&self, store: &Store) -> Result<()> {
        if limits::current().is_some() {
            return Ok(());
        }
        let asked = Limits { memory: self.memory.clone(), cpus: self.cpus, pids: self.pids };
        let explicit = !asked.is_empty();
        let configured = config::load(store.root(), &std::env::current_dir()?, &home_dir()?)?.limits;
        let wanted = asked.or(&configured);
        if wanted.is_empty() {
            return Ok(());
        }
        wanted.validate()?;
        if limits::available() {
            limits::reexec_in_scope(&wanted)?;
        }
        if explicit {
            bail!("--memory/--cpus/--pids need a systemd user session (systemd-run --user), which isn't available here");
        }
        eprintln!(
            "{} the [limits] in your config aren't enforced: no systemd user session here",
            Paint::stderr().yellow("agent: warning:")
        );
        Ok(())
    }
}

#[derive(Args)]
pub(crate) struct RunArgs {
    #[command(flatten)]
    pub(crate) grants: GrantArgs,
    #[command(flatten)]
    pub(crate) mode: Mode,
    /// Network: none (loopback only, the default) or host. --allow, or an allow
    /// list in your config, gives an allowlist instead.
    #[arg(long)]
    pub(crate) net: Option<Net>,
    /// The command to run
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
    pub(crate) command: Vec<String>,
}

#[derive(Args)]
pub(crate) struct DoArgs {
    #[command(flatten)]
    pub(crate) grants: GrantArgs,
    #[command(flatten)]
    pub(crate) mode: Mode,
    /// Which agent (default: `agent` in your config, else claude; see `agent agents`)
    #[arg(long)]
    pub(crate) agent: Option<String>,
    /// Watch and steer the agent in its own interface instead of running it to completion
    #[arg(short, long)]
    pub(crate) interactive: bool,
    /// Network: none or host, instead of the default allowlist of what the
    /// agent needs (extend that with --allow)
    #[arg(long)]
    pub(crate) net: Option<Net>,
    /// What the agent should do. Omit it to open an interactive session.
    #[arg(trailing_var_arg = true, value_name = "TASK")]
    pub(crate) task: Vec<String>,
}
