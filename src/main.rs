use agentos::approvals::{self, Asker, Kind, Request};
use agentos::broker::{self, Broker, Secret};
use agentos::changes::{self, Summary};
use agentos::config;
use agentos::control::{self, Call, PathRules, PathVerdict, Reply};
use agentos::doctor::{self, Level};
use agentos::gateway::{self, Budget, Endpoint, Ledger, Meter, Periodic, Price, Spend};
use agentos::journal::{Integrity, Journal};
use agentos::limits::{self, Limits};
use agentos::outbox;
use agentos::policy::{self, Question, Verdict};
use agentos::profiles::{self, AgentEvent, Output};
use agentos::proxy::{self, Allowlist, NetEvent};
use agentos::sandbox::{self, GrantMount, Mount, RunMount};
use agentos::store::{Access, Grant, Net, NewTask, Status, Store, Task};
use agentos::util::{self, display_path};
use agentos::vault::Vault;
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use nix::fcntl::OFlag;
use render::Paint;
use serde_json::json;
use std::fs;
use std::io::{BufRead, BufReader, IsTerminal};
use std::os::fd::{AsRawFd, OwnedFd};
use std::thread;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

mod render;
mod web;

/// Set when a task is started for you (by agentd's console), for the journal.
const STARTED_BY: &str = "AGENTOS_STARTED_BY";

/// Environment variables an agent inherits by default. Anything else (API
/// keys, tokens) must be passed explicitly with --env.
const PASS_ENV: &[&str] = &[
    "PATH", "TERM", "COLORTERM", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ", "NO_COLOR", "USER",
    "LOGNAME", "SHELL", "EDITOR", "VISUAL",
];

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
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    /// Your rules for what agents may do without asking (policy.cedar):
    /// list them, or check what they say about a request
    Policy {
        #[command(subcommand)]
        command: Option<PolicyCommand>,
    },
    /// MCP server for agents, run inside their sandbox: agentos's own, or
    /// the gateway to one of yours
    #[command(hide = true)]
    Mcp { server: Option<String> },
}

#[derive(Subcommand)]
enum PolicyCommand {
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
    },
}

#[derive(Args)]
struct GrantArgs {
    /// Grant read-write access to a directory. Writes are held in the task's
    /// transaction until you commit them. The current directory is granted
    /// this way by default.
    #[arg(long = "rw", value_name = "DIR")]
    rw: Vec<PathBuf>,
    /// Grant read-only access to a file or directory
    #[arg(long = "ro", value_name = "PATH")]
    ro: Vec<PathBuf>,
    /// Hide a path a grant would otherwise expose (e.g. --hide .env)
    #[arg(long, value_name = "PATH")]
    hide: Vec<PathBuf>,
    /// Pass an environment variable: NAME copies it from your shell, NAME=VALUE sets it.
    /// Values never reach the audit log.
    #[arg(long = "env", short = 'e', value_name = "NAME[=VALUE]")]
    env: Vec<String>,
    /// Don't grant the current directory
    #[arg(long)]
    no_cwd: bool,
    /// Let the agent reach this host through the egress proxy (HOST,
    /// *.DOMAIN or HOST:PORT; port 443 by default). Nothing else is reachable.
    #[arg(long, value_name = "HOST")]
    allow: Vec<String>,
    /// Broker a credential: the agent sees a placeholder in $NAME, and the
    /// proxy puts the real value (from your environment) into HEADER of
    /// requests to HOST, and nowhere else. HEADER defaults to authorization.
    #[arg(long, value_name = "NAME=HOST[/HEADER]")]
    secret: Vec<String>,
    /// Ask in the terminal when the agent reaches for a host that isn't
    /// allowed (default for headless `agent do`)
    #[arg(long, conflicts_with = "no_ask")]
    ask: bool,
    /// Never ask: hosts that aren't allowed are refused
    #[arg(long)]
    no_ask: bool,
}

#[derive(Args)]
struct Mode {
    /// Run in the background and give the terminal back; follow with
    /// `agent logs -f`, answer questions in agentd (`agent serve`)
    #[arg(long)]
    bg: bool,
    /// Stop the task after this long (e.g. 90s, 30m, 2h)
    #[arg(long, value_name = "DURATION", value_parser = humantime::parse_duration)]
    timeout: Option<Duration>,
    /// Memory limit for the task, e.g. 4G (needs a systemd user session)
    #[arg(long, value_name = "SIZE")]
    memory: Option<String>,
    /// CPU limit, in CPUs (e.g. 2 or 0.5)
    #[arg(long, value_name = "N")]
    cpus: Option<f32>,
    /// Limit on processes and threads
    #[arg(long, value_name = "N")]
    pids: Option<u32>,
    /// Budget for model calls: dollars (2usd, $2) or tokens (500k, 2M).
    /// Measured on the wire; once it's used up, model calls are refused.
    #[arg(long, value_name = "AMOUNT")]
    budget: Option<Budget>,
}

impl Mode {
    /// Re-runs this command inside a systemd scope carrying the resource
    /// limits (flags over config), unless that's already done. Returns only
    /// when there are no limits to apply (or none can be, from config).
    fn apply_limits(&self, store: &Store) -> Result<()> {
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
struct RunArgs {
    #[command(flatten)]
    grants: GrantArgs,
    #[command(flatten)]
    mode: Mode,
    /// Network: none (loopback only, the default) or host. --allow, or an allow
    /// list in your config, gives an allowlist instead.
    #[arg(long)]
    net: Option<Net>,
    /// The command to run
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Args)]
struct DoArgs {
    #[command(flatten)]
    grants: GrantArgs,
    #[command(flatten)]
    mode: Mode,
    /// Which agent (default: `agent` in your config, else claude; see `agent agents`)
    #[arg(long)]
    agent: Option<String>,
    /// Watch and steer the agent in its own interface instead of running it to completion
    #[arg(short, long)]
    interactive: bool,
    /// Network: none or host, instead of the default allowlist of what the
    /// agent needs (extend that with --allow)
    #[arg(long)]
    net: Option<Net>,
    /// What the agent should do. Omit it to open an interactive session.
    #[arg(trailing_var_arg = true, value_name = "TASK")]
    task: Vec<String>,
}

struct LoginPlan {
    vault: Arc<Vault>,
    hosts: Vec<String>,
    /// The credentials file in the agent's home.
    file: PathBuf,
    /// Placeholders in the sandbox, real tokens added by the broker. Without
    /// the proxy (--net host) the login is unsealed for the task instead.
    brokered: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ask {
    Never,
    /// agentd's console only (the terminal belongs to a full-screen agent).
    Console,
    /// The terminal and agentd's console, if running.
    TerminalAndConsole,
}

/// Everything needed to run one task, whether from `agent run` or `agent do`.
struct Plan {
    title: Option<String>,
    argv: Vec<String>,
    grants: GrantArgs,
    net: Net,
    /// Hosts reachable through the egress proxy (`Net::Proxy`).
    allow: Vec<String>,
    /// Credentials the broker adds on the wire.
    secrets: Vec<Secret>,
    /// The agent's login, sealed in the vault.
    login: Option<LoginPlan>,
    /// Read-only grants for the agent's own installation.
    install: Vec<PathBuf>,
    profile_env: Vec<(String, String)>,
    pass_env: Vec<String>,
    /// Agent profile name: gives the task a persistent home.
    agent: Option<String>,
    output: Output,
    /// Hosts the agent reaches for that stay closed on purpose: (host, why).
    expected_denials: Vec<(String, String)>,
    /// Who to ask about hosts outside the allowlist.
    ask: Ask,
    /// Fail rather than run without the current directory.
    needs_cwd: bool,
    timeout: Option<Duration>,
    /// For model calls, enforced by the gateway.
    budget: Option<Budget>,
    /// Your prices for models agentos doesn't know.
    prices: Vec<(String, Price)>,
    /// Model APIs the agent calls beyond the well-known ones.
    models: Vec<Endpoint>,
    /// Your MCP servers, reached through agentos.
    mcp: Vec<agentos::mcp::Server>,
    /// Budgets across tasks: (period, amount, this project's only).
    periodic: Vec<(gateway::Period, Budget, bool)>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("{} {e:#}", Paint::stderr().red("agent:"));
            ExitCode::from(2)
        }
    }
}

fn dispatch(cli: Cli) -> Result<i32> {
    // Inside a sandbox: no task store there, just the control socket.
    if let Command::Mcp { server } = &cli.command {
        let socket = Path::new(control::SOCKET);
        match server {
            None => agentos::mcp::serve_stdio(socket)?,
            Some(name) => agentos::mcp::relay_stdio(socket, name)?,
        }
        return Ok(0);
    }
    let store = Store::open()?;
    match cli.command {
        Command::Do(args) => cmd_do(&store, args),
        Command::Run(args) => cmd_run(&store, args),
        Command::Ls => cmd_ls(&store),
        Command::Diff { task, paths, stat, all } => cmd_diff(&store, task.as_deref(), &paths, stat, all),
        Command::Commit { task, paths, force, all, no_push } => cmd_commit(&store, task.as_deref(), &paths, force, all, no_push),
        Command::Push { task, force } => cmd_push(&store, task.as_deref(), force),
        Command::Rollback { task, paths } => cmd_rollback(&store, task.as_deref(), &paths),
        Command::Log { task, json } => cmd_log(&store, task.as_deref(), json),
        Command::Logs { task, follow } => cmd_logs(&store, task.as_deref(), follow),
        Command::Wait { task } => cmd_wait(&store, task.as_deref()),
        Command::Stop { task } => cmd_stop(&store, task.as_deref()),
        Command::Doctor => cmd_doctor(&store),
        Command::Trust { path } => cmd_trust(&store, path),
        Command::Agents => cmd_agents(&store),
        Command::Approvals { revoke } => cmd_approvals(&store, revoke),
        Command::Serve { listen, notify } => web::serve(&store, &listen, notify),
        Command::Vault { action, agent } => cmd_vault(&store, &action, &agent),
        Command::Policy { command } => cmd_policy(command),
        Command::Spend => cmd_spend(&store),
        Command::Revoke { target, task } => cmd_revoke(&store, target, task),
        Command::Mcp { .. } => unreachable!(),
    }
}

fn home_dir() -> Result<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    Ok(fs::canonicalize(&home).unwrap_or(home))
}

/// What the config files add to a task beyond its grants.
struct Applied {
    allow: Vec<String>,
    /// Those whose variable is set in your environment.
    secrets: Vec<Secret>,
    budget: Option<Budget>,
    prices: Vec<(String, Price)>,
    mcp: Vec<agentos::mcp::Server>,
    periodic: Vec<(gateway::Period, Budget, bool)>,
}

/// Merges your config and a trusted project config into this task's grants.
fn apply_config(store: &Store, grants: &mut GrantArgs) -> Result<Applied> {
    let (cwd, home) = (std::env::current_dir()?, home_dir()?);
    let mut settings = config::load(store.root(), &cwd, &home)?;
    for note in &settings.notes {
        eprintln!("{} {note}", Paint::stderr().yellow("agent:"));
    }
    // Hosts you approved "always" for this project count like your own config.
    settings.allow.extend(approvals::remembered(store.root(), &approvals::project_root(&cwd, &home))?);
    grants.ro.extend(settings.ro);
    grants.hide.extend(settings.hide);
    let mut secrets = Vec::new();
    for (name, target) in settings.secrets {
        if std::env::var_os(&name).is_some() {
            secrets.push(Secret::parse(&format!("{name}={target}"))?);
        }
    }
    Ok(Applied { allow: settings.allow, secrets, budget: settings.budget, prices: settings.prices, mcp: settings.mcp, periodic: settings.periodic })
}

/// The task's budget: --budget, else your config's. The gateway enforces it
/// in the egress proxy, so a task without the proxy has none.
fn task_budget(flag: Option<Budget>, configured: Option<Budget>, net: Net) -> Result<Option<Budget>> {
    match (flag, configured, net) {
        (Some(_), _, Net::Host) => bail!("--budget is enforced in the egress proxy, which --net host bypasses"),
        (None, Some(b), Net::Host) => {
            eprintln!("{} the budget in your config ({b}) isn't enforced with --net host", Paint::stderr().yellow("agent: warning:"));
            Ok(None)
        }
        // No network, no model calls.
        (_, _, Net::None) => Ok(None),
        (flag, configured, _) => Ok(flag.or(configured)),
    }
}

fn cmd_trust(store: &Store, path: Option<PathBuf>) -> Result<i32> {
    let home = home_dir()?;
    let path = match path {
        Some(p) => fs::canonicalize(&p).with_context(|| format!("{}: no such file", p.display()))?,
        None => config::find_project_config(&std::env::current_dir()?, &home)
            .context("no .agentos.toml here or in a parent directory (below your home)")?,
    };
    config::check_project(&path, &home)?;
    let out = Paint::stdout();
    println!("{}\n", out.bold(display_path(&path)));
    for line in fs::read_to_string(&path)?.lines() {
        println!("  {line}");
    }
    config::trust(store.root(), &path)?;
    println!("\n{} trusted: agentos applies it from now on, and ignores it again if it changes", out.green("✓"));
    Ok(0)
}

/// Seals the agent's login before it runs (or unseals it for a task without
/// the proxy, to be sealed again afterwards).
fn prepare_login(store: &Store, agent: &str, login: &profiles::Login, net: Net) -> Result<Option<LoginPlan>> {
    let vault = Arc::new(Vault::open(store.root(), agent)?);
    if vault.disabled() {
        return Ok(None);
    }
    let file = store.agent_home(agent)?.join(login.file);
    let err = Paint::stderr();
    let brokered = net == Net::Proxy;
    if brokered {
        if vault.seal_file(&file)? > 0 {
            eprintln!(
                "  {}",
                err.dim(format!("{agent}'s login is now sealed: the agent holds placeholders; `agent vault unseal` undoes it"))
            );
        }
        if !vault.knows_all(&file) {
            eprintln!("{} {agent}'s login placeholders aren't in the vault; log in again with `agent do` and /login", err.yellow("agent:"));
        }
    } else {
        vault.unseal_file(&file)?;
    }
    Ok(Some(LoginPlan { vault, hosts: login.hosts.iter().map(|h| h.to_string()).collect(), file, brokered }))
}

/// Where your agent definitions live: next to your config.
fn agents_dir(home: &Path) -> PathBuf {
    config::user_config_path(home).parent().map(|d| d.join("agents")).unwrap_or_else(|| home.join(".config/agentos/agents"))
}

fn cmd_agents(store: &Store) -> Result<i32> {
    let home = home_dir()?;
    let out = Paint::stdout();
    let default = config::load(store.root(), &std::env::current_dir()?, &home)?.agent.unwrap_or_else(|| "claude".into());
    for a in profiles::available(&agents_dir(&home)) {
        let mark = if a.name == default { out.cyan("*") } else { " ".into() };
        let program = match &a.program {
            Some(p) => out.dim(display_path(p)),
            None => out.yellow("not installed"),
        };
        println!("{mark} {:<12} {:<44} {program}", a.name, a.source);
    }
    println!("{}", out.dim(format!("add one: {}/NAME.toml (see README: Agents)", display_path(&agents_dir(&home)))));
    Ok(0)
}

fn cmd_vault(store: &Store, action: &str, agent: &str) -> Result<i32> {
    let login = profiles::login_for(agent).with_context(|| format!("unknown agent '{agent}'"))?;
    let vault = Vault::open(store.root(), agent)?;
    let file = store.agent_home(agent)?.join(login.file);
    let out = Paint::stdout();
    match action {
        "seal" => {
            vault.set_disabled(false)?;
            let n = vault.seal_file(&file)?;
            println!("{} {agent}'s login is sealed ({n} tokens moved to the vault)", out.green("✓"));
        }
        "unseal" => {
            let n = vault.unseal_file(&file)?;
            vault.set_disabled(true)?;
            println!("{} {agent}'s login is back in its home ({n} tokens) and won't be sealed; `agent vault seal` to resume", out.yellow("!"));
        }
        _ => {
            let text = fs::read_to_string(&file).unwrap_or_default();
            let state = if text.is_empty() {
                "not logged in".to_string()
            } else if vault.disabled() {
                "unsealed (sealing is off)".to_string()
            } else if text.contains("agentosplaceholder") {
                if vault.knows_all(&file) { "sealed".to_string() } else { "sealed, but the vault lost its tokens: log in again".to_string() }
            } else {
                "not sealed yet (sealed on the next `agent do`)".to_string()
            };
            println!("{agent}: {state}");
        }
    }
    Ok(0)
}

fn parse_secrets(specs: &[String]) -> Result<Vec<Secret>> {
    let secrets = specs.iter().map(|s| Secret::parse(s)).collect::<Result<Vec<_>>>()?;
    for (i, s) in secrets.iter().enumerate() {
        if secrets[..i].iter().any(|o| o.env == s.env) {
            bail!("--secret {}: given twice", s.env);
        }
    }
    Ok(secrets)
}

fn cmd_do(store: &Store, mut args: DoArgs) -> Result<i32> {
    let task = (!args.task.is_empty()).then(|| args.task.join(" "));
    if args.mode.bg {
        if task.is_none() || args.interactive {
            bail!("--bg runs a task headless: give it one, e.g. agent do --bg \"add a test for greet\"");
        }
        return launch_background(store);
    }
    args.mode.apply_limits(store)?;
    if task.is_none() && !std::io::stdin().is_terminal() {
        bail!("give the agent a task: agent do \"…\"");
    }
    let interactive = args.interactive || task.is_none();
    let home = home_dir()?;
    let agent = match args.agent.clone() {
        Some(a) => a,
        None => config::load(store.root(), &std::env::current_dir()?, &home)?.agent.unwrap_or_else(|| "claude".into()),
    };
    let applied = apply_config(store, &mut args.grants)?;
    let mcp_names: Vec<String> = applied.mcp.iter().map(|m| m.name.clone()).collect();
    let profile = profiles::load(&agent, task.as_deref(), interactive, &home, &agents_dir(&home), &mcp_names)?;
    let title = match &task {
        Some(t) => format!("{}: {t}", profile.name),
        None => format!("{} (interactive)", profile.name),
    };
    let (config_allow, config_secrets) = (applied.allow, applied.secrets);
    let net = args.net.unwrap_or(profile.net);
    let budget = task_budget(args.mode.budget, applied.budget, net)?;
    if net != Net::Proxy && !args.grants.allow.is_empty() {
        bail!("--allow only applies to the agent's default, proxied network; drop --net {net}");
    }
    let mut allow: Vec<String> = profile.allow.iter().map(|h| h.to_string()).collect();
    allow.extend(config_allow);
    allow.extend(args.grants.allow.iter().cloned());
    let mut secrets = parse_secrets(&args.grants.secret)?;
    let no_ask = args.grants.no_ask;
    if net == Net::Proxy {
        let from_profile = profile.brokered.iter().filter_map(|(var, host, header)| {
            std::env::var(var).ok().map(|value| Secret::new(var, host, header, value))
        });
        for secret in from_profile.chain(config_secrets) {
            if !secrets.iter().any(|s| s.env == secret.env) {
                secrets.push(secret);
            }
        }
    } else if !secrets.is_empty() {
        bail!("--secret needs the agent's default, proxied network; drop --net {net}");
    }
    let login = match &profile.login {
        Some(l) => prepare_login(store, &profile.name, l, net)?,
        None => None,
    };
    execute(
        store,
        Plan {
            title: Some(title),
            login,
            argv: profile.argv,
            grants: args.grants,
            net,
            allow,
            secrets,
            install: profile.install,
            profile_env: profile.env,
            pass_env: profile.pass_env,
            agent: Some(profile.name.clone()),
            // Claude's own full-screen interface owns the terminal: don't talk
            // over it, but agentd's console can still ask.
            ask: match (no_ask, &profile.output) {
                (true, _) => Ask::Never,
                (false, Output::ClaudeStream) => Ask::TerminalAndConsole,
                (false, Output::Inherit) => Ask::Console,
            },
            output: profile.output,
            expected_denials: profile.expected_denials,
            needs_cwd: true,
            timeout: args.mode.timeout,
            budget,
            prices: applied.prices,
            models: profile.models,
            mcp: applied.mcp,
            periodic: applied.periodic,
        },
    )
}

fn cmd_run(store: &Store, mut args: RunArgs) -> Result<i32> {
    if args.mode.bg {
        return launch_background(store);
    }
    args.mode.apply_limits(store)?;
    let argv = args.command;
    let applied = apply_config(store, &mut args.grants)?;
    let (config_allow, config_secrets) = (applied.allow, applied.secrets);
    let mut secrets = parse_secrets(&args.grants.secret)?;
    let ask = args.grants.ask;
    let asked = !args.grants.allow.is_empty() || !secrets.is_empty() || ask;
    let net = match args.net {
        Some(Net::Host) if asked => bail!("--allow/--secret/--ask and --net host contradict each other: they mean only those hosts"),
        Some(net) => net,
        None if asked || !config_allow.is_empty() => Net::Proxy,
        None => Net::None,
    };
    let budget = task_budget(args.mode.budget, applied.budget, net)?;
    let mut allow = Vec::new();
    if net == Net::Proxy {
        allow.extend(config_allow);
        allow.extend(args.grants.allow.iter().cloned());
        for secret in config_secrets {
            if !secrets.iter().any(|s| s.env == secret.env) {
                secrets.push(secret);
            }
        }
    }
    let code = execute(
        store,
        Plan {
            title: None,
            login: None,
            argv: argv.clone(),
            grants: args.grants,
            net,
            allow,
            secrets,
            install: Vec::new(),
            profile_env: Vec::new(),
            pass_env: Vec::new(),
            agent: None,
            output: Output::Inherit,
            expected_denials: Vec::new(),
            ask: if ask { Ask::TerminalAndConsole } else { Ask::Never },
            needs_cwd: false,
            timeout: args.mode.timeout,
            budget,
            prices: applied.prices,
            models: Vec::new(),
            mcp: applied.mcp,
            periodic: applied.periodic,
        },
    )?;
    if code == 127 && argv.len() == 1 && argv[0].contains(' ') {
        eprintln!(
            "{} `agent run` runs commands. To give \"{}\" to an AI agent, use:\n  agent do \"{}\"",
            Paint::stderr().cyan("hint:"),
            argv[0],
            argv[0]
        );
    }
    Ok(code)
}

/// Why the current directory can't be handed to an agent, if it can't.
fn cwd_refusal(cwd: &Path, home: &Path, store: &Path) -> Option<&'static str> {
    if cwd == home {
        Some("won't hand your whole home directory to an agent")
    } else if home.starts_with(cwd) {
        Some("this directory contains your home directory")
    } else if sandbox::is_system_path(cwd) || ["/proc", "/dev", "/run"].iter().any(|d| cwd.starts_with(d)) {
        Some("this is a system directory")
    } else if store.starts_with(cwd) {
        Some("this directory contains the agentos task store")
    } else {
        None
    }
}

fn execute(store: &Store, plan: Plan) -> Result<i32> {
    let home = home_dir()?;
    let cwd = std::env::current_dir()?;

    let mut grants: Vec<Grant> = Vec::new();
    for (paths, access, flag) in [(&plan.grants.rw, Access::Rw, "--rw"), (&plan.grants.ro, Access::Ro, "--ro")] {
        for p in paths {
            let path = fs::canonicalize(p).with_context(|| format!("{flag} {}: no such file or directory", p.display()))?;
            if path == Path::new("/") {
                bail!("{flag} /: granting the whole filesystem defeats the sandbox");
            }
            if access == Access::Rw && !path.is_dir() {
                bail!("--rw {}: only directories can be granted writable for now", p.display());
            }
            if access == Access::Rw && store.root().starts_with(&path) {
                bail!(
                    "--rw {}: contains the task store ({}), so the agent could rewrite its own audit log; set AGENTOS_HOME outside it",
                    p.display(),
                    display_path(store.root())
                );
            }
            if let Some(g) = grants.iter().find(|g| g.path == path) {
                if g.access == access {
                    continue;
                }
                bail!("{} is granted both read-only and read-write", display_path(&path));
            }
            grants.push(Grant { path, access, layer: None });
        }
    }
    if !plan.grants.no_cwd && !grants.iter().any(|g| cwd.starts_with(&g.path)) {
        match cwd_refusal(&cwd, &home, store.root()) {
            None => grants.insert(0, Grant { path: cwd.clone(), access: Access::Rw, layer: None }),
            Some(why) if plan.needs_cwd => bail!("{why}: cd into a project folder, or pass --rw DIR"),
            Some(_) => {}
        }
    }
    for path in &plan.install {
        if !grants.iter().any(|g| path.starts_with(&g.path)) {
            grants.push(Grant { path: path.clone(), access: Access::Ro, layer: None });
        }
    }
    let mut allow = if plan.net == Net::Proxy { plan.allow } else { Vec::new() };
    // A brokered credential's host is reachable by definition.
    for secret in &plan.secrets {
        if !allow.contains(&secret.host) {
            allow.push(secret.host.clone());
        }
    }
    let allowlist = Allowlist::parse(&allow)?;
    // Your rules, and the project's (forbids only): a file that doesn't
    // parse stops the task, never skipped.
    let policy_file = config::policy_path(&home);
    let yours = policy::load(&policy_file, &home)?;
    let project_rules = config::find_project_rules(&cwd, &home);
    let theirs = project_rules.as_deref().map(|f| policy::load_project(f, &home)).transpose()?;
    let rules = policy::combine(yours, theirs)?;
    // The model gateway meters calls on the hosts the broker relays. With a
    // budget, it relays the model APIs this task can reach even when it has
    // no credential to add for them.
    let budget = if plan.net == Net::Proxy { plan.budget } else { None };
    // Budgets shared with your other tasks (and this project's), and the
    // ledger they're counted in.
    let project = approvals::project_root(&cwd, &home);
    let periodic: Vec<Periodic> = plan
        .periodic
        .iter()
        .map(|(period, amount, mine)| Periodic { amount: *amount, period: *period, project: mine.then(|| project.clone()) })
        .collect();
    if plan.net == Net::Host && !periodic.is_empty() {
        eprintln!("{} your daily/weekly/monthly budgets aren't enforced with --net host", Paint::stderr().yellow("agent: warning:"));
    }
    let ledger = Arc::new(open_ledger(store, &home)?);
    let mut endpoints = gateway::builtin_endpoints();
    endpoints.extend(plan.models);
    let mut intercept: Vec<String> = Vec::new();
    if budget.is_some() || (plan.net == Net::Proxy && !periodic.is_empty()) {
        for e in &endpoints {
            if allowlist.allows(&e.host, 443) && !intercept.contains(&e.host) {
                intercept.push(e.host.clone());
            }
        }
    }
    let hidden = plan
        .grants
        .hide
        .iter()
        .map(|p| fs::canonicalize(p).with_context(|| format!("--hide {}: no such file or directory", p.display())))
        .collect::<Result<Vec<_>>>()?;

    let mut env = build_env(&plan.grants.env, &home)?;
    let brokered_env = plan.secrets.iter().map(|s| (s.env.clone(), s.placeholder.clone()));
    let brokering = !plan.secrets.is_empty() || plan.login.as_ref().is_some_and(|l| l.brokered) || !intercept.is_empty();
    // A shared budget that's already used up: don't start what can't run.
    if brokering {
        if let Some(over) = ledger.over(&periodic, util::now_ms()) {
            bail!("{over}. (Budgets across tasks are under [limits] in your config, or a project's.)");
        }
    }
    let ca_env = brokering
        .then(|| {
            // Node and Bun add to their roots; curl, Python, git and OpenSSL
            // read a whole bundle (system roots + the task CA).
            [("NODE_EXTRA_CA_CERTS", "ca.pem"), ("SSL_CERT_FILE", "ca-bundle.pem"), ("CURL_CA_BUNDLE", "ca-bundle.pem"), ("REQUESTS_CA_BUNDLE", "ca-bundle.pem"), ("GIT_SSL_CAINFO", "ca-bundle.pem")]
                .map(|(k, f)| (k.to_string(), format!("/run/agentos/{f}")))
        })
        .into_iter()
        .flatten();
    for (k, v) in plan.profile_env.into_iter().chain(brokered_env).chain(ca_env) {
        env.retain(|(name, _)| *name != k);
        env.push((k, v));
    }
    for k in plan.pass_env {
        if let (Ok(v), false) = (std::env::var(&k), env.iter().any(|(name, _)| *name == k)) {
            env.push((k, v));
        }
    }
    let mut env_names: Vec<String> = env.iter().map(|(k, _)| k.clone()).collect();
    env_names.push("AGENTOS_TASK".into());
    let home_source = plan.agent.as_deref().map(|name| store.agent_home(name)).transpose()?;

    let mut task = store.create(NewTask {
        title: plan.title,
        agent: plan.agent.clone(),
        command: plan.argv.clone(),
        cwd: cwd.clone(),
        grants,
        hidden,
        net: plan.net,
        allow,
        ask: plan.ask != Ask::Never && plan.net == Net::Proxy,
        secrets: plan.secrets.iter().map(|s| s.env.clone()).collect(),
        env: env_names,
        budget,
    })?;
    env.push(("AGENTOS_TASK".into(), task.id().to_string()));
    // A background task (agent … --bg) keeps what it prints with the task.
    if std::env::var_os("AGENTOS_BACKGROUND").is_some() {
        let log = fs::File::create(task.dir.join("output.log"))?;
        unsafe {
            libc::dup2(log.as_raw_fd(), 1);
            libc::dup2(log.as_raw_fd(), 2);
        }
    }
    let journal = task.journal();
    journal.append(
        "task.created",
        json!({
            "title": task.meta.title,
            "agent": task.meta.agent,
            "command": task.meta.command,
            "cwd": cwd,
            "grants": task.meta.grants,
            "hidden": task.meta.hidden,
            "net": task.meta.net,
            "allow": task.meta.allow,
            "ask": task.meta.ask,
            "secrets": plan.secrets.iter().map(|s| json!({ "env": s.env, "host": s.host, "header": s.header })).collect::<Vec<_>>(),
            "env": task.meta.env,
            "budget": budget,
            "started_by": std::env::var(STARTED_BY).ok(),
        }),
    )?;

    let err = Paint::stderr();
    // A writable grant that's a git repository gets an outbox for its pushes.
    let outbox = match task.meta.grants.iter().find(|g| g.access == Access::Rw && g.path.join(".git").is_dir()) {
        Some(g) => outbox::prepare(&task.dir, &g.path).unwrap_or_else(|e| {
            eprintln!("{} git outbox unavailable: {e:#}", err.yellow("agent: warning:"));
            None
        }),
        None => None,
    };
    let mut run_mounts = Vec::new();
    if let Some(o) = &outbox {
        env.extend(o.env.iter().cloned());
        run_mounts.extend(o.mounts.iter().map(|(src, name, writable)| RunMount { src: src.clone(), name: name.clone(), writable: *writable }));
        for w in &o.warnings {
            eprintln!("{} {w}", err.yellow("agent: warning:"));
        }
        journal.append("outbox.ready", json!({ "remotes": o.remotes }))?;
    }
    eprintln!("{}", render::banner(err, &task, outbox.is_some(), plan.login.as_ref().is_some_and(|l| l.brokered)));
    if !periodic.is_empty() && task.meta.net == Net::Proxy {
        eprintln!("  {}", err.dim(format!("spend: {}", ledger.status(&periodic, util::now_ms()).join(" · "))));
    }
    let rules = rules.map(|set| {
        let all = policy::rules(&set);
        let names: Vec<String> = all.iter().map(|(name, effect)| format!("{effect} {name}")).collect();
        let _ = journal.append("task.policy", json!({ "file": policy_file, "project_file": project_rules, "rules": names }));
        let theirs = all.iter().filter(|(name, _)| name.starts_with("project: ")).count();
        let mut shown = Vec::new();
        if all.len() > theirs {
            shown.push(format!("your rules: {} ({})", display_path(&policy_file), plural(all.len() - theirs, "rule")));
        }
        if let Some(f) = &project_rules {
            shown.push(format!("project rules: {} ({})", display_path(f), plural(theirs, "rule")));
        }
        eprintln!("  {}", err.dim(shown.join(" · ")));
        Arc::new(policy::Policy::new(set, plan.agent.as_deref().unwrap_or("command"), task.id(), &project))
    });
    if let Some(l) = limits::current() {
        eprintln!("  {}", err.dim(format!("limits: {}", l.describe())));
        journal.append("task.limits", json!({ "limits": l, "scope": limits::scope_name() }))?;
    }
    // The agent's line to agentos (`agent mcp` inside, see control.rs).
    let control_socket = task.dir.join("control.sock");
    let mut control_listener = Some(control::bind(&control_socket)?);
    // Yours: `agent revoke` and agentd reach the running task here.
    let owner_socket = task.dir.join(control::OWNER_SOCKET);
    let mut owner_listener = Some(control::bind(&owner_socket)?);
    run_mounts.push(RunMount { src: control_socket.clone(), name: "control.sock".into(), writable: true });
    run_mounts.push(RunMount { src: std::env::current_exe()?, name: "agent".into(), writable: false });
    // The proxy's socket must exist before the sandbox mounts it, but its
    // threads may only start once the sandbox has been forked.
    let (proxy_socket, mut proxy_listener) = if task.meta.net == Net::Proxy {
        let path = task.dir.join("net.sock");
        let listener = proxy::bind(&path)?;
        (Some(path), Some(listener))
    } else {
        (None, None)
    };
    let blocked = Arc::new(AtomicUsize::new(0));
    let expected_denials = plan.expected_denials;
    let ask = plan.ask;
    // The CA's private key never leaves this process; only its certificate
    // is written out for the sandbox to trust.
    let login = plan.login;
    let meter = brokering.then(|| {
        let spend = Spend { ledger: ledger.clone(), task: task.id().to_string(), project: project.clone(), budgets: periodic.clone() };
        Arc::new(Meter::new(endpoints, plan.prices, budget, meter_observer(journal.clone(), err, budget)).with_spend(spend))
    });
    if let (Some(b), Some(m)) = (budget, &meter) {
        let relayed: Vec<&str> = plan.secrets.iter().map(|s| s.host.as_str())
            .chain(login.iter().filter(|l| l.brokered).flat_map(|l| l.hosts.iter().map(String::as_str)))
            .chain(intercept.iter().map(String::as_str))
            .collect();
        if !m.hosts().iter().any(|h| relayed.contains(&h.as_str())) {
            eprintln!("{} the budget ({b}) has nothing to count: this task can't reach a model API agentos knows (see `models` in README: Agents)", err.yellow("agent: warning:"));
        }
    }
    let broker = if !brokering {
        None
    } else {
        let vault = login.as_ref().filter(|l| l.brokered).map(|l| (l.vault.clone(), l.hosts.clone()));
        let broker = Broker::new(plan.secrets, vault, meter.clone().map(|m| (m, intercept)))?;
        let (ca, bundle) = (task.dir.join("ca.pem"), task.dir.join("ca-bundle.pem"));
        fs::write(&ca, broker.ca_pem())?;
        fs::write(&bundle, broker::ca_bundle(broker.ca_pem()))?;
        for (src, name) in [(ca, "ca.pem"), (bundle, "ca-bundle.pem")] {
            run_mounts.push(RunMount { src, name: name.into(), writable: false });
        }
        Some(Arc::new(broker))
    };
    let spec = sandbox::Spec {
        rootfs: task.rootfs_dir(),
        grants: task
            .meta
            .grants
            .iter()
            .map(|g| GrantMount {
                path: g.path.clone(),
                kind: match g.layer {
                    Some(n) => Mount::Overlay { upper: task.layer_upper(n), work: task.layer_work(n) },
                    None => Mount::ReadOnly,
                },
            })
            .collect(),
        hide: task.meta.hidden.clone(),
        mask: vec![store.root().to_path_buf()],
        isolate_net: task.meta.net != Net::Host,
        proxy: proxy_socket.clone(),
        run_mounts,
        hostname: format!("agent-{}", task.id()),
        home,
        home_source,
        cwd: cwd.clone(),
        env,
        argv: plan.argv,
        staging: task.dir.join("attach"),
    };

    let (stdout_rx, stdout_tx) = match plan.output {
        Output::ClaudeStream => {
            let (rx, tx) = nix::unistd::pipe2(OFlag::O_CLOEXEC)?;
            (Some(rx), Some(tx))
        }
        Output::Inherit => (None, None),
    };
    let mut setup_error = None;
    let mut outcome = None;
    let mut proxy_handle = None;
    // Grow while the task runs, when the agent asks and you agree.
    let grants = Arc::new(Mutex::new(task.meta.grants.clone()));
    let mcp_servers = plan.mcp;
    let mut gateway_slot: Option<Arc<agentos::mcp::Gateway>> = None;
    let given: GivenList = Arc::default();
    let live_allow = Arc::new(std::sync::RwLock::new(allowlist));
    let result = sandbox::run(&spec, stdout_tx, |report, attacher| {
        let kind = if report.error.is_some() { "sandbox.failed" } else { "sandbox.ready" };
        if let Err(e) = journal.append(kind, json!(report)) {
            eprintln!("{} journal: {e:#}", err.yellow("agent: warning:"));
        }
        for w in &report.warnings {
            eprintln!("{} {w}", err.yellow("agent: warning:"));
        }
        setup_error = report.error.clone();
        let asker = (ask != Ask::Never)
            .then(|| {
                let project = approvals::project_root(&cwd, &home_dir().ok()?);
                Asker::open(store.root(), &project, ask == Ask::TerminalAndConsole, task.id(), &render::title(&task))
            })
            .flatten()
            .map(Arc::new);
        if let Some(listener) = proxy_listener.take() {
            let gate = gate(asker.clone(), rules.clone(), given.clone(), journal.clone(), expected_denials.clone(), err);
            let sink = net_sink(journal.clone(), blocked.clone(), expected_denials.clone(), err);
            proxy_handle = Some(proxy::serve(listener, live_allow.clone(), broker, Some(gate), sink));
        }
        if let Some(listener) = owner_listener.take() {
            let owner = Owner {
                given: given.clone(),
                allow: (task.meta.net == Net::Proxy).then(|| live_allow.clone()),
                asker: asker.clone(),
                attacher: attacher.clone(),
                proxy: proxy_handle.clone(),
                journal: journal.clone(),
                err,
            };
            control::serve(listener, Arc::new(move |call| owner.handle(call)), Arc::new(|_, _| {}));
        }
        let gateway = Arc::new(gateway_for(
            mcp_servers.clone(),
            &cwd,
            &task.dir,
            asker.clone(),
            rules.clone(),
            approvals::remembered_tools(store.root(), &project).unwrap_or_default(),
            journal.clone(),
            err,
        ));
        gateway_slot = Some(gateway.clone());
        if let (Some(listener), Ok(home)) = (control_listener.take(), home_dir()) {
            let control = Control {
                task_id: task.id().to_string(),
                store_root: store.root().to_path_buf(),
                // An agent that could change these would widen its next task.
                private: vec![store.root().to_path_buf(), config::user_config_path(&home), agents_dir(&home), config::policy_path(&home)],
                hidden: task.meta.hidden.clone(),
                home,
                cwd: cwd.clone(),
                grants: grants.clone(),
                allow: (task.meta.net == Net::Proxy).then(|| live_allow.clone()),
                net: task.meta.net,
                asker: asker.clone(),
                rules: rules.clone(),
                no_asker: match ask {
                    Ask::Never => "this task runs without questions (--no-ask)",
                    _ => "there's no terminal to ask at and agentd isn't running",
                },
                attacher,
                landlock: report.landlock.contains("enforced"),
                journal: journal.clone(),
                meter: meter.clone(),
                outbox: outbox.is_some(),
                mcp: mcp_servers.iter().map(|m| m.name.clone()).collect(),
                given: given.clone(),
                err,
            };
            let relay: control::Relay = Arc::new(move |name, conn| gateway.clone().relay(&name, conn));
            control::serve(listener, Arc::new(move |call| control.handle(call)), relay);
        }
        if let Some(limit) = plan.timeout {
            thread::spawn(move || {
                thread::sleep(limit);
                sandbox::stop(sandbox::Stop::Timeout);
            });
        }
        if let Some(rx) = stdout_rx {
            outcome = follow_agent(rx, &journal, &cwd);
        }
    });
    let exit_code = match result {
        Ok(code) => code,
        Err(e) => {
            setup_error = Some(format!("{e:#}"));
            125
        }
    };
    if let Some(handle) = proxy_handle {
        handle.drain(Duration::from_secs(2));
    }
    if let Some(path) = &proxy_socket {
        let _ = fs::remove_file(path);
    }
    let _ = fs::remove_file(&control_socket);
    let _ = fs::remove_file(&owner_socket);
    if let Some(g) = &gateway_slot {
        g.stop_all();
    }
    if let Ok(g) = grants.lock() {
        task.meta.grants = g.clone();
    }

    outbox::seal(&task.dir)?;
    // Whatever happened inside (a login with --net host, say), real tokens
    // don't stay in the agent's home.
    if let Some(l) = &login {
        match l.vault.seal_file(&l.file) {
            Ok(n) if n > 0 => {
                journal.append("login.sealed", json!({ "tokens": n }))?;
            }
            Ok(_) => {}
            Err(e) => eprintln!("{} couldn't seal the agent's login: {e:#}", err.yellow("agent: warning:")),
        }
    }
    let pushes = outbox::pending(&task.dir)?;
    if !pushes.is_empty() {
        let held: Vec<_> = pushes.iter().map(|p| json!({ "remote": p.remote, "ref": p.refname, "sha": p.sha })).collect();
        journal.append("outbox.held", json!({ "pushes": held }))?;
    }
    let summary = Summary::of(&changes::scan(&task.layers())?);
    let ended = util::now_ms();
    let oom = if limits::current().is_some() { limits::oom_kills() } else { 0 };
    if oom > 0 {
        journal.append("task.oom", json!({ "kills": oom }))?;
        eprintln!("{} the task ran out of memory ({}): the kernel killed {oom} process{}", err.yellow("agent ▸"), limits::current().and_then(|l| l.memory).unwrap_or_default(), if oom == 1 { "" } else { "es" });
    }
    if let Some(why) = sandbox::stopped() {
        let (reason, text) = match why {
            sandbox::Stop::Timeout => ("timeout", format!("stopped after {} (--timeout)", util::duration(ended - task.meta.started_at_ms))),
            sandbox::Stop::Stopped => ("stopped", "stopped".to_string()),
            sandbox::Stop::Budget => ("budget", "stopped: it kept calling the model after its budget was used up".to_string()),
        };
        journal.append("task.stopped", json!({ "reason": reason }))?;
        task.meta.stop = Some(reason.to_string());
        eprintln!("{} task {} {text}; what it did so far is held for review", err.yellow("agent ▸"), task.id());
    }
    if let Some(m) = &meter {
        let totals = m.totals();
        if totals.calls + totals.unmetered + totals.refused > 0 {
            journal.append("model.usage", json!({ "totals": totals, "budget": budget }))?;
            task.meta.usage = Some(totals);
        }
        if m.exhausted() && task.meta.stop.is_none() {
            task.meta.stop = Some("budget".into());
            eprintln!("{} task {} went over its budget; what it did so far is held for review", err.yellow("agent ▸"), task.id());
        }
    }
    task.meta.status = if setup_error.is_some() { Status::Failed } else { Status::Exited };
    task.meta.exit_code = Some(exit_code);
    task.meta.ended_at_ms = Some(ended);
    task.save()?;
    journal.append(
        "task.exited",
        json!({ "exit_code": exit_code, "duration_ms": ended - task.meta.started_at_ms, "changes": summary }),
    )?;
    if let Some(e) = setup_error {
        bail!("sandbox setup failed: {e}\n(run `agent doctor` to check this machine)");
    }
    eprintln!("{}", render::exit_summary(err, &task, &summary, &pushes, outcome.as_ref(), blocked.load(Ordering::SeqCst)));
    Ok(exit_code)
}

/// Asks at the terminal about hosts outside the allowlist, if there's a
/// terminal to ask at.
/// Decides each connection through the proxy: your rules first (a forbid
/// refuses even a listed host), then the allowlist, then you.
fn gate(asker: Option<Arc<Asker>>, rules: Option<Arc<policy::Policy>>, given: GivenList, journal: Journal, expected: Vec<(String, String)>, err: Paint) -> proxy::Gate {
    Arc::new(move |host: &str, port: u16, listed: bool| {
        let entry = approvals::entry(host, port);
        if taken_back(&given, "host", &entry) {
            return Err("you took it back from this task".into());
        }
        match rules.as_ref().map(|r| r.decide(&Question::connect(host, port))) {
            Some(Verdict::Forbid(rule)) => {
                let (who, name) = policy::whose(&rule);
                return Err(format!("forbidden by {who} rule \u{201c}{name}\u{201d}"));
            }
            Some(Verdict::Permit(rule)) if !listed => {
                let _ = journal.append("net.approval", json!({ "host": host, "port": port, "decision": "rule", "rule": rule }));
                give(&given, "host", &entry, None);
                return Ok(true);
            }
            _ => {}
        }
        let refused = || Err("not in the allowlist".to_string());
        if listed {
            return Ok(false);
        }
        if expected.iter().any(|(h, _)| h == host) {
            return refused();
        }
        let Some(asker) = &asker else { return refused() };
        let (decision, asked) = asker.ask(&Request::host(host, port), |s| err.cyan(s));
        if asked {
            let _ = journal.append("net.approval", json!({ "host": host, "port": port, "decision": decision.label() }));
        }
        if !decision.allows() {
            return refused();
        }
        give(&given, "host", &entry, None);
        Ok(true)
    })
}

/// What you granted while a task ran (folders, hosts): you can take it back.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Given {
    /// "folder" or "host".
    kind: String,
    /// A folder's path, or `host` / `host:port`.
    target: String,
    /// "read" or "write", for a folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access: Option<String>,
    #[serde(default)]
    revoked: bool,
}

type GivenList = Arc<Mutex<Vec<Given>>>;

fn give(given: &GivenList, kind: &str, target: &str, access: Option<&str>) {
    if let Ok(mut g) = given.lock() {
        if !g.iter().any(|x| x.kind == kind && x.target == target && !x.revoked) {
            g.push(Given { kind: kind.into(), target: target.into(), access: access.map(String::from), revoked: false });
        }
    }
}

fn taken_back(given: &GivenList, kind: &str, target: &str) -> bool {
    given.lock().is_ok_and(|g| g.iter().any(|x| x.kind == kind && x.target == target && x.revoked))
}

/// Your side of a running task, on its owner socket: what you granted while
/// it ran, and taking it back.
struct Owner {
    given: GivenList,
    allow: Option<proxy::LiveAllowlist>,
    asker: Option<Arc<Asker>>,
    attacher: Arc<sandbox::Attacher>,
    proxy: Option<proxy::Handle>,
    journal: Journal,
    err: Paint,
}

impl Owner {
    fn handle(&self, call: Call) -> Reply {
        match call {
            Call::Given => Reply::answer(self.given.lock().map(|g| serde_json::to_string(&*g).unwrap_or_default()).unwrap_or_default()),
            Call::Revoke { target } => self.revoke(&target),
            _ => Reply::error("this socket is the task owner's: given and revoke only"),
        }
    }

    fn revoke(&self, target: &str) -> Reply {
        let target = target.trim();
        let target = if target.len() > 1 { target.trim_end_matches('/') } else { target };
        let Ok(mut given) = self.given.lock() else { return Reply::error("internal: lock poisoned") };
        let matches = |g: &Given| !g.revoked && (g.target == target || (g.kind == "host" && format!("{}:443", g.target) == target));
        let Some(g) = given.iter_mut().find(|g| matches(g)) else {
            return Reply::error(format!("nothing granted while the task ran matches {target} (`agent revoke` lists them)"));
        };
        let mut closed = 0;
        if g.kind == "folder" {
            if let Err(e) = self.attacher.detach(Path::new(&g.target)) {
                return Reply::error(format!("couldn't take back {}: {e:#}", g.target));
            }
        } else {
            let (host, port) = match g.target.rsplit_once(':').and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?))) {
                Some((h, p)) => (h.to_string(), p),
                None => (g.target.clone(), 443),
            };
            if let Some(Ok(mut a)) = self.allow.as_ref().map(|a| a.write()) {
                a.remove(&g.target);
            }
            if let Some(a) = &self.asker {
                a.refuse(&Request::host(&host, port));
            }
            closed = self.proxy.as_ref().map_or(0, |p| p.close(&host, port));
        }
        g.revoked = true;
        let _ = self.journal.append("grant.revoked", json!({ "kind": g.kind, "target": g.target, "closed": closed }));
        let shown = if g.kind == "folder" { display_path(Path::new(&g.target)) } else { g.target.clone() };
        say(format!("{} you took back {shown}", self.err.cyan("agent ▸")));
        let also = match closed {
            0 => String::new(),
            n => format!(" and closed {}", plural(n, "open connection")),
        };
        Reply::answer(format!("took back {shown}{also}"))
    }
}

/// The gateway to your MCP servers for this task: asks you as the proxy
/// does, and tells you what it couldn't start.
fn gateway_for(
    servers: Vec<agentos::mcp::Server>,
    cwd: &Path,
    task_dir: &Path,
    asker: Option<Arc<Asker>>,
    rules: Option<Arc<policy::Policy>>,
    remembered: Vec<String>,
    journal: Journal,
    err: Paint,
) -> agentos::mcp::Gateway {
    let ask: Box<dyn Fn(&Request) -> Option<approvals::Decision> + Send + Sync> =
        Box::new(move |req: &Request| asker.as_ref().map(|a| a.ask(req, |s| err.cyan(s)).0));
    let tell: Box<dyn Fn(String) + Send + Sync> = Box::new(move |text| say(format!("{} {text}", err.yellow("agent: warning:"))));
    agentos::mcp::Gateway::new(servers, cwd.to_path_buf(), task_dir.to_path_buf(), ask, rules, remembered, journal, tell)
}

/// Answers what the agent asks agentos from inside its sandbox (through
/// `agent mcp`): what it has, and more when you agree.
struct Control {
    task_id: String,
    store_root: PathBuf,
    home: PathBuf,
    cwd: PathBuf,
    /// The task store, your config and agent definitions: never offered.
    private: Vec<PathBuf>,
    hidden: Vec<PathBuf>,
    grants: Arc<Mutex<Vec<Grant>>>,
    /// The proxy's allowlist, when the task has one.
    allow: Option<proxy::LiveAllowlist>,
    net: Net,
    asker: Option<Arc<Asker>>,
    /// Your rules, which answer before you're asked.
    rules: Option<Arc<policy::Policy>>,
    /// Why nobody can be asked, when there's no asker.
    no_asker: &'static str,
    attacher: Arc<sandbox::Attacher>,
    landlock: bool,
    journal: Journal,
    meter: Option<Arc<Meter>>,
    outbox: bool,
    /// Your MCP servers, reachable through agentos.
    mcp: Vec<String>,
    /// What you granted while it ran, and what you took back.
    given: GivenList,
    err: Paint,
}

impl Control {
    fn handle(&self, call: Call) -> Reply {
        match call {
            Call::Info => Reply::answer(self.info()),
            Call::Network { host, port, reason } => self.network(&host, port.unwrap_or(443), &reason),
            Call::Path { path, write, reason } => self.path(&path, write, &reason),
            Call::Mcp { .. } => Reply::error("MCP sessions are relayed, not answered"),
            Call::Given | Call::Revoke { .. } => Reply::error("only the user can take grants back"),
        }
    }

    fn info(&self) -> String {
        let mut out = vec![format!("This is agentos task {}.", self.task_id)];
        let mut grants = self.grants.lock().map(|g| g.clone()).unwrap_or_default();
        grants.retain(|g| !taken_back(&self.given, "folder", &g.path.display().to_string()));
        let list = |access: Access| grants.iter().filter(|g| g.access == access).map(|g| g.path.display().to_string()).collect::<Vec<_>>().join(", ");
        let (rw, ro) = (list(Access::Rw), list(Access::Ro));
        if !rw.is_empty() {
            out.push(format!("You can read and change: {rw}. Your changes are held for the user's review, not applied directly."));
        }
        if !ro.is_empty() {
            out.push(format!("You can read: {ro}."));
        }
        out.push(format!("System folders (/usr, /etc, …) are read-only. The rest of {} is hidden, apart from your own home.", self.home.display()));
        out.push(match (&self.allow, self.net) {
            (Some(allow), _) => {
                let hosts = allow.read().map(|a| a.describe()).unwrap_or_default();
                let others = if self.asker.is_some() { "the user is asked about others when you connect" } else { "others are refused" };
                format!("Network: HTTPS only, through the proxy in $HTTPS_PROXY, to {hosts}; {others}.")
            }
            (None, Net::Host) => "Network: unrestricted.".to_string(),
            (None, _) => "Network: none in this task.".to_string(),
        });
        if self.outbox {
            out.push("git push works, but your pushes are held until the user reviews them.".into());
        }
        if !self.mcp.is_empty() {
            out.push(format!(
                "The user's MCP servers, run by agentos outside the sandbox: {}. Read-only tools run directly; the user is asked before the others.",
                self.mcp.join(", ")
            ));
        }
        if let Some(m) = &self.meter {
            let t = m.totals();
            out.push(match m.budget() {
                Some(b) => format!("Budget for model calls: {} used.", t.against(b)),
                None => format!("Model calls so far: {}.", t.describe()),
            });
        }
        out.push(if self.asker.is_some() {
            "Need more? request_path_access or request_network_access, with a reason: the user decides.".to_string()
        } else {
            format!("Nobody can approve requests for more in this task: {}.", self.no_asker)
        });
        out.join("\n")
    }

    /// Asks you, and journals the request and your answer.
    /// Your rules answer first; then you're asked.
    fn ask(&self, kind: Kind, target: &str, reason: &str, question: Question) -> std::result::Result<approvals::Decision, Reply> {
        let reason = approvals::sanitize(reason, 300);
        let req = Request { kind, target: approvals::sanitize(target, 200), reason: Some(reason.clone()) };
        let label = match kind {
            Kind::Host => "host",
            Kind::Read => "read",
            Kind::Write => "write",
            Kind::Tool => "tool",
        };
        let record_rule = |decision: &str, rule: Option<&str>| {
            let mut data = json!({ "kind": label, "target": req.target, "reason": reason, "decision": decision });
            if let Some(rule) = rule {
                data["rule"] = json!(rule);
            }
            let _ = self.journal.append("agent.request", data);
        };
        let record = |decision: &str| record_rule(decision, None);
        match self.rules.as_ref().map(|r| r.decide(&question.with_reason(&reason))) {
            Some(Verdict::Permit(rule)) => {
                record_rule("rule", Some(&rule));
                return Ok(approvals::Decision::Once);
            }
            Some(Verdict::Forbid(rule)) => {
                record_rule("forbidden", Some(&rule));
                let (who, name) = policy::whose(&rule);
                let who = if who == "your" { "the user's" } else { who };
                return Err(Reply::answer(format!(
                    "Denied by {who} rules (\u{201c}{name}\u{201d}). Carry on without it, and don't try to get it another way."
                )));
            }
            _ => {}
        }
        let Some(asker) = &self.asker else {
            record("nobody to ask");
            say(format!("{} the agent asked for {} ({}), but {}", self.err.yellow("agent:"), req.target, label, self.no_asker));
            return Err(Reply::answer(format!("Not granted: nobody can approve requests in this task ({}). Tell the user what you need instead.", self.no_asker)));
        };
        let (decision, _) = asker.ask(&req, |s| self.err.cyan(s));
        record(decision.label());
        match decision {
            d if d.allows() => Ok(d),
            approvals::Decision::Timeout => Err(Reply::answer("No answer from the user in time. You can ask again later, or carry on without it.")),
            _ => Err(Reply::answer("Denied: the user said no. Carry on without it, and don't try to get it another way.")),
        }
    }

    fn network(&self, host: &str, port: u16, reason: &str) -> Reply {
        let Some(allow) = &self.allow else {
            return Reply::answer(match self.net {
                Net::Host => "The network isn't restricted in this task: just connect.",
                _ => "This task has no network at all. The user can rerun it with --allow HOST.",
            });
        };
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.contains(['*', '/', ':', ' ', '@']) {
            return Reply::error(format!("{host:?} isn't a host name; give one like pypi.org, and the port separately"));
        }
        let entry = approvals::entry(&host, port);
        if let Err(e) = Allowlist::parse(&[entry.clone()]) {
            return Reply::error(format!("{e:#}"));
        }
        if taken_back(&self.given, "host", &entry) {
            return Reply::answer(format!("Not granted: the user took {entry} back from this task. Carry on without it."));
        }
        if allow.read().is_ok_and(|a| a.allows(&host, port)) {
            return Reply::answer(format!("{entry} is already allowed: connect to it over HTTPS (through $HTTPS_PROXY)."));
        }
        match self.ask(Kind::Host, &entry, reason, Question::connect(&host, port)) {
            Ok(decision) => {
                if let Ok(mut a) = allow.write() {
                    let _ = a.add(&entry);
                }
                give(&self.given, "host", &entry, None);
                let always = if decision == approvals::Decision::Always { ", and for later tasks in this project" } else { "" };
                Reply::answer(format!("Granted: you can reach {entry} now{always}."))
            }
            Err(reply) => reply,
        }
    }

    fn path(&self, asked: &str, write: bool, reason: &str) -> Reply {
        let named = match control::resolve(asked, &self.home, &self.cwd) {
            Ok(p) => p,
            Err(e) => return Reply::error(format!("{e:#}")),
        };
        let grants = self.grants.lock().map(|g| g.clone()).unwrap_or_default();
        let rules = PathRules { home: &self.home, private: &self.private, hidden: &self.hidden, grants: &grants, landlock: self.landlock };
        // Off limits by name (whether or not it exists), then for what it
        // really is, symlinks resolved.
        let (path, verdict) = match control::forbidden(&named, &rules) {
            Some(why) => (named, Err(why)),
            None => match fs::canonicalize(&named) {
                Ok(path) => {
                    let verdict = control::check_path(&path, write, &rules);
                    (path, verdict)
                }
                Err(_) => return Reply::error(format!("{} doesn't exist", named.display())),
            },
        };
        let shown = display_path(&path);
        if taken_back(&self.given, "folder", &path.display().to_string()) {
            return Reply::answer(format!("Not granted: the user took {} back from this task. Carry on without it.", path.display()));
        }
        match verdict {
            Err(why) => {
                let kind = if write { "write" } else { "read" };
                let _ = self.journal.append("agent.request", json!({ "kind": kind, "target": shown, "reason": approvals::sanitize(reason, 300), "decision": "impossible", "why": why }));
                return Reply::answer(format!("Not possible: {why}."));
            }
            Ok(PathVerdict::AlreadyWritable) => return Reply::answer(format!("You can already read and change {}.", path.display())),
            Ok(PathVerdict::AlreadyReadable) if !write => return Reply::answer(format!("You can already read {}.", path.display())),
            Ok(_) => {}
        }
        if let Err(reply) = self.ask(if write { Kind::Write } else { Kind::Read }, &shown, reason, Question::path(write, &path)) {
            return reply;
        }
        match self.grant(&path, write) {
            Ok(()) if write => Reply::answer(format!(
                "Granted: you can now read and change {} (at that path). Your changes there are held for the user's review, like the rest.",
                path.display()
            )),
            Ok(()) => Reply::answer(format!("Granted: you can now read {} (at that path).", path.display())),
            Err(e) => {
                let _ = self.journal.append("grant.failed", json!({ "path": path, "error": format!("{e:#}") }));
                say(format!("{} couldn't add {shown} to the sandbox: {e:#}", self.err.yellow("agent: warning:")));
                Reply::error(format!("The user agreed, but agentos couldn't add {}: {e:#}", path.display()))
            }
        }
    }

    /// Mounts `path` into the running sandbox and records the grant (with a
    /// layer of its own when writable, so its changes are held like the rest).
    fn grant(&self, path: &Path, write: bool) -> Result<()> {
        let store = Store::open_at(&self.store_root)?;
        let mut task = store.load(&self.task_id)?;
        let mut grants = self.grants.lock().map_err(|_| anyhow::anyhow!("grants lock poisoned"))?;
        let layer = write.then(|| grants.iter().filter_map(|g| g.layer).max().map_or(0, |n| n + 1));
        let kind = match layer {
            Some(n) => {
                fs::create_dir_all(task.layer_upper(n))?;
                fs::create_dir_all(task.layer_work(n))?;
                Mount::Overlay { upper: task.layer_upper(n), work: task.layer_work(n) }
            }
            None => Mount::ReadOnly,
        };
        if let Err(e) = self.attacher.attach(&GrantMount { path: path.to_path_buf(), kind }) {
            if let Some(n) = layer {
                let _ = fs::remove_dir_all(task.layer_upper(n).parent().unwrap_or(Path::new("/nonexistent")));
            }
            return Err(e);
        }
        let access = if write { Access::Rw } else { Access::Ro };
        grants.push(Grant { path: path.to_path_buf(), access, layer });
        // On disk at once: `agent diff` must see the new layer even if this
        // process dies before the task ends.
        task.meta.grants = grants.clone();
        task.save()?;
        self.journal.append("grant.added", json!({ "path": path, "access": access, "layer": layer }))?;
        give(&self.given, "folder", &path.display().to_string(), Some(if write { "write" } else { "read" }));
        say(format!("{} {} {}", self.err.cyan("agent ▸"), if write { "now read-write:" } else { "now readable:" }, display_path(path)));
        Ok(())
    }
}

fn cmd_approvals(store: &Store, revoke: Option<String>) -> Result<i32> {
    let project = approvals::project_root(&std::env::current_dir()?, &home_dir()?);
    if let Some(entry) = revoke {
        if approvals::revoke(store.root(), &project, &entry)? {
            println!("revoked {entry} for {}", display_path(&project));
            return Ok(0);
        }
        bail!("{entry} isn't approved for {}", display_path(&project));
    }
    let all = approvals::all(store.root())?;
    if all.is_empty() {
        println!("no remembered approvals; answer [a] when an agent asks to remember one");
    }
    for (dir, hosts) in all {
        println!("{}", Paint::stdout().bold(display_path(Path::new(&dir))));
        for h in hosts {
            println!("  {h}");
        }
    }
    Ok(0)
}

/// Prints a line to stderr in one write, so it can't interleave with output
/// the agent writes to the same terminal at the same moment (eprintln! may
/// write a formatted line in pieces).
fn say(line: String) {
    use std::io::Write;
    let _ = std::io::stderr().write_all(format!("{line}\n").as_bytes());
}

/// Records each connection through the egress proxy and says so, live,
/// when one is refused.
fn net_sink(journal: Journal, blocked: Arc<AtomicUsize>, expected: Vec<(String, String)>, err: Paint) -> proxy::Sink {
    let explained = Mutex::new(HashSet::new());
    Arc::new(move |event: NetEvent| {
        let expected_why = expected
            .iter()
            .find(|(host, _)| *host == event.host && event.reason.as_deref() == Some("not in the allowlist"))
            .map(|(_, why)| why.clone());
        let mut data = json!(event);
        if expected_why.is_some() {
            data["expected"] = json!(true);
        }
        let _ = journal.append("net.connect", data);
        if let Some(why) = expected_why {
            // Deliberately closed: say why once, don't count it as a problem.
            if explained.lock().is_ok_and(|mut seen| seen.insert(event.host.clone())) {
                say(format!("  {}", err.dim(format!("{} stays closed: {why} (--allow {} opens it)", event.host, event.host))));
            }
        } else if !event.allowed {
            blocked.fetch_add(1, Ordering::SeqCst);
            let target = format!("{}:{}", event.host, event.port);
            let why = event.reason.as_deref().unwrap_or("refused");
            let hint = if why == "not in the allowlist" {
                let host = if event.port == 443 { event.host.clone() } else { target.clone() };
                format!(" (allow it with --allow {host})")
            } else {
                String::new()
            };
            say(format!("{} {target}: {why}{hint}", err.yellow("agent: blocked")));
        } else if let Some(reason) = &event.reason {
            say(format!("{} {}:{}: {reason}", err.yellow("agent: warning:"), event.host, event.port));
        }
    })
}

/// Journals every model call the gateway meters, and says so, live, when
/// the budget is nearly or entirely used up.
fn meter_observer(journal: Journal, err: Paint, budget: Option<Budget>) -> gateway::Observer {
    // An agent that keeps calling after being refused is stopped.
    const REFUSALS_BEFORE_STOP: u64 = 5;
    let warned = Mutex::new(HashSet::new());
    Arc::new(move |event: gateway::Event| match event {
        gateway::Event::Call(call, totals) => {
            let mut data = json!(call);
            data["total"] = json!({ "tokens": totals.usage.tokens(), "cost_usd": totals.cost_usd });
            let _ = journal.append("model.call", data);
        }
        gateway::Event::Unmetered { host, why } => {
            let _ = journal.append("model.unmetered", json!({ "host": host, "why": why }));
            if warned.lock().is_ok_and(|mut seen| seen.insert(host.to_string())) {
                say(format!("{} a model call to {host} couldn't be measured ({why}): it isn't counted", err.yellow("agent: warning:")));
            }
        }
        gateway::Event::Nearly(totals) => {
            let _ = journal.append("budget.nearly", json!({ "totals": totals }));
            let used = budget.map(|b| totals.against(b)).unwrap_or_default();
            say(format!("{} 80% of the budget used ({used})", err.cyan("agent ▸")));
        }
        gateway::Event::Exhausted(totals) => {
            let _ = journal.append("budget.exhausted", json!({ "totals": totals }));
            let used = budget.map(|b| totals.against(b)).unwrap_or_default();
            say(format!("{} budget used up ({used}): model calls are refused from now on", err.yellow("agent ▸")));
        }
        gateway::Event::Over(text) => {
            let _ = journal.append("budget.exhausted", json!({ "reason": text }));
            say(format!("{} {text}: model calls are refused from now on", err.yellow("agent ▸")));
        }
        gateway::Event::Refused(totals) => {
            let _ = journal.append("model.refused", json!({ "refused": totals.refused }));
            if totals.refused >= REFUSALS_BEFORE_STOP {
                sandbox::stop(sandbox::Stop::Budget);
            }
        }
    })
}

/// Shows an agent's structured output as it works and records the
/// interesting parts (tool calls, result, cost) in the journal. Returns the
/// final result, if the agent reported one.
fn follow_agent(rx: OwnedFd, journal: &Journal, cwd: &Path) -> Option<AgentEvent> {
    let (out, err) = (Paint::stdout(), Paint::stderr());
    let mut done = None;
    // Narration is shown one event late: the agent's last message is also its
    // result, which is printed in full, so it shouldn't appear twice.
    let mut narration: Option<String> = None;
    let flush = |narration: &mut Option<String>| {
        if let Some(text) = narration.take() {
            eprintln!("  {}", err.dim(render::first_line(&text, 110)));
        }
    };
    let mut recognized = false;
    let mut unrecognized: Vec<String> = Vec::new();
    let mut journal_ok = true;
    let mut record = |kind: &str, data: serde_json::Value| {
        if journal_ok && journal.append(kind, data).is_err() {
            journal_ok = false;
            eprintln!("{} could not write to the journal", err.yellow("agent: warning:"));
        }
    };
    for line in BufReader::new(fs::File::from(rx)).lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Some(events) = profiles::parse_claude_line(&line) else {
            if unrecognized.len() < 200 {
                unrecognized.push(line);
            }
            continue;
        };
        recognized = true;
        for event in events {
            if !matches!(event, AgentEvent::Text(_) | AgentEvent::Done { .. }) {
                flush(&mut narration);
            }
            match &event {
                AgentEvent::Session { model } => {
                    record("agent.session", json!({ "model": model }));
                    eprintln!("  {}", err.dim(format!("model {model}")));
                }
                AgentEvent::Text(text) => {
                    flush(&mut narration);
                    narration = Some(text.clone());
                }
                AgentEvent::Tool { name, target } => {
                    record("agent.tool", json!({ "name": name, "target": target }));
                    let shown = target.strip_prefix(&format!("{}/", cwd.display())).unwrap_or(target);
                    eprintln!("  {} {} {}", err.cyan("⏺"), err.bold(name), render::first_line(shown, 100));
                }
                AgentEvent::Done { text, is_error, turns, cost_usd } => {
                    record("agent.result", json!({ "is_error": is_error, "turns": turns, "cost_usd": cost_usd }));
                    if narration.as_deref().map(str::trim) == Some(text.trim()) {
                        narration = None;
                    }
                    flush(&mut narration);
                    if *is_error {
                        eprintln!("{} {text}", err.red("agent reported an error:"));
                        if text.contains("/login") {
                            eprintln!(
                                "{} log the agent in once: run `agent do` (interactive) and type /login.\n      Or export ANTHROPIC_API_KEY before running.",
                                err.cyan("hint:")
                            );
                        }
                    } else if !text.is_empty() {
                        println!("\n{}", out.bold(text));
                    }
                    done = Some(event.clone());
                }
                AgentEvent::Raw(line) => println!("{line}"),
            }
        }
    }
    flush(&mut narration);
    if !recognized && !unrecognized.is_empty() {
        eprintln!("{} unrecognized agent output, shown as-is:", err.yellow("agent: warning:"));
        for line in unrecognized {
            println!("{line}");
        }
    }
    done
}

fn build_env(extra: &[String], home: &Path) -> Result<Vec<(String, String)>> {
    let mut env: Vec<(String, String)> =
        PASS_ENV.iter().filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v))).collect();
    if !env.iter().any(|(k, _)| k == "PATH") {
        env.push(("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()));
    }
    env.push(("HOME".into(), home.display().to_string()));
    for item in extra {
        let (k, v) = match item.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (item.clone(), std::env::var(item).with_context(|| format!("--env {item}: not set in your environment"))?),
        };
        if k.is_empty() {
            bail!("--env: empty variable name");
        }
        env.retain(|(name, _)| *name != k);
        env.push((k, v));
    }
    Ok(env)
}

/// Re-runs this very command line detached (minus --bg), in a new session
/// with no terminal: its output goes to the task, its questions to agentd.
fn launch_background(store: &Store) -> Result<i32> {
    use std::os::unix::process::CommandExt;
    let id = store.new_id()?;
    let mut args = Vec::new();
    let mut in_command = false;
    for arg in std::env::args_os().skip(1) {
        if arg == "--" {
            in_command = true;
        }
        if in_command || arg != "--bg" {
            args.push(arg);
        }
    }
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.args(args)
        .env("AGENTOS_NEW_TASK_ID", &id)
        .env("AGENTOS_BACKGROUND", "1")
        .env("AGENTOS_HOME", store.root())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("start the background task")?;
    for _ in 0..200 {
        if store.load(&id).is_ok() {
            break;
        }
        if let Some(status) = child.try_wait()? {
            bail!("the task didn't start ({status}); run it without --bg to see why");
        }
        thread::sleep(Duration::from_millis(50));
    }
    let p = Paint::stderr();
    eprintln!("{} task {} is running in the background", p.cyan("agent ▸"), p.bold(&id));
    for (cmd, what) in [("logs", "follow it (-f)"), ("wait", "wait for it"), ("stop", "stop it")] {
        eprintln!("        {}  {what}", p.bold(format!("agent {cmd:<4} {id}")));
    }
    if approvals::agentd(store.root()).is_none() {
        eprintln!(
            "  {}",
            p.dim("nobody to ask about hosts outside the allowlist: they're refused (run `agent serve` to answer them)")
        );
    }
    println!("{id}");
    Ok(0)
}

fn cmd_logs(store: &Store, selector: Option<&str>, follow: bool) -> Result<i32> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let task = store.resolve(selector)?;
    let path = task.dir.join("output.log");
    let mut file = fs::File::open(&path).with_context(|| format!("task {} kept no output (only background tasks do)", task.id()))?;
    let mut out = std::io::stdout();
    let mut pos = 0u64;
    loop {
        file.seek(SeekFrom::Start(pos))?;
        let mut chunk = Vec::new();
        file.read_to_end(&mut chunk)?;
        pos += chunk.len() as u64;
        out.write_all(&chunk)?;
        out.flush()?;
        if !follow {
            return Ok(0);
        }
        let live = store.load(task.id()).map(|t| t.is_live()).unwrap_or(false);
        if !live && chunk.is_empty() {
            return Ok(0);
        }
        thread::sleep(Duration::from_millis(300));
    }
}

fn cmd_wait(store: &Store, selector: Option<&str>) -> Result<i32> {
    let id = store.resolve(selector)?.id().to_string();
    loop {
        let task = store.load(&id)?;
        if !task.is_live() {
            println!("task {id} {}", task.status_label());
            return Ok(task.meta.exit_code.unwrap_or(0));
        }
        thread::sleep(Duration::from_millis(300));
    }
}

fn cmd_stop(store: &Store, selector: Option<&str>) -> Result<i32> {
    let task = store.resolve(selector)?;
    let (true, Some(pid)) = (task.is_live(), task.meta.supervisor_pid) else {
        bail!("task {} isn't running ({})", task.id(), task.status_label());
    };
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), nix::sys::signal::Signal::SIGTERM)?;
    for _ in 0..100 {
        if !store.load(task.id())?.is_live() {
            println!("stopped task {}; its changes are held: agent diff {}", task.id(), task.id());
            return Ok(0);
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("task {} didn't stop within 10s", task.id())
}

fn cmd_ls(store: &Store) -> Result<i32> {
    let tasks = store.list()?;
    if tasks.is_empty() {
        println!("no tasks yet; start one with `agent do` or `agent run`");
    } else {
        print!("{}", render::task_table(Paint::stdout(), &tasks));
    }
    Ok(0)
}

fn absolutize_all(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    paths.iter().map(|p| util::absolutize(p).map_err(Into::into)).collect()
}

/// A task whose changes can still be committed or rolled back.
fn open_task(store: &Store, selector: Option<&str>) -> Result<Task> {
    let task = store.resolve(selector).map_err(|e| match selector {
        Some(s) if Path::new(s).exists() => e.context(format!("to name paths of the latest task, use: last {s}")),
        _ => e,
    })?;
    if task.is_live() {
        bail!("task {} is still running", task.id());
    }
    if !task.is_open() {
        bail!("task {} is already {}", task.id(), task.status_label());
    }
    Ok(task)
}

fn cmd_diff(store: &Store, selector: Option<&str>, paths: &[PathBuf], stat: bool, all: bool) -> Result<i32> {
    let task = store.resolve(selector)?;
    let changes = changes::select(changes::scan(&task.layers())?, &absolutize_all(paths)?);
    let pushes = if paths.is_empty() { held_pushes(&task)? } else { Vec::new() };
    print!("{}", render::diff(Paint::stdout(), &task, &changes, &pushes, stat, all));
    Ok(0)
}

/// Held pushes with their commit subject and how many commits they add.
fn held_pushes(task: &Task) -> Result<Vec<render::HeldPush>> {
    Ok(outbox::pending(&task.dir)?
        .into_iter()
        .map(|p| {
            let (subject, new_commits) = outbox::describe(&task.dir, &p);
            render::HeldPush { push: p, subject, new_commits }
        })
        .collect())
}

fn cmd_commit(store: &Store, selector: Option<&str>, paths: &[PathBuf], force: bool, all: bool, no_push: bool) -> Result<i32> {
    let mut task = open_task(store, selector)?;
    let layers = task.layers();
    let mut selected = changes::select(changes::scan(&layers)?, &absolutize_all(paths)?);
    // Naming paths explicitly includes ignored changes under them.
    let skipped = if paths.is_empty() && !all {
        let before = selected.len();
        selected.retain(|c| !c.ignored);
        before - selected.len()
    } else {
        0
    };
    // Naming paths means files only; pushes go with a plain commit.
    let pushes = if paths.is_empty() && !no_push { outbox::pending(&task.dir)? } else { Vec::new() };
    if selected.is_empty() && pushes.is_empty() {
        match skipped {
            0 => println!("nothing to commit"),
            n => println!("nothing to commit ({} ignored; `agent commit --all` includes them)", plural(n, "change")),
        }
        return Ok(0);
    }
    if !selected.is_empty() {
        if !force {
            let conflicts = changes::conflicts(&selected, task.meta.started_at_ms);
            if !conflicts.is_empty() {
                eprint!("{}", render::conflicts(Paint::stderr(), &task, &conflicts));
                return Ok(1);
            }
        }
        changes::commit(&layers, &selected)?;
        task.journal().append(
            "commit",
            json!({
                "forced": force,
                "changes": selected.iter().map(|c| json!({ "kind": c.kind, "path": c.path })).collect::<Vec<_>>(),
            }),
        )?;
        let pending = changes::scan(&layers)?.iter().filter(|c| !c.ignored).count();
        print!("{}", render::committed(Paint::stdout(), &task, &selected, pending));
    }
    let failed = send_pushes(&task, &pushes, false)?;
    finish_if_done(&mut task)?;
    Ok(if failed > 0 { 1 } else { 0 })
}

fn cmd_push(store: &Store, selector: Option<&str>, force: bool) -> Result<i32> {
    let mut task = open_task(store, selector)?;
    let pushes = outbox::pending(&task.dir)?;
    if pushes.is_empty() {
        println!("nothing to push");
        return Ok(0);
    }
    let failed = send_pushes(&task, &pushes, force)?;
    finish_if_done(&mut task)?;
    Ok(if failed > 0 { 1 } else { 0 })
}

/// Replays held pushes from outside the sandbox. Returns how many failed
/// (those stay held).
fn send_pushes(task: &Task, pushes: &[outbox::Push], force: bool) -> Result<usize> {
    let (out, err) = (Paint::stdout(), Paint::stderr());
    let journal = task.journal();
    let mut failed = 0;
    for p in pushes {
        let what = json!({ "remote": p.remote, "ref": p.refname, "sha": p.sha, "forced": force });
        match outbox::send(p, force) {
            Ok(()) => {
                journal.append("outbox.pushed", what)?;
                println!("  {} pushed {} to {} {}", out.green("↑"), &p.sha[..p.sha.len().min(7)], p.remote, p.short_ref());
            }
            Err(e) => {
                failed += 1;
                let mut what = what;
                what["error"] = json!(format!("{e:#}"));
                journal.append("outbox.failed", what)?;
                eprintln!("  {} {} {}: {e:#}", err.red("✗ push to"), p.remote, p.short_ref());
            }
        }
    }
    if failed > 0 {
        eprintln!(
            "{} {} still held. Once you've sorted it out: `agent push {}` (--force overwrites the remote)",
            err.yellow("agent:"),
            plural(failed, "push"),
            task.id()
        );
    }
    Ok(failed)
}

/// Closes the task once nothing is left: no file changes (ignored ones are
/// dropped) and no held pushes.
fn finish_if_done(task: &mut Task) -> Result<()> {
    let files = changes::scan(&task.layers())?;
    if files.iter().any(|c| !c.ignored) || !outbox::pending(&task.dir)?.is_empty() {
        return Ok(());
    }
    if !files.is_empty() {
        println!("{}", Paint::stdout().dim(format!("left out {}", render::ignored_summary(&files))));
    }
    let applied = task.journal().read()?.iter().any(|e| e.kind == "commit" || e.kind == "outbox.pushed");
    task.meta.status = if applied { Status::Committed } else { Status::Discarded };
    task.save()?;
    task.release_storage()
}

fn cmd_rollback(store: &Store, selector: Option<&str>, paths: &[PathBuf]) -> Result<i32> {
    let mut task = open_task(store, selector)?;
    let layers = task.layers();
    let pending = changes::scan(&layers)?;
    let journal = task.journal();
    let counted = |changes: &[changes::Change]| changes.iter().filter(|c| !c.ignored).count();
    if paths.is_empty() {
        let pushes = outbox::pending(&task.dir)?;
        let held: Vec<_> = pushes.iter().map(|p| json!({ "remote": p.remote, "ref": p.refname, "sha": p.sha })).collect();
        journal.append("rollback", json!({ "all": true, "changes": Summary::of(&pending), "pushes": held }))?;
        let committed_before = journal.read()?.iter().any(|e| e.kind == "commit" || e.kind == "outbox.pushed");
        let mut what = plural(counted(&pending), "change");
        if !pushes.is_empty() {
            what = format!("{what} and {}", plural(pushes.len(), "held push"));
        }
        if committed_before {
            println!("rolled back the remaining {what} from task {}", task.id());
        } else {
            println!("rolled back {what} from task {}; your files and remotes are as they were", task.id());
        }
        task.meta.status = if committed_before { Status::Committed } else { Status::Discarded };
        task.save()?;
        task.release_storage()?;
        return Ok(0);
    }
    let targets = absolutize_all(paths)?;
    changes::rollback(&layers, &pending, &targets)?;
    journal.append("rollback", json!({ "paths": targets }))?;
    let left = counted(&changes::scan(&layers)?);
    println!(
        "rolled back {} from task {}; {left} still pending",
        plural(counted(&pending).saturating_sub(left), "change"),
        task.id(),
    );
    finish_if_done(&mut task)?;
    Ok(0)
}

fn cmd_log(store: &Store, selector: Option<&str>, raw: bool) -> Result<i32> {
    let task = store.resolve(selector)?;
    let journal = task.journal();
    let events = journal.read().unwrap_or_default();
    let out = Paint::stdout();
    if raw {
        for e in &events {
            println!("{}", serde_json::to_string(e)?);
        }
    } else {
        print!("{}", render::log(out, &task, &events));
    }
    match journal.verify()? {
        Integrity::Intact { events, head } => {
            if !raw {
                println!("{} chain intact · {events} events · head {}", out.green("✓"), &head[..12]);
            }
            Ok(0)
        }
        Integrity::Broken { line, reason } => {
            println!("{} chain BROKEN at event {line}: {reason}", out.red("✗"));
            Ok(1)
        }
    }
}

fn cmd_policy(command: Option<PolicyCommand>) -> Result<i32> {
    let home = home_dir()?;
    let file = config::policy_path(&home);
    let out = Paint::stdout();
    let project_file = config::find_project_rules(&std::env::current_dir()?, &home);
    let theirs = project_file.as_deref().map(|f| policy::load_project(f, &home)).transpose()?;
    let Some(set) = policy::combine(policy::load(&file, &home)?, theirs)? else {
        println!("no rules yet: write them in {} (see README: Rules)", display_path(&file));
        return Ok(0);
    };
    match command {
        None => {
            let all = policy::rules(&set);
            for (title, project) in [(display_path(&file), false), (project_file.as_deref().map(display_path).unwrap_or_default(), true)] {
                let mine: Vec<_> = all.iter().filter(|(name, _)| name.starts_with("project: ") == project).collect();
                if mine.is_empty() {
                    continue;
                }
                println!("{}{}", out.bold(title), if project { out.dim(" (this project's: forbids only)") } else { String::new() });
                for (name, effect) in mine {
                    let effect = if *effect == "forbid" { out.red(*effect) } else { out.green(*effect) };
                    println!("  {effect}  {}", name.trim_start_matches("project: "));
                }
            }
        }
        Some(PolicyCommand::Check { action, target, args, agent }) => {
            let question = match policy::Action::parse(&action) {
                Some(policy::Action::Connect) => {
                    let (host, port) = target.rsplit_once(':').and_then(|(h, p)| Some((h, p.parse().ok()?))).unwrap_or((target.as_str(), 443));
                    Question::connect(&host.to_ascii_lowercase(), port)
                }
                Some(a @ (policy::Action::Read | policy::Action::Write)) => {
                    let path = control::resolve(&target, &home, &std::env::current_dir()?)?;
                    Question::path(a == policy::Action::Write, &path)
                }
                Some(policy::Action::Call) => {
                    let (server, tool) = target.split_once('.').context("call: give SERVER.TOOL, e.g. github.create_issue")?;
                    let args: serde_json::Value = match args {
                        Some(a) => serde_json::from_str(&a).context("--args: not JSON")?,
                        None => json!({}),
                    };
                    Question::call(server, tool, &args)
                }
                None => bail!("{action}: expected connect, read, write or call"),
            };
            let project = approvals::project_root(&std::env::current_dir()?, &home);
            match policy::Policy::new(set, &agent, "check", &project).decide(&question) {
                Verdict::Permit(rule) => println!("{} by \u{201c}{rule}\u{201d}: no question asked", out.green("permitted")),
                Verdict::Forbid(rule) => {
                    let (who, name) = policy::whose(&rule);
                    println!("{} by {who} rule \u{201c}{name}\u{201d}", out.red("forbidden"));
                }
                Verdict::Undecided => println!("no rule matches: the allowlist and your config decide, or you're asked"),
            }
        }
    }
    Ok(0)
}

fn cmd_revoke(store: &Store, target: Option<String>, task: Option<String>) -> Result<i32> {
    let task = match task {
        Some(id) => store.resolve(Some(&id))?,
        None => store.list()?.into_iter().rev().find(|t| t.is_live()).context("no task is running")?,
    };
    if !task.is_live() {
        bail!("task {} isn't running ({}): there's nothing to take back", task.id(), task.status_label());
    }
    let socket = task.dir.join(control::OWNER_SOCKET);
    let out = Paint::stdout();
    let Some(target) = target else {
        let reply = control::call(&socket, &Call::Given)?;
        let given: Vec<Given> = serde_json::from_str(&reply.text).unwrap_or_default();
        if given.is_empty() {
            println!("task {} got nothing while it ran: nothing to take back", task.id());
        }
        for g in given {
            let shown = if g.kind == "folder" { display_path(Path::new(&g.target)) } else { g.target.clone() };
            let access = g.access.map(|a| format!(" ({a})")).unwrap_or_default();
            let state = if g.revoked { out.dim(" taken back") } else { String::new() };
            println!("  {:<7} {shown}{access}{state}", g.kind);
        }
        return Ok(0);
    };
    // Paths as you mean them from here; the task knows them by their real path.
    let target = if target.contains('/') || target.starts_with('~') || target.starts_with('.') {
        let p = control::resolve(&target, &home_dir()?, &std::env::current_dir()?)?;
        fs::canonicalize(&p).unwrap_or(p).display().to_string()
    } else {
        target
    };
    let reply = control::call(&socket, &Call::Revoke { target })?;
    if !reply.ok {
        bail!("{}", reply.text);
    }
    println!("{} {} (task {})", out.green("✓"), reply.text, task.id());
    Ok(0)
}

/// The store's spend ledger. A new one starts with the last 40 days of
/// finished tasks, so nothing already spent is forgotten.
fn open_ledger(store: &Store, home: &Path) -> Result<Ledger> {
    let (ledger, fresh) = Ledger::open(store.root())?;
    if fresh {
        let since = util::now_ms().saturating_sub(40 * 86_400_000);
        for t in store.list()? {
            if let (Some(u), Some(ended)) = (&t.meta.usage, t.meta.ended_at_ms) {
                if ended >= since && u.calls > 0 {
                    let project = approvals::project_root(&t.meta.cwd, home).display().to_string();
                    let entry = gateway::Entry { ts_ms: ended, task: t.id().to_string(), project, usd: u.cost_usd, tokens: u.usage.tokens() };
                    ledger.add(&entry)?;
                }
            }
        }
    }
    Ok(ledger)
}

fn cmd_spend(store: &Store) -> Result<i32> {
    let (home, cwd) = (home_dir()?, std::env::current_dir()?);
    let ledger = open_ledger(store, &home)?;
    let project = approvals::project_root(&cwd, &home);
    let budgets = config::load(store.root(), &cwd, &home)?.periodic;
    let now = util::now_ms();
    let out = Paint::stdout();
    let limit = |period: gateway::Period, mine: bool| {
        budgets.iter().find(|(p, _, m)| *p == period && *m == mine).map(|(_, b, _)| format!(" of {b}")).unwrap_or_default()
    };
    println!("{}", out.dim(format!("{:<12}{:<26}{}", "", "all your tasks", format!("this project ({})", display_path(&project)))));
    for period in gateway::Period::ALL {
        let since = period.start(now);
        let (all, all_tokens) = ledger.spent(since, None);
        let (here, here_tokens) = ledger.spent(since, Some(&project));
        let col = |usd: f64, tokens: u64, mine: bool| format!("{} · {}{}", gateway::usd(usd), gateway::tokens(tokens), limit(period, mine));
        println!("{:<12}{:<26}{}", period.label(), col(all, all_tokens, false), col(here, here_tokens, true));
    }
    if let Some(over) = ledger.over(&budgets.iter().map(|(period, amount, mine)| Periodic { amount: *amount, period: *period, project: mine.then(|| project.clone()) }).collect::<Vec<_>>(), now) {
        println!("{} {over}", out.yellow("!"));
    }
    Ok(0)
}

fn cmd_doctor(store: &Store) -> Result<i32> {
    let out = Paint::stdout();
    let checks = doctor::run(store.root());
    for c in &checks {
        let mark = match c.level {
            Level::Ok => out.green("✓"),
            Level::Warn => out.yellow("!"),
            Level::Fail => out.red("✗"),
        };
        println!("{mark} {:<16} {}", c.name, c.detail);
    }
    Ok(if checks.iter().any(|c| c.level == Level::Fail) { 1 } else { 0 })
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}
