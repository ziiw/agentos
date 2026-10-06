use agentos::changes::{self, Summary};
use agentos::doctor::{self, Level};
use agentos::journal::{Integrity, Journal};
use agentos::profiles::{self, AgentEvent, Output};
use agentos::proxy::{self, Allowlist, NetEvent};
use agentos::sandbox::{self, GrantMount, Mount};
use agentos::store::{Access, Grant, Net, NewTask, Status, Store, Task};
use agentos::util::{self, display_path};
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use nix::fcntl::OFlag;
use render::Paint;
use serde_json::json;
use std::fs;
use std::io::{BufRead, BufReader, IsTerminal};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

mod render;

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
    },
    /// Discard a task's changes (all of them, or only those under PATHs)
    #[command(alias = "discard")]
    Rollback {
        /// Task id or prefix (`last` for the latest)
        task: Option<String>,
        paths: Vec<PathBuf>,
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
}

#[derive(Args)]
struct RunArgs {
    #[command(flatten)]
    grants: GrantArgs,
    /// Network: none (loopback only) or host. --allow gives an allowlist instead.
    #[arg(long, default_value = "none")]
    net: Net,
    /// The command to run
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Args)]
struct DoArgs {
    #[command(flatten)]
    grants: GrantArgs,
    /// Which agent
    #[arg(long, default_value = "claude")]
    agent: String,
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

/// Everything needed to run one task, whether from `agent run` or `agent do`.
struct Plan {
    title: Option<String>,
    argv: Vec<String>,
    grants: GrantArgs,
    net: Net,
    /// Hosts reachable through the egress proxy (`Net::Proxy`).
    allow: Vec<String>,
    /// Read-only grants for the agent's own installation.
    install: Vec<PathBuf>,
    profile_env: Vec<(String, String)>,
    pass_env: Vec<&'static str>,
    /// Agent profile name: gives the task a persistent home.
    agent: Option<&'static str>,
    output: Output,
    /// Fail rather than run without the current directory.
    needs_cwd: bool,
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
    let store = Store::open()?;
    match cli.command {
        Command::Do(args) => cmd_do(&store, args),
        Command::Run(args) => cmd_run(&store, args),
        Command::Ls => cmd_ls(&store),
        Command::Diff { task, paths, stat, all } => cmd_diff(&store, task.as_deref(), &paths, stat, all),
        Command::Commit { task, paths, force, all } => cmd_commit(&store, task.as_deref(), &paths, force, all),
        Command::Rollback { task, paths } => cmd_rollback(&store, task.as_deref(), &paths),
        Command::Log { task, json } => cmd_log(&store, task.as_deref(), json),
        Command::Doctor => cmd_doctor(&store),
    }
}

fn home_dir() -> Result<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    Ok(fs::canonicalize(&home).unwrap_or(home))
}

fn cmd_do(store: &Store, args: DoArgs) -> Result<i32> {
    let task = (!args.task.is_empty()).then(|| args.task.join(" "));
    if task.is_none() && !std::io::stdin().is_terminal() {
        bail!("give the agent a task: agent do \"…\"");
    }
    let interactive = args.interactive || task.is_none();
    let profile = profiles::load(&args.agent, task.as_deref(), interactive, &home_dir()?)?;
    let title = match &task {
        Some(t) => format!("{}: {t}", profile.name),
        None => format!("{} (interactive)", profile.name),
    };
    let net = args.net.unwrap_or(profile.net);
    if net != Net::Proxy && !args.grants.allow.is_empty() {
        bail!("--allow only applies to the agent's default, proxied network; drop --net {net}");
    }
    let mut allow: Vec<String> = profile.allow.iter().map(|h| h.to_string()).collect();
    allow.extend(args.grants.allow.iter().cloned());
    execute(
        store,
        Plan {
            title: Some(title),
            argv: profile.argv,
            grants: args.grants,
            net,
            allow,
            install: profile.install,
            profile_env: profile.env,
            pass_env: profile.pass_env,
            agent: Some(profile.name),
            output: profile.output,
            needs_cwd: true,
        },
    )
}

fn cmd_run(store: &Store, args: RunArgs) -> Result<i32> {
    let argv = args.command;
    let net = match (args.grants.allow.is_empty(), args.net) {
        (true, net) => net,
        (false, Net::Host) => bail!("--allow and --net host contradict each other: --allow means only those hosts"),
        (false, _) => Net::Proxy,
    };
    let allow = args.grants.allow.clone();
    let code = execute(
        store,
        Plan {
            title: None,
            argv: argv.clone(),
            grants: args.grants,
            net,
            allow,
            install: Vec::new(),
            profile_env: Vec::new(),
            pass_env: Vec::new(),
            agent: None,
            output: Output::Inherit,
            needs_cwd: false,
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
            if grants.iter().any(|g| g.path == path) {
                bail!("{} is granted twice", display_path(&path));
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
    let allow = if plan.net == Net::Proxy { plan.allow } else { Vec::new() };
    let allowlist = Allowlist::parse(&allow)?;
    let hidden = plan
        .grants
        .hide
        .iter()
        .map(|p| fs::canonicalize(p).with_context(|| format!("--hide {}: no such file or directory", p.display())))
        .collect::<Result<Vec<_>>>()?;

    let mut env = build_env(&plan.grants.env, &home)?;
    for (k, v) in plan.profile_env {
        env.retain(|(name, _)| *name != k);
        env.push((k, v));
    }
    for k in plan.pass_env {
        if let (Ok(v), false) = (std::env::var(k), env.iter().any(|(name, _)| name == k)) {
            env.push((k.to_string(), v));
        }
    }
    let mut env_names: Vec<String> = env.iter().map(|(k, _)| k.clone()).collect();
    env_names.push("AGENTOS_TASK".into());
    let home_source = plan.agent.map(|name| store.agent_home(name)).transpose()?;

    let mut task = store.create(NewTask {
        title: plan.title,
        agent: plan.agent.map(String::from),
        command: plan.argv.clone(),
        cwd: cwd.clone(),
        grants,
        hidden,
        net: plan.net,
        allow,
        env: env_names,
    })?;
    env.push(("AGENTOS_TASK".into(), task.id().to_string()));
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
            "env": task.meta.env,
        }),
    )?;

    let err = Paint::stderr();
    eprintln!("{}", render::banner(err, &task));
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
        hostname: format!("agent-{}", task.id()),
        home,
        home_source,
        cwd: cwd.clone(),
        env,
        argv: plan.argv,
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
    let result = sandbox::run(&spec, stdout_tx, |report| {
        let kind = if report.error.is_some() { "sandbox.failed" } else { "sandbox.ready" };
        if let Err(e) = journal.append(kind, json!(report)) {
            eprintln!("{} journal: {e:#}", err.yellow("agent: warning:"));
        }
        for w in &report.warnings {
            eprintln!("{} {w}", err.yellow("agent: warning:"));
        }
        setup_error = report.error.clone();
        if let Some(listener) = proxy_listener.take() {
            proxy_handle = Some(proxy::serve(listener, allowlist, net_sink(journal.clone(), blocked.clone(), err)));
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

    let summary = Summary::of(&changes::scan(&task.layers())?);
    let ended = util::now_ms();
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
    eprintln!("{}", render::exit_summary(err, &task, &summary, outcome.as_ref(), blocked.load(Ordering::SeqCst)));
    Ok(exit_code)
}

/// Records each connection through the egress proxy and says so, live,
/// when one is refused.
fn net_sink(journal: Journal, blocked: Arc<AtomicUsize>, err: Paint) -> proxy::Sink {
    Arc::new(move |event: NetEvent| {
        let _ = journal.append("net.connect", json!(event));
        if !event.allowed {
            blocked.fetch_add(1, Ordering::SeqCst);
            let target = format!("{}:{}", event.host, event.port);
            let why = event.reason.as_deref().unwrap_or("refused");
            let hint = if why == "not in the allowlist" {
                let host = if event.port == 443 { event.host.clone() } else { target.clone() };
                format!(" (allow it with --allow {host})")
            } else {
                String::new()
            };
            eprintln!("{} {target}: {why}{hint}", err.yellow("agent: blocked"));
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
    print!("{}", render::diff(Paint::stdout(), &task, &changes, stat, all));
    Ok(0)
}

fn cmd_commit(store: &Store, selector: Option<&str>, paths: &[PathBuf], force: bool, all: bool) -> Result<i32> {
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
    if selected.is_empty() {
        match skipped {
            0 => println!("nothing to commit"),
            n => println!("nothing to commit ({} ignored; `agent commit --all` includes them)", plural(n, "change")),
        }
        return Ok(0);
    }
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
    let remaining = changes::scan(&layers)?;
    let pending = remaining.iter().filter(|c| !c.ignored).count();
    print!("{}", render::committed(Paint::stdout(), &task, &selected, pending));
    if pending == 0 {
        if !remaining.is_empty() {
            println!("{}", Paint::stdout().dim(format!("left out {}", render::ignored_summary(&remaining))));
        }
        task.meta.status = Status::Committed;
        task.save()?;
        task.release_storage()?;
    }
    Ok(0)
}

fn cmd_rollback(store: &Store, selector: Option<&str>, paths: &[PathBuf]) -> Result<i32> {
    let mut task = open_task(store, selector)?;
    let layers = task.layers();
    let pending = changes::scan(&layers)?;
    let journal = task.journal();
    let committed_before = journal.read()?.iter().any(|e| e.kind == "commit");
    let counted = |changes: &[changes::Change]| changes.iter().filter(|c| !c.ignored).count();
    let remaining = if paths.is_empty() {
        journal.append("rollback", json!({ "all": true, "changes": Summary::of(&pending) }))?;
        let n = plural(counted(&pending), "change");
        if committed_before {
            println!("rolled back the remaining {n} from task {}", task.id());
        } else {
            println!("rolled back {n} from task {}; your files are as they were", task.id());
        }
        0
    } else {
        let targets = absolutize_all(paths)?;
        changes::rollback(&layers, &pending, &targets)?;
        journal.append("rollback", json!({ "paths": targets }))?;
        let left = counted(&changes::scan(&layers)?);
        println!(
            "rolled back {} from task {}; {left} still pending",
            plural(counted(&pending).saturating_sub(left), "change"),
            task.id(),
        );
        left
    };
    if remaining == 0 {
        task.meta.status = if committed_before { Status::Committed } else { Status::Discarded };
        task.save()?;
        task.release_storage()?;
    }
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
