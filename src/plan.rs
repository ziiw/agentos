//! Turning arguments and config into a task plan: `agent do`, `agent run`, and the small commands around them.

use crate::*;

pub(crate) struct LoginPlan {
    pub(crate) vault: Arc<Vault>,
    pub(crate) hosts: Vec<String>,
    /// The credentials file in the agent's home.
    pub(crate) file: PathBuf,
    /// Placeholders in the sandbox, real tokens added by the broker. Without
    /// the proxy (--net host) the login is unsealed for the task instead.
    pub(crate) brokered: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ask {
    Never,
    /// agentd's console only (the terminal belongs to a full-screen agent).
    Console,
    /// The terminal and agentd's console, if running.
    TerminalAndConsole,
}

/// Everything needed to run one task, whether from `agent run` or `agent do`.
pub(crate) struct Plan {
    pub(crate) title: Option<String>,
    pub(crate) argv: Vec<String>,
    pub(crate) grants: GrantArgs,
    pub(crate) net: Net,
    /// Hosts reachable through the egress proxy (`Net::Proxy`).
    pub(crate) allow: Vec<String>,
    /// Credentials the broker adds on the wire.
    pub(crate) secrets: Vec<Secret>,
    /// The agent's login, sealed in the vault.
    pub(crate) login: Option<LoginPlan>,
    /// Read-only grants for the agent's own installation.
    pub(crate) install: Vec<PathBuf>,
    pub(crate) profile_env: Vec<(String, String)>,
    pub(crate) pass_env: Vec<String>,
    /// Agent profile name: gives the task a persistent home.
    pub(crate) agent: Option<String>,
    pub(crate) output: Output,
    /// Hosts the agent reaches for that stay closed on purpose: (host, why).
    pub(crate) expected_denials: Vec<(String, String)>,
    /// Who to ask about hosts outside the allowlist.
    pub(crate) ask: Ask,
    /// Fail rather than run without the current directory.
    pub(crate) needs_cwd: bool,
    pub(crate) timeout: Option<Duration>,
    /// For model calls, enforced by the gateway.
    pub(crate) budget: Option<Budget>,
    /// Your prices for models agentos doesn't know.
    pub(crate) prices: Vec<(String, Price)>,
    /// Model APIs the agent calls beyond the well-known ones.
    pub(crate) models: Vec<Endpoint>,
    /// Hosts whose content doesn't taint the task (besides model APIs and credentials' hosts).
    pub(crate) taint_trusted: Vec<String>,
    /// Your MCP servers, reached through agentos.
    pub(crate) mcp: Vec<agentos::mcp::Server>,
    /// Budgets across tasks: (period, amount, this project's only).
    pub(crate) periodic: Vec<(gateway::Period, Budget, bool)>,
    /// Your corporate proxy from your config (else the environment's), and the hosts to skip it for.
    pub(crate) proxy: Option<String>,
    pub(crate) no_proxy: Vec<String>,
    /// Ports on your loopback the agent reaches at the same port (a local model server).
    pub(crate) local: Vec<u16>,
}

/// What the config files add to a task beyond its grants.
pub(crate) struct Applied {
    pub(crate) allow: Vec<String>,
    pub(crate) proxy: Option<String>,
    pub(crate) no_proxy: Vec<String>,
    pub(crate) local: Vec<u16>,
    /// `(NAME, HOST[/HEADER])`: brokered if NAME has a value (see [`secret_value`]).
    pub(crate) secrets: Vec<(String, String)>,
    pub(crate) secret_commands: keychain::Commands,
    pub(crate) budget: Option<Budget>,
    pub(crate) prices: Vec<(String, Price)>,
    pub(crate) mcp: Vec<agentos::mcp::Server>,
    pub(crate) periodic: Vec<(gateway::Period, Budget, bool)>,
    pub(crate) taint_trusted: Vec<String>,
}

/// Merges your config and a trusted project config into this task's grants.
pub(crate) fn apply_config(store: &Store, grants: &mut GrantArgs) -> Result<Applied> {
    let (cwd, home) = (std::env::current_dir()?, home_dir()?);
    let mut settings = config::load(store.root(), &cwd, &home)?;
    for note in &settings.notes {
        eprintln!("{} {note}", Paint::stderr().yellow("agent:"));
    }
    // Hosts you approved "always" for this project count like your own config.
    settings.allow.extend(approvals::remembered(store.root(), &approvals::project_root(&cwd, &home))?);
    grants.ro.extend(settings.ro);
    grants.hide.extend(settings.hide);
    Ok(Applied { allow: settings.allow, proxy: settings.proxy, no_proxy: settings.no_proxy, local: settings.local, secrets: settings.secrets, secret_commands: settings.secret_commands, budget: settings.budget, prices: settings.prices, mcp: settings.mcp, periodic: settings.periodic, taint_trusted: settings.taint_trusted })
}

/// The proxy the egress proxy goes through: your config's, else the one in
/// your environment (`HTTPS_PROXY`), minus the hosts you skip it for.
pub(crate) fn upstream_proxy(configured: Option<&str>, no_proxy: &[String]) -> Result<Option<proxy::Upstream>> {
    Ok(match configured {
        Some("") => None,
        Some(url) => Some(proxy::Upstream::parse(url, &[]).context("[network] proxy")?.bypassing(no_proxy)),
        None => proxy::Upstream::from_env()?.map(|u| u.bypassing(no_proxy)),
    })
}

/// The loopback ports a task gets: your config's and --local's, once each.
pub(crate) fn local_ports(configured: Vec<u16>, flags: &[u16]) -> Vec<u16> {
    let mut ports = configured;
    for p in flags {
        if !ports.contains(p) {
            ports.push(*p);
        }
    }
    ports.dedup();
    ports
}

/// The task's budget: --budget, else your config's. The gateway enforces it
/// in the egress proxy, so a task without the proxy has none.
pub(crate) fn task_budget(flag: Option<Budget>, configured: Option<Budget>, net: Net) -> Result<Option<Budget>> {
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

pub(crate) fn cmd_trust(store: &Store, path: Option<PathBuf>) -> Result<i32> {
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
pub(crate) fn prepare_login(store: &Store, agent: &str, login: &profiles::Login, net: Net) -> Result<Option<LoginPlan>> {
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
pub(crate) fn agents_dir(home: &Path) -> PathBuf {
    config::user_config_path(home).parent().map(|d| d.join("agents")).unwrap_or_else(|| home.join(".config/agentos/agents"))
}

pub(crate) fn cmd_agents(store: &Store) -> Result<i32> {
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

pub(crate) fn cmd_vault(store: &Store, action: &str, agent: &str) -> Result<i32> {
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

/// The real value of a secret: your environment's, else what its
/// `[secret_commands]` entry prints. A command that fails is a warning, and
/// the secret then counts as not set.
pub(crate) fn secret_value(name: &str, commands: &keychain::Commands) -> Option<String> {
    match keychain::lookup(name, commands) {
        Ok(value) => value,
        Err(why) => {
            eprintln!("{} {name}: {why}; going on without it", Paint::stderr().yellow("agent: warning:"));
            None
        }
    }
}

/// The secrets of your config that have a value.
pub(crate) fn resolve_config_secrets(entries: &[(String, String)], commands: &keychain::Commands) -> Result<Vec<Secret>> {
    let mut secrets = Vec::new();
    for (name, target) in entries {
        if let Some(value) = secret_value(name, commands) {
            secrets.push(Secret::parse_with(&format!("{name}={target}"), |_| Some(value))?);
        }
    }
    Ok(secrets)
}

pub(crate) fn parse_secrets(specs: &[String], commands: &keychain::Commands) -> Result<Vec<Secret>> {
    let secrets = specs.iter().map(|s| Secret::parse_with(s, |name| secret_value(name, commands))).collect::<Result<Vec<_>>>()?;
    for (i, s) in secrets.iter().enumerate() {
        if secrets[..i].iter().any(|o| o.env == s.env) {
            bail!("--secret {}: given twice", s.env);
        }
    }
    Ok(secrets)
}

pub(crate) fn cmd_do(store: &Store, mut args: DoArgs) -> Result<i32> {
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
    let (config_allow, config_secrets, commands) = (applied.allow, applied.secrets, applied.secret_commands);
    let local = local_ports(applied.local, &args.grants.local);
    let net = args.net.unwrap_or(profile.net);
    let budget = task_budget(args.mode.budget, applied.budget, net)?;
    if net != Net::Proxy && !args.grants.allow.is_empty() {
        bail!("--allow only applies to the agent's default, proxied network; drop --net {net}");
    }
    let mut allow: Vec<String> = profile.allow.iter().map(|h| h.to_string()).collect();
    allow.extend(config_allow);
    allow.extend(args.grants.allow.iter().cloned());
    let mut secrets = parse_secrets(&args.grants.secret, &commands)?;
    let no_ask = args.grants.no_ask;
    if net == Net::Proxy {
        let from_profile: Vec<Secret> = profile
            .brokered
            .iter()
            .filter_map(|(var, host, header)| secret_value(var, &commands).map(|value| Secret::new(var, host, header, value)))
            .collect();
        for secret in from_profile.into_iter().chain(resolve_config_secrets(&config_secrets, &commands)?) {
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
            taint_trusted: applied.taint_trusted.into_iter().chain(profile.allow.iter().cloned()).collect(),
            mcp: applied.mcp,
            periodic: applied.periodic,
            proxy: applied.proxy,
            no_proxy: applied.no_proxy,
            local,
        },
    )
}

pub(crate) fn cmd_run(store: &Store, mut args: RunArgs) -> Result<i32> {
    if args.mode.bg {
        return launch_background(store);
    }
    args.mode.apply_limits(store)?;
    let argv = args.command;
    let applied = apply_config(store, &mut args.grants)?;
    let (config_allow, config_secrets, commands) = (applied.allow, applied.secrets, applied.secret_commands);
    let local = local_ports(applied.local, &args.grants.local);
    let mut secrets = parse_secrets(&args.grants.secret, &commands)?;
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
        for secret in resolve_config_secrets(&config_secrets, &commands)? {
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
            taint_trusted: applied.taint_trusted,
            mcp: applied.mcp,
            periodic: applied.periodic,
            proxy: applied.proxy,
            no_proxy: applied.no_proxy,
            local,
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
pub(crate) fn cwd_refusal(cwd: &Path, home: &Path, store: &Path) -> Option<&'static str> {
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
