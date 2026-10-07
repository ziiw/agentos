//! Commands about your setup rather than one task: approvals, rules, spend, MCP sign-in.

use crate::*;

pub(crate) fn cmd_approvals(store: &Store, revoke: Option<String>) -> Result<i32> {
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

pub(crate) fn cmd_policy(command: Option<PolicyCommand>) -> Result<i32> {
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
        Some(PolicyCommand::Check { action, target, args, agent, tainted }) => {
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
            let sources = tainted
                .iter()
                .map(|k| match k.as_str() {
                    "web" => Ok(taint::Source::Web),
                    "tool" => Ok(taint::Source::Tool),
                    "file" => Ok(taint::Source::File),
                    other => bail!("--tainted {other}: expected web, tool or file"),
                })
                .collect::<Result<Vec<_>>>()?;
            match policy::Policy::new(set, &agent, "check", &project).pretend_tainted(&sources).decide(&question) {
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

pub(crate) fn cmd_revoke(store: &Store, target: Option<String>, task: Option<String>) -> Result<i32> {
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
pub(crate) fn open_ledger(store: &Store, home: &Path) -> Result<Ledger> {
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

pub(crate) fn cmd_spend(store: &Store) -> Result<i32> {
    let (home, cwd) = (home_dir()?, std::env::current_dir()?);
    let ledger = open_ledger(store, &home)?;
    let project = approvals::project_root(&cwd, &home);
    let budgets = config::load(store.root(), &cwd, &home)?.periodic;
    let now = util::now_ms();
    let out = Paint::stdout();
    let limit = |period: gateway::Period, mine: bool| {
        let Some((_, amount, _)) = budgets.iter().find(|(p, _, m)| *p == period && *m == mine) else { return String::new() };
        let st = ledger.standing(&Periodic { amount: *amount, period, project: mine.then(|| project.clone()) }, now);
        let raised = if st.raised { format!(" (raised from {amount})") } else { String::new() };
        format!(" of {}{raised}", st.cap)
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

pub(crate) fn cmd_raise(store: &Store, amount: Budget, task: Option<String>, period: Option<gateway::Period>, project: bool) -> Result<i32> {
    let Some(period) = period else {
        if project {
            bail!("--project goes with --today, --this-week or --this-month: a task's own budget has no project");
        }
        let task = match task {
            Some(id) => store.resolve(Some(&id))?,
            None => store.list()?.into_iter().rev().find(|t| t.is_live()).context("no task is running (to raise a budget across tasks: --today, --this-week or --this-month)")?,
        };
        if !task.is_live() {
            bail!("task {} isn't running ({}): its budget can't change anymore", task.id(), task.status_label());
        }
        let reply = control::call(&task.dir.join(control::OWNER_SOCKET), &Call::Raise { to: amount.spec(), by: approvals::AT_TERMINAL.into() })?;
        if !reply.ok {
            bail!("{}", reply.text);
        }
        println!("{}", reply.text);
        return Ok(0);
    };
    println!("{}", raise_shared(store, &home_dir()?, &std::env::current_dir()?, period, project, amount, approvals::AT_TERMINAL)?);
    Ok(0)
}

pub(crate) fn cmd_connect(store: &Store, name: Option<String>, forget: bool) -> Result<i32> {
    let (home, cwd) = (home_dir()?, std::env::current_dir()?);
    let servers = config::load(store.root(), &cwd, &home)?.mcp;
    let out = Paint::stdout();
    let Some(name) = name else {
        let remote: Vec<_> = servers.iter().filter(|s| s.url.is_some()).collect();
        if remote.is_empty() {
            println!("no remote MCP servers in your config: add one with [mcp.NAME] url = \"https://…\"");
        }
        for s in remote {
            let url = s.url.as_deref().unwrap_or_default();
            let state = match (&s.token, agentos::oauth::load(store.root(), &s.name).filter(|t| t.url == url)) {
                (Some(var), _) if std::env::var_os(var).is_some() => out.green(format!("token from ${var}")),
                (Some(var), _) => out.yellow(format!("token from ${var}, which isn't set")),
                (None, Some(t)) => out.green(format!("signed in at {}", t.issuer)),
                (None, None) => out.dim(format!("not signed in: agent connect {} (if it needs it)", s.name)),
            };
            println!("{:<12} {url}  {state}", s.name);
        }
        return Ok(0);
    };
    let server = servers.iter().find(|s| s.name == name).with_context(|| format!("no [mcp.{name}] in your config"))?;
    let Some(url) = &server.url else {
        bail!("{name} is a server agentos runs ({}): it gets its credentials through env, there's nothing to sign in to", server.describe());
    };
    if forget {
        if agentos::oauth::forget(store.root(), &name) {
            println!("forgot your sign-in to {name}");
        } else {
            println!("you weren't signed in to {name}");
        }
        return Ok(0);
    }
    if let Some(var) = &server.token {
        bail!("{name} uses the token in ${var} (token = in your config): remove that line to sign in instead");
    }
    let http = agentos::oauth::http();
    let tell = |text: &str| println!("  {text}");
    println!("{} signing in to {name} ({url})", out.cyan("agent ▸"));
    let Some(auth) = agentos::oauth::discover(&http, url)? else {
        println!("{} {name} answers without a sign-in: agents can use it as it is", out.cyan("agent ▸"));
        return Ok(0);
    };
    tell(&format!("authorization server: {}", auth.issuer));
    agentos::oauth::sign_in(store.root(), &name, url, &auth, &tell)?;
    // Check it works, as the gateway will use it.
    let token = agentos::oauth::access_token(store.root(), &name, url, false)?.context("signed in, but no token was kept")?;
    let probe = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "agentos", "version": env!("CARGO_PKG_VERSION") } } });
    let resp = http
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Authorization", &format!("Bearer {token}"))
        .send(probe.to_string().as_bytes())?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        bail!("signed in, but {name} still refuses the token (HTTP {status})");
    }
    let body = resp.into_body().read_to_string().unwrap_or_default();
    let server_name = body.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l.strip_prefix("data:").unwrap_or(l).trim()).ok())
        .find_map(|m| m["result"]["serverInfo"]["name"].as_str().map(str::to_string));
    let which = server_name.map(|n| format!(" ({n})")).unwrap_or_default();
    println!("{} signed in to {name}{which}: agents reach it through agentos, and never hold the token", out.cyan("agent ▸"));
    Ok(0)
}

pub(crate) fn cmd_doctor(store: &Store) -> Result<i32> {
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
