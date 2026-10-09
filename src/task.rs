//! Running a task: the sandbox, its proxy, gateway and journal, from start to the exit summary.

use crate::*;

pub(crate) fn execute(store: &Store, plan: Plan) -> Result<i32> {
    let home = home_dir()?;
    let cwd = std::env::current_dir()?;
    if plan.net == Net::Host && !plan.local.is_empty() {
        bail!("--local is for sandboxes with a network of their own; --net host already shares yours");
    }

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
    // Your corporate proxy, if you have one: allowed connections go through it.
    let upstream = if plan.net == Net::Proxy { upstream_proxy(plan.proxy.as_deref(), &plan.no_proxy)?.map(Arc::new) } else { None };
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
            let project = if over.budget.project.is_some() { " --project" } else { "" };
            bail!(
                "{over}.\n  To raise it until then: agent raise {} {}{project}\n  (Budgets across tasks are under [limits] in your config, or a project's.)",
                over.standing.offers()[0].spec(),
                over.budget.period.flag(),
            );
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
    if let Some(u) = &upstream {
        eprintln!("  {}", err.dim(format!("through your proxy {}", u.describe())));
        journal.append("net.upstream", json!({ "proxy": u.describe() }))?;
    }
    if !plan.local.is_empty() {
        let ports: Vec<String> = plan.local.iter().map(|p| format!("127.0.0.1:{p}")).collect();
        eprintln!("  {}", err.dim(format!("your machine's {} (--local)", ports.join(", "))));
        journal.append("task.local", json!({ "ports": plan.local }))?;
    }
    if !periodic.is_empty() && task.meta.net == Net::Proxy {
        eprintln!("  {}", err.dim(format!("spend: {}", ledger.status(&periodic, util::now_ms()).join(" · "))));
    }
    // What the task has read that it shouldn't trust. Its own model APIs and
    // the hosts of credentials you gave it don't count.
    let taint = {
        let mut trusted = plan.taint_trusted.clone();
        trusted.extend(endpoints.iter().map(|e| e.host.clone()));
        trusted.extend(plan.secrets.iter().map(|s| s.host.clone()));
        trusted.extend(plan.login.iter().flat_map(|l| l.hosts.iter().cloned()));
        Arc::new(taint::Taint::new(Some(journal.clone()), trusted))
    };
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
        Arc::new(policy::Policy::new(set, plan.agent.as_deref().unwrap_or("command"), task.id(), &project).with_taint(taint.clone()))
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
    // Servers on your loopback this task was given (a local model server):
    // a socket each, relayed to the real port once the sandbox is up.
    let mut local_listeners = Vec::new();
    for &port in &plan.local {
        let path = task.dir.join(format!("local-{port}.sock"));
        local_listeners.push((port, proxy::bind(&path)?, path.clone()));
        run_mounts.push(RunMount { src: path, name: format!("local-{port}.sock"), writable: true });
    }
    let mut local_handles = Vec::new();
    let blocked = Arc::new(AtomicUsize::new(0));
    let expected_denials = plan.expected_denials;
    let ask = plan.ask;
    // The CA's private key never leaves this process; only its certificate
    // is written out for the sandbox to trust.
    let login = plan.login;
    // Whether you're asked to raise a budget that runs out (set once the
    // sandbox is up and it's known whether anyone can be asked).
    let asking = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let meter = brokering.then(|| {
        let spend = Spend { ledger: ledger.clone(), task: task.id().to_string(), project: project.clone(), budgets: periodic.clone() };
        Arc::new(Meter::new(endpoints, plan.prices, budget, meter_observer(journal.clone(), err, asking.clone())).with_spend(spend))
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
        locals: plan.local.clone(),
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
        if let (Some(a), Some(m)) = (&asker, &meter) {
            m.set_raiser(raiser(a.clone(), journal.clone(), err));
            asking.store(true, Ordering::SeqCst);
        }
        if let Some(listener) = proxy_listener.take() {
            let gate = gate(asker.clone(), rules.clone(), taint.clone(), given.clone(), journal.clone(), expected_denials.clone(), err);
            let sink = net_sink(journal.clone(), blocked.clone(), expected_denials.clone(), err);
            proxy_handle = Some(proxy::serve(listener, live_allow.clone(), broker, Some(gate), upstream.clone(), sink));
        }
        for (port, listener, _) in local_listeners.drain(..) {
            local_handles.push(proxy::serve_local(listener, port, local_sink(journal.clone(), err)));
        }
        if let Some(listener) = owner_listener.take() {
            let owner = Owner {
                given: given.clone(),
                allow: (task.meta.net == Net::Proxy).then(|| live_allow.clone()),
                asker: asker.clone(),
                attacher: attacher.clone(),
                proxy: proxy_handle.clone(),
                meter: meter.clone(),
                task: task.id().to_string(),
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
            store.root(),
            taint.clone(),
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
                taint: taint.clone(),
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
    for handle in &local_handles {
        handle.drain(Duration::from_secs(2));
    }
    for &port in &plan.local {
        let _ = fs::remove_file(task.dir.join(format!("local-{port}.sock")));
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
    let calls = agentos::held::pending(&task.dir)?;
    if !calls.is_empty() {
        let held: Vec<_> = calls.iter().map(|c| json!({ "call": c.target(), "seq": c.seq })).collect();
        journal.append("outbox.held_calls", json!({ "calls": held }))?;
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
        // Raised while it ran: the budget it ended with.
        task.meta.budget = m.budget();
        if totals.calls + totals.unmetered + totals.refused > 0 {
            journal.append("model.usage", json!({ "totals": totals, "budget": task.meta.budget }))?;
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
    eprintln!("{}", render::exit_summary(err, &task, &summary, &pushes, outcome.as_ref(), blocked.load(Ordering::SeqCst), taint.describe().as_deref(), &calls));
    Ok(exit_code)
}

/// Asks at the terminal about hosts outside the allowlist, if there's a
/// terminal to ask at.
/// Decides each connection through the proxy: your rules first (a forbid
/// refuses even a listed host), then the allowlist, then you.
pub(crate) fn gate(asker: Option<Arc<Asker>>, rules: Option<Arc<policy::Policy>>, taint: Arc<taint::Taint>, given: GivenList, journal: Journal, expected: Vec<(String, String)>, err: Paint) -> proxy::Gate {
    Arc::new(move |host: &str, port: u16, listed: bool| {
        let verdict = (|| -> std::result::Result<bool, String> {
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
        })();
        // Whatever it fetches from there is input the agent shouldn't trust.
        if verdict.is_ok() {
            taint.web(host);
        }
        verdict
    })
}

/// The gateway to your MCP servers for this task: asks you as the proxy
/// does, and tells you what it couldn't start.
pub(crate) fn gateway_for(
    servers: Vec<agentos::mcp::Server>,
    cwd: &Path,
    task_dir: &Path,
    asker: Option<Arc<Asker>>,
    rules: Option<Arc<policy::Policy>>,
    remembered: Vec<String>,
    journal: Journal,
    store_root: &Path,
    taint: Arc<taint::Taint>,
    err: Paint,
) -> agentos::mcp::Gateway {
    let ask: Box<dyn Fn(&Request) -> Option<approvals::Decision> + Send + Sync> =
        Box::new(move |req: &Request| asker.as_ref().map(|a| a.ask(req, |s| err.cyan(s)).0));
    let tell: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |text| say(format!("{} {text}", err.yellow("agent: warning:"))));
    agentos::mcp::Gateway::new(servers, cwd.to_path_buf(), task_dir.to_path_buf(), ask, rules, remembered, journal, tell, store_root.to_path_buf(), taint)
}

/// Prints a line to stderr in one write, so it can't interleave with output
/// the agent writes to the same terminal at the same moment (eprintln! may
/// write a formatted line in pieces).
pub(crate) fn say(line: String) {
    use std::io::Write;
    let _ = std::io::stderr().write_all(format!("{line}\n").as_bytes());
}

/// Records each connection through the egress proxy and says so, live,
/// when one is refused.
pub(crate) fn net_sink(journal: Journal, blocked: Arc<AtomicUsize>, expected: Vec<(String, String)>, err: Paint) -> proxy::Sink {
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

/// Records each connection to a server on your loopback, and says so once
/// per port when nothing is listening there.
pub(crate) fn local_sink(journal: Journal, err: Paint) -> proxy::LocalSink {
    let warned = Mutex::new(HashSet::new());
    Arc::new(move |event: proxy::LocalEvent| {
        let _ = journal.append("net.local", json!(event));
        if let Some(reason) = &event.reason {
            if warned.lock().is_ok_and(|mut seen| seen.insert(event.port)) {
                say(format!("{} {reason}", err.yellow("agent: warning:")));
            }
        }
    })
}

/// Journals every model call the gateway meters, and says so, live, when
/// the budget is nearly or entirely used up.
pub(crate) fn meter_observer(journal: Journal, err: Paint, asking: Arc<std::sync::atomic::AtomicBool>) -> gateway::Observer {
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
        gateway::Event::Nearly(totals, budget) => {
            let _ = journal.append("budget.nearly", json!({ "totals": totals, "budget": budget }));
            say(format!("{} 80% of the budget used ({}): model calls go one at a time from now on", err.cyan("agent ▸"), totals.against(budget)));
        }
        gateway::Event::Exhausted(totals, budget) => {
            let asks = asking.load(Ordering::SeqCst);
            let _ = journal.append("budget.exhausted", json!({ "totals": totals, "budget": budget, "asks": asks }));
            say(format!("{} budget used up ({}): {}", err.yellow("agent ▸"), totals.against(budget), after_exhausted(asks)));
        }
        gateway::Event::Over(text) => {
            let asks = asking.load(Ordering::SeqCst);
            let _ = journal.append("budget.exhausted", json!({ "reason": text, "asks": asks }));
            say(format!("{} {text}: {}", err.yellow("agent ▸"), after_exhausted(asks)));
        }
        gateway::Event::Unmeterable { host, path, why, refused } => {
            let _ = journal.append("model.unmeterable", json!({ "host": host, "path": path, "why": why, "refused": refused }));
            if refused {
                say(format!("{} refused {host}{path}: {why}, so it can't count against the budget", err.yellow("agent ▸")));
            } else if warned.lock().is_ok_and(|mut seen| seen.insert(format!("{host} {why}"))) {
                say(format!("{} {why}: calls to {host}{path} aren't counted", err.yellow("agent: warning:")));
            }
        }
        gateway::Event::Refused(totals) => {
            let _ = journal.append("model.refused", json!({ "refused": totals.refused }));
            if totals.refused >= REFUSALS_BEFORE_STOP {
                sandbox::stop(sandbox::Stop::Budget);
            }
        }
    })
}

pub(crate) fn after_exhausted(asks: bool) -> &'static str {
    if asks { "you're asked before the next model call goes" } else { "model calls are refused from now on" }
}

/// When a budget runs out mid-task, the next model call waits while you're
/// asked (at the terminal or in agentd) whether to raise it, rather than
/// failing. A "no" stands for the rest of the task, unless the budget is
/// raised another way (`agent raise`).
pub(crate) fn raiser(asker: Arc<Asker>, journal: Journal, err: Paint) -> gateway::Raiser {
    let declined: Mutex<HashSet<String>> = Mutex::default();
    Box::new(move |m: &Meter| {
        // An amount that's still too low is asked about again, a few times.
        for _ in 0..3 {
            let Some(short) = m.shortfall() else { return true };
            let key = short.key();
            if declined.lock().is_ok_and(|d| d.contains(&key)) {
                return false;
            }
            let req = Request { kind: Kind::Budget, target: short.what(), reason: Some(short.spent()), taint: None };
            let settled = || m.shortfall().is_none_or(|s| s.key() != key);
            match asker.ask_raise(&req, short.cap(), &short.offers(), settled, |s| err.cyan(s)) {
                approvals::Raised::Settled => {}
                approvals::Raised::To(to, via) => match m.raise_short(&short, to, via) {
                    Ok(from) => {
                        let _ = journal.append(
                            "budget.raised",
                            json!({ "scope": short.scope(), "what": short.what(), "from": from, "to": to, "by": via, "asked": true }),
                        );
                        say(format!("{} {} raised to {to}: the agent goes on", err.cyan("agent ▸"), short.what()));
                    }
                    Err(e) => say(format!("{} couldn't raise {} to {to}: {e}", err.yellow("agent: warning:"), short.what())),
                },
                approvals::Raised::No(why) => {
                    let _ = journal.append("budget.declined", json!({ "scope": short.scope(), "what": short.what(), "cap": short.cap(), "why": why }));
                    if why == "denied" {
                        if let Ok(mut d) = declined.lock() {
                            d.insert(key);
                        }
                    }
                    return false;
                }
            }
        }
        m.shortfall().is_none()
    })
}

/// Shows an agent's structured output as it works and records the
/// interesting parts (tool calls, result, cost) in the journal. Returns the
/// final result, if the agent reported one.
pub(crate) fn follow_agent(rx: OwnedFd, journal: &Journal, cwd: &Path) -> Option<AgentEvent> {
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

pub(crate) fn build_env(extra: &[String], home: &Path) -> Result<Vec<(String, String)>> {
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
pub(crate) fn launch_background(store: &Store) -> Result<i32> {
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
