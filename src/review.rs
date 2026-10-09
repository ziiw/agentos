//! After a task: looking at it, committing, pushing, rolling back.

use crate::*;

pub(crate) fn cmd_logs(store: &Store, selector: Option<&str>, follow: bool) -> Result<i32> {
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

pub(crate) fn cmd_wait(store: &Store, selector: Option<&str>) -> Result<i32> {
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

pub(crate) fn cmd_stop(store: &Store, selector: Option<&str>) -> Result<i32> {
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

pub(crate) fn cmd_ls(store: &Store) -> Result<i32> {
    let tasks = store.list()?;
    if tasks.is_empty() {
        println!("no tasks yet; start one with `agent do` or `agent run`");
    } else {
        print!("{}", render::task_table(Paint::stdout(), &tasks));
    }
    Ok(0)
}

pub(crate) fn absolutize_all(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    paths.iter().map(|p| util::absolutize(p).map_err(Into::into)).collect()
}

/// A task whose changes can still be committed or rolled back.
pub(crate) fn open_task(store: &Store, selector: Option<&str>) -> Result<Task> {
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

pub(crate) fn cmd_diff(store: &Store, selector: Option<&str>, paths: &[PathBuf], stat: bool, all: bool) -> Result<i32> {
    let task = store.resolve(selector)?;
    let changes = changes::select(changes::scan(&task.layers())?, &absolutize_all(paths)?);
    let pushes = if paths.is_empty() { held_pushes(&task)? } else { Vec::new() };
    let calls = if paths.is_empty() { agentos::held::pending(&task.dir)? } else { Vec::new() };
    print!("{}", render::diff(Paint::stdout(), &task, &changes, &pushes, &calls, stat, all));
    Ok(0)
}

/// Held pushes with their commit subject and how many commits they add.
pub(crate) fn held_pushes(task: &Task) -> Result<Vec<render::HeldPush>> {
    Ok(outbox::pending(&task.dir)?
        .into_iter()
        .map(|p| {
            let (subject, new_commits) = outbox::describe(&task.dir, &p);
            render::HeldPush { push: p, subject, new_commits }
        })
        .collect())
}

pub(crate) fn cmd_commit(store: &Store, selector: Option<&str>, paths: &[PathBuf], force: bool, all: bool, no_push: bool) -> Result<i32> {
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
    let calls = if paths.is_empty() && !no_push { agentos::held::pending(&task.dir)? } else { Vec::new() };
    if selected.is_empty() && pushes.is_empty() && calls.is_empty() {
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
    let mut failed = send_pushes(&task, &pushes, false)?;
    failed += send_calls(store, &task, &calls, failed > 0)?;
    finish_if_done(&mut task)?;
    Ok(if failed > 0 { 1 } else { 0 })
}

pub(crate) fn cmd_push(store: &Store, selector: Option<&str>, force: bool) -> Result<i32> {
    let mut task = open_task(store, selector)?;
    let pushes = outbox::pending(&task.dir)?;
    let calls = agentos::held::pending(&task.dir)?;
    if pushes.is_empty() && calls.is_empty() {
        println!("nothing to push");
        return Ok(0);
    }
    let mut failed = send_pushes(&task, &pushes, force)?;
    failed += send_calls(store, &task, &calls, failed > 0)?;
    finish_if_done(&mut task)?;
    Ok(if failed > 0 { 1 } else { 0 })
}

/// Replays held pushes from outside the sandbox. Returns how many failed
/// (those stay held).
pub(crate) fn send_pushes(task: &Task, pushes: &[outbox::Push], force: bool) -> Result<usize> {
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

/// Runs held tool calls from outside the sandbox, in order, with your
/// credentials. A call that fails stays held. `wait`: a push failed, so the
/// calls (which may depend on it) wait too. Returns how many didn't run.
pub(crate) fn send_calls(store: &Store, task: &Task, calls: &[agentos::held::Held], wait: bool) -> Result<usize> {
    if calls.is_empty() {
        return Ok(0);
    }
    let (out, err) = (Paint::stdout(), Paint::stderr());
    if wait {
        eprintln!("{} {} waiting for the failed push: `agent push {}` once it's sorted out", err.yellow("agent:"), plural(calls.len(), &format!("held {}", agentos::held::noun(calls))), task.id());
        return Ok(calls.len());
    }
    let journal = task.journal();
    let (cwd, home) = (task.meta.cwd.clone(), home_dir()?);
    let settings = config::load(store.root(), &cwd, &home)?;
    let (servers, commands) = (settings.mcp, settings.secret_commands);
    let tell: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |text| eprintln!("{} {text}", Paint::stderr().yellow("agent: warning:")));
    let taint = Arc::new(taint::Taint::new(None, Vec::new()));
    let gateway = agentos::mcp::Gateway::new(servers, cwd, task.dir.clone(), Box::new(|_| None), None, Vec::new(), journal.clone(), tell, store.root().to_path_buf(), taint);
    let mut failed = 0;
    for c in calls {
        let what = json!({ "server": c.server, "tool": c.tool, "arguments": approvals::sanitize(&c.args.to_string(), 1000), "seq": c.seq });
        // An API request, not a tool call: sent from here, with its credential put back.
        if c.http.is_some() {
            match agentos::held::send_http(c, &|env| secret_value(env, &commands)) {
                Ok((status, first)) if (200..300).contains(&status) => {
                    agentos::held::remove(&task.dir, c.seq);
                    let mut what = what;
                    what["result"] = json!(status);
                    journal.append("outbox.called", what)?;
                    println!("  {} sent {} \u{2192} {status} {}", out.green("\u{2191}"), c.target(), out.dim(render::first_line(&first, 60)));
                }
                other => {
                    failed += 1;
                    let why = match other {
                        Ok((status, first)) => format!("the server answered {status}: {}", render::first_line(&first, 120)),
                        Err(e) => e,
                    };
                    let mut what = what;
                    what["error"] = json!(approvals::sanitize(&why, 500));
                    journal.append("outbox.call_failed", what)?;
                    eprintln!("  {} {}: {}", err.red("\u{2717} request"), c.target(), render::first_line(&why, 200));
                }
            }
            continue;
        }
        match gateway.release(&c.server, &c.tool, &c.args) {
            Ok(r) if !r.is_error => {
                agentos::held::remove(&task.dir, c.seq);
                let mut what = what;
                what["result"] = json!(approvals::sanitize(&r.text, 500));
                journal.append("outbox.called", what)?;
                println!("  {} ran {}: {}", out.green("\u{23f5}"), c.target(), render::first_line(&r.text, 80));
            }
            other => {
                failed += 1;
                let why = match other {
                    Ok(r) => r.text,
                    Err(e) => format!("{e:#}"),
                };
                let mut what = what;
                what["error"] = json!(approvals::sanitize(&why, 500));
                journal.append("outbox.call_failed", what)?;
                eprintln!("  {} {}: {}", err.red("\u{2717} tool call"), c.target(), render::first_line(&why, 200));
            }
        }
    }
    gateway.stop_all();
    if failed > 0 {
        eprintln!("{} {} still held. Once you've sorted it out: `agent push {}`", err.yellow("agent:"), plural(failed, agentos::held::noun(calls)), task.id());
    }
    Ok(failed)
}

/// Closes the task once nothing is left: no file changes (ignored ones are
/// dropped) and no held pushes.
pub(crate) fn finish_if_done(task: &mut Task) -> Result<()> {
    let files = changes::scan(&task.layers())?;
    if files.iter().any(|c| !c.ignored) || !outbox::pending(&task.dir)?.is_empty() || !agentos::held::pending(&task.dir)?.is_empty() {
        return Ok(());
    }
    if !files.is_empty() {
        println!("{}", Paint::stdout().dim(format!("left out {}", render::ignored_summary(&files))));
    }
    let applied = task.journal().read()?.iter().any(|e| e.kind == "commit" || e.kind == "outbox.pushed" || e.kind == "outbox.called");
    task.meta.status = if applied { Status::Committed } else { Status::Discarded };
    task.save()?;
    task.release_storage()
}

pub(crate) fn cmd_rollback(store: &Store, selector: Option<&str>, paths: &[PathBuf]) -> Result<i32> {
    let mut task = open_task(store, selector)?;
    let layers = task.layers();
    let pending = changes::scan(&layers)?;
    let journal = task.journal();
    let counted = |changes: &[changes::Change]| changes.iter().filter(|c| !c.ignored).count();
    if paths.is_empty() {
        let pushes = outbox::pending(&task.dir)?;
        let held: Vec<_> = pushes.iter().map(|p| json!({ "remote": p.remote, "ref": p.refname, "sha": p.sha })).collect();
        let calls = agentos::held::pending(&task.dir)?;
        let dropped: Vec<_> = calls.iter().map(|c| json!({ "call": c.target(), "arguments": approvals::sanitize(&c.args.to_string(), 300) })).collect();
        journal.append("rollback", json!({ "all": true, "changes": Summary::of(&pending), "pushes": held, "calls": dropped }))?;
        for c in &calls {
            agentos::held::remove(&task.dir, c.seq);
        }
        let committed_before = journal.read()?.iter().any(|e| e.kind == "commit" || e.kind == "outbox.pushed" || e.kind == "outbox.called");
        let mut what = plural(counted(&pending), "change");
        if !pushes.is_empty() {
            what = format!("{what} and {}", plural(pushes.len(), "held push"));
        }
        if !calls.is_empty() {
            what = format!("{what} and {}", plural(calls.len(), &format!("held {}", agentos::held::noun(&calls))));
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

pub(crate) fn cmd_log(store: &Store, selector: Option<&str>, raw: bool) -> Result<i32> {
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
