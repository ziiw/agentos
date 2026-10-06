//! Human-readable output for the CLI.

use agentos::changes::{self, Change, Entry, Kind, Summary};
use agentos::gateway::{self, Budget, Totals, Usage};
use agentos::journal::Event;
use agentos::outbox::Push;
use agentos::profiles::AgentEvent;
use agentos::store::{Access, Net, Task};
use agentos::util::{self, display_path};
use serde_json::Value;
use similar::{ChangeTag, TextDiff};
use std::fmt::{Display, Write};
use std::fs;
use std::io::IsTerminal;
use std::path::Path;

const MAX_DIFF_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct Paint(bool);

impl Paint {
    pub fn stdout() -> Self {
        Paint(std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none())
    }
    /// No colors, e.g. for agentd's console.
    pub fn plain() -> Self {
        Paint(false)
    }
    pub fn stderr() -> Self {
        Paint(std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none())
    }
    fn wrap(self, code: &str, s: impl Display) -> String {
        if self.0 { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
    pub fn bold(self, s: impl Display) -> String {
        self.wrap("1", s)
    }
    pub fn dim(self, s: impl Display) -> String {
        self.wrap("2", s)
    }
    pub fn red(self, s: impl Display) -> String {
        self.wrap("31", s)
    }
    pub fn green(self, s: impl Display) -> String {
        self.wrap("32", s)
    }
    pub fn yellow(self, s: impl Display) -> String {
        self.wrap("33", s)
    }
    pub fn cyan(self, s: impl Display) -> String {
        self.wrap("36", s)
    }
}

pub fn command_line(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty() || a.chars().any(|c| c.is_whitespace() || "'\"$`\\;&|<>(){}*?!".contains(c)) {
                format!("'{}'", a.replace('\'', r"'\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn bytes(n: u64) -> String {
    match n {
        0..=999 => format!("{n} B"),
        1000..=999_999 => format!("{:.1} kB", n as f64 / 1e3),
        _ => format!("{:.1} MB", n as f64 / 1e6),
    }
}

/// A held git push, described for review.
pub struct HeldPush {
    pub push: Push,
    pub subject: String,
    /// Commits it adds over what you last fetched, when known.
    pub new_commits: Option<usize>,
}

/// How to name a task: its title, or the command it ran.
pub fn title(task: &Task) -> String {
    task.meta.title.clone().unwrap_or_else(|| command_line(&task.meta.command))
}

pub fn first_line(s: &str, max: usize) -> String {
    truncate(s.lines().find(|l| !l.trim().is_empty()).unwrap_or(""), max)
}

fn truncate(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max { flat } else { format!("{}…", flat.chars().take(max - 1).collect::<String>()) }
}

fn summary_short(p: Paint, s: &Summary) -> String {
    let git = if s.git > 0 { p.cyan(" git") } else { String::new() };
    if s.total() == 0 {
        return if s.git > 0 { p.cyan("git") } else { p.dim("none") };
    }
    format!("{} {} {}{git}", p.green(format!("+{}", s.added)), p.yellow(format!("~{}", s.modified)), p.red(format!("-{}", s.deleted)))
}

pub fn banner(p: Paint, task: &Task, outbox: bool, login_sealed: bool) -> String {
    let mut parts = vec![format!("task {}", p.bold(task.id()))];
    if let Some(t) = &task.meta.title {
        parts.push(p.bold(truncate(t, 60)));
    }
    for g in &task.meta.grants {
        let label = if g.access == Access::Rw { "rw" } else { "ro" };
        parts.push(format!("{} {}", p.dim(label), display_path(&g.path)));
    }
    let mut net = net_label(&task.meta.net, &task.meta.allow);
    if task.meta.ask {
        net = if task.meta.allow.is_empty() { "asks you first".into() } else { format!("{net}, asks about others") };
    }
    parts.push(format!("{} {net}", p.dim("net")));
    if !task.meta.secrets.is_empty() {
        parts.push(format!("{} {}", p.dim("brokered"), task.meta.secrets.join(",")));
    }
    if outbox {
        parts.push(format!("{} held", p.dim("git push")));
    }
    if login_sealed {
        parts.push(format!("{} sealed", p.dim("login")));
    }
    if let Some(b) = task.meta.budget {
        parts.push(format!("{} {b}", p.dim("budget")));
    }
    format!("{} {}", p.cyan("agent ▸"), parts.join("  "))
}

/// "none", "host", or the allowlist: "api.anthropic.com +3".
fn net_label(net: &Net, allow: &[String]) -> String {
    match (net, allow) {
        (Net::Proxy, []) => "proxy (nothing allowed)".into(),
        (Net::Proxy, [one]) => one.clone(),
        (Net::Proxy, [first, rest @ ..]) => format!("{first} +{}", rest.len()),
        (other, _) => other.to_string(),
    }
}

pub fn exit_summary(p: Paint, task: &Task, s: &Summary, pushes: &[Push], outcome: Option<&AgentEvent>, blocked: usize) -> String {
    let id = task.id();
    let took = util::duration(task.meta.ended_at_ms.unwrap_or(0).saturating_sub(task.meta.started_at_ms));
    let mut head = format!("{} task {} exited {} in {took}", p.cyan("agent ▸"), p.bold(id), task.meta.exit_code.unwrap_or(-1));
    // Measured by the gateway when it could; else what the agent says.
    if let Some(u) = task.meta.usage.as_ref().filter(|u| u.calls > 0) {
        let _ = write!(head, " · {}", u.describe());
    }
    if let Some(AgentEvent::Done { turns, cost_usd, .. }) = outcome {
        if let (Some(cost), None) = (cost_usd, task.meta.usage.as_ref().filter(|u| u.calls > 0)) {
            let _ = write!(head, " · ${cost:.2}");
        }
        if let Some(n) = turns {
            let _ = write!(head, " · {n} turn{}", if *n == 1 { "" } else { "s" });
        }
    }
    if blocked > 0 {
        let _ = write!(head, " · {}", p.yellow(format!("{blocked} connection{} blocked", if blocked == 1 { "" } else { "s" })));
    }
    let ignored = if s.ignored > 0 { p.dim(format!(" · {} ignored", s.ignored)) } else { String::new() };
    if s.total() == 0 && s.git == 0 && pushes.is_empty() {
        return format!("{head} · no changes{ignored}");
    }
    let n = s.total();
    let mut held = Vec::new();
    if n > 0 || s.git > 0 {
        held.push(format!("{} ({})", if n == 1 { "1 change".to_string() } else { format!("{n} changes") }, summary_short(p, s)));
    }
    if !pushes.is_empty() {
        let targets: Vec<String> = pushes.iter().map(|x| format!("{} {}", x.remote, x.short_ref())).collect();
        let what = if pushes.len() == 1 { "1 git push".to_string() } else { format!("{} git pushes", pushes.len()) };
        held.push(format!("{what} ({})", targets.join(", ")));
    }
    let mut out = format!("{head} · {} held for review{ignored}", held.join(" and "));
    let hints = [("diff", "review"), ("commit", "apply to your files"), ("rollback", "discard")];
    let width = hints.iter().map(|(cmd, _)| cmd.len()).max().unwrap_or(0);
    for (cmd, what) in hints {
        let _ = write!(out, "\n        {}  {what}", p.bold(format!("agent {cmd:<width$} {id}")));
    }
    out
}

pub fn task_table(p: Paint, tasks: &[Task]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", p.dim(format!("{:<10}{:<13}{:<10}{:<14}{:<9}{}", "ID", "STATUS", "STARTED", "CHANGES", "COST", "COMMAND")));
    // Pad on the visible width; color codes would throw off {:<n}.
    let pad = |s: String, visible: usize, width: usize| format!("{s}{}", " ".repeat(width.saturating_sub(visible)));
    for t in tasks.iter().rev() {
        let summary = if t.is_open() { changes::scan(&t.layers()).ok().map(|c| Summary::of(&c)) } else { None };
        let pushes = if t.is_open() { agentos::outbox::pending(&t.dir).map(|v| v.len()).unwrap_or(0) } else { 0 };
        let (mut changes, mut visible_changes) = match &summary {
            Some(s) => (summary_short(p, s), summary_short(Paint(false), s).chars().count()),
            None => (p.dim("-"), 1),
        };
        if pushes > 0 {
            let extra = format!(" ↑{pushes}");
            visible_changes += extra.chars().count();
            changes.push_str(&p.cyan(extra));
        }
        let status = t.status_label();
        let cost = t.meta.usage.as_ref().filter(|u| u.calls > 0).map(|u| gateway::usd(u.cost_usd)).unwrap_or_else(|| "-".into());
        let _ = writeln!(
            out,
            "{:<10}{}{:<10}{}{:<9}{}",
            t.id(),
            pad(status_color(p, &status), status.chars().count(), 13),
            util::ago(t.meta.started_at_ms),
            pad(changes, visible_changes, 14),
            cost,
            truncate(&title(t), 60)
        );
    }
    out
}

fn status_color(p: Paint, status: &str) -> String {
    match status {
        "running" => p.cyan(status),
        "committed" => p.green(status),
        "discarded" => p.dim(status),
        "crashed" | "failed" => p.red(status),
        _ => p.yellow(status),
    }
}

fn text(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > MAX_DIFF_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    if bytes.iter().take(8000).any(|&b| b == 0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Old and new text for a file change, or None if either side isn't text.
fn texts(c: &Change) -> Option<(String, String)> {
    if c.entry != Entry::File {
        return None;
    }
    let old = if c.kind == Kind::Added { String::new() } else { text(&c.path)? };
    let new = if c.kind == Kind::Deleted { String::new() } else { text(&c.upper)? };
    Some((old, new))
}

fn detail(p: Paint, c: &Change) -> String {
    match (c.kind, c.entry) {
        (Kind::Deleted, Entry::Dir) => p.dim(match changes::count_files(&c.path) {
            1 => "1 file".to_string(),
            n => format!("{n} files"),
        }),
        (_, Entry::Dir) => String::new(),
        (Kind::Deleted, _) => String::new(),
        (_, Entry::Symlink) => p.dim(format!("→ {}", fs::read_link(&c.upper).map(|t| t.display().to_string()).unwrap_or_default())),
        (_, Entry::Other) => p.dim("special file"),
        (_, Entry::File) => match texts(c) {
            Some((old, new)) => {
                let diff = TextDiff::from_lines(&old, &new);
                let (mut add, mut del) = (0, 0);
                for ch in diff.iter_all_changes() {
                    match ch.tag() {
                        ChangeTag::Insert => add += 1,
                        ChangeTag::Delete => del += 1,
                        ChangeTag::Equal => {}
                    }
                }
                format!("{} {}", p.green(format!("+{add}")), p.red(format!("-{del}")))
            }
            None => p.dim("binary or large"),
        },
    }
}

fn change_path(c: &Change) -> String {
    let mut s = display_path(&c.path);
    if c.entry == Entry::Dir {
        s.push('/');
    }
    s
}

fn kind_mark(p: Paint, k: Kind) -> String {
    match k {
        Kind::Added => p.green("A"),
        Kind::Modified => p.yellow("M"),
        Kind::Deleted => p.red("D"),
    }
}

/// "3 ignored changes: __pycache__/, build/" — just the outermost paths.
pub fn ignored_summary(changes: &[Change]) -> String {
    let ignored: Vec<&Change> = changes.iter().filter(|c| c.ignored).collect();
    let roots: Vec<String> = ignored
        .iter()
        .filter(|c| !ignored.iter().any(|o| o.path != c.path && c.path.starts_with(&o.path)))
        .map(|c| c.rel.display().to_string() + if c.entry == Entry::Dir { "/" } else { "" })
        .collect();
    let more = if roots.len() > 3 { format!(" +{} more", roots.len() - 3) } else { String::new() };
    let n = ignored.len();
    format!("{n} ignored change{}: {}{more}", if n == 1 { "" } else { "s" }, roots.iter().take(3).cloned().collect::<Vec<_>>().join(", "))
}

pub fn diff(p: Paint, task: &Task, changes: &[Change], pushes: &[HeldPush], stat_only: bool, show_ignored: bool) -> String {
    let mut out = String::new();
    let state = if task.is_live() { p.cyan("running") } else { p.dim(task.status_label()) };
    let _ = writeln!(
        out,
        "{} {} · {} · {}",
        p.bold("task"),
        p.bold(task.id()),
        truncate(&title(task), 60),
        state
    );
    // Git's bookkeeping under .git is summarized per repository; --all lists it.
    let shown: Vec<&Change> = changes.iter().filter(|c| show_ignored || (!c.ignored && !c.git)).collect();
    let git_files = if show_ignored { 0 } else { changes.iter().filter(|c| c.git && !c.ignored).count() };
    let hidden = changes.iter().filter(|c| c.ignored).count() - shown.iter().filter(|c| c.ignored).count();
    if shown.is_empty() && pushes.is_empty() && git_files == 0 {
        let _ = writeln!(out, "{}", p.dim("no pending changes"));
    } else if !shown.is_empty() {
        let width = shown.iter().map(|c| change_path(c).chars().count()).max().unwrap_or(0).min(70);
        out.push('\n');
        for c in &shown {
            let path = change_path(c);
            let pad = " ".repeat(width.saturating_sub(path.chars().count()));
            let note = if c.ignored { p.dim("  (ignored)") } else { String::new() };
            let _ = writeln!(out, "  {}  {path}{pad}  {}{note}", kind_mark(p, c.kind), detail(p, c));
        }
    }
    if git_files > 0 {
        if shown.is_empty() {
            out.push('\n');
        }
        for layer in task.layers() {
            let n = changes.iter().filter(|c| c.git && !c.ignored && c.layer == layer.index).count();
            if n == 0 {
                continue;
            }
            let did = changes::git_activity(&layer);
            let what = if did.is_empty() { "git internals changed".to_string() } else { did.join("; ") };
            let path = format!("{}/.git", display_path(&layer.source));
            let _ = writeln!(out, "  {}  {path}  {}  {}", p.cyan("G"), truncate(&what, 90), p.dim(format!("({n} files)")));
        }
    }
    if hidden > 0 {
        let _ = writeln!(out, "  {}", p.dim(format!("+ {}, not committed (--all to see and include them)", ignored_summary(changes))));
    }
    if !pushes.is_empty() {
        let _ = writeln!(out, "\n  {}", p.bold("held git pushes (sent by `agent commit` or `agent push`)"));
        for h in pushes {
            let count = match h.new_commits {
                Some(1) => " · 1 new commit".to_string(),
                Some(n) => format!(" · {n} new commits"),
                None => String::new(),
            };
            let _ = writeln!(
                out,
                "  {}  {} {}  {} {}{}",
                p.cyan("↑"),
                h.push.remote,
                p.bold(h.push.short_ref()),
                p.yellow(&h.push.sha[..h.push.sha.len().min(7)]),
                truncate(&h.subject, 60),
                p.dim(count)
            );
        }
    }
    if shown.iter().any(|c| c.path.file_name().is_some_and(|n| n == agentos::config::PROJECT_FILE)) {
        let _ = writeln!(
            out,
            "\n{} this task changes {} (what agents may access). Once committed, agentos ignores it until you run `agent trust` again.",
            p.yellow("!"),
            agentos::config::PROJECT_FILE
        );
    }
    if stat_only {
        return out;
    }
    for c in shown {
        let Some((old, new)) = texts(c) else { continue };
        let shown = display_path(&c.path);
        let (a, b) = match c.kind {
            Kind::Added => ("/dev/null".to_string(), format!("b/{shown}")),
            Kind::Deleted => (format!("a/{shown}"), "/dev/null".to_string()),
            Kind::Modified => (format!("a/{shown}"), format!("b/{shown}")),
        };
        out.push('\n');
        let unified = TextDiff::from_lines(&old, &new).unified_diff().context_radius(3).header(&a, &b).to_string();
        for line in unified.lines() {
            let painted = if line.starts_with("+++") || line.starts_with("---") {
                p.bold(line)
            } else if line.starts_with('+') {
                p.green(line)
            } else if line.starts_with('-') {
                p.red(line)
            } else if line.starts_with("@@") {
                p.cyan(line)
            } else {
                line.to_string()
            };
            let _ = writeln!(out, "{painted}");
        }
    }
    out
}

pub fn conflicts(p: Paint, task: &Task, conflicts: &[&Change]) -> String {
    let mut out = format!(
        "{} these files changed on your side while task {} was running:\n",
        p.red("conflict:"),
        task.id()
    );
    for c in conflicts {
        let _ = writeln!(out, "  {}  {}", kind_mark(p, c.kind), change_path(c));
    }
    let _ = writeln!(
        out,
        "nothing was committed. Review with `agent diff {}`, then commit other paths, or overwrite with --force.",
        task.id()
    );
    out
}

pub fn committed(p: Paint, task: &Task, applied: &[Change], remaining: usize) -> String {
    let mut out = String::new();
    for c in applied.iter().filter(|c| !c.git) {
        let _ = writeln!(out, "  {}  {}", kind_mark(p, c.kind), change_path(c));
    }
    let git = applied.iter().filter(|c| c.git).count();
    if git > 0 {
        let _ = writeln!(out, "  {}  .git  {}", p.cyan("G"), p.dim(format!("({git} files: the agent's git work)")));
    }
    let n = applied.len() - git;
    let what = match (n, git) {
        (0, _) => "the agent's git work".to_string(),
        (1, 0) => "1 change".to_string(),
        (n, 0) => format!("{n} changes"),
        (1, _) => "1 change and the agent's git work".to_string(),
        (n, _) => format!("{n} changes and the agent's git work"),
    };
    let _ = write!(out, "{} committed {what} from task {}", p.green("✓"), task.id());
    if remaining > 0 {
        let _ = write!(out, "; {remaining} still pending");
    }
    out.push('\n');
    out
}

pub fn log(p: Paint, task: &Task, events: &[Event]) -> String {
    let mut out = format!(
        "{} {} · {}\n",
        p.bold("task"),
        p.bold(task.id()),
        truncate(&title(task), 70)
    );
    for e in events {
        let _ = writeln!(out, "  {}  {:<15} {}", p.dim(util::rfc3339(e.ts_ms)), e.kind, describe(p, e));
    }
    out
}

fn describe(p: Paint, e: &Event) -> String {
    let d = &e.data;
    let s = |v: &Value| v.as_str().unwrap_or("").to_string();
    let list = |v: &Value| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_default();
    match e.kind.as_str() {
        "task.created" => {
            let mut parts: Vec<String> = d["grants"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|g| format!("{} {}", s(&g["access"]), display_path(Path::new(&s(&g["path"])))))
                .collect();
            match d["allow"].as_array() {
                Some(hosts) if !hosts.is_empty() => parts.push(format!("net only {}", list(&d["allow"]))),
                _ => parts.push(format!("net {}", s(&d["net"]))),
            }
            let secrets: Vec<String> = d["secrets"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|x| format!("{}→{}", s(&x["env"]), s(&x["host"])))
                .collect();
            if !secrets.is_empty() {
                parts.push(format!("brokered {}", secrets.join(",")));
            }
            parts.push(format!("env {}", list(&d["env"])));
            parts.join(" · ")
        }
        "net.connect" => {
            let target = format!("{}:{}", s(&d["host"]), d["port"]);
            if d["brokered"].as_bool() == Some(true) && d["reason"].is_string() {
                format!("{} {target} · {}", p.red("✗"), s(&d["reason"]))
            } else if d["brokered"].as_bool() == Some(true) {
                let n = d["requests"].as_u64().unwrap_or(0);
                let mut requests = format!("{n} request{}", if n == 1 { "" } else { "s" });
                // Relayed only to meter model calls: no credential to add.
                if let Some(injected) = d["injected"].as_u64().filter(|i| *i > 0) {
                    let _ = write!(requests, ", credential added to {injected}");
                }
                format!(
                    "{} {target} · {requests} · ↑{} ↓{} · {}",
                    p.green("✓"),
                    bytes(d["bytes_out"].as_u64().unwrap_or(0)),
                    bytes(d["bytes_in"].as_u64().unwrap_or(0)),
                    util::duration(d["ms"].as_u64().unwrap_or(0))
                )
            } else if d["allowed"].as_bool() == Some(true) {
                format!(
                    "{} {target} · ↑{} ↓{} · {}",
                    p.green("✓"),
                    bytes(d["bytes_out"].as_u64().unwrap_or(0)),
                    bytes(d["bytes_in"].as_u64().unwrap_or(0)),
                    util::duration(d["ms"].as_u64().unwrap_or(0))
                )
            } else if d["expected"].as_bool() == Some(true) {
                format!("{} {target} · closed on purpose", p.dim("✗ blocked"))
            } else {
                format!("{} {target} · {}", p.red("✗ blocked"), s(&d["reason"]))
            }
        }
        "sandbox.ready" => format!("landlock {} · seccomp {} · proc {}", s(&d["landlock"]), s(&d["seccomp"]), s(&d["proc"])),
        "agent.session" => format!("model {}", s(&d["model"])),
        "login.sealed" => format!("{} tokens moved to the vault", d["tokens"]),
        "task.limits" => {
            let l: agentos::limits::Limits = serde_json::from_value(d["limits"].clone()).unwrap_or_default();
            format!("{} ({})", l.describe(), s(&d["scope"]))
        }
        "task.oom" => p.red(format!("out of memory: the kernel killed {} process(es)", d["kills"])),
        "task.stopped" => match d["reason"].as_str() {
            Some("timeout") => p.yellow("timed out (--timeout)"),
            Some("budget") => p.yellow("stopped: kept calling the model over budget"),
            _ => p.yellow("stopped"),
        },
        "model.call" => {
            let u: Usage = serde_json::from_value(d["usage"].clone()).unwrap_or_default();
            let mut parts = vec![s(&d["model"])];
            let mut input = format!("{} in", gateway::tokens(u.input + u.cache_write + u.cache_write_1h));
            if u.cache_read > 0 {
                let _ = write!(input, " +{} cached", gateway::tokens(u.cache_read));
            }
            parts.push(input);
            parts.push(format!("{} out", gateway::tokens(u.output)));
            if d["fast"].as_bool() == Some(true) {
                parts.push("fast".into());
            }
            let cost = gateway::usd(d["cost_usd"].as_f64().unwrap_or(0.0));
            parts.push(if d["assumed_price"].as_bool() == Some(true) { format!("≤ {cost} (unknown price)") } else { cost });
            parts.push(format!("total {}", gateway::usd(d["total"]["cost_usd"].as_f64().unwrap_or(0.0))));
            if d["partial"].as_bool() == Some(true) {
                parts.push(p.yellow("cut short"));
            }
            parts.join(" · ")
        }
        "model.usage" => {
            let t: Totals = serde_json::from_value(d["totals"].clone()).unwrap_or_default();
            let mut parts = vec![format!("{} model call{}", t.calls, if t.calls == 1 { "" } else { "s" }), t.describe()];
            if let Ok(b) = serde_json::from_value::<Budget>(d["budget"].clone()) {
                parts.push(format!("budget {b}"));
            }
            if t.refused > 0 {
                parts.push(p.yellow(format!("{} refused", t.refused)));
            }
            if t.unmetered > 0 {
                parts.push(p.yellow(format!("{} not measured", t.unmetered)));
            }
            parts.join(" · ")
        }
        "model.unmetered" => p.yellow(format!("{}: {}", s(&d["host"]), s(&d["why"]))),
        "model.refused" => p.yellow("over budget: refused, not sent"),
        "budget.nearly" | "budget.exhausted" => {
            let t: Totals = serde_json::from_value(d["totals"].clone()).unwrap_or_default();
            let what = if e.kind == "budget.nearly" { p.yellow("80% used") } else { p.red("used up: model calls refused from now on") };
            format!("{what} · {}", t.describe())
        }
        "outbox.ready" => {
            let remotes: Vec<String> = d["remotes"].as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
            format!("git pushes to {} are held", remotes.join(", "))
        }
        "outbox.held" | "outbox.pushed" | "outbox.failed" => {
            let items: Vec<&Value> = match d["pushes"].as_array() {
                Some(a) => a.iter().collect(),
                None => vec![d],
            };
            let list: Vec<String> = items
                .iter()
                .map(|x| {
                    let sha = s(&x["sha"]);
                    let r = s(&x["ref"]);
                    format!("{} {} {}", s(&x["remote"]), r.strip_prefix("refs/heads/").unwrap_or(&r), &sha[..sha.len().min(7)])
                })
                .collect();
            match e.kind.as_str() {
                "outbox.held" => format!("{} {}", p.cyan("↑ held"), list.join(", ")),
                "outbox.pushed" => format!("{} {}", p.green("↑ pushed"), list.join(", ")),
                _ => format!("{} {} · {}", p.red("✗ push failed"), list.join(", "), truncate(&s(&d["error"]), 80)),
            }
        }
        "net.approval" => {
            let target = format!("{}:{}", s(&d["host"]), d["port"]);
            match d["decision"].as_str().unwrap_or_default() {
                "once" => format!("{} {target} · you allowed it for this task", p.green("?")),
                "always" => format!("{} {target} · you allowed it, always, for this project", p.green("?")),
                "timeout" => format!("{} {target} · no answer, denied", p.yellow("?")),
                _ => format!("{} {target} · you denied it", p.yellow("?")),
            }
        }
        "agent.tool" => format!("{} {}", s(&d["name"]), truncate(&s(&d["target"]), 80)),
        "agent.request" => {
            let what = match d["kind"].as_str() {
                Some("read") => format!("read {}", s(&d["target"])),
                Some("write") => format!("change {}", s(&d["target"])),
                _ => format!("reach {}", s(&d["target"])),
            };
            let answer = match d["decision"].as_str().unwrap_or_default() {
                "once" => p.green("you allowed it"),
                "always" => p.green("you allowed it, always, for this project"),
                "timeout" => p.yellow("no answer, not granted"),
                "impossible" => p.yellow(format!("not possible: {}", truncate(&s(&d["why"]), 80))),
                _ => p.yellow("you denied it"),
            };
            format!("{} asked to {what} · \u{201c}{}\u{201d} · {answer}", p.cyan("?"), truncate(&s(&d["reason"]), 80))
        }
        "grant.added" => {
            let access = if d["access"].as_str() == Some("rw") { "read-write" } else { "read-only" };
            format!("{} {} {access}, while the task ran", p.green("+"), display_path(Path::new(&s(&d["path"]))))
        }
        "grant.failed" => p.red(format!("couldn't add {}: {}", display_path(Path::new(&s(&d["path"]))), truncate(&s(&d["error"]), 80))),
        "agent.result" => {
            let mut parts = vec![if d["is_error"].as_bool() == Some(true) { p.red("error") } else { "ok".into() }];
            if let Some(n) = d["turns"].as_u64() {
                parts.push(format!("{n} turn{}", if n == 1 { "" } else { "s" }));
            }
            if let Some(c) = d["cost_usd"].as_f64() {
                parts.push(format!("${c:.4}"));
            }
            parts.join(" · ")
        }
        "sandbox.failed" => p.red(s(&d["error"])),
        "task.exited" => format!(
            "exit {} · {} · +{} ~{} -{}",
            d["exit_code"],
            util::duration(d["duration_ms"].as_u64().unwrap_or(0)),
            d["changes"]["added"],
            d["changes"]["modified"],
            d["changes"]["deleted"]
        ),
        "commit" => {
            let all = d["changes"].as_array().cloned().unwrap_or_default();
            let in_git = |c: &Value| s(&c["path"]).contains("/.git/");
            let git = all.iter().filter(|c| in_git(c)).count();
            let changes: Vec<Value> = all.into_iter().filter(|c| !in_git(c)).collect();
            let first: Vec<String> = changes.iter().take(3).map(|c| display_path(Path::new(&s(&c["path"])))).collect();
            let mut more = if changes.len() > 3 { format!(" +{} more", changes.len() - 3) } else { String::new() };
            if git > 0 {
                more.push_str(&format!(" + .git ({git} files)"));
            }
            let forced = if d["forced"].as_bool() == Some(true) { " (forced)" } else { "" };
            let n = if changes.len() == 1 { "1 change".to_string() } else { format!("{} changes", changes.len()) };
            format!("{n}: {}{more}{forced}", first.join(", "))
        }
        "rollback" if d["all"].as_bool() == Some(true) => format!(
            "all pending (+{} ~{} -{})",
            d["changes"]["added"], d["changes"]["modified"], d["changes"]["deleted"]
        ),
        "rollback" => d["paths"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| display_path(Path::new(&s(v))))
            .collect::<Vec<_>>()
            .join(", "),
        _ => truncate(&d.to_string(), 100),
    }
}
