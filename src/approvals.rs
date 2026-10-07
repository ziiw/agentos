//! Live approvals: when an agent reaches for a host that isn't allowed, ask
//! the human at the terminal instead of failing, while the connection waits.
//! Agents can also ask on purpose, with a reason, for a host or for access
//! to a folder (see `control.rs`).
//!
//! "Always" answers are remembered per project in the task store, which no
//! sandbox can see, and applied to later tasks like an allowlist from your
//! own config.

use crate::gateway::Budget;
use crate::util::display_path;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// For the rest of the task.
    Once,
    /// This one tool call only (asked again next time).
    Call,
    Always,
    /// Don't run this tool call now: hold it for review with the task's
    /// other changes (tool calls only).
    Hold,
    Deny,
    /// Nobody answered in time.
    Timeout,
}

impl Decision {
    pub fn allows(self) -> bool {
        matches!(self, Decision::Once | Decision::Call | Decision::Always)
    }

    pub fn label(self) -> &'static str {
        match self {
            Decision::Once => "once",
            Decision::Call => "call",
            Decision::Always => "always",
            Decision::Hold => "hold",
            Decision::Deny => "deny",
            Decision::Timeout => "timeout",
        }
    }
}

/// The directory approvals are remembered for: the nearest parent with a
/// `.git` or `.agentos.toml` (below `$HOME`), else `cwd` itself.
pub fn project_root(cwd: &Path, home: &Path) -> PathBuf {
    cwd.ancestors()
        .take_while(|d| *d != home && *d != Path::new("/"))
        .find(|d| d.join(".git").exists() || d.join(crate::config::PROJECT_FILE).is_file())
        .unwrap_or(cwd)
        .to_path_buf()
}

fn db_path(store_root: &Path) -> PathBuf {
    store_root.join("approvals.json")
}

fn load_db(store_root: &Path) -> Result<BTreeMap<String, Vec<String>>> {
    match fs::read(db_path(store_root)) {
        Ok(raw) => serde_json::from_slice(&raw).context("approvals.json is corrupt"),
        Err(_) => Ok(BTreeMap::new()),
    }
}

fn save_db(store_root: &Path, db: &BTreeMap<String, Vec<String>>) -> Result<()> {
    let tmp = db_path(store_root).with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(db)?)?;
    fs::rename(&tmp, db_path(store_root))?;
    Ok(())
}

/// Remembered tools are stored as `tool:SERVER.TOOL`, next to hosts.
const TOOL_PREFIX: &str = "tool:";

/// Hosts approved "always" for `project`, as allowlist entries.
pub fn remembered(store_root: &Path, project: &Path) -> Result<Vec<String>> {
    let all = load_db(store_root)?.remove(&project.display().to_string()).unwrap_or_default();
    Ok(all.into_iter().filter(|e| !e.starts_with(TOOL_PREFIX)).collect())
}

/// MCP tools (`server.tool`) approved "always" for `project`.
pub fn remembered_tools(store_root: &Path, project: &Path) -> Result<Vec<String>> {
    let all = load_db(store_root)?.remove(&project.display().to_string()).unwrap_or_default();
    Ok(all.iter().filter_map(|e| e.strip_prefix(TOOL_PREFIX)).map(str::to_string).collect())
}

pub fn remember(store_root: &Path, project: &Path, entry: &str) -> Result<()> {
    let mut db = load_db(store_root)?;
    let hosts = db.entry(project.display().to_string()).or_default();
    if !hosts.iter().any(|h| h == entry) {
        hosts.push(entry.to_string());
    }
    save_db(store_root, &db)
}

/// All remembered approvals: project → hosts.
pub fn all(store_root: &Path) -> Result<BTreeMap<String, Vec<String>>> {
    load_db(store_root)
}

/// Forgets `entry` for `project`. Returns whether it was there.
pub fn revoke(store_root: &Path, project: &Path, entry: &str) -> Result<bool> {
    let mut db = load_db(store_root)?;
    let key = project.display().to_string();
    let Some(hosts) = db.get_mut(&key) else { return Ok(false) };
    let before = hosts.len();
    hosts.retain(|h| h != entry);
    let removed = hosts.len() != before;
    if hosts.is_empty() {
        db.remove(&key);
    }
    save_db(store_root, &db)?;
    Ok(removed)
}

/// Allowlist entry for a host and port: `host`, or `host:port` off 443.
pub fn entry(host: &str, port: u16) -> String {
    if port == 443 { host.to_string() } else { format!("{host}:{port}") }
}

/// Whether `agent serve` (agentd) is running, and where.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Agentd {
    pub pid: u32,
    pub listen: String,
    pub token: String,
}

pub fn agentd_path(store_root: &Path) -> PathBuf {
    store_root.join("agentd.json")
}

/// The running agentd, if any.
pub fn agentd(store_root: &Path) -> Option<Agentd> {
    let d: Agentd = serde_json::from_slice(&fs::read(agentd_path(store_root)).ok()?).ok()?;
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(d.pid as i32), None).ok()?;
    Some(d)
}

/// What you're asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Reaching a host (`target` is `host` or `host:port`).
    Host,
    /// Reading a path.
    Read,
    /// Changing a path (held for review, like everything else).
    Write,
    /// Calling a tool of one of your MCP servers (`target` is `server.tool`,
    /// `reason` its arguments).
    Tool,
    /// A budget that's used up while a model call waits (`target` says
    /// which, `reason` how much is spent): how far to raise it, if at all.
    Budget,
}

/// One question: what, and the agent's reason when it asked on purpose.
#[derive(Debug, Clone)]
pub struct Request {
    pub kind: Kind,
    pub target: String,
    pub reason: Option<String>,
    /// What the task has read that it shouldn't trust, when that's why you're asked.
    pub taint: Option<String>,
}

impl Request {
    /// A connection the agent attempted.
    pub fn host(host: &str, port: u16) -> Request {
        Request { kind: Kind::Host, target: entry(host, port), reason: None, taint: None }
    }

    fn key(&self) -> String {
        format!("{:?}:{}", self.kind, self.target)
    }

    /// What "always" remembers for this project, if anything.
    fn remembered_as(&self) -> Option<String> {
        match self.kind {
            Kind::Host => Some(self.target.clone()),
            Kind::Tool => Some(format!("{TOOL_PREFIX}{}", self.target)),
            Kind::Read | Kind::Write | Kind::Budget => None,
        }
    }
}

/// Text from the agent, made safe to show you: no control characters (a
/// terminal would obey escape sequences), and not too long.
pub fn sanitize(text: &str, max: usize) -> String {
    let clean: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let clean = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    match clean.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &clean[..i]),
        None => clean,
    }
}

/// A question waiting for an answer in agentd's console.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Question {
    pub id: String,
    pub task: String,
    pub title: String,
    #[serde(default = "host_kind")]
    pub kind: Kind,
    pub target: String,
    /// The agent's own words, when it asked on purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What the task has read that it shouldn't trust, when that's why you're asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint: Option<String>,
    pub project: PathBuf,
    pub asked_ms: u64,
    /// For a budget: what to raise it to, as offered (first is [y]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offers: Vec<String>,
}

fn host_kind() -> Kind {
    Kind::Host
}

fn queue(store_root: &Path, which: &str) -> PathBuf {
    store_root.join("approvals").join(which)
}

/// Questions agentd should show.
pub fn questions(store_root: &Path) -> Vec<Question> {
    let mut out: Vec<Question> = fs::read_dir(queue(store_root, "pending"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| serde_json::from_slice(&fs::read(e.path()).ok()?).ok())
        .collect();
    out.sort_by_key(|q| q.asked_ms);
    out
}

/// agentd's side: answer a question.
pub fn answer(store_root: &Path, id: &str, decision: Decision) -> Result<()> {
    answer_with(store_root, id, decision.label())
}

/// agentd's side: raise the budget a question is about.
pub fn answer_raise(store_root: &Path, id: &str, to: Budget) -> Result<()> {
    answer_with(store_root, id, &format!("raise {}", to.spec()))
}

fn answer_with(store_root: &Path, id: &str, text: &str) -> Result<()> {
    if !id.chars().all(|c| c.is_ascii_hexdigit()) || !queue(store_root, "pending").join(format!("{id}.json")).exists() {
        anyhow::bail!("no such question");
    }
    let dir = queue(store_root, "answers");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(format!("{id}.json")), text)?;
    Ok(())
}

/// Forgets questions whose task is gone: `live(task)` says which aren't.
pub fn drop_stale(store_root: &Path, live: impl Fn(&str) -> bool) {
    for q in questions(store_root) {
        if !live(&q.task) {
            let _ = fs::remove_file(queue(store_root, "pending").join(format!("{}.json", q.id)));
        }
    }
}

/// An answer typed at the terminal, or sent by agentd (a decision's label).
/// For a tool, [y] means this call and [t] the whole task.
fn parse_decision(text: &str, kind: Kind) -> Decision {
    match (text.trim().to_ascii_lowercase().as_str(), kind) {
        ("y" | "yes" | "call", Kind::Tool) => Decision::Call,
        ("t" | "task" | "once", Kind::Tool) => Decision::Once,
        ("h" | "hold", Kind::Tool) => Decision::Hold,
        ("y" | "yes" | "o" | "once" | "call", _) => Decision::Once,
        ("a" | "always", _) => Decision::Always,
        _ => Decision::Deny,
    }
}

/// An answer to a budget question: [y] for the first offer, an amount (a
/// bare number counts in the budget's own unit), or anything else for no.
fn parse_raise(text: &str, cap: Budget, offers: &[Budget]) -> Option<Budget> {
    let t = text.trim();
    let t = t.strip_prefix("raise").map(str::trim).unwrap_or(t);
    match t.to_ascii_lowercase().as_str() {
        "y" | "yes" => offers.first().copied(),
        _ => match t.parse::<f64>() {
            Ok(n) => cap.same_unit(n),
            Err(_) => t.parse().ok(),
        },
    }
}

/// How a budget question ended.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Raised {
    /// You raised it to this, answering there ("terminal", "agentd console").
    To(Budget, &'static str),
    /// It doesn't need raising anymore (raised elsewhere meanwhile).
    Settled,
    /// "denied", or "no answer".
    No(&'static str),
}

/// What came back from a question.
enum Heard {
    /// An answer, and where it was given.
    Text(String, &'static str),
    Timeout,
    Settled,
    /// The terminal went away.
    Gone,
}

pub const AT_TERMINAL: &str = "terminal";
pub const IN_AGENTD: &str = "agentd console";

/// Asks about hosts outside the allowlist, and what agents ask for: at the
/// terminal, in agentd's console, or both (the first answer wins). One
/// question at a time; answers last for the task.
pub struct Asker {
    tty: Option<Mutex<File>>,
    web: bool,
    asking: Mutex<()>,
    answers: Mutex<HashMap<String, Decision>>,
    store_root: PathBuf,
    project: PathBuf,
    task: String,
    title: String,
}

impl Asker {
    /// `None` when there's nobody to ask: no terminal (or `use_tty` off, e.g.
    /// over a full-screen agent) and no agentd.
    pub fn open(store_root: &Path, project: &Path, use_tty: bool, task: &str, title: &str) -> Option<Asker> {
        let tty = use_tty.then(|| OpenOptions::new().read(true).write(true).open("/dev/tty").ok()).flatten();
        let web = agentd(store_root).is_some();
        if tty.is_none() && !web {
            return None;
        }
        Some(Asker {
            tty: tty.map(Mutex::new),
            web,
            asking: Mutex::new(()),
            answers: Mutex::new(HashMap::new()),
            store_root: store_root.to_path_buf(),
            project: project.to_path_buf(),
            task: task.to_string(),
            title: title.to_string(),
        })
    }

    /// From now on in this task, `req` is refused without asking (you took
    /// it back).
    pub fn refuse(&self, req: &Request) {
        if let Ok(mut answers) = self.answers.lock() {
            answers.insert(req.key(), Decision::Deny);
        }
    }

    /// Your answer to `req`, and whether you were asked just now (rather
    /// than answered earlier in this task). Blocks until answered. "Always"
    /// only exists for hosts.
    pub fn ask(&self, req: &Request, paint: impl Fn(&str) -> String) -> (Decision, bool) {
        let key = req.key();
        // Nobody answered last time: an agent asking again gets asked again.
        // ("This call" answers aren't kept at all.)
        // A yes given before the task read untrusted input doesn't carry over
        // to after; a no does.
        let tainted_key = format!("{key}!tainted");
        let cached = || {
            let answers = self.answers.lock().ok()?;
            let earlier = answers.get(&key).copied();
            let answer = match (&req.taint, earlier) {
                (Some(_), Some(d)) if d.allows() => answers.get(&tainted_key).copied(),
                _ => earlier,
            };
            answer.filter(|d| *d != Decision::Timeout)
        };
        if let Some(d) = cached() {
            return (d, false);
        }
        // Serialize questions; whoever waited may find theirs answered.
        let Ok(_turn) = self.asking.lock() else { return (Decision::Deny, false) };
        if let Some(d) = cached() {
            return (d, false);
        }

        let mut tty = self.tty.as_ref().and_then(|t| t.lock().ok());
        let elsewhere = if self.web { " (or answer in agentd)" } else { "" };
        let what = match (req.kind, &req.reason) {
            (Kind::Host, None) => format!("the agent wants to reach {}", req.target),
            (Kind::Host, Some(_)) => format!("the agent asks to reach {}", req.target),
            (Kind::Read, _) => format!("the agent asks to read {}", req.target),
            (Kind::Write, _) => format!("the agent asks to change {} (held for your review)", req.target),
            (Kind::Tool, _) => format!("the agent wants to call {}", req.target),
            (Kind::Budget, _) => format!("{} is used up", req.target),
        };
        let why = match (req.kind, req.reason.as_deref()) {
            (_, None) => String::new(),
            (Kind::Tool, Some(args)) => format!("\n  with: {args}"),
            (_, Some(r)) => format!("\n  its reason: \u{201c}{r}\u{201d}"),
        };
        let why = match &req.taint {
            Some(t) => format!("{why}\n  {}", paint(&format!("\u{26a0} this task has read untrusted input: {t}"))),
            None => why,
        };
        let project = display_path(&self.project);
        let options = match req.kind {
            Kind::Host => format!("[y] this task · [a] always, in {project} · [N] deny"),
            Kind::Tool => format!("[y] this call · [h] hold it for review · [t] this task · [a] always, in {project} · [N] deny"),
            Kind::Read | Kind::Write | Kind::Budget => "[y] this task · [N] deny".to_string(),
        };
        let prompt = format!("\n{} {what}{why}\n  {options}{elsewhere} › ", paint("agent ▸"));
        let decision = match self.hear(&mut tty, req, Vec::new(), &prompt, &|| false) {
            Heard::Text(text, via) => {
                let d = parse_decision(&text, req.kind);
                if let (Some(t), true) = (tty.as_mut(), via == IN_AGENTD) {
                    let _ = writeln!(t, "{} (answered in agentd)", d.label());
                }
                d
            }
            Heard::Timeout => Decision::Timeout,
            Heard::Settled | Heard::Gone => Decision::Deny,
        };
        // A path is granted for this task only.
        let remembered = req.remembered_as();
        let decision = if decision == Decision::Always && remembered.is_none() { Decision::Once } else { decision };

        if let Some(t) = tty.as_mut() {
            if decision == Decision::Timeout {
                let _ = writeln!(t, "(no answer in {}s: denied)", ANSWER_TIMEOUT.as_secs());
            }
        }
        if let (Decision::Always, Some(entry)) = (decision, &remembered) {
            if let Err(e) = remember(&self.store_root, &self.project, entry) {
                if let Some(t) = tty.as_mut() {
                    let _ = writeln!(t, "(couldn't remember it: {e:#}; allowed for this task)");
                }
            }
        }
        if let (Ok(mut answers), false) = (self.answers.lock(), matches!(decision, Decision::Call | Decision::Hold)) {
            if req.taint.is_some() {
                answers.insert(tainted_key, decision);
            }
            answers.insert(key, decision);
        }
        (decision, true)
    }

    /// A budget is used up while a model call waits: asks how far to raise
    /// it. `settled` ends the question early (it was raised elsewhere).
    pub fn ask_raise(&self, req: &Request, cap: Budget, offers: &[Budget], settled: impl Fn() -> bool, paint: impl Fn(&str) -> String) -> Raised {
        // One question at a time: by then, it may have been raised already.
        let Ok(_turn) = self.asking.lock() else { return Raised::No("denied") };
        if settled() {
            return Raised::Settled;
        }
        let mut tty = self.tty.as_ref().and_then(|t| t.lock().ok());
        let elsewhere = if self.web { " (or answer in agentd)" } else { "" };
        let spent = req.reason.as_deref().map(|r| format!(" ({r})")).unwrap_or_default();
        let (first, other) = (offers.first().copied().unwrap_or(cap), offers.get(1).copied().unwrap_or(cap));
        let prompt = format!(
            "\n{} {} is used up{spent}; the agent's next model call waits\n  [y] raise it to {first} · or type an amount, e.g. {} · [N] no, let it stop{elsewhere} › ",
            paint("agent ▸"),
            req.target,
            other.spec(),
        );
        let (raised, echo) = match self.hear(&mut tty, req, offers.iter().map(|b| b.to_string()).collect(), &prompt, &settled) {
            Heard::Text(text, via) => {
                let raised = match parse_raise(&text, cap, offers) {
                    Some(to) => Raised::To(to, via),
                    None => Raised::No("denied"),
                };
                let echo = (via == IN_AGENTD).then(|| match raised {
                    Raised::To(to, _) => format!("raise to {to} (answered in agentd)"),
                    _ => "no (answered in agentd)".to_string(),
                });
                (raised, echo)
            }
            Heard::Settled => (Raised::Settled, Some("(raised elsewhere: the agent goes on)".to_string())),
            Heard::Timeout => (Raised::No("no answer"), Some(format!("(no answer in {}s: it stays used up)", ANSWER_TIMEOUT.as_secs()))),
            Heard::Gone => (Raised::No("denied"), None),
        };
        if let (Some(t), Some(echo)) = (tty.as_mut(), echo) {
            let _ = writeln!(t, "{echo}");
        }
        raised
    }

    /// Puts a question to you, at the terminal (`prompt`) and in agentd,
    /// and waits for the answer, or until `settled`.
    fn hear(&self, tty: &mut Option<MutexGuard<'_, File>>, req: &Request, offers: Vec<String>, prompt: &str, settled: &dyn Fn() -> bool) -> Heard {
        let id = crate::util::random_hex(8).unwrap_or_default();
        let pending = queue(&self.store_root, "pending").join(format!("{id}.json"));
        let answer_file = queue(&self.store_root, "answers").join(format!("{id}.json"));
        if self.web {
            let q = Question {
                id: id.clone(),
                task: self.task.clone(),
                title: self.title.clone(),
                kind: req.kind,
                target: req.target.clone(),
                reason: req.reason.clone(),
                taint: req.taint.clone(),
                project: self.project.clone(),
                asked_ms: crate::util::now_ms(),
                offers,
            };
            let _ = fs::create_dir_all(pending.parent().unwrap_or(Path::new(".")));
            let _ = fs::write(&pending, serde_json::to_vec(&q).unwrap_or_default());
        }
        if let Some(t) = tty.as_mut() {
            // One write, so it can't interleave with the agent's own output.
            let _ = t.write_all(prompt.as_bytes());
            let _ = t.flush();
        }
        let deadline = Instant::now() + ANSWER_TIMEOUT;
        let mut line = Vec::new();
        let heard = loop {
            if Instant::now() >= deadline {
                break Heard::Timeout;
            }
            if settled() {
                break Heard::Settled;
            }
            if let Ok(text) = fs::read_to_string(&answer_file) {
                break Heard::Text(text, IN_AGENTD);
            }
            match tty.as_mut() {
                Some(t) => match read_line_for(t, &mut line, Duration::from_millis(250)) {
                    Some(true) => break Heard::Text(String::from_utf8_lossy(&line).into_owned(), AT_TERMINAL),
                    Some(false) => {}
                    None => break Heard::Gone,
                },
                None => std::thread::sleep(Duration::from_millis(250)),
            }
        };
        let _ = fs::remove_file(&pending);
        let _ = fs::remove_file(&answer_file);
        heard
    }
}

/// Reads terminal input into `line` for up to `wait`. `Some(true)` once a
/// full line is in, `Some(false)` if not yet, `None` if the terminal is gone.
fn read_line_for(tty: &mut File, line: &mut Vec<u8>, wait: Duration) -> Option<bool> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    let ms = PollTimeout::try_from(wait.as_millis() as i32).unwrap_or(PollTimeout::ZERO);
    let mut fds = [PollFd::new(tty.as_fd(), PollFlags::POLLIN)];
    match poll(&mut fds, ms) {
        Ok(0) | Err(nix::errno::Errno::EINTR) => return Some(false),
        Ok(_) => {}
        Err(_) => return None,
    }
    let mut buf = [0u8; 64];
    match tty.read(&mut buf) {
        Ok(0) | Err(_) => None,
        Ok(n) => {
            for &b in &buf[..n] {
                if b == b'\n' {
                    return Some(true);
                }
                line.push(b);
            }
            Some(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembered_per_project_and_revocable() {
        let dir = tempfile::tempdir().unwrap();
        let (store, a, b) = (dir.path(), Path::new("/p/a"), Path::new("/p/b"));
        remember(store, a, "pypi.org").unwrap();
        remember(store, a, "pypi.org").unwrap();
        remember(store, a, "internal.dev:8443").unwrap();
        assert_eq!(remembered(store, a).unwrap(), vec!["pypi.org", "internal.dev:8443"]);
        assert!(remembered(store, b).unwrap().is_empty());
        assert!(revoke(store, a, "pypi.org").unwrap());
        assert!(!revoke(store, a, "pypi.org").unwrap());
        assert_eq!(remembered(store, a).unwrap(), vec!["internal.dev:8443"]);
    }

    #[test]
    fn agent_text_is_made_safe_to_show() {
        assert_eq!(sanitize("need\x1b[2Jthe\ndocs\r\t please", 100), "need [2Jthe docs please");
        assert_eq!(sanitize("abcdef", 3), "abc…");
        assert_eq!(Request::host("pypi.org", 443).key(), "Host:pypi.org");
    }

    #[test]
    fn answers_mean_what_they_say_per_kind() {
        assert_eq!(parse_decision("y", Kind::Tool), Decision::Call);
        assert_eq!(parse_decision("t", Kind::Tool), Decision::Once);
        assert_eq!(parse_decision("once", Kind::Tool), Decision::Once, "agentd's 'for this task'");
        assert_eq!(parse_decision("y", Kind::Host), Decision::Once);
        assert_eq!(parse_decision("a", Kind::Read), Decision::Always);
        assert_eq!(parse_decision("", Kind::Tool), Decision::Deny);

        let dir = tempfile::tempdir().unwrap();
        let (store, p) = (dir.path(), Path::new("/p/a"));
        remember(store, p, "pypi.org").unwrap();
        remember(store, p, "tool:notes.post_note").unwrap();
        assert_eq!(remembered(store, p).unwrap(), vec!["pypi.org"], "tools aren't hosts");
        assert_eq!(remembered_tools(store, p).unwrap(), vec!["notes.post_note"]);
    }

    #[test]
    fn budget_answers() {
        let (usd, tok) = (Budget::Usd(0.5), Budget::Tokens(1_000_000));
        let offers = [Budget::Usd(0.9), Budget::Usd(1.2)];
        assert_eq!(parse_raise("y\n", usd, &offers), Some(Budget::Usd(0.9)), "[y]: the first offer");
        assert_eq!(parse_raise("raise 1.2usd", usd, &offers), Some(Budget::Usd(1.2)), "agentd's answer");
        assert_eq!(parse_raise("3", usd, &offers), Some(Budget::Usd(3.0)), "a bare number in the budget's unit");
        assert_eq!(parse_raise("3", tok, &offers), Some(Budget::Tokens(3)));
        assert_eq!(parse_raise("2M", tok, &offers), Some(Budget::Tokens(2_000_000)));
        assert_eq!(parse_raise("$4", tok, &offers), Some(Budget::Usd(4.0)), "checked when applied");
        for no in ["", "n", "no", "deny", "-1", "nan"] {
            assert_eq!(parse_raise(no, usd, &offers), None, "{no:?}");
        }
    }

    #[test]
    fn project_root_is_the_repo() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let (home, repo) = (root.join("home"), root.join("home/code/app"));
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(repo.join("src/deep")).unwrap();
        assert_eq!(project_root(&repo.join("src/deep"), &home), repo);
        let loose = root.join("home/scratch");
        fs::create_dir_all(&loose).unwrap();
        assert_eq!(project_root(&loose, &home), loose);
    }
}
