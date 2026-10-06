//! Live approvals: when an agent reaches for a host that isn't allowed, ask
//! the human at the terminal instead of failing, while the connection waits.
//!
//! "Always" answers are remembered per project in the task store, which no
//! sandbox can see, and applied to later tasks like an allowlist from your
//! own config.

use crate::util::display_path;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Once,
    Always,
    Deny,
    /// Nobody answered in time.
    Timeout,
}

impl Decision {
    pub fn allows(self) -> bool {
        matches!(self, Decision::Once | Decision::Always)
    }

    pub fn label(self) -> &'static str {
        match self {
            Decision::Once => "once",
            Decision::Always => "always",
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

/// Hosts approved "always" for `project`, as allowlist entries.
pub fn remembered(store_root: &Path, project: &Path) -> Result<Vec<String>> {
    Ok(load_db(store_root)?.remove(&project.display().to_string()).unwrap_or_default())
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

/// A question waiting for an answer in agentd's console.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Question {
    pub id: String,
    pub task: String,
    pub title: String,
    pub target: String,
    pub project: PathBuf,
    pub asked_ms: u64,
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
    if !id.chars().all(|c| c.is_ascii_hexdigit()) || !queue(store_root, "pending").join(format!("{id}.json")).exists() {
        anyhow::bail!("no such question");
    }
    let dir = queue(store_root, "answers");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(format!("{id}.json")), decision.label())?;
    Ok(())
}

fn parse_decision(text: &str) -> Decision {
    match text.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" | "o" | "once" => Decision::Once,
        "a" | "always" => Decision::Always,
        _ => Decision::Deny,
    }
}

/// Asks about hosts outside the allowlist: at the terminal, in agentd's
/// console, or both (the first answer wins). One question at a time; answers
/// last for the task.
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

    /// Whether the agent may reach `host:port`, and whether you were asked
    /// just now (rather than answered earlier in this task). Blocks until answered.
    pub fn ask(&self, host: &str, port: u16, paint: impl Fn(&str) -> String) -> (Decision, bool) {
        let key = entry(host, port);
        let cached = || self.answers.lock().ok().and_then(|a| a.get(&key).copied());
        if let Some(d) = cached() {
            return (d, false);
        }
        // Serialize questions; whoever waited may find theirs answered.
        let Ok(_turn) = self.asking.lock() else { return (Decision::Deny, false) };
        if let Some(d) = cached() {
            return (d, false);
        }

        let mut tty = self.tty.as_ref().and_then(|t| t.lock().ok());
        let id = crate::util::random_hex(8).unwrap_or_default();
        let pending = queue(&self.store_root, "pending").join(format!("{id}.json"));
        let answer_file = queue(&self.store_root, "answers").join(format!("{id}.json"));
        if self.web {
            let q = Question {
                id: id.clone(),
                task: self.task.clone(),
                title: self.title.clone(),
                target: key.clone(),
                project: self.project.clone(),
                asked_ms: crate::util::now_ms(),
            };
            let _ = fs::create_dir_all(pending.parent().unwrap_or(Path::new(".")));
            let _ = fs::write(&pending, serde_json::to_vec(&q).unwrap_or_default());
        }
        if let Some(t) = tty.as_mut() {
            let elsewhere = if self.web { " (or answer in agentd)" } else { "" };
            let _ = write!(
                t,
                "\n{} the agent wants to reach {} · [y] this task · [a] always, in {} · [N] deny{elsewhere} › ",
                paint("agent ▸"),
                key,
                display_path(&self.project)
            );
            let _ = t.flush();
        }

        let deadline = Instant::now() + ANSWER_TIMEOUT;
        let mut line = Vec::new();
        let decision = loop {
            if Instant::now() >= deadline {
                break Decision::Timeout;
            }
            if let Ok(text) = fs::read_to_string(&answer_file) {
                let d = parse_decision(&text);
                if let Some(t) = tty.as_mut() {
                    let _ = writeln!(t, "{} (answered in agentd)", d.label());
                }
                break d;
            }
            match tty.as_mut() {
                Some(t) => match read_line_for(t, &mut line, Duration::from_millis(250)) {
                    Some(true) => break parse_decision(&String::from_utf8_lossy(&line)),
                    Some(false) => {}
                    None => break Decision::Deny,
                },
                None => std::thread::sleep(Duration::from_millis(250)),
            }
        };
        let _ = fs::remove_file(&pending);
        let _ = fs::remove_file(&answer_file);

        if let Some(t) = tty.as_mut() {
            if decision == Decision::Timeout {
                let _ = writeln!(t, "(no answer in {}s: denied)", ANSWER_TIMEOUT.as_secs());
            }
        }
        if decision == Decision::Always {
            if let Err(e) = remember(&self.store_root, &self.project, &key) {
                if let Some(t) = tty.as_mut() {
                    let _ = writeln!(t, "(couldn't remember it: {e:#}; allowed for this task)");
                }
            }
        }
        if let Ok(mut answers) = self.answers.lock() {
            answers.insert(key, decision);
        }
        (decision, true)
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
