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

/// Asks at the terminal, one question at a time; answers last for the task.
pub struct Asker {
    tty: Mutex<File>,
    answers: Mutex<HashMap<String, Decision>>,
    store_root: PathBuf,
    project: PathBuf,
}

impl Asker {
    /// `None` without a controlling terminal (CI, cron, pipes): nobody to ask.
    pub fn open(store_root: &Path, project: &Path) -> Option<Asker> {
        let tty = OpenOptions::new().read(true).write(true).open("/dev/tty").ok()?;
        Some(Asker {
            tty: Mutex::new(tty),
            answers: Mutex::new(HashMap::new()),
            store_root: store_root.to_path_buf(),
            project: project.to_path_buf(),
        })
    }

    /// Whether the agent may reach `host:port`, and whether you were asked
    /// just now (rather than answered earlier in this task). Blocks until answered.
    pub fn ask(&self, host: &str, port: u16, paint: impl Fn(&str) -> String) -> (Decision, bool) {
        let key = entry(host, port);
        if let Some(d) = self.answers.lock().ok().and_then(|a| a.get(&key).copied()) {
            return (d, false);
        }
        // Holding the terminal serializes questions; whoever waited may find
        // their answer already given.
        let Ok(mut tty) = self.tty.lock() else { return (Decision::Deny, false) };
        if let Some(d) = self.answers.lock().ok().and_then(|a| a.get(&key).copied()) {
            return (d, false);
        }
        let question = format!(
            "\n{} the agent wants to reach {} · [y] this task · [a] always, in {} · [N] deny › ",
            paint("agent ▸"),
            key,
            display_path(&self.project)
        );
        let decision = match tty.write_all(question.as_bytes()).and_then(|_| tty.flush()) {
            Ok(()) => read_answer(&mut tty),
            Err(_) => Decision::Deny,
        };
        if decision == Decision::Timeout {
            let _ = writeln!(tty, "(no answer in {}s: denied)", ANSWER_TIMEOUT.as_secs());
        }
        if decision == Decision::Always {
            if let Err(e) = remember(&self.store_root, &self.project, &key) {
                let _ = writeln!(tty, "(couldn't remember it: {e:#}; allowed for this task)");
            }
        }
        if let Ok(mut answers) = self.answers.lock() {
            answers.insert(key, decision);
        }
        (decision, true)
    }
}

fn read_answer(tty: &mut File) -> Decision {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    let deadline = Instant::now() + ANSWER_TIMEOUT;
    let mut line = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Decision::Timeout;
        }
        let ms = PollTimeout::try_from(left.as_millis().min(i32::MAX as u128) as i32).unwrap_or(PollTimeout::MAX);
        let mut fds = [PollFd::new(tty.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, ms) {
            Ok(0) => return Decision::Timeout,
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return Decision::Deny,
        }
        let mut byte = [0u8; 1];
        match tty.read(&mut byte) {
            Ok(0) | Err(_) => return Decision::Deny,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
        }
    }
    match String::from_utf8_lossy(&line).trim().to_ascii_lowercase().as_str() {
        "y" | "yes" | "o" | "once" => Decision::Once,
        "a" | "always" => Decision::Always,
        _ => Decision::Deny,
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
