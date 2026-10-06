//! Outbox: an agent's `git push` is held with its other changes and only
//! reaches the remote when you commit.
//!
//! Each remote of the project gets an empty bare repository in the task
//! (`outbox/<remote>.git`). Inside the sandbox, git is configured (through
//! `GIT_CONFIG_*`, which outranks every config file) to push each remote
//! there, so `git push` works offline and without credentials. The outbox
//! borrows the project's existing objects through `alternates`, so a push
//! only stores what's new.
//!
//! On commit, agentos replays each held ref from your own git, outside the
//! sandbox, with your usual credentials. If the remote moved meanwhile, git
//! rejects the push like any other, and it stays held.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Where the outbox repositories appear inside the sandbox.
const SANDBOX_OUTBOX: &str = "/run/agentos/outbox";
/// Where the project's real `.git` appears (read-only) inside the sandbox.
const SANDBOX_BASE: &str = "/run/agentos/base.git";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    /// The project's real `.git` directory.
    git_dir: PathBuf,
    /// Remote name → URL, as configured when the task started.
    remotes: BTreeMap<String, String>,
}

/// What the sandbox needs to route pushes into the outbox.
pub struct Prepared {
    pub env: Vec<(String, String)>,
    /// (host path, name under /run/agentos, writable)
    pub mounts: Vec<(PathBuf, String, bool)>,
    pub remotes: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Push {
    pub remote: String,
    pub url: String,
    pub refname: String,
    pub sha: String,
    repo: PathBuf,
}

impl Push {
    /// `main` for `refs/heads/main`, otherwise the full ref.
    pub fn short_ref(&self) -> &str {
        self.refname.strip_prefix("refs/heads/").unwrap_or(&self.refname)
    }
}

fn outbox_dir(task_dir: &Path) -> PathBuf {
    task_dir.join("outbox")
}

fn git(args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "safe.directory=*"]).args(args).stdin(Stdio::null());
    cmd
}

fn output(mut cmd: Command) -> Result<String> {
    let out = cmd.output().context("run git")?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Sets up an outbox if `project` is a git work tree with remotes and git is
/// installed. Called before the sandbox starts.
pub fn prepare(task_dir: &Path, project: &Path) -> Result<Option<Prepared>> {
    let git_dir = project.join(".git");
    if !git_dir.is_dir() || Command::new("git").arg("--version").output().is_err() {
        return Ok(None);
    }
    let listing = output({
        let mut c = git(&["config", "--get-regexp", r"^remote\..*\.(url|pushurl)$"]);
        c.current_dir(project);
        c
    })
    .unwrap_or_default();
    let mut remotes = BTreeMap::new();
    let mut warnings = Vec::new();
    for line in listing.lines() {
        let Some((key, url)) = line.split_once(' ') else { continue };
        let key = key.strip_prefix("remote.").unwrap_or(key);
        if let Some(name) = key.strip_suffix(".url") {
            remotes.insert(name.to_string(), url.to_string());
        } else if let Some(name) = key.strip_suffix(".pushurl") {
            warnings.push(format!(
                "remote {name} has an explicit pushurl; pushes to it also try the real remote (and fail without network)"
            ));
        }
    }
    if remotes.is_empty() {
        return Ok(None);
    }

    let dir = outbox_dir(task_dir);
    fs::create_dir_all(&dir)?;
    let mut env = vec![("GIT_CONFIG_COUNT".to_string(), remotes.len().to_string())];
    for (i, name) in remotes.keys().enumerate() {
        let repo = dir.join(format!("{name}.git"));
        output(git(&["init", "--bare", "--quiet", &repo.display().to_string()]))?;
        fs::write(repo.join("objects/info/alternates"), format!("{SANDBOX_BASE}/objects\n"))?;
        env.push((format!("GIT_CONFIG_KEY_{i}"), format!("remote.{name}.pushurl")));
        env.push((format!("GIT_CONFIG_VALUE_{i}"), format!("{SANDBOX_OUTBOX}/{name}.git")));
    }
    let manifest = Manifest { git_dir: git_dir.clone(), remotes: remotes.clone() };
    fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(Some(Prepared {
        env,
        mounts: vec![(dir, "outbox".into(), true), (git_dir, "base.git".into(), false)],
        remotes,
        warnings,
    }))
}

fn manifest(task_dir: &Path) -> Option<Manifest> {
    let raw = fs::read(outbox_dir(task_dir).join("manifest.json")).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// After the sandbox exits: point the outboxes at the project's objects by
/// their real path, so they can be pushed from outside.
pub fn seal(task_dir: &Path) -> Result<()> {
    let Some(m) = manifest(task_dir) else { return Ok(()) };
    for name in m.remotes.keys() {
        let alternates = outbox_dir(task_dir).join(format!("{name}.git/objects/info/alternates"));
        fs::write(alternates, format!("{}\n", m.git_dir.join("objects").display()))?;
    }
    Ok(())
}

/// Pushes the agent made that haven't been sent yet.
pub fn pending(task_dir: &Path) -> Result<Vec<Push>> {
    let Some(m) = manifest(task_dir) else { return Ok(Vec::new()) };
    let mut pushes = Vec::new();
    for (name, url) in &m.remotes {
        let repo = outbox_dir(task_dir).join(format!("{name}.git"));
        if !repo.is_dir() {
            continue;
        }
        let refs = output(git(&["--git-dir", &repo.display().to_string(), "for-each-ref", "--format=%(objectname) %(refname)"]))?;
        for line in refs.lines() {
            if let Some((sha, refname)) = line.split_once(' ') {
                pushes.push(Push { remote: name.clone(), url: url.clone(), refname: refname.into(), sha: sha.into(), repo: repo.clone() });
            }
        }
    }
    Ok(pushes)
}

/// The pushed commit's subject, and how many commits it adds over what you
/// last fetched from that remote (if anything).
pub fn describe(task_dir: &Path, p: &Push) -> (String, Option<usize>) {
    let repo = p.repo.display().to_string();
    let subject = output(git(&["--git-dir", &repo, "log", "-1", "--format=%s", &p.sha])).unwrap_or_default();
    let count = manifest(task_dir).and_then(|m| {
        let tracking = format!("refs/remotes/{}/{}", p.remote, p.short_ref());
        let base = output(git(&["--git-dir", &m.git_dir.display().to_string(), "rev-parse", "--verify", "--quiet", &tracking])).ok()?;
        output(git(&["--git-dir", &repo, "rev-list", "--count", &p.sha, "--not", &base])).ok()?.parse().ok()
    });
    (subject, count)
}

/// Sends a held push to the real remote, with your own git and credentials.
/// On success it leaves the outbox.
pub fn send(p: &Push, force: bool) -> Result<()> {
    let repo = p.repo.display().to_string();
    let refspec = format!("{}{}:{}", if force { "+" } else { "" }, p.sha, p.refname);
    let out = Command::new("git")
        .args(["--git-dir", &repo, "push", "--porcelain", &p.url, &refspec])
        .stdin(Stdio::null())
        .output()
        .context("run git push")?;
    if !out.status.success() {
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        let reason = text
            .lines()
            .find(|l| l.starts_with('!'))
            .or_else(|| text.lines().rev().find(|l| !l.trim().is_empty()))
            .unwrap_or("push failed")
            .trim_start_matches('!')
            .trim();
        bail!("{reason}");
    }
    output(git(&["--git-dir", &repo, "update-ref", "-d", &p.refname]))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(dir: &Path, args: &[&str]) {
        let ok = Command::new("git").args(args).current_dir(dir).env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@t").output().unwrap();
        assert!(ok.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&ok.stderr));
    }

    #[test]
    fn held_pushes_replay_to_the_real_remote() {
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skipping: no git");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let (remote, project, task) = (root.join("remote.git"), root.join("project"), root.join("task"));
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&task).unwrap();
        run(&root, &["init", "--bare", "-q", "remote.git"]);
        run(&project, &["init", "-q", "-b", "main"]);
        run(&project, &["remote", "add", "origin", &remote.display().to_string()]);
        fs::write(project.join("a"), "1").unwrap();
        run(&project, &["add", "a"]);
        run(&project, &["commit", "-qm", "one"]);
        run(&project, &["push", "-q", "origin", "main"]);

        let prepared = prepare(&task, &project).unwrap().expect("outbox for a repo with a remote");
        assert_eq!(prepared.remotes.get("origin").map(String::as_str), Some(remote.display().to_string().as_str()));
        assert!(prepared.env.contains(&("GIT_CONFIG_KEY_0".into(), "remote.origin.pushurl".into())));

        // What the agent's push does, minus the sandbox: commit and push into the outbox.
        fs::write(project.join("a"), "2").unwrap();
        run(&project, &["commit", "-qam", "two"]);
        let outbox = task.join("outbox/origin.git");
        fs::write(outbox.join("objects/info/alternates"), format!("{}\n", project.join(".git/objects").display())).unwrap();
        run(&project, &["push", "-q", &outbox.display().to_string(), "main:refs/heads/feature"]);
        seal(&task).unwrap();

        let held = pending(&task).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!((held[0].remote.as_str(), held[0].short_ref()), ("origin", "feature"));
        assert_eq!(describe(&task, &held[0]), ("two".to_string(), None));
        assert!(output(git(&["--git-dir", &remote.display().to_string(), "rev-parse", "--verify", "-q", "refs/heads/feature"])).is_err(), "nothing reached the remote yet");

        send(&held[0], false).unwrap();
        let landed = output(git(&["--git-dir", &remote.display().to_string(), "rev-parse", "refs/heads/feature"])).unwrap();
        assert_eq!(landed, held[0].sha);
        assert!(pending(&task).unwrap().is_empty(), "sent pushes leave the outbox");
    }
}
