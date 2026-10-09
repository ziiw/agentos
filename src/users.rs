//! People besides you who can use agentd's console, each with a token and a role.
//!
//! agentd's own token is yours: it can do everything. For a team that shares
//! one (on a server, over a private network), `agent users add NAME --role …`
//! makes another token with less: a **viewer** reads tasks, diffs and
//! journals; an **approver** also answers agents' questions and stops tasks
//! or takes back what they were given; an **admin** also starts tasks,
//! commits, pushes, rolls back and raises budgets. What a named person does
//! is written into the journal of the task it touched, under their name.
//!
//! People who sign in with your identity provider (`[console.oidc]`, see
//! `oidc.rs`) get a **session**: a token of the same kind that ends, kept the
//! same way (a hash, in the store). `agent users` lists them, and
//! `agent users remove sso:alice@example.com` ends theirs at once.
//!
//! A token can also be limited to projects (`--project DIR`, as many as you
//! like): its holder sees and acts on tasks that ran in those folders and
//! nothing else, and a task elsewhere looks like one that doesn't exist.
//!
//! Only a hash of each token is kept (in the task store, which no sandbox
//! can see); the token itself is shown once, when it's made.

use crate::util::{hex, now_ms, random_hex};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Approver,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Result<Role> {
        match s {
            "viewer" => Ok(Role::Viewer),
            "approver" => Ok(Role::Approver),
            "admin" => Ok(Role::Admin),
            other => bail!("{other:?} isn't a role: viewer, approver or admin"),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Approver => "approver",
            Role::Admin => "admin",
        }
    }

    /// What the role may do, for `agent users`.
    pub fn describe(self) -> &'static str {
        match self {
            Role::Viewer => "reads tasks, diffs and journals",
            Role::Approver => "also answers questions, stops tasks, takes back grants",
            Role::Admin => "also starts tasks, commits, pushes, rolls back, raises budgets",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub role: Role,
    /// The folders whose tasks this person can see; none means every task.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<PathBuf>,
    token_sha256: String,
    pub created_ms: u64,
}

impl User {
    /// Whether a task that ran in `cwd` is theirs to see.
    pub fn covers(&self, cwd: &Path) -> bool {
        covers(&self.projects, cwd)
    }
}

/// Whether a task that ran in `cwd` is within `projects` (none: all of them).
pub fn covers(projects: &[PathBuf], cwd: &Path) -> bool {
    projects.is_empty() || projects.iter().any(|p| cwd.starts_with(p))
}

fn file(root: &Path) -> PathBuf {
    root.join("users.json")
}

fn hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

pub fn list(root: &Path) -> Vec<User> {
    fs::read(file(root)).ok().and_then(|raw| serde_json::from_slice(&raw).ok()).unwrap_or_default()
}

fn save(root: &Path, users: &[User]) -> Result<()> {
    let tmp = file(root).with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(users)?)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, file(root)).context("save users.json")
}

/// A name you can read in a journal: lowercase letters, digits, - and _.
pub fn valid_name(name: &str) -> Result<()> {
    let ok = !name.is_empty() && name.len() <= 32 && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        bail!("{name:?} isn't a user name: lowercase letters, digits, - and _ (32 at most)");
    }
    if ["you", "owner"].contains(&name) {
        bail!("{name:?} is taken: that's you, with agentd's own token");
    }
    Ok(())
}

/// Adds someone and returns their token: shown once, never kept. With
/// `projects` (absolute folders), only the tasks that ran in them are theirs.
pub fn add(root: &Path, name: &str, role: Role, projects: &[PathBuf]) -> Result<String> {
    valid_name(name)?;
    for p in projects {
        if !p.is_absolute() || p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            bail!("{}: a project is an absolute folder, without ..", p.display());
        }
    }
    let mut users = list(root);
    if users.iter().any(|u| u.name == name) {
        bail!("{name} already has a token; `agent users remove {name}` first to make another");
    }
    let token = random_hex(16)?;
    let mut projects = projects.to_vec();
    projects.dedup();
    users.push(User { name: name.to_string(), role, projects, token_sha256: hash(&token), created_ms: now_ms() });
    save(root, &users)?;
    Ok(token)
}

pub fn remove(root: &Path, name: &str) -> Result<()> {
    let mut users = list(root);
    let before = users.len();
    users.retain(|u| u.name != name);
    let ended = end_sessions_of(root, name);
    if users.len() == before && ended == 0 {
        bail!("no user named {name} (see `agent users`)");
    }
    if users.len() != before {
        save(root, &users)?;
    }
    Ok(())
}

/// Whose token this is, if anyone's: a person you gave one, or someone signed in.
pub fn authenticate(root: &Path, token: &str) -> Option<User> {
    let wanted = hash(token);
    list(root).into_iter().find(|u| u.token_sha256 == wanted).or_else(|| {
        let _one_at_a_time = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
        read_sessions(root).into_iter().find(|s| s.token_sha256 == wanted).map(|s| User { name: s.name, role: s.role, projects: s.projects, token_sha256: s.token_sha256, created_ms: s.created_ms })
    })
}

// ---- sign-ins through an identity provider ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub name: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<PathBuf>,
    token_sha256: String,
    pub created_ms: u64,
    pub expires_ms: u64,
}

/// Only one thing at a time changes the sessions file.
static SESSIONS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// More sign-ins than this at once is a mistake (or an attack).
const MAX_SESSIONS: usize = 2000;

fn sessions_file(root: &Path) -> PathBuf {
    root.join("sessions.json")
}

/// The sessions that haven't run out.
fn read_sessions(root: &Path) -> Vec<Session> {
    let now = now_ms();
    let all: Vec<Session> = fs::read(sessions_file(root)).ok().and_then(|raw| serde_json::from_slice(&raw).ok()).unwrap_or_default();
    all.into_iter().filter(|s| s.expires_ms > now).collect()
}

fn write_sessions(root: &Path, sessions: &[Session]) -> Result<()> {
    let tmp = sessions_file(root).with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(sessions)?)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, sessions_file(root)).context("save sessions.json")
}

/// Signs someone in for `ttl`: their token (shown to them once, only a hash kept).
/// `projects` are absolute folders; none means every project.
pub fn start_session(root: &Path, name: &str, role: Role, projects: &[PathBuf], ttl: std::time::Duration) -> Result<String> {
    for p in projects {
        if !p.is_absolute() || p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            bail!("{}: a project is an absolute folder, without ..", p.display());
        }
    }
    let _one_at_a_time = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let mut sessions = read_sessions(root);
    if sessions.len() >= MAX_SESSIONS {
        bail!("too many people are signed in ({MAX_SESSIONS})");
    }
    let token = random_hex(16)?;
    let now = now_ms();
    sessions.push(Session { name: name.to_string(), role, projects: projects.to_vec(), token_sha256: hash(&token), created_ms: now, expires_ms: now + ttl.as_millis() as u64 });
    write_sessions(root, &sessions)?;
    Ok(token)
}

/// Ends the session this token opens; whether there was one.
pub fn end_session(root: &Path, token: &str) -> bool {
    let _one_at_a_time = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let wanted = hash(token);
    let mut sessions = read_sessions(root);
    let before = sessions.len();
    sessions.retain(|s| s.token_sha256 != wanted);
    sessions.len() != before && write_sessions(root, &sessions).is_ok()
}

/// Ends every session of one person; how many there were.
fn end_sessions_of(root: &Path, name: &str) -> usize {
    let _one_at_a_time = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let mut sessions = read_sessions(root);
    let before = sessions.len();
    sessions.retain(|s| s.name != name);
    let ended = before - sessions.len();
    if ended > 0 {
        let _ = write_sessions(root, &sessions);
    }
    ended
}

/// Who is signed in now.
pub fn sessions(root: &Path) -> Vec<Session> {
    let _one_at_a_time = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    read_sessions(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_shown_once_and_kept_hashed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(list(dir.path()).is_empty() && authenticate(dir.path(), "anything").is_none());
        let alice = add(dir.path(), "alice", Role::Approver, &[]).unwrap();
        let bob = add(dir.path(), "bob", Role::Viewer, &[]).unwrap();
        assert_ne!(alice, bob);
        assert_eq!(authenticate(dir.path(), &alice).map(|u| (u.name, u.role)), Some(("alice".into(), Role::Approver)));
        assert_eq!(authenticate(dir.path(), &bob).map(|u| u.role), Some(Role::Viewer));
        assert!(authenticate(dir.path(), "nope").is_none() && authenticate(dir.path(), "").is_none());
        let stored = fs::read_to_string(file(dir.path())).unwrap();
        assert!(!stored.contains(&alice) && !stored.contains(&bob), "only hashes are kept");
        assert_eq!(fs::metadata(file(dir.path())).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(add(dir.path(), "alice", Role::Admin, &[]).is_err(), "one token each");
        remove(dir.path(), "alice").unwrap();
        assert!(authenticate(dir.path(), &alice).is_none() && authenticate(dir.path(), &bob).is_some());
        assert!(remove(dir.path(), "alice").is_err());
    }

    #[test]
    fn people_signed_in_elsewhere_get_a_token_that_ends() {
        let dir = tempfile::tempdir().unwrap();
        let app = PathBuf::from("/home/me/code/app");
        let token = start_session(dir.path(), "sso:alice@example.com", Role::Approver, &[app.clone()], std::time::Duration::from_secs(3600)).unwrap();
        let other = start_session(dir.path(), "sso:bob@example.com", Role::Viewer, &[], std::time::Duration::from_secs(3600)).unwrap();
        assert_ne!(token, other);
        let alice = authenticate(dir.path(), &token).unwrap();
        assert_eq!((alice.name.as_str(), alice.role, alice.projects.as_slice()), ("sso:alice@example.com", Role::Approver, &[app][..]));
        assert!(authenticate(dir.path(), "nope").is_none());
        assert_eq!(fs::metadata(sessions_file(dir.path())).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!fs::read_to_string(sessions_file(dir.path())).unwrap().contains(&token), "only hashes are kept");
        assert_eq!(sessions(dir.path()).len(), 2);
        // They are not local users, and a local user can't be named like them.
        assert!(list(dir.path()).is_empty() && valid_name("sso:alice@example.com").is_err());
        // Signing out ends that session only.
        assert!(end_session(dir.path(), &token) && !end_session(dir.path(), &token));
        assert!(authenticate(dir.path(), &token).is_none() && authenticate(dir.path(), &other).is_some());
        // `remove` ends all of a person's.
        let again = start_session(dir.path(), "sso:bob@example.com", Role::Viewer, &[], std::time::Duration::from_secs(60)).unwrap();
        remove(dir.path(), "sso:bob@example.com").unwrap();
        assert!(authenticate(dir.path(), &other).is_none() && authenticate(dir.path(), &again).is_none());
        assert!(remove(dir.path(), "sso:bob@example.com").is_err());
        // They run out.
        let short = start_session(dir.path(), "sso:carol@example.com", Role::Admin, &[], std::time::Duration::from_millis(1)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(authenticate(dir.path(), &short).is_none() && sessions(dir.path()).is_empty());
        // A scope that could be read as "everything" is refused.
        for bad in ["relative", "/home/me/../you"] {
            assert!(start_session(dir.path(), "sso:x", Role::Viewer, &[PathBuf::from(bad)], std::time::Duration::from_secs(60)).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_token_can_be_limited_to_projects() {
        let dir = tempfile::tempdir().unwrap();
        let (app, lib) = (PathBuf::from("/home/me/code/app"), PathBuf::from("/home/me/code/lib"));
        let token = add(dir.path(), "carol", Role::Admin, &[app.clone(), lib.clone()]).unwrap();
        add(dir.path(), "dave", Role::Viewer, &[]).unwrap();
        let carol = authenticate(dir.path(), &token).unwrap();
        assert_eq!(carol.projects, [app.clone(), lib.clone()]);
        assert!(carol.covers(&app) && carol.covers(&app.join("src/deep")) && carol.covers(&lib));
        for outside in ["/home/me/code/application", "/home/me/code", "/home/me/code/other", "/", "/home/me/code/app/../other"] {
            // (a path with .. never reaches here: task folders are canonical)
            if outside.contains("..") {
                continue;
            }
            assert!(!carol.covers(Path::new(outside)), "{outside}");
        }
        let dave = list(dir.path()).into_iter().find(|u| u.name == "dave").unwrap();
        assert!(dave.projects.is_empty() && dave.covers(Path::new("/anywhere")), "no projects: all of them");
        // Kept in the file only when there are some.
        let stored = fs::read_to_string(file(dir.path())).unwrap();
        assert_eq!(stored.matches("projects").count(), 1);
        for bad in ["relative/dir", "/home/me/../you/app", ""] {
            assert!(add(dir.path(), "erin", Role::Viewer, &[PathBuf::from(bad)]).is_err(), "{bad:?}");
        }
        assert_eq!(list(dir.path()).len(), 2, "a refused add leaves nothing behind");
    }

    #[test]
    fn names_and_roles() {
        for ok in ["alice", "ci-bot", "a_1"] {
            assert!(valid_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Alice", "a b", "you", "owner", &"x".repeat(33), "a/b"] {
            assert!(valid_name(bad).is_err(), "{bad}");
        }
        assert!(Role::Viewer < Role::Approver && Role::Approver < Role::Admin);
        assert_eq!(Role::parse("approver").unwrap(), Role::Approver);
        assert!(Role::parse("root").is_err());
    }
}
