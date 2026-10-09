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
    if users.len() == before {
        bail!("no user named {name} (see `agent users`)");
    }
    save(root, &users)
}

/// Whose token this is, if anyone's.
pub fn authenticate(root: &Path, token: &str) -> Option<User> {
    let wanted = hash(token);
    list(root).into_iter().find(|u| u.token_sha256 == wanted)
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
