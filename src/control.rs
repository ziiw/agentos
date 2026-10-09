//! The agent's line to agentos from inside its sandbox: a unix socket at
//! /run/agentos/control.sock, served by the supervisor. Agents use it
//! through `agent mcp` (an MCP server, see `mcp.rs`) to see what they were
//! granted and to ask, with a reason, for more. You answer the questions;
//! the agent never decides.

use crate::sandbox::is_system_path;
use crate::store::{Access, Grant};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

/// Where the socket appears inside the sandbox.
pub const SOCKET: &str = "/run/agentos/control.sock";
/// The `agent` binary, inside the sandbox (for `agent mcp`).
pub const BINARY: &str = "/run/agentos/agent";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Call {
    /// What the sandbox allows.
    Info,
    /// Reach a host that isn't allowed.
    Network {
        host: String,
        #[serde(default)]
        port: Option<u16>,
        reason: String,
    },
    /// Read (or change) a path the sandbox doesn't show (or keeps read-only).
    Path {
        path: String,
        #[serde(default)]
        write: bool,
        reason: String,
    },
    /// Talk MCP to one of your servers: after a reply line, the connection
    /// carries the session (see `mcp::Gateway`).
    Mcp { server: String },
    /// Yours only (the task's owner socket, never in the sandbox): what you
    /// granted while the task ran.
    Given,
    /// Yours only: take back a folder or host granted while the task ran.
    Revoke { target: String },
    /// Yours only: raise the task's budget (`to` as `Budget::spec`), from
    /// `by` ("terminal", "agentd console").
    Raise { to: String, by: String },
}

/// The task's owner socket, in its folder in the task store: how you (the
/// CLI, agentd) reach a running task. Never mounted into the sandbox.
pub const OWNER_SOCKET: &str = "owner.sock";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    /// False when the call itself failed (malformed, or nothing could be
    /// done); a refusal is a normal answer.
    pub ok: bool,
    /// For the agent to read.
    pub text: String,
}

impl Reply {
    pub fn answer(text: impl Into<String>) -> Reply {
        Reply { ok: true, text: text.into() }
    }

    pub fn error(text: impl Into<String>) -> Reply {
        Reply { ok: false, text: text.into() }
    }
}

pub type Handler = Arc<dyn Fn(Call) -> Reply + Send + Sync>;

/// Takes over a connection that asked for an MCP server by name.
pub type Relay = Arc<dyn Fn(String, UnixStream) + Send + Sync>;

/// Creates the socket; serve it with [`serve`] once the sandbox is forked.
pub fn bind(path: &Path) -> Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))
}

/// One call per connection: a JSON line in, a JSON line out (or an MCP
/// session, handed to `relay`). Each runs on its own thread, since an
/// answer can take as long as you do.
pub fn serve(listener: UnixListener, handler: Handler, relay: Relay) {
    thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let (handler, relay) = (handler.clone(), relay.clone());
            thread::spawn(move || {
                // Byte by byte, so nothing after the first line is consumed.
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                while line.len() < 64 * 1024 && !line.ends_with(b"\n") {
                    match (&conn).read(&mut byte) {
                        Ok(1) => line.push(byte[0]),
                        _ => return,
                    }
                }
                let reply = match serde_json::from_slice::<Call>(&line) {
                    Ok(Call::Mcp { server }) => return relay(server, conn),
                    Ok(call) => handler(call),
                    Err(e) => Reply::error(format!("malformed request: {e}")),
                };
                let _ = writeln!(&conn, "{}", serde_json::to_string(&reply).unwrap_or_default());
            });
        }
    });
}

/// The agent's side.
pub fn call(socket: &Path, c: &Call) -> Result<Reply> {
    let mut conn = UnixStream::connect(socket).with_context(|| format!("can't reach agentos at {}", socket.display()))?;
    writeln!(conn, "{}", serde_json::to_string(c)?)?;
    let mut line = String::new();
    BufReader::new(conn).read_line(&mut line)?;
    serde_json::from_str(line.trim()).context("agentos sent a malformed reply")
}

/// What a path request comes to, before anyone is asked.
#[derive(Debug, PartialEq)]
pub enum PathVerdict {
    AlreadyReadable,
    AlreadyWritable,
    /// Worth asking about.
    Ask,
}

/// What a sandbox may be given mid-task, beyond what it has.
pub struct PathRules<'a> {
    pub home: &'a Path,
    /// agentos's own state: the task store and your config.
    pub private: &'a [PathBuf],
    pub hidden: &'a [PathBuf],
    pub grants: &'a [Grant],
    /// With Landlock enforcing, writes are possible only where its rules,
    /// fixed when the task started, allow them: under $HOME.
    pub landlock: bool,
}

/// Credentials and keys in your home: never handed to an agent, even when
/// it asks nicely.
pub const SENSITIVE: &[&str] = &[
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".netrc", ".npmrc", ".pypirc", ".git-credentials",
    ".password-store", ".config/gh", ".config/gcloud", ".local/share/keyrings", ".claude", ".claude.json",
];

/// What the agent named (absolute, `~/…`, or relative to the task's
/// folder), as an absolute path; `..` is resolved by name, symlinks aren't.
pub fn resolve(asked: &str, home: &Path, cwd: &Path) -> Result<PathBuf> {
    let asked = asked.trim();
    let p = match asked.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if asked == "~" => home.to_path_buf(),
        None if Path::new(asked).is_absolute() => PathBuf::from(asked),
        None => cwd.join(asked),
    };
    Ok(crate::util::absolutize(&p)?)
}

/// Why `path` is never offered, whatever it is (or whether it exists).
pub fn forbidden(path: &Path, r: &PathRules) -> Option<String> {
    let overlaps = |p: &Path| p.starts_with(path) || path.starts_with(p);
    let shown = crate::util::display_path(path);
    if path == Path::new("/") {
        return Some("that's the whole filesystem".into());
    }
    if r.home.starts_with(path) {
        return Some(format!("{shown} contains your whole home folder; ask for the folder you need"));
    }
    if let Some(p) = r.private.iter().find(|p| overlaps(p)) {
        return Some(format!("{shown} overlaps agentos's own records ({}), which no agent can see", crate::util::display_path(p)));
    }
    if let Some(s) = SENSITIVE.iter().map(|s| r.home.join(s)).find(|s| overlaps(s)) {
        return Some(format!("{shown} holds credentials ({}), which agents never get", crate::util::display_path(&s)));
    }
    if r.hidden.iter().any(|h| path.starts_with(h)) {
        return Some(format!("{shown} is hidden from this task"));
    }
    if let Some(h) = r.hidden.iter().find(|h| h.starts_with(path)) {
        return Some(format!("{shown} contains {}, which is hidden from this task", crate::util::display_path(h)));
    }
    None
}

/// Whether `path` (canonical: symlinks resolved) may be offered, and what
/// it would add. `Err` says why not, for the agent.
pub fn check_path(path: &Path, write: bool, r: &PathRules) -> std::result::Result<PathVerdict, String> {
    let shown = crate::util::display_path(path);
    if let Some(why) = forbidden(path, r) {
        return Err(why);
    }
    if is_system_path(path) {
        return if write { Err(format!("{shown} is a system folder; those stay read-only")) } else { Ok(PathVerdict::AlreadyReadable) };
    }
    if let Some(g) = r.grants.iter().find(|g| g.path != path && g.path.starts_with(path)) {
        return Err(format!(
            "{shown} contains {}, which you already have; ask for something that doesn't contain it",
            crate::util::display_path(&g.path)
        ));
    }
    // The nearest grant that covers it.
    let covering = r.grants.iter().filter(|g| path.starts_with(&g.path)).max_by_key(|g| g.path.components().count());
    match covering.map(|g| g.access) {
        Some(Access::Rw) => return Ok(PathVerdict::AlreadyWritable),
        Some(Access::Ro) if !write => return Ok(PathVerdict::AlreadyReadable),
        _ => {}
    }
    if write {
        if !path.is_dir() {
            return Err(format!("{shown} is a file; only folders can be made writable"));
        }
        if path.as_os_str().as_encoded_bytes().iter().any(|b| matches!(b, b',' | b':' | b'\\')) {
            return Err(format!("{shown}: folders with ',', ':' or '\\' in their path can't be made writable yet"));
        }
        if r.landlock && !path.starts_with(r.home) {
            return Err(format!(
                "{shown} can't be made writable while the task runs: outside your home, write access is fixed when the task starts. The user can rerun the task with --rw {shown}"
            ));
        }
    }
    Ok(PathVerdict::Ask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_paths_can_be_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        for d in ["code/app/src", "code/lib/docs", "code/other", ".ssh", ".local/share/agentos", "code/app/secret"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::fs::write(home.join("code/lib/README"), "hi").unwrap();
        let grants = vec![
            Grant { path: home.join("code/app"), access: Access::Rw, layer: Some(0) },
            Grant { path: home.join("code/lib/docs"), access: Access::Ro, layer: None },
        ];
        let (private, hidden) = ([home.join(".local/share/agentos")], [home.join("code/app/secret")]);
        let rules = PathRules { home: &home, private: &private, hidden: &hidden, grants: &grants, landlock: true };
        let check = |p: &str, write| check_path(&home.join(p), write, &rules);

        assert_eq!(check("code/other", false), Ok(PathVerdict::Ask));
        assert_eq!(check("code/other", true), Ok(PathVerdict::Ask));
        assert_eq!(check("code/lib/README", false), Ok(PathVerdict::Ask));
        assert!(check("code/lib/README", true).unwrap_err().contains("only folders"));
        assert_eq!(check("code/app/src", true), Ok(PathVerdict::AlreadyWritable));
        assert_eq!(check("code/lib/docs", false), Ok(PathVerdict::AlreadyReadable));
        assert_eq!(check("code/lib/docs", true), Ok(PathVerdict::Ask), "a read-only grant can become writable");
        assert!(check("code/lib", false).unwrap_err().contains("contains"), "it would cover a grant");
        assert!(check("code", false).unwrap_err().contains("contains"));
        assert!(check(".ssh", false).unwrap_err().contains("credentials"));
        assert!(check("code/app/secret", false).unwrap_err().contains("hidden"));
        assert!(check(".local/share/agentos", false).unwrap_err().contains("records"));
        assert!(check_path(&home, false, &rules).unwrap_err().contains("home"));
        assert!(check_path(&root, false, &rules).is_err());
        assert!(check_path(Path::new("/"), false, &rules).is_err());
        assert_eq!(check_path(Path::new("/usr"), false, &rules), Ok(PathVerdict::AlreadyReadable));
        assert!(check_path(Path::new("/usr"), true, &rules).is_err());
        let outside = root.join("srv");
        std::fs::create_dir_all(&outside).unwrap();
        assert!(check_path(&outside, true, &rules).unwrap_err().contains("--rw"), "Landlock: writable only under $HOME");
        assert_eq!(check_path(&outside, false, &rules), Ok(PathVerdict::Ask));
        let no_landlock = PathRules { landlock: false, ..rules };
        assert_eq!(check_path(&outside, true, &no_landlock), Ok(PathVerdict::Ask));
    }

    #[test]
    fn names_resolve_like_the_agent_means_them() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let (home, cwd) = (root.join("home"), root.join("home/code/app"));
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(home.join("code/lib")).unwrap();
        assert_eq!(resolve("~/code/lib", &home, &cwd).unwrap(), home.join("code/lib"));
        assert_eq!(resolve("../lib", &home, &cwd).unwrap(), home.join("code/lib"));
        assert_eq!(resolve(&home.join("code/lib/").display().to_string(), &home, &cwd).unwrap(), home.join("code/lib"));
        assert_eq!(resolve("~/../../x", &home, &cwd).unwrap(), root.parent().unwrap().join("x"));
        // Refused by name, before anything is looked up.
        let rules = PathRules { home: &home, private: &[], hidden: &[], grants: &[], landlock: false };
        assert!(forbidden(&resolve("~/.ssh/id_ed25519", &home, &cwd).unwrap(), &rules).unwrap().contains("credentials"));
        assert!(forbidden(&resolve("~/code/lib", &home, &cwd).unwrap(), &rules).is_none());
    }

    #[test]
    fn a_call_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let listener = bind(&sock).unwrap();
        serve(
            listener,
            Arc::new(|c| match c {
                Call::Network { host, .. } => Reply::answer(format!("denied: {host}")),
                _ => Reply::answer("info"),
            }),
            Arc::new(|_, _| {}),
        );
        let reply = call(&sock, &Call::Network { host: "pypi.org".into(), port: None, reason: "deps".into() }).unwrap();
        assert_eq!(reply, Reply::answer("denied: pypi.org"));
        assert_eq!(call(&sock, &Call::Info).unwrap().text, "info");
    }
}
