//! Agent profiles: what a given agent needs in order to run in a sandbox,
//! and how to read what it reports while it works.
//!
//! An agent runs with its own permission prompts switched off: agentos holds
//! every change for review, so the agent doesn't need to ask.

use crate::sandbox::is_system_path;
use crate::store::Net;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const AGENTS: &[&str] = &["claude"];

pub enum Output {
    /// The agent talks to your terminal directly.
    Inherit,
    /// Claude Code's `--output-format stream-json`, rendered and journaled by agentos.
    ClaudeStream,
}

pub struct Profile {
    pub name: &'static str,
    pub argv: Vec<String>,
    /// The agent's own installation, granted read-only.
    pub install: Vec<PathBuf>,
    pub env: Vec<(String, String)>,
    /// Passed through from your shell when set (credentials, endpoints).
    pub pass_env: Vec<&'static str>,
    pub net: Net,
    /// Hosts the agent needs, for `Net::Proxy`.
    pub allow: Vec<&'static str>,
    /// Credentials brokered when set in your environment: (variable, host, header).
    pub brokered: Vec<(&'static str, &'static str, &'static str)>,
    pub output: Output,
}

/// `task: None` opens an interactive session.
pub fn load(agent: &str, task: Option<&str>, interactive: bool, home: &Path) -> Result<Profile> {
    match agent {
        "claude" => claude(task, interactive, home),
        other => bail!("unknown agent '{other}' (available: {})", AGENTS.join(", ")),
    }
}

fn claude(task: Option<&str>, interactive: bool, home: &Path) -> Result<Profile> {
    let bin = find_on_path("claude").context(
        "Claude Code isn't installed (no `claude` on your PATH). Install it with:\n  curl -fsSL https://claude.ai/install.sh | bash",
    )?;
    let bin = fs::canonicalize(&bin)?;
    let mut argv = vec![bin.display().to_string(), "--dangerously-skip-permissions".to_string()];
    let output = match task {
        Some(t) if !interactive => {
            argv.extend(["-p", t, "--output-format", "stream-json", "--verbose"].map(String::from));
            Output::ClaudeStream
        }
        Some(t) => {
            argv.push(t.to_string());
            Output::Inherit
        }
        None => Output::Inherit,
    };
    Ok(Profile {
        name: "claude",
        install: install_roots(&bin, home),
        argv,
        env: vec![
            // The installation is read-only in the sandbox, and fewer
            // destinations make the network easier to lock down.
            ("DISABLE_AUTOUPDATER".into(), "1".into()),
            ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".into(), "1".into()),
        ],
        pass_env: vec!["ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL"],
        // The agent gets placeholders; the proxy adds the real values on the wire.
        brokered: vec![
            ("ANTHROPIC_API_KEY", "api.anthropic.com", "x-api-key"),
            ("ANTHROPIC_AUTH_TOKEN", "api.anthropic.com", "authorization"),
        ],
        net: Net::Proxy,
        // The API, plus what logging in and refreshing a login talk to.
        // Anything else shows up as "blocked" in the output and the journal.
        allow: vec!["api.anthropic.com", "console.anthropic.com", "platform.claude.com", "claude.ai"],
        output,
    })
}

pub fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join(name))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

/// Directories that must be visible for `bin` to run: its install dir and,
/// for scripts, the interpreter's. System dirs are visible already.
fn install_roots(bin: &Path, home: &Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for path in std::iter::once(bin.to_path_buf()).chain(interpreter(bin)) {
        if !is_system_path(&path) {
            roots.push(install_root(&path, home));
        }
    }
    let all = roots.clone();
    roots.retain(|r| !all.iter().any(|other| other != r && r.starts_with(other)));
    roots.dedup();
    roots
}

/// `…/node/v22/bin/node` → `…/node/v22`; otherwise the containing dir. Never
/// $HOME or anything above it.
fn install_root(path: &Path, home: &Path) -> PathBuf {
    let dir = path.parent().unwrap_or(path);
    match dir.parent() {
        Some(up) if dir.file_name().is_some_and(|n| n == "bin") && !home.starts_with(up) => up.to_path_buf(),
        _ => dir.to_path_buf(),
    }
}

/// The interpreter named by a `#!` line, resolved like the kernel and env(1) would.
fn interpreter(bin: &Path) -> Option<PathBuf> {
    let mut head = [0u8; 256];
    let n = fs::File::open(bin).ok()?.read(&mut head).ok()?;
    let line = std::str::from_utf8(&head[..n]).ok()?.strip_prefix("#!")?.lines().next()?.to_string();
    let mut words = line.split_whitespace();
    let prog = words.next()?;
    let path = if prog.ends_with("/env") {
        find_on_path(words.find(|w| !w.starts_with('-'))?)?
    } else {
        PathBuf::from(prog)
    };
    fs::canonicalize(path).ok()
}

/// One thing an agent reported while working.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentEvent {
    Session { model: String },
    Text(String),
    Tool { name: String, target: String },
    Done { text: String, is_error: bool, turns: Option<u64>, cost_usd: Option<f64> },
    /// A line that isn't part of the structured stream; shown as-is.
    Raw(String),
}

/// Parses one line of Claude Code's stream-json output. Returns `None` for
/// JSON it doesn't recognize, so callers can fall back to raw output if the
/// format ever changes under us.
pub fn parse_claude_line(line: &str) -> Option<Vec<AgentEvent>> {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return Some(vec![AgentEvent::Raw(line.to_string())]);
    };
    let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
    match v["type"].as_str()? {
        "system" if v["subtype"] == "init" => Some(vec![AgentEvent::Session { model: s(&v["model"]) }]),
        "system" | "user" => Some(Vec::new()),
        "assistant" => Some(
            v["message"]["content"]
                .as_array()?
                .iter()
                .filter_map(|block| match block["type"].as_str()? {
                    "text" => Some(s(&block["text"])).filter(|t| !t.trim().is_empty()).map(AgentEvent::Text),
                    "tool_use" => Some(AgentEvent::Tool { name: s(&block["name"]), target: tool_target(&block["input"]) }),
                    _ => None,
                })
                .collect(),
        ),
        "result" => Some(vec![AgentEvent::Done {
            text: s(&v["result"]),
            is_error: v["is_error"].as_bool().unwrap_or(v["subtype"] != "success"),
            turns: v["num_turns"].as_u64(),
            cost_usd: v["total_cost_usd"].as_f64(),
        }]),
        _ => None,
    }
}

/// The most telling argument of a tool call: the file, command, pattern, URL…
fn tool_target(input: &Value) -> String {
    ["file_path", "notebook_path", "command", "pattern", "url", "query", "path", "description", "prompt"]
        .iter()
        .find_map(|k| input[k].as_str())
        .and_then(|s| s.lines().next())
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_claude_stream_json() {
        let init = r#"{"type":"system","subtype":"init","session_id":"s","model":"claude-x","tools":[]}"#;
        assert_eq!(parse_claude_line(init), Some(vec![AgentEvent::Session { model: "claude-x".into() }]));

        let turn = r#"{"type":"assistant","message":{"content":[
            {"type":"text","text":"I'll add a test."},
            {"type":"tool_use","id":"t1","name":"Bash","input":{"command":"pytest -q\nmore","description":"Run tests"}}]}}"#
            .replace('\n', " ");
        assert_eq!(
            parse_claude_line(&turn),
            Some(vec![
                AgentEvent::Text("I'll add a test.".into()),
                AgentEvent::Tool { name: "Bash".into(), target: "pytest -q".into() },
            ])
        );

        let result = r#"{"type":"result","subtype":"success","is_error":false,"num_turns":3,"result":"Done.","total_cost_usd":0.0421}"#;
        assert_eq!(
            parse_claude_line(result),
            Some(vec![AgentEvent::Done { text: "Done.".into(), is_error: false, turns: Some(3), cost_usd: Some(0.0421) }])
        );

        assert_eq!(parse_claude_line(r#"{"type":"user","message":{}}"#), Some(vec![]));
        assert_eq!(parse_claude_line(r#"{"type":"something_new"}"#), None);
        assert_eq!(parse_claude_line("plain text"), Some(vec![AgentEvent::Raw("plain text".into())]));
    }

    #[test]
    fn install_roots_never_expose_home() {
        let home = Path::new("/home/u");
        assert_eq!(install_root(Path::new("/home/u/.nvm/versions/node/v22/bin/node"), home), Path::new("/home/u/.nvm/versions/node/v22"));
        assert_eq!(install_root(Path::new("/home/u/bin/claude"), home), Path::new("/home/u/bin"));
        assert_eq!(
            install_root(Path::new("/home/u/.local/share/claude/versions/2.1.0"), home),
            Path::new("/home/u/.local/share/claude/versions")
        );
    }
}
