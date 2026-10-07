//! MCP, both ways.
//!
//! - `agent mcp`: agentos's own MCP server (JSON-RPC over stdio), run by an
//!   agent inside its sandbox. Its tools let the agent see what it was
//!   granted and ask you, with a reason, for a folder or a host; the
//!   supervisor does the work through the control socket (`control.rs`).
//! - `agent mcp NAME`: the gateway to one of *your* MCP servers. agentos runs
//!   the server outside the sandbox, with your credentials, which the agent
//!   never sees; the agent's calls go through the supervisor, which journals
//!   every tool call and asks you before the ones that change things.

use crate::approvals::{Decision, Kind, Request};
use crate::control::{self, Call, Reply};
use crate::journal::Journal;
use crate::policy::{Policy as Rules, Question, Verdict};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Protocol versions we speak; tools work the same in all of them.
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "You run inside an agentos sandbox: you see only the folders you were granted, \
your file changes and git pushes are held for the user's review, and the network is an allowlist. \
When you need a folder or a host you don't have, ask for it with these tools and a one-sentence reason \
instead of working around the restriction. The user decides.";

fn tools() -> Value {
    json!([
        {
            "name": "sandbox_info",
            "description": "What this agentos sandbox gives you: the folders you can read and change, \
the hosts you can reach, your budget, and where your changes and git pushes go. \
Call it when something is denied or unreachable, before asking for more.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "request_path_access",
            "description": "Ask the user for a folder (or file) you can't see, or can't change, in this sandbox. \
The user decides; the answer comes when they do, which can take a minute. Write access is transactional: \
your changes there are held for the user's review like the rest of your work.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute, ~/…, or relative to the task's folder" },
                    "access": { "type": "string", "enum": ["read", "write"] },
                    "reason": { "type": "string", "description": "One sentence, shown to the user" }
                },
                "required": ["path", "access", "reason"]
            }
        },
        {
            "name": "request_network_access",
            "description": "Ask the user to let you reach a host that this sandbox blocks (connections to it are refused). \
The user decides; the answer comes when they do. Only HTTPS goes through.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": { "type": "string", "description": "A host name, like pypi.org" },
                    "port": { "type": "integer", "description": "Defaults to 443" },
                    "reason": { "type": "string", "description": "One sentence, shown to the user" }
                },
                "required": ["host", "reason"]
            }
        }
    ])
}

/// The tool call, as a call to agentos.
fn to_call(name: &str, args: &Value) -> std::result::Result<Call, String> {
    let text = |key: &str| args[key].as_str().map(str::to_string).filter(|s| !s.trim().is_empty());
    let reason = || text("reason").ok_or_else(|| "give a reason: one sentence the user will read".to_string());
    match name {
        "sandbox_info" => Ok(Call::Info),
        "request_path_access" => {
            let path = text("path").ok_or("path is required")?;
            let write = match args["access"].as_str() {
                Some("read") | None => false,
                Some("write") => true,
                Some(other) => return Err(format!("access must be \"read\" or \"write\", not {other:?}")),
            };
            Ok(Call::Path { path, write, reason: reason()? })
        }
        "request_network_access" => {
            let host = text("host").ok_or("host is required")?;
            let port = match &args["port"] {
                Value::Null => None,
                v => Some(v.as_u64().and_then(|p| u16::try_from(p).ok()).ok_or("port must be a number from 1 to 65535")?),
            };
            Ok(Call::Network { host, port, reason: reason()? })
        }
        other => Err(format!("unknown tool {other}")),
    }
}

/// The answer to one JSON-RPC message, if it needs one.
pub fn handle(msg: &Value, ask: &dyn Fn(&Call) -> Result<Reply>) -> Option<Value> {
    // Notifications (no id) and the client's own responses get no reply.
    let id = msg.get("id")?.clone();
    let method = msg.get("method")?.as_str().unwrap_or("");
    let params = &msg["params"];
    let result = match method {
        "initialize" => {
            let wanted = params["protocolVersion"].as_str().unwrap_or("");
            let version = VERSIONS.iter().find(|v| **v == wanted).unwrap_or(&VERSIONS[1]);
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "agentos", "version": env!("CARGO_PKG_VERSION") },
                "instructions": INSTRUCTIONS,
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or("");
            let reply = to_call(name, &params["arguments"])
                .map_err(Reply::error)
                .and_then(|c| ask(&c).map_err(|e| Reply::error(format!("{e:#}"))))
                .unwrap_or_else(|r| r);
            Ok(json!({ "content": [{ "type": "text", "text": reply.text }], "isError": !reply.ok }))
        }
        _ => Err(json!({ "code": -32601, "message": format!("method not found: {method}") })),
    };
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
    })
}

/// One of your MCP servers, from `[mcp.NAME]` in your config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    #[serde(skip)]
    pub name: String,
    pub command: Vec<String>,
    /// Variables passed from your environment to the server (and only to it).
    #[serde(default)]
    pub env: Vec<String>,
    /// Per tool. Without an entry: allowed when the server marks the tool
    /// read-only, asked otherwise.
    #[serde(default)]
    pub tools: BTreeMap<String, Policy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Allow,
    Ask,
    Deny,
}

impl Server {
    pub fn validate(&self) -> Result<()> {
        let name = &self.name;
        if name.is_empty() || name == "agentos" || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            bail!("[mcp.{name}]: names are letters, digits, - and _ (and not \"agentos\")");
        }
        if self.command.first().is_none_or(|c| c.is_empty()) {
            bail!("[mcp.{name}]: command is empty");
        }
        Ok(())
    }
}

/// Serves MCP on stdin/stdout until the agent closes it.
pub fn serve_stdio(socket: &Path) -> Result<()> {
    let ask = |c: &Call| control::call(socket, c);
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&msg, &ask),
            Err(e) => Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": format!("parse error: {e}") } })),
        };
        if let Some(r) = reply {
            writeln!(out, "{r}")?;
            out.flush()?;
        }
    }
    Ok(())
}

/// `agent mcp NAME`, inside the sandbox: connects the agent's MCP client to
/// your server NAME, which agentos runs outside.
pub fn relay_stdio(socket: &Path, name: &str) -> Result<()> {
    let mut conn = UnixStream::connect(socket).with_context(|| format!("can't reach agentos at {}", socket.display()))?;
    writeln!(conn, "{}", serde_json::to_string(&Call::Mcp { server: name.to_string() })?)?;
    let mut from_agentos = BufReader::new(conn.try_clone()?);
    let mut line = String::new();
    from_agentos.read_line(&mut line)?;
    let reply: Reply = serde_json::from_str(line.trim()).context("agentos sent a malformed reply")?;
    if !reply.ok {
        bail!("{}", reply.text);
    }
    std::thread::spawn(move || {
        let _ = forward(&mut std::io::stdin().lock(), &mut conn);
        let _ = conn.shutdown(std::net::Shutdown::Write);
    });
    forward(&mut from_agentos, &mut std::io::stdout().lock())?;
    Ok(())
}

/// Copies as data arrives. (`io::copy` splices a pipe into a socket, and the
/// kernel can hold that data back until the pipe closes: an MCP client
/// keeps it open and waits for answers.)
fn forward(r: &mut impl std::io::Read, w: &mut impl Write) -> std::io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                w.write_all(&buf[..n])?;
                w.flush()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Methods that go through the gateway. Anything else (a server's own
/// extensions) could do what tools/call does without being asked about.
const RELAYED: &[&str] = &[
    "initialize", "ping", "tools/list", "tools/call", "resources/list", "resources/templates/list", "resources/read",
    "resources/subscribe", "resources/unsubscribe", "prompts/list", "prompts/get", "completion/complete", "logging/setLevel",
];

/// The supervisor's side: your MCP servers, run outside the sandbox, and
/// every tool call the agent makes through them, journaled and governed.
pub struct Gateway {
    pub servers: Vec<Server>,
    /// Where servers run (the task's folder, the real one).
    pub cwd: PathBuf,
    /// Server output goes to `mcp-NAME.log` here.
    pub log_dir: PathBuf,
    /// Asks you; `None` when nobody can be asked.
    pub ask: Box<dyn Fn(&Request) -> Option<Decision> + Send + Sync>,
    /// Your rules, which answer before you're asked.
    pub rules: Option<Arc<Rules>>,
    /// `server.tool` approved "always" for this project.
    pub remembered: Vec<String>,
    pub journal: Journal,
    /// Tells you something, live.
    pub say: Box<dyn Fn(String) + Send + Sync>,
    children: Mutex<Vec<u32>>,
}

/// One relayed session's bookkeeping.
#[derive(Default)]
struct Session {
    /// Tool → marked read-only by the server.
    read_only: HashMap<String, bool>,
    /// Pending tools/list requests (ids).
    listing: HashSet<String>,
    /// Pending tools/call requests, by id.
    calls: HashMap<String, Pending>,
}

/// A tool call on its way to the server.
struct Pending {
    tool: String,
    args: Value,
    /// How it was allowed (journaled as `decision`).
    how: &'static str,
    rule: Option<String>,
    started: Instant,
}

fn send(w: &Mutex<impl Write>, msg: &Value) {
    if let Ok(mut w) = w.lock() {
        let _ = writeln!(w, "{msg}");
        let _ = w.flush();
    }
}

/// A tool call's arguments, short enough to show you and to journal.
fn summary(args: &Value, max: usize) -> String {
    crate::approvals::sanitize(&args.to_string(), max)
}

impl Gateway {
    pub fn new(
        servers: Vec<Server>,
        cwd: PathBuf,
        log_dir: PathBuf,
        ask: Box<dyn Fn(&Request) -> Option<Decision> + Send + Sync>,
        rules: Option<Arc<Rules>>,
        remembered: Vec<String>,
        journal: Journal,
        say: Box<dyn Fn(String) + Send + Sync>,
    ) -> Gateway {
        Gateway { servers, cwd, log_dir, ask, rules, remembered, journal, say, children: Mutex::new(Vec::new()) }
    }

    /// Ends the servers still running (the task is over).
    pub fn stop_all(&self) {
        if let Ok(pids) = self.children.lock() {
            for pid in pids.iter() {
                let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(*pid as i32), nix::sys::signal::Signal::SIGTERM);
            }
        }
    }

    fn spawn(&self, server: &Server) -> Result<Child> {
        let mut cmd = Command::new(&server.command[0]);
        cmd.args(&server.command[1..]).current_dir(&self.cwd).env_clear();
        for k in ["PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "TMPDIR", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
        for k in &server.env {
            match std::env::var_os(k) {
                Some(v) => {
                    cmd.env(k, v);
                }
                None => (self.say)(format!("MCP server {}: {k} isn't set in your environment", server.name)),
            }
        }
        let log = std::fs::File::create(self.log_dir.join(format!("mcp-{}.log", server.name)))?;
        use std::os::unix::process::CommandExt;
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(log).process_group(0);
        let child = cmd.spawn().with_context(|| format!("start {}", server.command[0]))?;
        if let Ok(mut pids) = self.children.lock() {
            pids.push(child.id());
        }
        Ok(child)
    }

    /// Relays one agent connection to a fresh process of server `name`,
    /// until either side hangs up.
    pub fn relay(self: Arc<Self>, name: &str, conn: UnixStream) {
        let reply = |r: Reply| {
            let _ = writeln!(&conn, "{}", serde_json::to_string(&r).unwrap_or_default());
        };
        let Some(server) = self.servers.iter().find(|s| s.name == name).cloned() else {
            return reply(Reply::error(format!("no MCP server named {name} in the user's agentos config")));
        };
        let mut child = match self.spawn(&server) {
            Ok(c) => c,
            Err(e) => return reply(Reply::error(format!("{e:#}"))),
        };
        reply(Reply::answer("connected"));
        let _ = self.journal.append("mcp.start", json!({ "server": name, "command": server.command[0] }));
        let (Some(stdin), Some(stdout), Ok(conn_out)) = (child.stdin.take(), child.stdout.take(), conn.try_clone()) else {
            let _ = child.kill();
            return;
        };
        let to_server = Arc::new(Mutex::new(stdin));
        let to_agent = Arc::new(Mutex::new(conn_out));
        let session = Arc::new(Mutex::new(Session::default()));

        // Server → agent: note which tools are read-only, hide denied ones,
        // and journal each call's outcome.
        let back = {
            let (gw, server, session, to_agent) = (self.clone(), server.clone(), session.clone(), to_agent.clone());
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    let msg = gw.from_server(&server, &session, line);
                    if let Ok(mut w) = to_agent.lock() {
                        let _ = writeln!(w, "{msg}");
                    }
                }
                if let Ok(w) = to_agent.lock() {
                    let _ = w.shutdown(std::net::Shutdown::Both);
                }
            })
        };
        // Agent → server: policy on each tools/call.
        for line in BufReader::new(&conn).lines() {
            let Ok(line) = line else { break };
            self.clone().from_agent(&server, &session, &to_server, &to_agent, line);
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = back.join();
    }

    fn from_server(&self, server: &Server, session: &Mutex<Session>, line: String) -> String {
        let Ok(mut msg) = serde_json::from_str::<Value>(&line) else { return line };
        let (Some(id), None) = (msg.get("id").map(|i| i.to_string()), msg.get("method")) else { return line };
        let Ok(mut s) = session.lock() else { return line };
        if s.listing.remove(&id) {
            if let Some(tools) = msg["result"]["tools"].as_array_mut() {
                tools.retain(|t| {
                    let name = t["name"].as_str().unwrap_or_default();
                    s.read_only.insert(name.to_string(), t["annotations"]["readOnlyHint"].as_bool() == Some(true));
                    server.tools.get(name) != Some(&Policy::Deny)
                });
                return msg.to_string();
            }
        }
        if let Some(p) = s.calls.remove(&id) {
            let failed = msg.get("error").is_some() || msg["result"]["isError"].as_bool() == Some(true);
            let mut data = json!({
                "server": server.name, "tool": p.tool, "arguments": summary(&p.args, 1000), "decision": p.how,
                "error": failed, "bytes": line.len(), "ms": p.started.elapsed().as_millis() as u64,
            });
            if let Some(rule) = p.rule {
                data["rule"] = json!(rule);
            }
            let _ = self.journal.append("mcp.call", data);
        }
        line
    }

    fn from_agent(self: Arc<Self>, server: &Server, session: &Arc<Mutex<Session>>, to_server: &Arc<Mutex<ChildStdin>>, to_agent: &Arc<Mutex<UnixStream>>, line: String) {
        let refuse = |id: &Value, code: i64, message: String| {
            send(to_agent, &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }));
        };
        let msg: Value = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(_) => return refuse(&Value::Null, -32700, "agentos: unparseable message".into()),
        };
        if msg.is_array() {
            return refuse(&Value::Null, -32600, "agentos: batches aren't relayed; send one message at a time".into());
        }
        let Some(method) = msg.get("method").and_then(Value::as_str) else {
            // The agent's answer to a request from the server.
            return send(to_server, &msg);
        };
        let id = msg.get("id").cloned();
        if !method.starts_with("notifications/") && !RELAYED.contains(&method) {
            if let Some(id) = &id {
                refuse(id, -32601, format!("agentos: {method} isn't relayed to your MCP servers"));
            }
            return;
        }
        let Some(id) = id else {
            // Only real notifications go through without an id: a "tools/call"
            // sent as one would skip the questions, and a lax server might run it.
            if method.starts_with("notifications/") {
                send(to_server, &msg);
            }
            return;
        };
        match method {
            "tools/list" => {
                if let Ok(mut s) = session.lock() {
                    s.listing.insert(id.to_string());
                }
                send(to_server, &msg)
            }
            "tools/call" => {
                let tool = msg["params"]["name"].as_str().unwrap_or_default().to_string();
                let args = msg["params"]["arguments"].clone();
                let read_only = session.lock().ok().and_then(|s| s.read_only.get(&tool).copied()).unwrap_or(false);
                let target = format!("{}.{tool}", server.name);
                let verdict = self.rules.as_ref().map(|r| r.decide(&Question::call(&server.name, &tool, &args))).unwrap_or(Verdict::Undecided);
                let forward = |how: &'static str, rule: Option<String>| {
                    if let Ok(mut s) = session.lock() {
                        s.calls.insert(id.to_string(), Pending { tool: tool.clone(), args: args.clone(), how, rule, started: Instant::now() });
                    }
                    send(to_server, &msg);
                };
                let deny = |how: &'static str, rule: Option<String>, text: String| {
                    let mut data = json!({ "server": server.name, "tool": tool, "arguments": summary(&args, 1000), "decision": how, "error": true, "bytes": 0, "ms": 0 });
                    if let Some(rule) = rule {
                        data["rule"] = json!(rule);
                    }
                    let _ = self.journal.append("mcp.call", data);
                    send(to_agent, &json!({ "jsonrpc": "2.0", "id": id, "result": { "content": [{ "type": "text", "text": text }], "isError": true } }));
                };
                // Your config's deny, then your rules, then the rest.
                let policy = match (server.tools.get(&tool), &verdict) {
                    (Some(Policy::Deny), _) => Policy::Deny,
                    (_, Verdict::Forbid(rule)) => {
                        let (who, name) = crate::policy::whose(rule);
                        let who = if who == "your" { "the user's" } else { who };
                        return deny("forbidden", Some(rule.clone()), format!("agentos: {who} rules forbid this call (\u{201c}{name}\u{201d})."));
                    }
                    (_, Verdict::Permit(rule)) => return forward("rule", Some(rule.clone())),
                    (Some(p), _) => *p,
                    (None, _) if read_only || self.remembered.contains(&target) => Policy::Allow,
                    (None, _) => Policy::Ask,
                };
                match policy {
                    Policy::Allow if read_only => forward("read-only", None),
                    Policy::Allow => forward("allowed", None),
                    Policy::Deny => deny("denied by config", None, format!("agentos: the user's config doesn't allow {target}.")),
                    Policy::Ask => {
                        // Asking can take a while; other messages keep flowing.
                        let (gw, server, session, to_server, to_agent) = (self.clone(), server.clone(), session.clone(), to_server.clone(), to_agent.clone());
                        std::thread::spawn(move || {
                            let req = Request { kind: Kind::Tool, target: target.clone(), reason: Some(summary(&args, 300)) };
                            match (gw.ask)(&req) {
                                Some(d) if d.allows() => {
                                    if let Ok(mut s) = session.lock() {
                                        s.calls.insert(id.to_string(), Pending { tool, args, how: d.label(), rule: None, started: Instant::now() });
                                    }
                                    send(&to_server, &msg);
                                }
                                other => {
                                    let (how, text) = match other {
                                        None => ("nobody to ask", format!("agentos: {target} needs the user's approval, and nobody can be asked in this task.")),
                                        Some(Decision::Timeout) => ("timeout", format!("agentos: the user didn't answer about {target} in time.")),
                                        Some(_) => ("deny", format!("agentos: the user denied this call to {target}. Don't try to do it another way.")),
                                    };
                                    let _ = gw.journal.append(
                                        "mcp.call",
                                        json!({ "server": server.name, "tool": tool, "arguments": summary(&args, 1000), "decision": how, "error": true, "bytes": 0, "ms": 0 }),
                                    );
                                    send(&to_agent, &json!({ "jsonrpc": "2.0", "id": id, "result": { "content": [{ "type": "text", "text": text }], "isError": true } }));
                                }
                            }
                        });
                    }
                }
            }
            _ => send(to_server, &msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpc(method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params })
    }

    #[test]
    fn speaks_mcp() {
        let calls = std::sync::Mutex::new(Vec::new());
        let ask = |c: &Call| {
            calls.lock().unwrap().push(c.clone());
            Ok(Reply::answer("granted"))
        };
        let init = handle(&rpc("initialize", json!({ "protocolVersion": "2025-03-26" })), &ask).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(init["id"], 7);
        let unknown = handle(&rpc("initialize", json!({ "protocolVersion": "1999-01-01" })), &ask).unwrap();
        assert_eq!(unknown["result"]["protocolVersion"], "2025-06-18");
        assert!(handle(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }), &ask).is_none());

        let list = handle(&rpc("tools/list", json!({})), &ask).unwrap();
        let names: Vec<&str> = list["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["sandbox_info", "request_path_access", "request_network_access"]);

        let args = json!({ "path": "~/code/lib", "access": "write", "reason": "fix the bug there" });
        let r = handle(&rpc("tools/call", json!({ "name": "request_path_access", "arguments": args })), &ask).unwrap();
        assert_eq!(r["result"]["content"][0]["text"], "granted");
        assert_eq!(r["result"]["isError"], false);
        let r = handle(&rpc("tools/call", json!({ "name": "request_network_access", "arguments": { "host": "pypi.org", "port": 8443, "reason": "deps" } })), &ask).unwrap();
        assert_eq!(r["result"]["isError"], false);
        assert_eq!(
            *calls.lock().unwrap(),
            [
                Call::Path { path: "~/code/lib".into(), write: true, reason: "fix the bug there".into() },
                Call::Network { host: "pypi.org".into(), port: Some(8443), reason: "deps".into() }
            ]
        );

        // Bad arguments come back as tool errors, without bothering anyone.
        let r = handle(&rpc("tools/call", json!({ "name": "request_network_access", "arguments": { "host": "pypi.org" } })), &ask).unwrap();
        assert_eq!(r["result"]["isError"], true);
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("reason"));
        assert_eq!(calls.lock().unwrap().len(), 2);
        let r = handle(&rpc("resources/list", json!({})), &ask).unwrap();
        assert_eq!(r["error"]["code"], -32601);
    }
}
