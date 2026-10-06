//! `agent serve`: agentd, a small web console for your tasks and approvals,
//! so the human in the loop doesn't have to sit at the terminal.
//!
//! It listens on 127.0.0.1 by default, and every API call needs the token it
//! prints (`#token=…` in the URL keeps it out of logs). Actions run the
//! `agent` CLI itself, so commit, push and rollback behave exactly as in the
//! terminal, with your own git and credentials.

use crate::render::{self, Paint};
use agentos::approvals::{self, Agentd, Decision};
use agentos::changes::{self, Summary};
use agentos::outbox;
use agentos::store::{Store, Task};
use agentos::util;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const INDEX: &str = include_str!("web/index.html");

pub fn serve(store: &Store, listen: &str, notify: Option<String>) -> Result<i32> {
    if let Some(d) = approvals::agentd(store.root()) {
        bail!("agentd is already running (pid {}, http://{})", d.pid, d.listen);
    }
    let server = Server::http(listen).map_err(|e| anyhow!("listen on {listen}: {e}"))?;
    let addr = server.server_addr().to_ip().context("agentd needs an IP address to listen on")?;
    let token = util::random_hex(16)?;
    let info = Agentd { pid: std::process::id(), listen: addr.to_string(), token: token.clone() };
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(approvals::agentd_path(store.root()))?;
    f.write_all(&serde_json::to_vec_pretty(&info)?)?;

    let out = Paint::stdout();
    println!("{} agentd is running", out.cyan("agent ▸"));
    println!("  open      http://{addr}/#token={token}");
    if addr.ip().is_unspecified() {
        println!("  {}", out.dim("listening on every interface: use this machine's address, e.g. its Tailscale name"));
    }
    println!("  {}", out.dim("questions from agents show up there too; Ctrl-C stops it"));
    if let Some(url) = notify {
        let root = store.root().to_path_buf();
        thread::spawn(move || notifier(root, url));
    }

    for mut request in server.incoming_requests() {
        let (root, token) = (store.root().to_path_buf(), token.clone());
        thread::spawn(move || {
            let mut parts = request_parts(&request);
            parts.body = read_body(&mut request);
            let reply = handle_request(parts, &root, &token);
            let _ = respond(request, reply);
        });
    }
    Ok(0)
}

struct Parts {
    method: Method,
    path: String,
    query: String,
    auth: Option<String>,
    body: String,
}

fn request_parts(req: &Request) -> Parts {
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').map(|(p, q)| (p.to_string(), q.to_string())).unwrap_or((url, String::new()));
    let auth = req.headers().iter().find(|h| h.field.equiv("Authorization")).map(|h| h.value.to_string());
    Parts { method: req.method().clone(), path, query, auth, body: String::new() }
}

enum Reply {
    Html(&'static str),
    Json(u16, Value),
}

fn respond(req: Request, reply: Reply) -> std::io::Result<()> {
    let (status, body, kind) = match reply {
        Reply::Html(html) => (200, html.to_string(), "text/html; charset=utf-8"),
        Reply::Json(status, value) => (status, value.to_string(), "application/json"),
    };
    let header = Header::from_bytes("Content-Type", kind).expect("static header");
    let nocache = Header::from_bytes("Cache-Control", "no-store").expect("static header");
    req.respond(Response::from_string(body).with_status_code(StatusCode(status)).with_header(header).with_header(nocache))
}

fn handle_request(mut parts: Parts, root: &PathBuf, token: &str) -> Reply {
    if parts.method == Method::Get && (parts.path == "/" || parts.path == "/index.html") {
        return Reply::Html(INDEX);
    }
    let bearer = parts.auth.as_deref().and_then(|a| a.strip_prefix("Bearer ")).map(str::to_string);
    let query_token = parts.query.split('&').find_map(|kv| kv.strip_prefix("token=")).map(str::to_string);
    if bearer.or(query_token).as_deref() != Some(token) {
        return Reply::Json(401, json!({ "error": "missing or wrong token: open the link agent serve printed" }));
    }
    let store = match Store::open_at(root) {
        Ok(s) => s,
        Err(e) => return Reply::Json(500, json!({ "error": format!("{e:#}") })),
    };
    let segments: Vec<&str> = parts.path.trim_matches('/').split('/').collect();
    let result = match (&parts.method, segments.as_slice()) {
        (Method::Get, ["api", "tasks"]) => tasks(&store),
        (Method::Get, ["api", "tasks", id]) => task(&store, id),
        (Method::Post, ["api", "tasks", id, action]) if ["commit", "push", "rollback"].contains(action) => run_cli(&store, action, id),
        (Method::Get, ["api", "approvals"]) => Ok(json!(approvals::questions(store.root()))),
        (Method::Post, ["api", "approvals", id]) => {
            let decision = std::mem::take(&mut parts.body);
            decide(&store, id, &decision)
        }
        _ => return Reply::Json(404, json!({ "error": "not found" })),
    };
    match result {
        Ok(v) => Reply::Json(200, v),
        Err(e) => Reply::Json(400, json!({ "error": format!("{e:#}") })),
    }
}

fn task_json(t: &Task) -> Value {
    let open = t.is_open();
    let summary = if open { changes::scan(&t.layers()).ok().map(|c| Summary::of(&c)) } else { None };
    let pushes = if open { outbox::pending(&t.dir).map(|p| p.len()).unwrap_or(0) } else { 0 };
    // What a running task is up to: its latest tool call or connection.
    let doing = t.is_live().then(|| {
        t.journal().read().ok()?.iter().rev().find_map(|e| match e.kind.as_str() {
            "agent.tool" => Some(format!("{} {}", e.data["name"].as_str()?, e.data["target"].as_str().unwrap_or(""))),
            "net.connect" => Some(format!("connected to {}", e.data["host"].as_str()?)),
            _ => None,
        })
    });
    json!({
        "id": t.id(),
        "title": render::title(t),
        "status": t.status_label(),
        "live": t.is_live(),
        "doing": doing.flatten(),
        "open": open,
        "started_ms": t.meta.started_at_ms,
        "changes": summary,
        "pushes": pushes,
    })
}

fn tasks(store: &Store) -> Result<Value> {
    let list: Vec<Value> = store.list()?.iter().rev().take(50).map(task_json).collect();
    Ok(json!(list))
}

fn task(store: &Store, id: &str) -> Result<Value> {
    let t = store.resolve(Some(id))?;
    let changes = changes::scan(&t.layers())?;
    let pushes = if t.is_open() { crate::held_pushes(&t)? } else { Vec::new() };
    let events = t.journal().read().unwrap_or_default();
    let mut v = task_json(&t);
    v["diff"] = json!(render::diff(Paint::plain(), &t, &changes, &pushes, false, false));
    v["log"] = json!(render::log(Paint::plain(), &t, &events));
    Ok(v)
}

/// Runs `agent ACTION ID` and returns its output: the console does exactly
/// what the terminal would.
fn run_cli(store: &Store, action: &str, id: &str) -> Result<Value> {
    let t = store.resolve(Some(id))?;
    let out = Command::new(std::env::current_exe()?)
        .args([action, t.id()])
        .env("AGENTOS_HOME", store.root())
        .env("NO_COLOR", "1")
        .output()?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    Ok(json!({ "ok": out.status.success(), "output": text }))
}

fn decide(store: &Store, id: &str, body: &str) -> Result<Value> {
    let decision = match serde_json::from_str::<Value>(body).ok().and_then(|v| v["decision"].as_str().map(str::to_string)).as_deref() {
        Some("once") => Decision::Once,
        Some("always") => Decision::Always,
        Some("deny") => Decision::Deny,
        _ => bail!("decision must be once, always or deny"),
    };
    approvals::answer(store.root(), id, decision)?;
    Ok(json!({ "ok": true }))
}

/// Pings `url` (e.g. an ntfy.sh topic) with curl: once per new question, and
/// when a task you started finishes.
fn notifier(root: PathBuf, url: String) {
    let send = |title: &str, message: &str| {
        let sent = Command::new("curl").args(["-fsS", "-m", "10", "-H", &format!("Title: {title}"), "-d", message, &url]).output();
        if !sent.is_ok_and(|o| o.status.success()) {
            eprintln!("agentd: couldn't notify {url}");
        }
    };
    let mut asked = HashSet::new();
    let mut running: HashSet<String> = HashSet::new();
    loop {
        for q in approvals::questions(&root) {
            if asked.insert(q.id.clone()) {
                send("agentos: an agent is asking", &format!("{} wants to reach {}", q.title, q.target));
            }
        }
        if let Ok(store) = Store::open_at(&root) {
            for t in store.list().unwrap_or_default() {
                let id = t.id().to_string();
                if t.is_live() {
                    running.insert(id);
                } else if running.remove(&id) {
                    let held = changes::scan(&t.layers()).map(|c| Summary::of(&c).total()).unwrap_or(0);
                    let pushes = outbox::pending(&t.dir).map(|p| p.len()).unwrap_or(0);
                    let mut what = format!("{}: {}", render::title(&t), t.status_label());
                    if held + pushes > 0 {
                        what.push_str(&format!(" · {held} changes and {pushes} pushes held for review"));
                    }
                    send("agentos: a task finished", &what);
                }
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// Reads a request body (small JSON for POSTs).
fn read_body(req: &mut Request) -> String {
    let mut body = String::new();
    let _ = req.as_reader().take(64 * 1024).read_to_string(&mut body);
    body
}
