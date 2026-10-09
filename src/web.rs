//! `agent serve`: agentd, a small web console for your tasks and approvals,
//! so the human in the loop doesn't have to sit at the terminal.
//!
//! It listens on 127.0.0.1 by default, and every API call needs the token it
//! prints (`#token=…` in the URL keeps it out of logs). Actions run the
//! `agent` CLI itself, so starting a task, commit, push and rollback behave
//! exactly as in the terminal, with your own git and credentials. Tasks can
//! only be started in your projects: folders you list in your config, and
//! folders you've run agents in.

use crate::render::{self, Paint};
use agentos::approvals::{self, Agentd, Decision};
use agentos::config;
use agentos::gateway::{Budget, Period, Periodic};
use agentos::profiles;
use agentos::schedule::{self, Schedule};
use agentos::store::Access;
use agentos::changes::{self, Summary};
use agentos::gateway;
use agentos::outbox;
use agentos::store::{Store, Task};
use agentos::users::{self, Role};
use agentos::util;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::io::Write;
use std::path::{Path, PathBuf};
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
    // Tasks on a timer ([schedule.*] in your config), kept going across restarts.
    {
        let root = store.root().to_path_buf();
        thread::spawn(move || scheduler(root));
        let home = crate::home_dir()?;
        for s in config::load(store.root(), &home, &home).map(|c| c.schedules).unwrap_or_default() {
            let unguarded = if s.budget.is_none() && config::load(store.root(), &home, &home).map(|c| c.budget.is_none()).unwrap_or(true) { ", and no budget" } else { "" };
            println!("  {}", out.dim(format!("schedule {}: every {}{unguarded}", s.name, s.every)));
        }
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
    /// `X-Agentos-Token` or `X-Gitlab-Token`: the ways a webhook sender can present a hook's token.
    token_header: Option<String>,
    cookie: Option<String>,
    body: String,
}

fn request_parts(req: &Request) -> Parts {
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').map(|(p, q)| (p.to_string(), q.to_string())).unwrap_or((url, String::new()));
    let auth = req.headers().iter().find(|h| h.field.equiv("Authorization")).map(|h| h.value.to_string());
    let token_header = req.headers().iter().find(|h| h.field.equiv("X-Agentos-Token") || h.field.equiv("X-Gitlab-Token")).map(|h| h.value.to_string());
    let cookie = req.headers().iter().find(|h| h.field.equiv("Cookie")).map(|h| h.value.to_string());
    Parts { method: req.method().clone(), path, query, auth, token_header, cookie, body: String::new() }
}

enum Reply {
    Html(&'static str),
    Json(u16, Value),
    Png(Vec<u8>),
    /// Sends the browser elsewhere, with a cookie to set (or clear) if there is one.
    Redirect(String, Option<String>),
    /// A page for a person: what a sign-in says when it doesn't work out.
    Page(u16, String),
}

fn respond(req: Request, reply: Reply) -> std::io::Result<()> {
    let nocache = Header::from_bytes("Cache-Control", "no-store").expect("static header");
    let mut extra = Vec::new();
    let (status, body, kind) = match reply {
        Reply::Html(html) => (200, html.as_bytes().to_vec(), "text/html; charset=utf-8"),
        Reply::Json(status, value) => (status, value.to_string().into_bytes(), "application/json"),
        Reply::Png(png) => (200, png, "image/png"),
        Reply::Page(status, html) => (status, html.into_bytes(), "text/html; charset=utf-8"),
        Reply::Redirect(location, cookie) => {
            // (header values with a line break in them are refused by Header::from_bytes)
            extra.extend(Header::from_bytes("Location", location));
            extra.extend(cookie.and_then(|c| Header::from_bytes("Set-Cookie", c).ok()));
            (302, Vec::new(), "text/plain")
        }
    };
    let header = Header::from_bytes("Content-Type", kind).expect("static header");
    let mut response = Response::from_data(body).with_status_code(StatusCode(status)).with_header(header).with_header(nocache);
    for h in extra {
        response.add_header(h);
    }
    req.respond(response)
}

/// Who is asking: you (agentd's own token), or someone you gave a token and a role.
struct Who {
    name: String,
    role: Role,
    owner: bool,
    /// The folders whose tasks this person sees; none: every task.
    projects: Vec<PathBuf>,
}

impl Who {
    fn scoped(&self) -> bool {
        !self.projects.is_empty()
    }

    /// Whether a task that ran in `cwd` is theirs to see.
    fn sees(&self, cwd: &Path) -> bool {
        users::covers(&self.projects, cwd)
    }

    /// What the journal and a task's `started_by` call them.
    fn label(&self) -> String {
        if self.owner { "agentd console".to_string() } else { format!("agentd console ({})", self.name) }
    }
}

/// The least role an endpoint needs: reading is for everyone, answering and
/// the safe ways of interrupting a task for approvers, the rest for admins.
fn needs(method: &Method, segments: &[&str]) -> Role {
    match (method, segments) {
        (Method::Get, _) | (Method::Post, ["api", "logout"]) => Role::Viewer,
        (Method::Post, ["api", "approvals", _]) | (Method::Post, ["api", "tasks", _, "stop" | "revoke" | "input"]) => Role::Approver,
        _ => Role::Admin,
    }
}

fn handle_request(mut parts: Parts, root: &PathBuf, token: &str) -> Reply {
    if parts.method == Method::Get && (parts.path == "/" || parts.path == "/index.html") {
        return Reply::Html(INDEX);
    }
    let segments: Vec<&str> = parts.path.trim_matches('/').split('/').collect();
    // Signing in with your identity provider: how a person without a link gets one.
    if parts.method == Method::Get {
        match parts.path.as_str() {
            "/auth/config" => return Reply::Json(200, json!({ "sso": sso_config(root).is_some() })),
            "/login" => return sso_login(root),
            "/oidc/callback" => return sso_callback(&parts, root),
            _ => {}
        }
    }
    // A hook has a token of its own and opens nothing else.
    if let (Method::Post, ["api", "hooks", name]) = (&parts.method, segments.as_slice()) {
        return hook(&parts, name, root);
    }
    let bearer = parts.auth.as_deref().and_then(|a| a.strip_prefix("Bearer ")).map(str::to_string);
    let query_token = parts.query.split('&').find_map(|kv| kv.strip_prefix("token=")).map(str::to_string);
    let given = bearer.or(query_token);
    let who = match given.as_deref() {
        Some(t) if t == token => Who { name: "you".into(), role: Role::Admin, owner: true, projects: Vec::new() },
        Some(t) => match users::authenticate(root, t) {
            Some(u) => Who { name: u.name, role: u.role, owner: false, projects: u.projects },
            None => return Reply::Json(401, json!({ "error": "missing or wrong token: open the link agent serve printed" })),
        },
        None => return Reply::Json(401, json!({ "error": "missing or wrong token: open the link agent serve printed" })),
    };
    let needed = needs(&parts.method, &segments);
    if who.role < needed {
        return Reply::Json(403, json!({ "error": format!("{} is {} {}: that needs {} {}", who.name, article(who.role), who.role.name(), article(needed), needed.name()) }));
    }
    let store = match Store::open_at(root) {
        Ok(s) => s,
        Err(e) => return Reply::Json(500, json!({ "error": format!("{e:#}") })),
    };
    // What a person (not you) does to a task is written into its journal, under their name.
    let touched: Option<(String, String)> = match (&parts.method, segments.as_slice()) {
        (Method::Post, ["api", "tasks", id, action]) => Some((id.to_string(), action.to_string())),
        (Method::Post, ["api", "approvals", id]) => approvals::questions(store.root()).into_iter().find(|q| q.id == *id).map(|q| (q.task, format!("answered {}", q.target))),
        _ => None,
    };
    let body_for_note = parts.body.clone();
    if who.scoped() {
        if let Some(refusal) = outside(&store, &who, &parts, &segments) {
            return refusal;
        }
    }
    // A picture, not JSON: what a task's screen shows (as it is now, or as it ended).
    if let (Method::Get, ["api", "tasks", id, "screen.png"]) = (&parts.method, segments.as_slice()) {
        return match screen(&store, id, &parts.query) {
            Ok(png) => Reply::Png(png),
            Err(e) => Reply::Json(404, json!({ "error": format!("{e:#}") })),
        };
    }
    let result = match (&parts.method, segments.as_slice()) {
        (Method::Post, ["api", "logout"]) => match given.as_deref() {
            Some(t) if users::end_session(root, t) => Ok(json!({ "ok": true })),
            _ => Err(anyhow!("this isn't a single sign-on session: there is nothing to sign out of")),
        },
        (Method::Get, ["api", "whoami"]) => Ok(json!({ "name": who.name, "role": who.role.name(), "owner": who.owner, "projects": who.projects })),
        (Method::Get, ["api", "tasks"]) => tasks(&store, &who),
        (Method::Post, ["api", "tasks"]) => start(&store, &parts.body, &who.label(), None),
        (Method::Get, ["api", "launchpad"]) => launchpad(&store, &who),
        (Method::Get, ["api", "schedules"]) => schedules(&store, &who),
        (Method::Post, ["api", "schedules", name, "run"]) => run_schedule_now(&store, name, &who),
        (Method::Get, ["api", "tasks", id]) => task(&store, id),
        (Method::Post, ["api", "tasks", id, "revoke"]) => revoke(&store, id, &parts.body),
        (Method::Post, ["api", "tasks", id, "raise"]) => raise_task(&store, id, &parts.body),
        (Method::Get, ["api", "spend"]) => spend(&store),
        (Method::Post, ["api", "spend", "raise"]) => raise_shared(&store, &parts.body),
        (Method::Post, ["api", "tasks", id, "input"]) => input(&store, id, &parts.body, &who),
        (Method::Post, ["api", "tasks", id, action]) if ["commit", "push", "rollback", "stop"].contains(action) => run_cli(&store, action, id),
        (Method::Get, ["api", "approvals"]) => {
            // A task that ended while asking leaves its question behind.
            approvals::drop_stale(store.root(), |id| store.resolve(Some(id)).is_ok_and(|t| t.is_live()));
            let asked = approvals::questions(store.root());
            Ok(json!(asked.into_iter().filter(|q| !who.scoped() || store.resolve(Some(&q.task)).is_ok_and(|t| who.sees(&t.meta.cwd))).collect::<Vec<_>>()))
        }
        (Method::Post, ["api", "approvals", id]) => {
            let decision = std::mem::take(&mut parts.body);
            decide(&store, id, &decision)
        }
        _ => return Reply::Json(404, json!({ "error": "not found" })),
    };
    match result {
        Ok(v) => {
            if let (false, Some((task, action))) = (who.owner, touched)
                && let Ok(t) = store.resolve(Some(&task))
            {
                let decision = serde_json::from_str::<Value>(&body_for_note).ok().and_then(|b| b["decision"].as_str().map(str::to_string));
                let _ = t.journal().append("console.action", json!({ "by": who.name, "role": who.role.name(), "action": action, "decision": decision }));
            }
            Reply::Json(200, v)
        }
        Err(e) => Reply::Json(400, json!({ "error": format!("{e:#}") })),
    }
}

// ---- signing in with your identity provider ----

/// The settings for it, if it's set up (and where your secret commands are, for the client secret).
fn sso_config(root: &Path) -> Option<(agentos::oidc::Config, PathBuf, agentos::keychain::Commands)> {
    let home = crate::home_dir().ok()?;
    let settings = config::load(root, &home, &home).ok()?;
    Some((settings.oidc?, home, settings.secret_commands))
}

fn esc(s: &str) -> String {
    s.chars().map(|c| match c { '&' => "&amp;".into(), '<' => "&lt;".into(), '>' => "&gt;".into(), '"' => "&quot;".into(), '\'' => "&#39;".into(), c => c.to_string() }).collect()
}

/// What a person sees when signing in doesn't work out.
fn sso_page(status: u16, message: &str) -> Reply {
    Reply::Page(
        status,
        format!(
            "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width, initial-scale=1\"><title>agentd</title>\
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:34em;margin:12vh auto;padding:0 16px;color:#1d1d1b}}\
@media(prefers-color-scheme:dark){{body{{background:#141413;color:#ecebe6}}a{{color:#748ffc}}}}</style>\
<h1 style=\"font-size:20px\">agentd</h1><p>{}</p><p><a href=\"/login\">Try again</a></p>",
            esc(message)
        ),
    )
}

/// `GET /login`: off to your identity provider.
fn sso_login(root: &Path) -> Reply {
    let Some((cfg, _, _)) = sso_config(root) else { return sso_page(404, "Single sign-on isn't set up here.") };
    match agentos::oidc::begin(&cfg) {
        Ok((location, browser)) => {
            // The callback wants this cookie back: the sign-in finishes in the browser that began it.
            let cookie = format!("agentd_oidc={browser}; HttpOnly; SameSite=Lax; Path=/oidc; Max-Age=600{}", if cfg.secure() { "; Secure" } else { "" });
            Reply::Redirect(location, Some(cookie))
        }
        Err(e) => {
            eprintln!("agentd: single sign-on: {e:#}");
            sso_page(502, &format!("agentd can't reach the identity provider ({}).", e.root_cause()))
        }
    }
}

/// `GET /oidc/callback`: the provider sends the person back with a code.
fn sso_callback(parts: &Parts, root: &Path) -> Reply {
    let Some((cfg, home, commands)) = sso_config(root) else { return sso_page(404, "Single sign-on isn't set up here.") };
    let secret = match cfg.client_secret.as_deref().map(|var| agentos::keychain::lookup(var, &commands)) {
        None => None,
        Some(Ok(Some(secret))) if !secret.is_empty() => Some(secret),
        Some(_) => {
            eprintln!("agentd: single sign-on: {} isn't set where agentd runs", cfg.client_secret.as_deref().unwrap_or(""));
            return sso_page(500, "agentd's client secret for your identity provider isn't set where it runs.");
        }
    };
    let browser = parts.cookie.as_deref().and_then(|c| c.split(';').filter_map(|kv| kv.trim().strip_prefix("agentd_oidc=")).next()).map(str::to_string);
    let cleared = format!("agentd_oidc=; HttpOnly; SameSite=Lax; Path=/oidc; Max-Age=0{}", if cfg.secure() { "; Secure" } else { "" });
    let identity = match agentos::oidc::finish(&cfg, secret.as_deref(), &parts.query, browser.as_deref(), util::now_ms() / 1000) {
        Ok(id) => id,
        Err(why) => {
            eprintln!("agentd: single sign-on refused: {why}");
            return sso_page(400, &why);
        }
    };
    let (role, projects) = match agentos::oidc::grant(&cfg, &identity) {
        Ok(Some(granted)) => granted,
        Ok(None) => {
            eprintln!("agentd: single sign-on: {} has no role", identity.name());
            return sso_page(403, &format!("You're signed in as {}, but agentd has no role for you. Ask whoever runs it to add you under [console.oidc.roles].", identity.email.as_deref().unwrap_or(&identity.sub)));
        }
        Err(why) => return sso_page(500, &why),
    };
    // A role limited to projects stays limited, even if a folder isn't there (it then matches nothing).
    let projects: Vec<PathBuf> = projects.iter().map(|p| expand(&home, p)).map(|p| fs::canonicalize(&p).unwrap_or(p)).collect();
    match cfg.session_ttl().and_then(|ttl| users::start_session(root, &identity.name(), role, &projects, ttl)) {
        Ok(token) => {
            eprintln!("agentd: {} signed in as {}", identity.name(), role.name());
            Reply::Redirect(format!("/#token={token}"), Some(cleared))
        }
        Err(e) => sso_page(500, &format!("{e:#}")),
    }
}

/// What a token limited to some projects may not touch. A task or a
/// question elsewhere is answered the way one that doesn't exist is, so
/// nothing tells them it's there; such a token names a task by its whole id
/// (a prefix could match one it can't see).
fn outside(store: &Store, who: &Who, parts: &Parts, segments: &[&str]) -> Option<Reply> {
    let refuse = |status: u16, why: String| Some(Reply::Json(status, json!({ "error": why })));
    match (&parts.method, segments) {
        (Method::Post, ["api", "tasks"]) => {
            // (a body that isn't a request is for `start` to complain about)
            let project = serde_json::from_str::<Value>(&parts.body).ok().and_then(|v| v["project"].as_str().map(PathBuf::from))?;
            if fs::canonicalize(&project).is_ok_and(|p| who.sees(&p)) {
                return None;
            }
            refuse(403, format!("{}'s token is limited to {}", who.name, who.projects.iter().map(|p| util::display_path(p)).collect::<Vec<_>>().join(", ")))
        }
        (_, ["api", "tasks", id, rest @ ..]) => {
            if store.list().ok()?.iter().any(|t| t.id() == *id && who.sees(&t.meta.cwd)) {
                return None;
            }
            refuse(if rest == ["screen.png"] { 404 } else { 400 }, format!("no task matching '{id}' (see `agent ls`)"))
        }
        (Method::Post, ["api", "approvals", id]) => {
            let q = approvals::questions(store.root()).into_iter().find(|q| q.id == *id)?;
            if store.resolve(Some(&q.task)).is_ok_and(|t| who.sees(&t.meta.cwd)) {
                return None;
            }
            refuse(400, "no such question".into())
        }
        // Money across tasks isn't split by project.
        (_, ["api", "spend", ..]) => refuse(403, format!("{}'s token is limited to some projects: budgets across tasks are for tokens that aren't", who.name)),
        (Method::Post, ["api", "schedules", name, "run"]) => {
            let home = crate::home_dir().ok()?;
            let s = config::load(store.root(), &home, &home).ok()?.schedules.into_iter().find(|s| s.name == *name)?;
            if fs::canonicalize(expand(&home, &s.project)).is_ok_and(|p| who.sees(&p)) {
                return None;
            }
            refuse(400, format!("no [schedule.{name}] in your config"))
        }
        _ => None,
    }
}

/// A project as a config writes it (`~/code/app` or absolute).
fn expand(home: &Path, project: &str) -> PathBuf {
    match project.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if project == "~" => home.to_path_buf(),
        None => PathBuf::from(project),
    }
}

fn task_json(t: &Task) -> Value {
    let open = t.is_open();
    let summary = if open { changes::scan(&t.layers()).ok().map(|c| Summary::of(&c)) } else { None };
    let pushes = if open { outbox::pending(&t.dir).map(|p| p.len()).unwrap_or(0) } else { 0 };
    // Tool calls and API requests held for review, sent with the pushes.
    let calls = if open { agentos::held::pending(&t.dir).map(|c| c.len()).unwrap_or(0) } else { 0 };
    let live = t.is_live();
    let events = if live { t.journal().read().unwrap_or_default() } else { Vec::new() };
    // What a running task is up to: its latest tool call or connection.
    let doing = events.iter().rev().find_map(|e| match e.kind.as_str() {
        "agent.tool" => Some(format!("{} {}", e.data["name"].as_str()?, e.data["target"].as_str().unwrap_or(""))),
        "net.connect" => Some(format!("connected to {}", e.data["host"].as_str()?)),
        _ => None,
    });
    // Spent on model calls: running totals while live, the final count after.
    let (cost, tokens) = match &t.meta.usage {
        Some(u) if u.calls > 0 => (Some(u.cost_usd), Some(u.usage.tokens())),
        _ => match events.iter().rev().find(|e| e.kind == "model.call") {
            Some(e) => (e.data["total"]["cost_usd"].as_f64(), e.data["total"]["tokens"].as_u64()),
            None => (None, None),
        },
    };
    json!({
        "id": t.id(),
        "title": render::title(t),
        "status": t.status_label(),
        "live": live,
        "doing": doing,
        "cost": cost.map(gateway::usd),
        "tokens": tokens.map(gateway::tokens),
        "budget": live_budget(t, &events).map(|b| b.to_string()),
        "open": open,
        "started_ms": t.meta.started_at_ms,
        "changes": summary,
        "pushes": pushes,
        "calls": calls,
        "screen": agentos::display::info(&t.dir)
            .filter(|_| agentos::display::is_up(&t.dir) || t.dir.join(agentos::display::FINAL).is_file())
            .map(|i| json!({ "width": i.width, "height": i.height, "live": t.is_live() && agentos::display::is_up(&t.dir) })),
    })
}

/// A task's budget: as raised while it runs, if it was.
fn live_budget(t: &Task, events: &[agentos::journal::Event]) -> Option<Budget> {
    let raised = events.iter().rev().find(|e| e.kind == "budget.raised" && e.data["scope"] == "task");
    raised.and_then(|e| serde_json::from_value(e.data["to"].clone()).ok()).or(t.meta.budget)
}

fn tasks(store: &Store, who: &Who) -> Result<Value> {
    let list: Vec<Value> = store.list()?.iter().rev().filter(|t| who.sees(&t.meta.cwd)).take(50).map(task_json).collect();
    Ok(json!(list))
}

fn task(store: &Store, id: &str) -> Result<Value> {
    let t = store.resolve(Some(id))?;
    let changes = changes::scan(&t.layers())?;
    let pushes = if t.is_open() { crate::held_pushes(&t)? } else { Vec::new() };
    let events = t.journal().read().unwrap_or_default();
    let mut v = task_json(&t);
    v["diff"] = json!(render::diff(Paint::plain(), &t, &changes, &pushes, &(if t.is_open() { agentos::held::pending(&t.dir).unwrap_or_default() } else { Vec::new() }), false, false));
    v["log"] = json!(render::log(Paint::plain(), &t, &events));
    v["output"] = json!(output_tail(&t, 16 * 1024));
    // What you granted while it runs, to take back.
    if t.is_live() {
        let socket = t.dir.join(agentos::control::OWNER_SOCKET);
        if let Ok(reply) = agentos::control::call(&socket, &agentos::control::Call::Given) {
            v["given"] = serde_json::from_str(&reply.text).unwrap_or(Value::Null);
        }
    }
    Ok(v)
}

/// Takes back a folder or host from a running task.
fn revoke(store: &Store, id: &str, body: &str) -> Result<Value> {
    let t = store.resolve(Some(id))?;
    let target = serde_json::from_str::<Value>(body).ok().and_then(|v| v["target"].as_str().map(str::to_string)).context("expected {target}")?;
    let reply = agentos::control::call(&t.dir.join(agentos::control::OWNER_SOCKET), &agentos::control::Call::Revoke { target })?;
    Ok(json!({ "ok": reply.ok, "output": reply.text }))
}

/// The end of what a background task printed.
fn output_tail(t: &Task, max: u64) -> Option<String> {
    use std::io::{Seek, SeekFrom};
    let mut f = fs::File::open(t.dir.join("output.log")).ok()?;
    let len = f.metadata().ok()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(max))).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    // Cut at a line boundary when it's a tail.
    Some(if len > max { text.split_once('\n').map(|(_, rest)| rest.to_string()).unwrap_or(text) } else { text })
}

/// Folders tasks can be started in from the console, most recent first:
/// those you list (`[console] projects`), and those you've run agents in.
fn projects(store: &Store, home: &Path) -> Result<Vec<PathBuf>> {
    let settings = config::load(store.root(), home, home)?;
    let mut used: Vec<(u64, PathBuf)> = store
        .list()?
        .into_iter()
        .filter(|t| t.meta.grants.iter().any(|g| g.access == Access::Rw && g.path == t.meta.cwd))
        .map(|t| (t.meta.started_at_ms, t.meta.cwd))
        .collect();
    used.sort_by(|a, b| b.0.cmp(&a.0));
    let mut out: Vec<PathBuf> = Vec::new();
    for p in settings.projects.into_iter().chain(used.into_iter().map(|(_, p)| p)) {
        let ok = p.is_dir() && crate::cwd_refusal(&p, home, store.root()).is_none();
        if ok && !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(out)
}

/// What the "new task" form offers: your projects and your agents.
fn launchpad(store: &Store, who: &Who) -> Result<Value> {
    let home = crate::home_dir()?;
    let default = config::load(store.root(), &home, &home)?.agent.unwrap_or_else(|| "claude".into());
    let agents: Vec<Value> = profiles::available(&crate::agents_dir(&home))
        .into_iter()
        .map(|a| json!({ "name": a.name, "installed": a.program.is_some(), "default": a.name == default }))
        .collect();
    let projects: Vec<Value> = projects(store, &home)?
        .iter()
        .filter(|p| who.sees(p))
        .map(|p| json!({ "path": p, "shown": util::display_path(p) }))
        .collect();
    Ok(json!({ "projects": projects, "agents": agents }))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    project: PathBuf,
    task: String,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    budget: Option<String>,
    #[serde(default)]
    timeout: Option<String>,
}

/// Only one hook at a time is checked against what agentd remembers of it.
static HOOKS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Whether two secrets are the same, without telling how much of one was right.
fn same_secret(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};
    Sha256::digest(a.as_bytes()).iter().zip(Sha256::digest(b.as_bytes()).iter()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// `POST /api/hooks/NAME`: an event starts the hook's task. Its token is
/// the only credential that works here, and works nowhere else; the event's
/// words are untrusted, so the task starts tainted.
fn hook(parts: &Parts, name: &str, root: &PathBuf) -> Reply {
    let wrong = || Reply::Json(401, json!({ "error": "missing or wrong token for this hook" }));
    let broken = |why: String| Reply::Json(500, json!({ "error": why }));
    let (Ok(store), Ok(home)) = (Store::open_at(root), crate::home_dir()) else { return broken("agentd can't open its store".into()) };
    let Ok(settings) = config::load(root, &home, &home) else { return broken("agentd can't read its config".into()) };
    // An unknown hook and a wrong token look the same from outside.
    let Some(h) = settings.hooks.iter().find(|h| h.name == name) else { return wrong() };
    let given = parts.auth.as_deref().and_then(|a| a.strip_prefix("Bearer ")).map(str::to_string).or_else(|| parts.token_header.clone());
    let Some(given) = given else { return wrong() };
    let want = match agentos::keychain::lookup(&h.token, &settings.secret_commands) {
        Ok(Some(v)) if !v.is_empty() => v,
        _ => return broken(format!("the hook's token ({}) isn't set where agentd runs", h.token)),
    };
    let _one_at_a_time = HOOKS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut states = schedule::load_hooks(root);
    let state = states.entry(h.name.clone()).or_default();
    if !same_secret(&given, &want) {
        state.refused += 1;
        let _ = schedule::save_hooks(root, &states);
        return wrong();
    }
    let now = util::now_ms();
    let every = h.min_interval().unwrap_or(Duration::from_secs(60));
    if now < state.last_fire_ms + every.as_millis() as u64 {
        state.refused += 1;
        let _ = schedule::save_hooks(root, &states);
        return Reply::Json(429, json!({ "error": format!("too soon: this hook runs at most every {}", humantime::format_duration(every)) }));
    }
    if state.last_task.as_deref().is_some_and(|id| store.resolve(Some(id)).is_ok_and(|t| t.is_live())) {
        state.refused += 1;
        let _ = schedule::save_hooks(root, &states);
        return Reply::Json(409, json!({ "error": "the last run of this hook is still going" }));
    }
    let project = match h.project.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(&h.project),
    };
    let body = json!({ "project": project, "task": h.task_for(&parts.body), "agent": h.agent, "budget": h.budget, "timeout": h.timeout });
    match start(&store, &body.to_string(), &format!("agentd hook {}", h.name), Some(&format!("hook {}", h.name))) {
        Ok(v) => {
            state.last_fire_ms = now;
            state.last_task = v["id"].as_str().map(str::to_string);
            state.fired += 1;
            let _ = schedule::save_hooks(root, &states);
            Reply::Json(202, v)
        }
        Err(e) => Reply::Json(400, json!({ "error": format!("{e:#}") })),
    }
}

/// Only one thing at a time changes what agentd remembers of its schedules.
static SCHEDULES: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Checks every few seconds which schedules are due and starts them. Reads your
/// config each time, so editing a schedule needs no restart.
fn scheduler(root: PathBuf) {
    loop {
        thread::sleep(Duration::from_secs(5));
        let (Ok(store), Ok(home)) = (Store::open_at(&root), crate::home_dir()) else { continue };
        let Ok(settings) = config::load(&root, &home, &home) else { continue };
        let _one_at_a_time = SCHEDULES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut states = schedule::load(&root);
        let (now, mut changed) = (util::now_ms(), false);
        for s in &settings.schedules {
            let state = states.entry(s.name.clone()).or_insert_with(|| {
                changed = true;
                schedule::State::new(now)
            });
            if s.interval().is_ok_and(|every| state.due(now, every)) {
                let _ = fire(&store, &home, s, state, now);
                changed = true;
            }
        }
        if changed {
            let _ = schedule::save(&root, &states);
        }
    }
}

/// Starts a schedule's task, unless its last one is still going. The task
/// is started as from the console, and says which schedule started it.
fn fire(store: &Store, home: &Path, s: &Schedule, state: &mut schedule::State, now: u64) -> Result<String> {
    if state.last_task.as_deref().is_some_and(|id| store.resolve(Some(id)).is_ok_and(|t| t.is_live())) {
        state.skipped += 1;
        state.last_error = Some("the previous run is still going".into());
        bail!("the previous run of {} is still going", s.name);
    }
    let started = (|| -> Result<String> {
        let project = match s.project.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None if s.project == "~" => home.to_path_buf(),
            None if Path::new(&s.project).is_absolute() => PathBuf::from(&s.project),
            None => bail!("project {}: use an absolute path or ~/…", s.project),
        };
        let project = fs::canonicalize(&project).with_context(|| format!("project {}: no such folder", s.project))?;
        let body = json!({ "project": project, "task": s.task, "agent": s.agent, "budget": s.budget, "timeout": s.timeout });
        let started = start(store, &body.to_string(), &format!("agentd schedule {}", s.name), None)?;
        started["id"].as_str().map(str::to_string).context("agentd didn't get a task id back")
    })();
    state.last_start_ms = now;
    match started {
        Ok(id) => {
            state.last_task = Some(id.clone());
            state.runs += 1;
            state.last_error = None;
            Ok(id)
        }
        Err(e) => {
            state.last_error = Some(format!("{e:#}"));
            Err(e)
        }
    }
}

/// Your schedules and where each stands.
fn schedules(store: &Store, who: &Who) -> Result<Value> {
    let home = crate::home_dir()?;
    let settings = config::load(store.root(), &home, &home)?;
    let states = schedule::load(store.root());
    Ok(json!(settings
        .schedules
        .iter()
        .filter(|s| !who.scoped() || fs::canonicalize(expand(&home, &s.project)).is_ok_and(|p| who.sees(&p)))
        .map(|s| {
            let state = states.get(&s.name).cloned().unwrap_or_default();
            let next = (state.first_seen_ms > 0).then(|| s.interval().ok().map(|every| state.next_ms(every))).flatten();
            json!({
                "name": s.name, "every": s.every, "project": s.project, "task": s.task, "agent": s.agent,
                "next_ms": next, "last_start_ms": state.last_start_ms, "last_task": state.last_task,
                "runs": state.runs, "skipped": state.skipped, "error": state.last_error,
            })
        })
        .collect::<Vec<_>>()))
}

/// "Run now": a schedule's task, ahead of its time. The next run is an interval from now.
fn run_schedule_now(store: &Store, name: &str, who: &Who) -> Result<Value> {
    let home = crate::home_dir()?;
    let s = config::load(store.root(), &home, &home)?.schedules.into_iter().find(|s| s.name == name).with_context(|| format!("no [schedule.{name}] in your config"))?;
    let _one_at_a_time = SCHEDULES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut states = schedule::load(store.root());
    let now = util::now_ms();
    let state = states.entry(s.name.clone()).or_insert_with(|| schedule::State::new(now));
    let result = fire(store, &home, &s, state, now);
    schedule::save(store.root(), &states)?;
    let id = result?;
    if let Ok(t) = store.resolve(Some(&id)) {
        let _ = t.journal().append("console.action", json!({ "by": who.name, "role": who.role.name(), "action": format!("ran schedule {name} now"), "decision": null }));
    }
    Ok(json!({ "id": id }))
}

/// What a task's screen shows: live while it runs, else the picture it left.
/// `?w=N` brings it down to N pixels wide (live pictures only).
fn screen(store: &Store, id: &str, query: &str) -> Result<Vec<u8>> {
    let t = store.resolve(Some(id))?;
    let width = query.split('&').find_map(|kv| kv.strip_prefix("w=")).and_then(|v| v.parse::<u32>().ok()).map(|w| w.clamp(160, 3840));
    if t.is_live() && agentos::display::is_up(&t.dir) {
        return agentos::display::screenshot_file(&t.dir.join("fb/Xvfb_screen0"), width);
    }
    fs::read(t.dir.join(agentos::display::FINAL)).with_context(|| format!("task {} has no screen", t.id()))
}

/// A person acting on a running task's screen: a click, a key, some typing.
/// The text typed is never journaled, only that something was.
fn input(store: &Store, id: &str, body: &str, who: &Who) -> Result<Value> {
    use agentos::display::Input;
    let t = store.resolve(Some(id))?;
    if !t.is_live() || !agentos::display::is_up(&t.dir) {
        bail!("task {} has no screen up: it isn't running, or wasn't started with --display", t.id());
    }
    let v: Value = serde_json::from_str(body).context("expected {kind: click|key|type, …}")?;
    let num = |k: &str| v[k].as_u64().and_then(|n| u32::try_from(n).ok());
    let action = match v["kind"].as_str() {
        Some("click") => Input::Click { x: num("x").context("click needs x")?, y: num("y").context("click needs y")?, button: num("button").unwrap_or(1) },
        Some("key") => Input::Key(v["key"].as_str().context("key needs {key}")?.to_string()),
        Some("type") => Input::Type(v["text"].as_str().context("type needs {text}")?.to_string()),
        _ => bail!("kind is click, key or type"),
    };
    agentos::display::act(&t.dir, &action)?;
    let what = match &action {
        Input::Click { x, y, button } => json!({ "kind": "click", "x": x, "y": y, "button": button }),
        Input::Key(key) => json!({ "kind": "key", "key": key }),
        Input::Type(text) => json!({ "kind": "type", "characters": text.chars().count() }),
    };
    let _ = t.journal().append("display.input", json!({ "by": who.name, "input": what }));
    Ok(json!({ "ok": true }))
}

fn article(role: Role) -> &'static str {
    if role == Role::Viewer { "a" } else { "an" }
}

/// Starts `agent do --bg` in one of your projects, exactly as from a
/// terminal there. Returns the task's id.
fn start(store: &Store, body: &str, by: &str, tainted_by: Option<&str>) -> Result<Value> {
    let req: Start = serde_json::from_str(body).context("expected {project, task, agent?, budget?, timeout?}")?;
    let home = crate::home_dir()?;
    let blank = |s: &Option<String>| s.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let (agent, budget, timeout) = (blank(&req.agent), blank(&req.budget), blank(&req.timeout));
    if !projects(store, &home)?.contains(&req.project) {
        bail!("{} isn't one of your projects: run an agent there from a terminal first, or list it under [console] projects in your config", util::display_path(&req.project));
    }
    let task = req.task.trim();
    if task.is_empty() || task.len() > 20_000 {
        bail!("describe the task (up to 20,000 characters)");
    }
    if let Some(a) = &agent {
        if !profiles::available(&crate::agents_dir(&home)).iter().any(|x| x.name == *a) {
            bail!("unknown agent '{a}'");
        }
    }
    if let Some(b) = &budget {
        b.parse::<Budget>().map_err(|e| anyhow!("budget {e}"))?;
    }
    if let Some(t) = &timeout {
        humantime::parse_duration(t).with_context(|| format!("timeout {t}: expected e.g. 30m or 2h"))?;
    }
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.current_dir(&req.project).args(["do", "--bg"]);
    for (flag, value) in [("--agent", &agent), ("--budget", &budget), ("--timeout", &timeout)] {
        if let Some(v) = value {
            cmd.args([flag, v]);
        }
    }
    // Whatever agentd's own environment says, a task is tainted at the start only by the hook that started it.
    cmd.env_remove("AGENTOS_START_TAINT");
    if let Some(why) = tainted_by {
        cmd.env("AGENTOS_START_TAINT", why);
    }
    let out = cmd
        .arg("--")
        .arg(task)
        .env("AGENTOS_HOME", store.root())
        .env("NO_COLOR", "1")
        .env(crate::STARTED_BY, by)
        .stdin(std::process::Stdio::null())
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    match stdout.lines().last().map(str::trim) {
        Some(id) if out.status.success() && !id.is_empty() => Ok(json!({ "id": id })),
        _ => bail!("{}", String::from_utf8_lossy(&out.stderr).trim()),
    }
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
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let decision = match v["decision"].as_str() {
        Some("once") => Decision::Once,
        Some("call") => Decision::Call,
        Some("hold") => Decision::Hold,
        Some("always") => Decision::Always,
        Some("deny") => Decision::Deny,
        // A budget question: how far to raise it.
        Some("raise") => {
            let to: Budget = v["to"].as_str().context("raise needs {to}, e.g. 2usd")?.parse().map_err(|e| anyhow!("{e}"))?;
            approvals::answer_raise(store.root(), id, to)?;
            return Ok(json!({ "ok": true }));
        }
        _ => bail!("decision must be once, call, always, deny or raise"),
    };
    approvals::answer(store.root(), id, decision)?;
    Ok(json!({ "ok": true }))
}

/// Raises a running task's own budget (as `agent raise AMOUNT` does).
fn raise_task(store: &Store, id: &str, body: &str) -> Result<Value> {
    let t = store.resolve(Some(id))?;
    let to: Budget = serde_json::from_str::<Value>(body).ok().and_then(|v| v["to"].as_str().map(str::to_string)).context("expected {to}")?.parse().map_err(|e| anyhow!("{e}"))?;
    if !t.is_live() {
        bail!("task {} isn't running: its budget can't change anymore", t.id());
    }
    let call = agentos::control::Call::Raise { to: to.spec(), by: approvals::IN_AGENTD.into() };
    let reply = agentos::control::call(&t.dir.join(agentos::control::OWNER_SOCKET), &call)?;
    Ok(json!({ "ok": reply.ok, "output": reply.text }))
}

/// Your budgets across tasks: yours, and those of your projects.
fn shared_budgets(store: &Store, home: &Path) -> Result<Vec<Periodic>> {
    let mut out: Vec<Periodic> = config::load(store.root(), home, home)?
        .periodic
        .into_iter()
        .filter(|(_, _, mine)| !mine)
        .map(|(period, amount, _)| Periodic { amount, period, project: None })
        .collect();
    for dir in projects(store, home)? {
        let Ok(settings) = config::load(store.root(), &dir, home) else { continue };
        let project = approvals::project_root(&dir, home);
        for (period, amount, mine) in settings.periodic {
            let b = Periodic { amount, period, project: Some(project.clone()) };
            if mine && !out.contains(&b) {
                out.push(b);
            }
        }
    }
    Ok(out)
}

/// What agents spent, today, this week and this month; where each budget
/// across tasks stands; and today's tasks by what they spent.
fn spend(store: &Store) -> Result<Value> {
    let home = crate::home_dir()?;
    let ledger = crate::open_ledger(store, &home)?;
    let now = util::now_ms();
    let periods: Vec<Value> = Period::ALL
        .iter()
        .map(|p| {
            let (usd, tokens) = ledger.spent(p.start(now), None);
            json!({ "period": p.key(), "label": p.label(), "spent": gateway::usd(usd), "tokens": gateway::tokens(tokens) })
        })
        .collect();
    let budgets: Vec<Value> = shared_budgets(store, &home)?
        .iter()
        .map(|b| {
            let st = ledger.standing(b, now);
            json!({
                "period": b.period.key(),
                "label": b.period.label(),
                "resets": b.period.resets(),
                "project": b.project,
                "scope": b.project.as_deref().map(util::display_path).unwrap_or_else(|| "all your tasks".into()),
                "spent": st.against(),
                "cap": st.cap.to_string(),
                "configured": b.amount.to_string(),
                "raised": st.raised,
                "fraction": st.fraction(),
                "over": st.over(),
                "offers": st.offers().iter().map(|o| json!({ "shown": o.to_string(), "to": o.spec() })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let today: Vec<Value> = ledger
        .by_task(Period::Day.start(now))
        .into_iter()
        .take(8)
        .map(|(id, usd, tokens)| {
            let title = store.resolve(Some(&id)).map(|t| render::title(&t)).unwrap_or_else(|_| id.clone());
            json!({ "id": id, "title": title, "spent": gateway::usd(usd), "tokens": gateway::tokens(tokens) })
        })
        .collect();
    Ok(json!({ "periods": periods, "budgets": budgets, "today": today }))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RaiseShared {
    period: String,
    #[serde(default)]
    project: Option<PathBuf>,
    to: String,
}

/// Raises a budget across tasks until it resets (as `agent raise AMOUNT
/// --today` does), for all your tasks or one of your projects.
fn raise_shared(store: &Store, body: &str) -> Result<Value> {
    let req: RaiseShared = serde_json::from_str(body).context("expected {period, project?, to}")?;
    let home = crate::home_dir()?;
    let period = Period::ALL.into_iter().find(|p| p.key() == req.period).context("period must be daily, weekly or monthly")?;
    let to: Budget = req.to.parse().map_err(|e| anyhow!("{e}"))?;
    let cwd = match &req.project {
        Some(p) => projects(store, &home)?
            .into_iter()
            .find(|dir| approvals::project_root(dir, &home) == *p)
            .with_context(|| format!("{} isn't one of your projects", util::display_path(p)))?,
        None => home.clone(),
    };
    let text = crate::raise_shared(store, &home, &cwd, period, req.project.is_some(), to, approvals::IN_AGENTD)?;
    Ok(json!({ "ok": true, "output": text }))
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
                let what = match q.kind {
                    approvals::Kind::Host => "to reach",
                    approvals::Kind::Read => "to read",
                    approvals::Kind::Write => "to change",
                    approvals::Kind::Tool => "to call",
                    approvals::Kind::Budget => {
                        let spent = q.reason.as_deref().map(|r| format!(" ({r})")).unwrap_or_default();
                        send("agentos: a budget is used up", &format!("{}: {} is used up{spent}. Raise it?", q.title, q.target));
                        continue;
                    }
                };
                send("agentos: an agent is asking", &format!("{} asks {what} {}", q.title, q.target));
            }
        }
        if let Ok(store) = Store::open_at(&root) {
            for t in store.list().unwrap_or_default() {
                let id = t.id().to_string();
                if t.is_live() {
                    running.insert(id);
                } else if running.remove(&id) {
                    let held = changes::scan(&t.layers()).map(|c| Summary::of(&c).total()).unwrap_or(0);
                    let pushes = outbox::pending(&t.dir).map(|p| p.len()).unwrap_or(0) + agentos::held::pending(&t.dir).map(|c| c.len()).unwrap_or(0);
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
