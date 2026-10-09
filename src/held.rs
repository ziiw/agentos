//! Held tool calls: the second half of the outbox.
//!
//! A call to one of your MCP servers that changes things and whose result
//! the agent doesn't need (create an issue, post a message) can be held
//! instead of run: `tools = { create_issue = "hold" }` in your config, a
//! server's `hold = true` for all its tools that aren't read-only, or [h]
//! when you're asked. The agent is told it's queued. The call is stored in
//! the task, shown by `agent diff` with its arguments, and run by `agent
//! commit` from outside the sandbox with your credentials, together with
//! the task's files and held pushes. `agent rollback` drops it.
//!
//! The same queue holds API requests: `--hold HOST` (or `hold` under
//! `[network]`) makes the agent's writes to that host (POST, PUT, PATCH,
//! DELETE) wait here too, answered with a 202 and sent, with the credential
//! the broker would have added, when you commit.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Held {
    /// Order of arrival; calls are released in this order.
    pub seq: u32,
    pub server: String,
    pub tool: String,
    pub args: Value,
    pub at_ms: u64,
    /// For an API request rather than a tool call: all of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpPart>,
}

/// A held API request, as the agent made it, minus its credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpPart {
    pub method: String,
    pub host: String,
    /// Path and query.
    pub target: String,
    /// What the agent sent, except framing; a brokered credential's value is blank.
    pub headers: Vec<(String, String)>,
    pub credentials: Vec<Credential>,
    /// Hex.
    pub body: String,
}

/// A header that carried a brokered credential: filled in again when it's sent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    /// Index into `headers`.
    pub header: usize,
    /// The variable the real value comes from (your environment or `[secret_commands]`).
    pub env: String,
    /// The header was `Bearer …`.
    pub bearer: bool,
}

impl Held {
    /// `server.tool`, or `POST host/path` for an API request.
    pub fn target(&self) -> String {
        match &self.http {
            Some(h) => format!("{} {}{}", h.method, h.host, h.target.split('?').next().unwrap_or_default()),
            None => format!("{}.{}", self.server, self.tool),
        }
    }
}

/// A host whose writes are held: a name, as the agent connects to it.
pub fn valid_host(host: &str) -> std::result::Result<(), String> {
    let ok = !host.is_empty() && host.len() <= 253 && host.split('.').all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    if ok { Ok(()) } else { Err(format!("{host:?} isn't a host name (exact names only, like api.github.com: no wildcards or ports)")) }
}

/// What to call a set of held calls: tool calls, API requests, or either.
pub fn noun(calls: &[Held]) -> &'static str {
    match (calls.iter().any(|c| c.http.is_some()), calls.iter().any(|c| c.http.is_none())) {
        (true, false) => "API request",
        (true, true) => "held call",
        _ => "tool call",
    }
}

fn dir(task_dir: &Path) -> PathBuf {
    task_dir.join("held-calls")
}

fn file(task_dir: &Path, seq: u32) -> PathBuf {
    dir(task_dir).join(format!("{seq:04}.json"))
}

/// Stores a call, returning it with its place in the queue.
pub fn hold(task_dir: &Path, server: &str, tool: &str, args: &Value) -> Result<Held> {
    store(task_dir, server, tool, args.clone(), None)
}

/// Stores an API request the same way.
pub fn hold_http(task_dir: &Path, part: HttpPart) -> Result<Held> {
    let body = unhex(&part.body);
    let preview = match std::str::from_utf8(&body) {
        Ok(text) => text.chars().take(200).collect::<String>(),
        Err(_) => format!("({} bytes, not text)", body.len()),
    };
    let args = serde_json::json!({ "body": preview, "bytes": body.len() });
    store(task_dir, "http", &part.method.clone(), args, Some(part))
}

/// Requests held from several connections at once must not take the same place in the queue.
static QUEUE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn store(task_dir: &Path, server: &str, tool: &str, args: Value, http: Option<HttpPart>) -> Result<Held> {
    let _one_at_a_time = QUEUE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    fs::create_dir_all(dir(task_dir)).context("create held-calls")?;
    let seq = pending(task_dir)?.last().map_or(1, |h| h.seq + 1);
    let held = Held { seq, server: server.to_string(), tool: tool.to_string(), args, at_ms: crate::util::now_ms(), http };
    let tmp = dir(task_dir).join(format!(".{seq:04}.tmp"));
    fs::write(&tmp, serde_json::to_vec_pretty(&held)?)?;
    fs::rename(&tmp, file(task_dir, seq))?;
    Ok(held)
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).filter_map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()).collect()
}

/// Sends a held API request now, from this process: `secret` gives the real
/// value of a credential's variable. Returns the status and the first line of
/// the answer. Nothing is followed: a redirect is an answer.
pub fn send_http(held: &Held, secret: &dyn Fn(&str) -> Option<String>) -> std::result::Result<(u16, String), String> {
    send_http_to(held, "https", secret)
}

fn send_http_to(held: &Held, scheme_and_authority: &str, secret: &dyn Fn(&str) -> Option<String>) -> std::result::Result<(u16, String), String> {
    let part = held.http.as_ref().ok_or("not an API request")?;
    let mut headers = part.headers.clone();
    for c in &part.credentials {
        let real = secret(&c.env).ok_or_else(|| format!("{} isn't set in your environment (or by a [secret_commands] entry), so the credential can't be added", c.env))?;
        if let Some(h) = headers.get_mut(c.header) {
            h.1 = if c.bearer { format!("Bearer {real}") } else { real };
        }
    }
    let url = if scheme_and_authority.contains("://") { format!("{scheme_and_authority}{}", part.target) } else { format!("{scheme_and_authority}://{}{}", part.host, part.target) };
    let mut request = ureq::http::Request::builder().method(part.method.as_str()).uri(url.as_str());
    for (name, value) in &headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let body = unhex(&part.body);
    let request = request.body(&body[..]).map_err(|e| format!("can't build the request: {e}"))?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_connect(Some(std::time::Duration::from_secs(15)))
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .build()
        .into();
    let mut response = agent.run(request).map_err(|e| format!("{e}"))?;
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    Ok((status, text.lines().next().unwrap_or_default().chars().take(200).collect()))
}

/// The calls still held, in order.
pub fn pending(task_dir: &Path) -> Result<Vec<Held>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir(task_dir)) {
        Ok(e) => e,
        Err(_) => return Ok(out),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let raw = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            out.push(serde_json::from_slice::<Held>(&raw).with_context(|| format!("{}: corrupt", path.display()))?);
        }
    }
    out.sort_by_key(|h| h.seq);
    Ok(out)
}

/// Forgets a call: it ran, or you dropped it.
pub fn remove(task_dir: &Path, seq: u32) {
    let _ = fs::remove_file(file(task_dir, seq));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn calls_queue_in_order_and_leave_when_done() {
        let dir = tempfile::tempdir().unwrap();
        assert!(pending(dir.path()).unwrap().is_empty());
        let a = hold(dir.path(), "tracker", "create_issue", &json!({ "title": "one" })).unwrap();
        let b = hold(dir.path(), "chat", "post", &json!({ "text": "two" })).unwrap();
        assert_eq!((a.seq, b.seq), (1, 2));
        let all = pending(dir.path()).unwrap();
        assert_eq!(all.iter().map(Held::target).collect::<Vec<_>>(), ["tracker.create_issue", "chat.post"]);
        assert_eq!(all[0].args["title"], "one");
        remove(dir.path(), 1);
        let c = hold(dir.path(), "chat", "post", &json!({})).unwrap();
        assert_eq!(c.seq, 3, "numbers aren't reused while later calls wait");
        assert_eq!(pending(dir.path()).unwrap().len(), 2);
    }

    #[test]
    fn requests_held_at_the_same_moment_each_keep_their_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let threads: Vec<_> = (0..24)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    hold_http(
                        &path,
                        HttpPart { method: "POST".into(), host: "api.example.com".into(), target: format!("/n/{i}"), headers: vec![], credentials: vec![], body: String::new() },
                    )
                    .unwrap()
                    .seq
                })
            })
            .collect();
        let mut seqs: Vec<u32> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        seqs.sort();
        assert_eq!(seqs, (1..=24).collect::<Vec<_>>(), "no two took the same place");
        assert_eq!(pending(dir.path()).unwrap().len(), 24, "and none was overwritten");
    }

    #[test]
    fn api_requests_wait_without_their_credentials_and_go_out_with_them() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let part = HttpPart {
            method: "POST".into(),
            host: "api.example.com".into(),
            target: "/v1/issues?draft=1".into(),
            headers: vec![("content-type".into(), "application/json".into()), ("authorization".into(), String::new()), ("x-note".into(), "hi".into())],
            credentials: vec![Credential { header: 1, env: "TRACKER_TOKEN".into(), bearer: true }],
            body: crate::util::hex(br#"{"title":"one"}"#),
        };
        let held = hold_http(dir.path(), part.clone()).unwrap();
        assert_eq!(held.target(), "POST api.example.com/v1/issues");
        assert_eq!(held.args["body"], r#"{"title":"one"}"#);
        assert_eq!(noun(std::slice::from_ref(&held)), "API request");
        let other = hold(dir.path(), "chat", "post", &json!({})).unwrap();
        assert_eq!(noun(&[held.clone(), other]), "held call");
        assert_eq!(pending(dir.path()).unwrap()[0].http.as_ref(), Some(&part));

        // Sent to a stand-in server, with the credential put back.
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", server.local_addr().unwrap());
        let seen = std::thread::spawn(move || {
            let (mut c, _) = server.accept().unwrap();
            let (mut raw, mut buf) = (Vec::new(), [0u8; 1024]);
            while !String::from_utf8_lossy(&raw).ends_with(r#"{"title":"one"}"#) {
                let n = c.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
            }
            c.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncreated").unwrap();
            String::from_utf8(raw).unwrap()
        });
        let secret = |env: &str| (env == "TRACKER_TOKEN").then(|| "real-secret".to_string());
        let (status, first) = send_http_to(&held, &base, &secret).unwrap();
        assert_eq!((status, first.as_str()), (201, "created"));
        let raw = seen.join().unwrap();
        assert!(raw.starts_with("POST /v1/issues?draft=1 HTTP/1.1\r\n"), "{raw}");
        assert!(raw.to_lowercase().contains("authorization: bearer real-secret\r\n"), "{raw}");
        assert!(raw.contains("x-note: hi") && raw.ends_with(r#"{"title":"one"}"#), "{raw}");
        // Without the credential's value there is nothing to send.
        assert!(send_http_to(&held, &base, &|_| None).unwrap_err().contains("TRACKER_TOKEN isn't set"));
    }
}
