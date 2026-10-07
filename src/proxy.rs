//! Egress proxy: the only way out of a sandbox started with `--allow`.
//!
//! The sandbox gets its own network namespace with nothing but loopback, so
//! the agent can't reach anything directly, not even DNS. A small forwarder
//! inside listens on 127.0.0.1 and hands each connection through a unix
//! socket to this proxy, which runs outside the sandbox, accepts
//! `CONNECT host:port` for allowlisted hosts only, and reports every attempt.
//!
//! ```text
//! agent ──HTTPS_PROXY──▶ 127.0.0.1:port ──▶ /run/agentos/proxy.sock ═══╪═══▶ proxy ──▶ api.anthropic.com
//!                       (forwarder, inside)                      sandbox│      (allowlist, journal)
//! ```

use crate::broker::Broker;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct Allowlist {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq)]
struct Rule {
    host: String,
    /// `*.example.com`: subdomains of `host`, not `host` itself.
    wildcard: bool,
    port: u16,
}

/// `--allow @name`: the hosts a package manager or service needs.
pub const PRESETS: &[(&str, &[&str])] = &[
    ("pypi", &["pypi.org", "files.pythonhosted.org"]),
    ("npm", &["registry.npmjs.org"]),
    ("crates", &["crates.io", "index.crates.io", "static.crates.io"]),
    ("github", &["github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com"]),
    ("go", &["proxy.golang.org", "sum.golang.org"]),
];

/// Expands `@preset` entries into their hosts.
pub fn expand(entries: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in entries {
        match entry.strip_prefix('@') {
            Some(name) => {
                let Some((_, hosts)) = PRESETS.iter().find(|(n, _)| *n == name) else {
                    let known: Vec<String> = PRESETS.iter().map(|(n, _)| format!("@{n}")).collect();
                    bail!("--allow {entry}: unknown preset (known: {})", known.join(" "));
                };
                out.extend(hosts.iter().map(|h| h.to_string()));
            }
            None => out.push(entry.clone()),
        }
    }
    Ok(out)
}

impl Allowlist {
    /// Entries look like `api.example.com`, `*.example.com`, `host:8443` or
    /// a preset like `@pypi`. The port defaults to 443.
    pub fn parse(entries: &[String]) -> Result<Allowlist> {
        let mut rules = Vec::new();
        for entry in &expand(entries)? {
            let e = entry.trim().to_ascii_lowercase();
            let (host, port) = match e.rsplit_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().with_context(|| format!("--allow {entry}: bad port"))?),
                None => (e.as_str(), 443),
            };
            let (host, wildcard) = match host.strip_prefix("*.") {
                Some(rest) => (rest, true),
                None => (host, false),
            };
            let host = host.trim_end_matches('.');
            if host.is_empty() || host.contains(['*', '/', '[', ']', ' ']) {
                bail!("--allow {entry}: expected a host like api.example.com, *.example.com or host:port");
            }
            rules.push(Rule { host: host.to_string(), wildcard, port });
        }
        Ok(Allowlist { rules })
    }

    /// The entries: "api.anthropic.com, *.example.com, internal.dev:8443".
    pub fn describe(&self) -> String {
        let entries: Vec<String> = self
            .rules
            .iter()
            .map(|r| {
                let host = if r.wildcard { format!("*.{}", r.host) } else { r.host.clone() };
                if r.port == 443 { host } else { format!("{host}:{}", r.port) }
            })
            .collect();
        if entries.is_empty() { "no hosts".into() } else { entries.join(", ") }
    }

    /// Adds an entry (as for `parse`) to a live allowlist.
    pub fn add(&mut self, entry: &str) -> Result<()> {
        self.rules.extend(Allowlist::parse(&[entry.to_string()])?.rules);
        Ok(())
    }

    pub fn allows(&self, host: &str, port: u16) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.rules.iter().any(|r| {
            r.port == port
                && if r.wildcard { host.strip_suffix(&r.host).is_some_and(|sub| sub.ends_with('.') && sub.len() > 1) } else { host == r.host }
        })
    }
}

/// One connection attempt, as recorded in the journal.
#[derive(Debug, Clone, Serialize)]
pub struct NetEvent {
    pub host: String,
    pub port: u16,
    /// Whether a tunnel was established.
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub ms: u64,
    /// Relayed by the credential broker rather than tunneled.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub brokered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requests: Option<u64>,
    /// Requests the broker added a credential to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injected: Option<u64>,
    /// Not in the allowlist, but approved when the agent asked.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub approved: bool,
}

pub type Sink = Arc<dyn Fn(NetEvent) + Send + Sync>;

/// Decides about every connection; `listed` says whether the allowlist has
/// the host. `Ok(approved)` lets it through (`approved`: although it isn't
/// listed, e.g. you said yes); `Err(reason)` refuses it, even a listed host
/// (your policy forbids it).
pub type Gate = Arc<dyn Fn(&str, u16, bool) -> std::result::Result<bool, String> + Send + Sync>;

pub struct Handle {
    active: Arc<AtomicUsize>,
}

impl Handle {
    /// Waits up to `timeout` for open connections to finish and report.
    pub fn drain(&self, timeout: Duration) {
        let start = Instant::now();
        while self.active.load(Ordering::SeqCst) > 0 && start.elapsed() < timeout {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Creates the proxy's socket. Call before forking the sandbox, which
/// mounts it; start serving with [`serve`] afterwards.
pub fn bind(path: &Path) -> Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))
}

/// An allowlist that grows while the task runs (hosts you approve when the
/// agent asks).
pub type LiveAllowlist = Arc<std::sync::RwLock<Allowlist>>;

/// Serves connections on background threads, reporting each one to `sink`.
/// Hosts the `broker` holds credentials for are relayed through it.
/// Threads must only be started after the sandbox has been forked.
pub fn serve(listener: UnixListener, allow: LiveAllowlist, broker: Option<Arc<Broker>>, gate: Option<Gate>, sink: Sink) -> Handle {
    let active = Arc::new(AtomicUsize::new(0));
    let counter = active.clone();
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            let (allow, broker, gate, sink, counter) = (allow.clone(), broker.clone(), gate.clone(), sink.clone(), counter.clone());
            thread::spawn(move || {
                if let Some(event) = handle(client, &allow, broker.as_deref(), gate.as_ref()) {
                    sink(event);
                }
                counter.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Handle { active }
}

fn handle(mut client: UnixStream, allow: &LiveAllowlist, broker: Option<&Broker>, gate: Option<&Gate>) -> Option<NetEvent> {
    let start = Instant::now();
    let head = read_head(&mut client).ok()?;
    let mut words = head.lines().next().unwrap_or_default().split_whitespace();
    let (method, target) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
    let mut event = NetEvent {
        host: String::new(),
        port: 0,
        allowed: false,
        reason: None,
        bytes_out: 0,
        bytes_in: 0,
        ms: 0,
        brokered: false,
        requests: None,
        injected: None,
        approved: false,
    };
    let mut refuse = |status: &str, reason: &str, mut event: NetEvent| {
        let _ = write!(client, "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nagentos: {reason}\n");
        event.reason = Some(reason.to_string());
        event.ms = start.elapsed().as_millis() as u64;
        Some(event)
    };

    if !method.eq_ignore_ascii_case("CONNECT") {
        (event.host, event.port) = plain_http_target(target);
        return refuse("405 Method Not Allowed", "only HTTPS (CONNECT) goes through the agentos proxy", event);
    }
    let Some((host, port)) = split_host_port(target) else {
        return refuse("400 Bad Request", "malformed CONNECT target", event);
    };
    (event.host, event.port) = (host.clone(), port);
    let listed = allow.read().is_ok_and(|a| a.allows(&host, port));
    // The agent's connection waits while you're asked.
    match gate.map(|g| g(&host, port, listed)) {
        Some(Ok(approved)) => event.approved = approved,
        Some(Err(reason)) => return refuse("403 Forbidden", &reason, event),
        None if listed => {}
        None => return refuse("403 Forbidden", "not in the allowlist", event),
    }
    let addrs: Vec<SocketAddr> = match (host.as_str(), port).to_socket_addrs() {
        Ok(a) => a.filter(|a| is_public(a.ip())).collect(),
        Err(_) => return refuse("502 Bad Gateway", "can't resolve host", event),
    };
    if addrs.is_empty() {
        // An allowed name must not become a way into the host's own services.
        return refuse("403 Forbidden", "resolves only to private or local addresses", event);
    }
    let Some(upstream) = addrs.iter().find_map(|a| TcpStream::connect_timeout(a, Duration::from_secs(10)).ok()) else {
        return refuse("502 Bad Gateway", "connection failed", event);
    };
    if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
        return None;
    }
    event.allowed = true;
    match broker.filter(|b| b.brokers(&host)) {
        Some(broker) => {
            event.brokered = true;
            match broker.relay(&host, client, upstream) {
                Ok((up, down, requests, injected)) => {
                    (event.bytes_out, event.bytes_in) = (up, down);
                    (event.requests, event.injected) = (Some(requests), Some(injected));
                }
                // Typically the agent not trusting the task CA.
                Err(e) => event.reason = Some(format!("credential relay failed: {e:#}")),
            }
        }
        None => (event.bytes_out, event.bytes_in) = pump(client, upstream),
    }
    event.ms = start.elapsed().as_millis() as u64;
    Some(event)
}

/// Reads the request head byte by byte so nothing after it is consumed.
fn read_head(s: &mut UnixStream) -> io::Result<String> {
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() > MAX_HEAD {
            return Err(io::Error::other("request head too large"));
        }
        match s.read(&mut byte)? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            _ => buf.push(byte[0]),
        }
    }
    s.set_read_timeout(None)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn split_host_port(target: &str) -> Option<(String, u16)> {
    let (host, port) = match target.strip_prefix('[') {
        Some(rest) => rest.split_once("]:")?,
        None => target.rsplit_once(':')?,
    };
    Some((host.to_ascii_lowercase(), port.parse().ok()?))
}

fn plain_http_target(url: &str) -> (String, u16) {
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or_default();
    split_host_port(authority).unwrap_or((authority.to_ascii_lowercase(), 80))
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (a == 100 && (b & 0xc0) == 64))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                let first = v6.segments()[0];
                !(v6.is_loopback() || v6.is_unspecified() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80)
            }
        },
    }
}

/// A connected, full-duplex stream.
pub trait Duplex: Read + Write + Send + Sized + 'static {
    fn split(&self) -> io::Result<Self>;
    fn close(&self, how: Shutdown);
}

impl Duplex for TcpStream {
    fn split(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn close(&self, how: Shutdown) {
        let _ = self.shutdown(how);
    }
}

impl Duplex for UnixStream {
    fn split(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn close(&self, how: Shutdown) {
        let _ = self.shutdown(how);
    }
}

/// Copies both ways until either side is done. Returns bytes (a→b, b→a).
pub fn pump<A: Duplex, B: Duplex>(a: A, b: B) -> (u64, u64) {
    let (Ok(mut a_read), Ok(mut b_write)) = (a.split(), b.split()) else { return (0, 0) };
    let forward = thread::spawn(move || {
        let n = copy(&mut a_read, &mut b_write);
        b_write.close(Shutdown::Write);
        n
    });
    let (mut b_read, mut a_write) = (b, a);
    let back = copy(&mut b_read, &mut a_write);
    // The far end is done: unblock the other direction too.
    a_write.close(Shutdown::Both);
    b_read.close(Shutdown::Both);
    (forward.join().unwrap_or(0), back)
}

fn copy(r: &mut impl Read, w: &mut impl Write) -> u64 {
    let mut buf = [0u8; 32 * 1024];
    let mut total = 0;
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => return total,
            Ok(n) => {
                if w.write_all(&buf[..n]).is_err() {
                    return total;
                }
                total += n as u64;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> Allowlist {
        Allowlist::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn allowlist_matching() {
        let a = list(&["api.anthropic.com", "*.example.com", "internal.dev:8443"]);
        assert!(a.allows("api.anthropic.com", 443));
        assert!(a.allows("API.Anthropic.com.", 443));
        assert!(!a.allows("api.anthropic.com", 80));
        assert!(!a.allows("evil-api.anthropic.com", 443));
        assert!(!a.allows("anthropic.com", 443));
        assert!(a.allows("a.b.example.com", 443));
        assert!(!a.allows("example.com", 443), "wildcards cover subdomains only");
        assert!(!a.allows("notexample.com", 443));
        assert!(a.allows("internal.dev", 8443));
        assert!(!a.allows("internal.dev", 443));
        assert!(Allowlist::parse(&["https://x.com/path".into()]).is_err());
        assert!(Allowlist::parse(&["*".into()]).is_err());

        let p = list(&["@pypi", "@github"]);
        assert!(p.allows("files.pythonhosted.org", 443) && p.allows("api.github.com", 443));
        assert!(!p.allows("example.com", 443));
        assert!(Allowlist::parse(&["@nope".into()]).is_err());

        let mut live = list(&["api.anthropic.com"]);
        live.add("pypi.org").unwrap();
        live.add("*.example.com:8443").unwrap();
        assert!(live.allows("pypi.org", 443) && live.allows("api.anthropic.com", 443));
        assert_eq!(live.describe(), "api.anthropic.com, pypi.org, *.example.com:8443");
        assert!(live.add("not a host").is_err());
    }

    #[test]
    fn connect_targets() {
        assert_eq!(split_host_port("api.anthropic.com:443"), Some(("api.anthropic.com".into(), 443)));
        assert_eq!(split_host_port("[2001:db8::1]:443"), Some(("2001:db8::1".into(), 443)));
        assert_eq!(split_host_port("nohost"), None);
        assert_eq!(plain_http_target("http://example.com/x"), ("example.com".into(), 80));
    }

    #[test]
    fn private_addresses_are_not_public() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["160.79.104.10", "1.1.1.1", "2607:6bc0::10"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
