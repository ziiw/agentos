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

    /// Removes an entry (as given to `parse` or `add`); returns whether it was there.
    pub fn remove(&mut self, entry: &str) -> bool {
        let Ok(gone) = Allowlist::parse(&[entry.to_string()]) else { return false };
        let before = self.rules.len();
        self.rules.retain(|r| !gone.rules.contains(r));
        self.rules.len() != before
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

/// A proxy the egress proxy goes through to reach the internet, typically a
/// corporate one (an HTTP `CONNECT` proxy, or SOCKS5): allowed connections are
/// tunneled through it instead of being made directly. It's reached by this process, outside the sandbox,
/// so the sandbox never sees it or its password.
#[derive(Clone)]
pub struct Upstream {
    host: String,
    port: u16,
    /// HTTP `CONNECT` (the usual corporate proxy) or SOCKS5 (an `ssh -D` tunnel, say).
    socks: bool,
    /// For HTTP: `Basic …`, for `Proxy-Authorization`, from `user:password@` in the URL.
    auth: Option<String>,
    /// For SOCKS5: the user and password from the URL (RFC 1929).
    login: Option<(String, String)>,
    /// Hosts reached directly (NO_PROXY).
    bypass: Vec<Bypass>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Upstream({})", self.describe())
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Bypass {
    All,
    /// `example.com`, `.example.com` or `*.example.com`: that name and its subdomains.
    Domain(String, Option<u16>),
    /// `10.0.0.0/8`, or one address.
    Net(u32, u8, Option<u16>),
}

impl Bypass {
    fn parse(entry: &str) -> Option<Bypass> {
        let e = entry.trim().to_ascii_lowercase();
        if e.is_empty() {
            return None;
        }
        if e == "*" {
            return Some(Bypass::All);
        }
        let (name, port) = match e.rsplit_once(':') {
            Some((n, p)) if !n.contains(':') && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (n, p.parse().ok()),
            _ => (e.as_str(), None),
        };
        let (addr, bits) = name.split_once('/').unwrap_or((name, "32"));
        if let (Ok(ip), Ok(bits)) = (addr.parse::<std::net::Ipv4Addr>(), bits.parse::<u8>()) {
            return (bits <= 32).then(|| Bypass::Net(u32::from(ip), bits, port));
        }
        let domain = name.trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.');
        (!domain.is_empty() && !domain.contains(['/', '*', ' '])).then(|| Bypass::Domain(domain.to_string(), port))
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        match self {
            Bypass::All => true,
            Bypass::Domain(domain, p) => {
                p.is_none_or(|p| p == port) && (host == domain || host.strip_suffix(domain.as_str()).is_some_and(|sub| sub.ends_with('.')))
            }
            Bypass::Net(net, bits, p) => {
                let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - u32::from(*bits)) };
                p.is_none_or(|p| p == port) && host.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| u32::from(ip) & mask == net & mask)
            }
        }
    }
}

impl Upstream {
    /// `url` is `http://[user[:password]@]host[:port]` or `socks5://…` (the
    /// name is resolved by the proxy either way). `no_proxy`: hosts to reach
    /// directly (`example.com` and its subdomains, `10.0.0.0/8`, `*`).
    pub fn parse(url: &str, no_proxy: &[String]) -> Result<Upstream> {
        let (socks, rest) = match url.trim().split_once("://") {
            Some(("http", rest)) => (false, rest),
            Some(("socks5" | "socks5h", rest)) => (true, rest),
            Some((scheme, _)) => bail!("{scheme}:// proxies aren't supported, only http:// and socks5:// ones (the tunnel to the host is TLS either way)"),
            None => (false, url.trim()),
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let (userinfo, hostport) = authority.rsplit_once('@').map_or((None, authority), |(u, h)| (Some(u), h));
        let (host, port) = match hostport.strip_prefix('[') {
            Some(v6) => {
                let (host, after) = v6.split_once(']').context("unbalanced [ in the proxy address")?;
                (host, after.strip_prefix(':').filter(|p| !p.is_empty()))
            }
            None => match hostport.rsplit_once(':') {
                Some((h, p)) => (h, Some(p).filter(|p| !p.is_empty())),
                None => (hostport, None),
            },
        };
        let port = port.map(|p| p.parse::<u16>().with_context(|| format!("bad proxy port {p:?}"))).transpose()?.unwrap_or(if socks { 1080 } else { 80 });
        if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c.is_control()) {
            bail!("expected a proxy like http://proxy.example.com:3128 or socks5://127.0.0.1:1080");
        }
        let auth = userinfo.filter(|_| !socks).map(|u| format!("Basic {}", crate::util::base64(percent_decode(u).as_bytes())));
        let login = userinfo.filter(|_| socks).map(|u| {
            let (user, password) = u.split_once(':').unwrap_or((u, ""));
            (percent_decode(user), percent_decode(password))
        });
        if login.as_ref().is_some_and(|(u, p)| u.len() > 255 || p.len() > 255) {
            bail!("a SOCKS5 user name and password are at most 255 bytes each");
        }
        let bypass = no_proxy.iter().flat_map(|l| l.split(',')).filter_map(Bypass::parse).collect();
        Ok(Upstream { host: host.to_ascii_lowercase(), port, socks, auth, login, bypass })
    }

    /// The proxy your shell uses: `HTTPS_PROXY` (or `ALL_PROXY`), minus `NO_PROXY`.
    pub fn from_env() -> Result<Option<Upstream>> {
        let var = |names: &[&str]| names.iter().find_map(|n| std::env::var(n).ok().filter(|v| !v.trim().is_empty()));
        let Some((name, url)) = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"].iter().find_map(|n| var(&[n]).map(|v| (*n, v))) else {
            return Ok(None);
        };
        let no_proxy: Vec<String> = var(&["NO_PROXY", "no_proxy"]).into_iter().collect();
        Upstream::parse(&url, &no_proxy).map(Some).with_context(|| format!("{name} in your environment"))
    }

    /// Hosts to reach directly, besides those already listed.
    pub fn bypassing(mut self, entries: &[String]) -> Upstream {
        self.bypass.extend(entries.iter().flat_map(|l| l.split(',')).filter_map(Bypass::parse));
        self
    }

    /// `host:port`, never the password.
    pub fn describe(&self) -> String {
        if self.host.contains(':') { format!("[{}]:{}", self.host, self.port) } else { format!("{}:{}", self.host, self.port) }
    }

    fn bypasses(&self, host: &str, port: u16) -> bool {
        self.bypass.iter().any(|b| b.matches(host, port))
    }

    /// Opens a tunnel to `host:port` through the proxy. The error says what
    /// went wrong, for the agent's refusal and the journal.
    fn connect(&self, host: &str, port: u16) -> std::result::Result<TcpStream, String> {
        let mut stream = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.find_map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(10)).ok()))
            .ok_or_else(|| format!("can't reach the upstream proxy {}", self.describe()))?;
        if self.socks {
            self.socks5(&mut stream, host, port)?;
            return Ok(stream);
        }
        let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(auth) = &self.auth {
            request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
        }
        request.push_str("\r\n");
        let lost = |e: io::Error| format!("the upstream proxy {} dropped the connection ({e})", self.describe());
        stream.write_all(request.as_bytes()).map_err(lost)?;
        // The answer is read byte by byte: whatever follows it belongs to the tunnel.
        stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(lost)?;
        let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > MAX_HEAD || stream.read(&mut byte).map_err(lost)? == 0 {
                return Err(format!("the upstream proxy {} sent no usable answer", self.describe()));
            }
            head.push(byte[0]);
        }
        stream.set_read_timeout(None).map_err(lost)?;
        let head = String::from_utf8_lossy(&head);
        let status = head.lines().next().unwrap_or_default().trim();
        match status.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()) {
            Some(200..=299) => Ok(stream),
            Some(407) => Err(format!("the upstream proxy {} wants a login (407): put user:password@ in its address", self.describe())),
            _ => Err(format!("the upstream proxy {} refused: {}", self.describe(), status.chars().take(80).collect::<String>())),
        }
    }
}

impl Upstream {
    /// SOCKS5 (RFC 1928, with RFC 1929 passwords): ask the proxy to connect to
    /// `host:port`, by name, so that it does the lookup.
    fn socks5(&self, stream: &mut TcpStream, host: &str, port: u16) -> std::result::Result<(), String> {
        let proxy = self.describe();
        let lost = |e: io::Error| format!("the upstream proxy {proxy} dropped the connection ({e})");
        stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(lost)?;
        // Offer "no login", and a password too if we have one.
        let hello: &[u8] = if self.login.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] };
        stream.write_all(hello).map_err(lost)?;
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).map_err(lost)?;
        match answer {
            [5, 0] => {}
            [5, 2] => {
                let (user, password) = self.login.as_ref().ok_or_else(|| format!("the upstream proxy {proxy} wants a login: put user:password@ in its address"))?;
                let mut login = vec![1, user.len() as u8];
                login.extend(user.as_bytes());
                login.push(password.len() as u8);
                login.extend(password.as_bytes());
                stream.write_all(&login).map_err(lost)?;
                let mut ok = [0u8; 2];
                stream.read_exact(&mut ok).map_err(lost)?;
                if ok[1] != 0 {
                    return Err(format!("the upstream proxy {proxy} refused that login"));
                }
            }
            [5, 0xff] => return Err(format!("the upstream proxy {proxy} accepts no login method we have: put user:password@ in its address")),
            _ => return Err(format!("{proxy} doesn't answer like a SOCKS5 proxy")),
        }
        // CONNECT, to a name (or an address, which has its own type).
        let mut request = vec![5, 1, 0];
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                request.push(1);
                request.extend(ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                request.push(4);
                request.extend(ip.octets());
            }
            Err(_) if host.len() <= 255 => {
                request.extend([3, host.len() as u8]);
                request.extend(host.as_bytes());
            }
            Err(_) => return Err("that host name is too long for SOCKS5".into()),
        }
        request.extend(port.to_be_bytes());
        stream.write_all(&request).map_err(lost)?;
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).map_err(lost)?;
        if head[0] != 5 {
            return Err(format!("{proxy} doesn't answer like a SOCKS5 proxy"));
        }
        if head[1] != 0 {
            let why = match head[1] {
                1 => "a general failure",
                2 => "the connection isn't allowed by its rules",
                3 => "the network is unreachable",
                4 => "the host is unreachable",
                5 => "the connection was refused",
                6 => "the connection timed out",
                7 => "CONNECT isn't supported",
                8 => "that address type isn't supported",
                _ => "an unknown error",
            };
            return Err(format!("the upstream proxy {proxy} refused: {why} (SOCKS5 reply {})", head[1]));
        }
        // The address it bound: read and dropped, so what follows is the tunnel.
        let skip = match head[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            3 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).map_err(lost)?;
                len[0] as usize + 2
            }
            _ => return Err(format!("{proxy} doesn't answer like a SOCKS5 proxy")),
        };
        let mut rest = vec![0u8; skip];
        stream.read_exact(&mut rest).map_err(lost)?;
        stream.set_read_timeout(None).map_err(lost)
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (b[i], s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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
    /// The upstream proxy the tunnel went through (`host:port`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

pub type Sink = Arc<dyn Fn(NetEvent) + Send + Sync>;

/// Decides about every connection; `listed` says whether the allowlist has
/// the host. `Ok(approved)` lets it through (`approved`: although it isn't
/// listed, e.g. you said yes); `Err(reason)` refuses it, even a listed host
/// (your policy forbids it).
pub type Gate = Arc<dyn Fn(&str, u16, bool) -> std::result::Result<bool, String> + Send + Sync>;

#[derive(Clone)]
pub struct Handle {
    active: Arc<AtomicUsize>,
    open: Open,
}

/// Connections being relayed: (id, host, port, the agent's end).
type Open = Arc<std::sync::Mutex<Vec<(u64, String, u16, UnixStream)>>>;

impl Handle {
    /// Closes every open connection to `host:port`; returns how many.
    pub fn close(&self, host: &str, port: u16) -> usize {
        let Ok(open) = self.open.lock() else { return 0 };
        let mut n = 0;
        for (_, h, p, stream) in open.iter() {
            if h == host && *p == port {
                let _ = stream.shutdown(Shutdown::Both);
                n += 1;
            }
        }
        n
    }

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

/// One connection from the sandbox to a server on this machine's loopback.
#[derive(Debug, Clone, Serialize)]
pub struct LocalEvent {
    pub port: u16,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub ms: u64,
}

pub type LocalSink = Arc<dyn Fn(LocalEvent) + Send + Sync>;

/// Serves `port` on this machine's loopback to the sandbox, which reaches it
/// at the same port on its own: every connection that arrives on `listener`
/// is passed to 127.0.0.1:`port` (or `[::1]`) and reported to `sink`. Only
/// that port: the rest of your loopback stays out of reach.
pub fn serve_local(listener: UnixListener, port: u16, sink: LocalSink) -> Handle {
    let active = Arc::new(AtomicUsize::new(0));
    let counter = active.clone();
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            let (sink, counter) = (sink.clone(), counter.clone());
            thread::spawn(move || {
                sink(relay_local(client, port));
                counter.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Handle { active, open: Arc::default() }
}

fn relay_local(client: UnixStream, port: u16) -> LocalEvent {
    let start = Instant::now();
    let mut event = LocalEvent { port, ok: false, reason: None, bytes_out: 0, bytes_in: 0, ms: 0 };
    let targets = [SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))];
    match targets.iter().find_map(|a| TcpStream::connect_timeout(a, Duration::from_secs(5)).ok()) {
        Some(server) => {
            event.ok = true;
            (event.bytes_out, event.bytes_in) = pump(client, server);
        }
        None => event.reason = Some(format!("nothing is listening on 127.0.0.1:{port} on this machine")),
    }
    event.ms = start.elapsed().as_millis() as u64;
    event
}

/// An allowlist that grows while the task runs (hosts you approve when the
/// agent asks).
pub type LiveAllowlist = Arc<std::sync::RwLock<Allowlist>>;

/// Serves connections on background threads, reporting each one to `sink`.
/// Hosts the `broker` holds credentials for are relayed through it.
/// Threads must only be started after the sandbox has been forked.
pub fn serve(
    listener: UnixListener,
    allow: LiveAllowlist,
    broker: Option<Arc<Broker>>,
    gate: Option<Gate>,
    upstream: Option<Arc<Upstream>>,
    sink: Sink,
) -> Handle {
    let active = Arc::new(AtomicUsize::new(0));
    let open: Open = Arc::default();
    let (counter, registry) = (active.clone(), open.clone());
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            let (allow, broker, gate, upstream, sink, counter, registry) =
                (allow.clone(), broker.clone(), gate.clone(), upstream.clone(), sink.clone(), counter.clone(), registry.clone());
            thread::spawn(move || {
                if let Some(event) = handle(client, &allow, broker.as_deref(), gate.as_ref(), upstream.as_deref(), &registry) {
                    sink(event);
                }
                counter.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Handle { active, open }
}

fn handle(
    mut client: UnixStream,
    allow: &LiveAllowlist,
    broker: Option<&Broker>,
    gate: Option<&Gate>,
    upstream: Option<&Upstream>,
    open: &Open,
) -> Option<NetEvent> {
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
        via: None,
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
    let Some((host, port)) = split_host_port(target).filter(|(h, _)| h.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._:".contains(&b))) else {
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
    let upstream = match upstream.filter(|u| !u.bypasses(&host, port)) {
        Some(proxy) => {
            // Names are checked against what this machine resolves, where it can: an
            // allowed name must not become a way into private addresses either.
            if !public_enough(&host, port) {
                return refuse("403 Forbidden", "resolves only to private or local addresses", event);
            }
            event.via = Some(proxy.describe());
            match proxy.connect(&host, port) {
                Ok(stream) => stream,
                Err(why) => return refuse("502 Bad Gateway", &why, event),
            }
        }
        None => {
            let addrs: Vec<SocketAddr> = match (host.as_str(), port).to_socket_addrs() {
                Ok(a) => a.filter(|a| is_public(a.ip())).collect(),
                Err(_) => return refuse("502 Bad Gateway", "can't resolve host", event),
            };
            if addrs.is_empty() {
                // An allowed name must not become a way into the host's own services.
                return refuse("403 Forbidden", "resolves only to private or local addresses", event);
            }
            let Some(stream) = addrs.iter().find_map(|a| TcpStream::connect_timeout(a, Duration::from_secs(10)).ok()) else {
                return refuse("502 Bad Gateway", "connection failed", event);
            };
            stream
        }
    };
    if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
        return None;
    }
    event.allowed = true;
    // Registered while it lasts, so taking the host back can close it.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::SeqCst);
    if let (Ok(mut o), Ok(c)) = (open.lock(), client.try_clone()) {
        o.push((id, host.clone(), port, c));
    }
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
    if let Ok(mut o) = open.lock() {
        o.retain(|(i, ..)| *i != id);
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

/// Whether a host may be tunneled through an upstream proxy, which does its
/// own name lookups: a literal address must be public, and a name that
/// resolves here must resolve to something public. A name this machine can't
/// resolve (corporate DNS often answers only the proxy) is left to the proxy.
fn public_enough(host: &str, port: u16) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_public(ip);
    }
    match (host, port).to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<SocketAddr> = addrs.collect();
            addrs.is_empty() || addrs.iter().any(|a| is_public(a.ip()))
        }
        Err(_) => true,
    }
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
        assert!(live.remove("pypi.org") && !live.allows("pypi.org", 443) && !live.remove("pypi.org"));
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

    #[test]
    fn upstream_proxy_addresses_and_no_proxy() {
        let u = Upstream::parse("http://user:p%40ss@Proxy.Corp.example:3128/", &["localhost,.corp.example".into(), "10.0.0.0/8".into()]).unwrap();
        assert_eq!(u.describe(), "proxy.corp.example:3128", "the password is never shown");
        assert_eq!(u.auth, Some(format!("Basic {}", crate::util::base64(b"user:p@ss"))));
        assert_eq!(format!("{u:?}"), "Upstream(proxy.corp.example:3128)");
        assert_eq!(Upstream::parse("proxy:8080", &[]).unwrap().describe(), "proxy:8080");
        assert_eq!(Upstream::parse("http://proxy", &[]).unwrap().describe(), "proxy:80");
        assert_eq!(Upstream::parse("http://[::1]:3128", &[]).unwrap().describe(), "[::1]:3128");
        for bad in ["ftp://proxy:21", "https://proxy:443", "http://", "http://proxy:notaport", "http://[::1"] {
            assert!(Upstream::parse(bad, &[]).is_err(), "{bad}");
        }

        assert!(u.bypasses("localhost", 443) && u.bypasses("git.corp.example", 443) && u.bypasses("corp.example", 443));
        assert!(!u.bypasses("notcorp.example", 443) && !u.bypasses("example.com", 443));
        assert!(u.bypasses("10.1.2.3", 443) && !u.bypasses("11.0.0.1", 443));
        assert!(Upstream::parse("proxy:1", &["*".into()]).unwrap().bypasses("anything.test", 1));
        let by_port = Upstream::parse("proxy:1", &["example.com:8443".into()]).unwrap();
        assert!(by_port.bypasses("example.com", 8443) && !by_port.bypasses("example.com", 443));
        assert!(!Upstream::parse("proxy:1", &[]).unwrap().bypasses("example.com", 443));
        assert!(Upstream::parse("proxy:1", &[]).unwrap().bypassing(&["a.test, b.test".into()]).bypasses("b.test", 443));
    }

    /// A stand-in corporate proxy: reads one CONNECT, answers `status`, then
    /// (if it said yes) echoes what comes next. Returns what the CONNECT said.
    fn fake_proxy(status: &'static str) -> (u16, thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
            while !head.ends_with(b"\r\n\r\n") {
                c.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            write!(c, "HTTP/1.1 {status}\r\n\r\n").unwrap();
            if status.starts_with("200") {
                let mut buf = [0u8; 64];
                let n = c.read(&mut buf).unwrap();
                c.write_all(&buf[..n]).unwrap();
            }
            String::from_utf8(head).unwrap()
        });
        (port, worker)
    }

    #[test]
    fn tunnels_through_an_upstream_proxy() {
        let (port, seen) = fake_proxy("200 Connection established");
        let u = Upstream::parse(&format!("http://user:pw@127.0.0.1:{port}"), &[]).unwrap();
        let mut tunnel = u.connect("example.com", 443).unwrap();
        tunnel.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        tunnel.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello", "what follows the answer belongs to the tunnel");
        let request = seen.join().unwrap();
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"), "{request}");
        assert!(request.contains(&format!("Proxy-Authorization: Basic {}\r\n", crate::util::base64(b"user:pw"))));
    }

    #[test]
    fn an_upstream_proxy_that_says_no_is_explained() {
        for (status, says) in [("407 Proxy Authentication Required", "wants a login"), ("403 Forbidden", "refused: HTTP/1.1 403 Forbidden")] {
            let (port, seen) = fake_proxy(status);
            let err = Upstream::parse(&format!("127.0.0.1:{port}"), &[]).unwrap().connect("example.com", 443).unwrap_err();
            assert!(err.contains(says), "{err}");
            seen.join().unwrap();
        }
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let err = Upstream::parse(&format!("127.0.0.1:{free}"), &[]).unwrap().connect("example.com", 443).unwrap_err();
        assert!(err.contains("can't reach the upstream proxy"), "{err}");
    }

    #[test]
    fn allowed_connections_go_through_the_upstream_proxy() {
        let (port, seen) = fake_proxy("200 Connection established");
        let upstream = Upstream::parse(&format!("127.0.0.1:{port}"), &[]).unwrap();
        let allow: LiveAllowlist = Arc::new(std::sync::RwLock::new(list(&["93.184.216.34"])));
        let (mut agent, server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || handle(server, &allow, None, None, Some(&upstream), &Open::default()));
        agent.write_all(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n").unwrap();
        let (mut answer, mut byte) = (Vec::new(), [0u8; 1]);
        while !answer.ends_with(b"\r\n\r\n") {
            agent.read_exact(&mut byte).unwrap();
            answer.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200"));
        agent.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        agent.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping");
        agent.shutdown(Shutdown::Write).unwrap();
        let event = worker.join().unwrap().unwrap();
        assert!(event.allowed && event.reason.is_none(), "{event:?}");
        assert_eq!(event.via, Some(format!("127.0.0.1:{port}")));
        assert_eq!((event.bytes_out, event.bytes_in), (4, 4));
        assert!(seen.join().unwrap().starts_with("CONNECT 93.184.216.34:443 "));
    }

    #[test]
    fn names_for_an_upstream_proxy_are_checked_where_they_can_be() {
        assert!(!public_enough("127.0.0.1", 443) && !public_enough("10.0.0.5", 443) && public_enough("1.1.1.1", 443));
        assert!(!public_enough("localhost", 443), "a name this machine resolves to loopback is refused");
        assert!(public_enough("no-such-host.invalid", 443), "a name only the proxy can resolve is its to resolve");
    }

    #[test]
    fn a_connect_target_with_odd_characters_is_refused_unrecorded() {
        let (mut agent, server) = UnixStream::pair().unwrap();
        agent.write_all(b"CONNECT \x1b[2Jevil:443 HTTP/1.1\r\n\r\n").unwrap();
        let allow: LiveAllowlist = Arc::new(std::sync::RwLock::new(list(&["evil"])));
        let event = handle(server, &allow, None, None, None, &Open::default()).unwrap();
        assert_eq!((event.host.as_str(), event.allowed, event.reason.as_deref()), ("", false, Some("malformed CONNECT target")));
    }

    #[test]
    fn a_local_port_is_served_to_the_sandbox() {
        // A "model server" on this machine's loopback: echoes four bytes.
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        thread::spawn(move || {
            for mut c in server.incoming().flatten() {
                let mut buf = [0u8; 4];
                if c.read_exact(&mut buf).is_ok() {
                    let _ = c.write_all(&buf);
                }
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("local.sock");
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = events.clone();
        let handle = serve_local(bind(&socket).unwrap(), port, Arc::new(move |e| seen.lock().unwrap().push(e)));
        let mut agent = UnixStream::connect(&socket).unwrap();
        agent.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        agent.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping");
        drop(agent);
        handle.drain(Duration::from_secs(2));
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].ok && events[0].port == port && (events[0].bytes_out, events[0].bytes_in) == (4, 4), "{:?}", events[0]);
    }

    #[test]
    fn a_local_port_with_nothing_behind_it_is_explained() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("local.sock");
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = events.clone();
        let handle = serve_local(bind(&socket).unwrap(), port, Arc::new(move |e| seen.lock().unwrap().push(e)));
        drop(UnixStream::connect(&socket).unwrap());
        for _ in 0..100 {
            if !events.lock().unwrap().is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        handle.drain(Duration::from_secs(2));
        let events = events.lock().unwrap();
        assert!(!events[0].ok && events[0].reason.as_deref() == Some(&*format!("nothing is listening on 127.0.0.1:{port} on this machine")), "{:?}", events[0]);
    }

    /// A stand-in SOCKS5 proxy: speaks the handshake, records what it was asked
    /// (the login and the target), answers `reply`, then echoes once.
    fn fake_socks(want_login: Option<(&'static str, &'static str)>, reply: u8) -> (u16, thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut seen = String::new();
            let mut hello = [0u8; 2];
            c.read_exact(&mut hello).unwrap();
            let mut methods = vec![0u8; hello[1] as usize];
            c.read_exact(&mut methods).unwrap();
            if let Some((user, password)) = want_login {
                if !methods.contains(&2) {
                    c.write_all(&[5, 0xff]).unwrap();
                    return seen;
                }
                c.write_all(&[5, 2]).unwrap();
                let mut v = [0u8; 2];
                c.read_exact(&mut v).unwrap();
                let mut u = vec![0u8; v[1] as usize];
                c.read_exact(&mut u).unwrap();
                let mut plen = [0u8; 1];
                c.read_exact(&mut plen).unwrap();
                let mut p = vec![0u8; plen[0] as usize];
                c.read_exact(&mut p).unwrap();
                seen += &format!("login={}:{} ", String::from_utf8_lossy(&u), String::from_utf8_lossy(&p));
                let good = u == user.as_bytes() && p == password.as_bytes();
                c.write_all(&[1, if good { 0 } else { 1 }]).unwrap();
                if !good {
                    return seen;
                }
            } else {
                c.write_all(&[5, 0]).unwrap();
            }
            let mut head = [0u8; 4];
            c.read_exact(&mut head).unwrap();
            let host = match head[3] {
                3 => {
                    let mut len = [0u8; 1];
                    c.read_exact(&mut len).unwrap();
                    let mut name = vec![0u8; len[0] as usize];
                    c.read_exact(&mut name).unwrap();
                    String::from_utf8(name).unwrap()
                }
                1 => {
                    let mut ip = [0u8; 4];
                    c.read_exact(&mut ip).unwrap();
                    std::net::Ipv4Addr::from(ip).to_string()
                }
                other => panic!("address type {other}"),
            };
            let mut port = [0u8; 2];
            c.read_exact(&mut port).unwrap();
            seen += &format!("connect={host}:{} atyp={}", u16::from_be_bytes(port), head[3]);
            c.write_all(&[5, reply, 0, 1, 127, 0, 0, 1, 0, 80]).unwrap();
            if reply == 0 {
                let mut buf = [0u8; 16];
                let n = c.read(&mut buf).unwrap();
                c.write_all(&buf[..n]).unwrap();
            }
            seen
        });
        (port, worker)
    }

    #[test]
    fn socks5_upstream_proxies() {
        let u = Upstream::parse("socks5://user:p%40ss@Proxy.Corp.example", &[]).unwrap();
        assert_eq!((u.describe().as_str(), u.socks, u.login.clone()), ("proxy.corp.example:1080", true, Some(("user".into(), "p@ss".into()))));
        assert_eq!(Upstream::parse("socks5h://127.0.0.1:9050", &[]).unwrap().describe(), "127.0.0.1:9050");
        assert_eq!(format!("{u:?}"), "Upstream(proxy.corp.example:1080)", "never the password");

        // A name goes to the proxy as a name, and the bytes after the answer are the tunnel.
        let (port, seen) = fake_socks(None, 0);
        let mut tunnel = Upstream::parse(&format!("socks5://127.0.0.1:{port}"), &[]).unwrap().connect("example.com", 443).unwrap();
        tunnel.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        tunnel.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        assert_eq!(seen.join().unwrap(), "connect=example.com:443 atyp=3");
        // An address goes as an address; a login, when the proxy wants one.
        let (port, seen) = fake_socks(Some(("alice", "s3cret")), 0);
        Upstream::parse(&format!("socks5://alice:s3cret@127.0.0.1:{port}"), &[]).unwrap().connect("93.184.216.34", 443).unwrap();
        assert_eq!(seen.join().unwrap(), "login=alice:s3cret connect=93.184.216.34:443 atyp=1");
        // …and it's explained when that fails.
        let (port, seen) = fake_socks(Some(("alice", "s3cret")), 0);
        let err = Upstream::parse(&format!("socks5://alice:wrong@127.0.0.1:{port}"), &[]).unwrap().connect("example.com", 443).unwrap_err();
        assert!(err.contains("refused that login"), "{err}");
        seen.join().unwrap();
        let (port, seen) = fake_socks(Some(("alice", "s3cret")), 0);
        let err = Upstream::parse(&format!("socks5://127.0.0.1:{port}"), &[]).unwrap().connect("example.com", 443).unwrap_err();
        assert!(err.contains("wants a login") || err.contains("accepts no login"), "{err}");
        drop(seen);
        let (port, seen) = fake_socks(None, 2);
        let err = Upstream::parse(&format!("socks5://127.0.0.1:{port}"), &[]).unwrap().connect("example.com", 443).unwrap_err();
        assert!(err.contains("refused: the connection isn't allowed by its rules (SOCKS5 reply 2)"), "{err}");
        seen.join().unwrap();
    }
}
