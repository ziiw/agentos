//! Credential broker: the agent never holds your real credentials.
//!
//! Inside the sandbox a brokered variable (say `ANTHROPIC_API_KEY`) holds a
//! placeholder. Connections to the credential's host are terminated by the
//! egress proxy with a certificate from a per-task CA that only the sandbox
//! trusts; the proxy swaps the placeholder for the real value in the one
//! request header it belongs in, and forwards over real, verified TLS.
//!
//! Only that header, only on that host: a placeholder pasted into a request
//! body, or sent to any other host, stays a placeholder. Otherwise an agent
//! could get the real key echoed back, or put it in front of the model.
//!
//! Model API calls relayed here are also metered (see `gateway`).

use crate::gateway::{self, Api, Meter, Reader};
use crate::vault::Vault;
use anyhow::{Context, Result, bail};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Instant;

/// A credential the proxy adds on the agent's behalf.
#[derive(Clone)]
pub struct Secret {
    /// Environment variable the agent sees (holding the placeholder).
    pub env: String,
    pub host: String,
    /// Header that carries it, lowercase: `x-api-key`, or `authorization` (as `Bearer …`).
    pub header: String,
    pub placeholder: String,
    pub value: String,
}

impl Secret {
    /// `spec` is `NAME=HOST/HEADER` (header defaults to `authorization`); the
    /// real value comes from `NAME` in your environment.
    pub fn parse(spec: &str) -> Result<Secret> {
        Secret::parse_with(spec, |env| std::env::var(env).ok())
    }

    /// Like [`Secret::parse`], with the real value of `NAME` given by `value`
    /// (your environment, a keychain command…).
    pub fn parse_with(spec: &str, value: impl FnOnce(&str) -> Option<String>) -> Result<Secret> {
        let (env, rest) = spec.split_once('=').with_context(|| format!("--secret {spec}: expected NAME=HOST[/HEADER]"))?;
        let (host, header) = rest.split_once('/').unwrap_or((rest, "authorization"));
        if env.is_empty() || host.is_empty() || header.is_empty() || host.contains(':') {
            bail!("--secret {spec}: expected NAME=HOST[/HEADER], e.g. ANTHROPIC_API_KEY=api.anthropic.com/x-api-key");
        }
        let value = value(env).with_context(|| format!("--secret {spec}: {env} is not set in your environment (or by a [secret_commands] entry)"))?;
        Ok(Secret::new(env, host, header, value))
    }

    pub fn new(env: &str, host: &str, header: &str, value: String) -> Secret {
        let suffix = crate::util::random_hex(12).unwrap_or_else(|_| "000000000000".into());
        Secret {
            env: env.to_string(),
            host: host.to_ascii_lowercase(),
            header: header.to_ascii_lowercase(),
            placeholder: format!("agentos-placeholder-{}-{suffix}", env.to_ascii_lowercase().replace('_', "-")),
            value,
        }
    }

    /// Replaces the placeholder in this header, if this is the header and it
    /// holds exactly the placeholder (or `Bearer <placeholder>`).
    fn inject(&self, name: &str, value: &mut String) -> bool {
        if !name.eq_ignore_ascii_case(&self.header) {
            return false;
        }
        if *value == self.placeholder {
            *value = self.value.clone();
        } else if value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer ")) == Some(&self.placeholder) {
            *value = format!("Bearer {}", self.value);
        } else {
            return false;
        }
        true
    }
}

/// The per-task CA and TLS settings for brokered hosts.
pub struct Broker {
    secrets: Vec<Secret>,
    /// An agent's sealed login, and the hosts it's used with.
    vault: Option<(Arc<Vault>, Vec<String>)>,
    /// Meters model calls on the hosts relayed here.
    meter: Option<Arc<Meter>>,
    servers: HashMap<String, Arc<ServerConfig>>,
    client: Arc<ClientConfig>,
    ca_pem: String,
}

impl Broker {
    /// `meter`: the task's model gateway, and the hosts to relay for it even
    /// without a credential to add (model APIs, when there's a budget).
    pub fn new(secrets: Vec<Secret>, vault: Option<(Arc<Vault>, Vec<String>)>, meter: Option<(Arc<Meter>, Vec<String>)>) -> Result<Broker> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let ca_key = KeyPair::generate()?;
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca.distinguished_name.push(DnType::CommonName, "agentos task CA (this sandbox only)");
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca.self_signed(&ca_key)?;

        let mut servers = HashMap::new();
        let vault_hosts = vault.iter().flat_map(|(_, hosts)| hosts.iter().cloned());
        let metered_hosts = meter.iter().flat_map(|(_, hosts)| hosts.iter().cloned());
        for host in secrets.iter().map(|s| s.host.clone()).chain(vault_hosts).chain(metered_hosts) {
            if servers.contains_key(&host) {
                continue;
            }
            let key = KeyPair::generate()?;
            let leaf = CertificateParams::new(vec![host.clone()])?.signed_by(&key, &ca_cert, &ca_key)?;
            let mut config = ServerConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.der().clone(), ca_cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )?;
            // One request at a time is all the relay understands.
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            servers.insert(host, Arc::new(config));
        }

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];

        let meter = meter.map(|(m, _)| m);
        Ok(Broker { secrets, vault, meter, servers, client: Arc::new(client), ca_pem: ca_cert.pem() })
    }

    /// The CA certificate (public) the sandbox must trust.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn brokers(&self, host: &str) -> bool {
        self.servers.contains_key(&host.to_ascii_lowercase())
    }

    /// Relays HTTP/1.1 between the agent and `host`, injecting credentials.
    /// Returns (bytes up, bytes down, requests, credentials injected).
    pub fn relay(&self, host: &str, client: UnixStream, upstream: TcpStream) -> Result<(u64, u64, u64, u64)> {
        let server_config = self.servers.get(host).context("host is not brokered")?.clone();
        let agent = StreamOwned::new(ServerConnection::new(server_config)?, client);
        let name = ServerName::try_from(host.to_string())?;
        let remote = StreamOwned::new(ClientConnection::new(self.client.clone(), name)?, upstream);
        let secrets: Vec<&Secret> = self.secrets.iter().filter(|s| s.host == host).collect();
        let vault = self.vault.as_ref().filter(|(_, hosts)| hosts.iter().any(|h| h == host)).map(|(v, _)| v.as_ref());
        relay_http(agent, remote, host, &secrets, vault, self.meter.as_deref())
    }
}

/// Bundle of the system's CAs plus the task CA, for clients that read a
/// single file (curl, Python, git, OpenSSL).
pub fn ca_bundle(task_ca: &str) -> String {
    let system = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    format!("{system}\n{task_ca}")
}

struct Head {
    start: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn parse(raw: &str) -> Head {
        let mut lines = raw.split("\r\n").filter(|l| !l.is_empty());
        let start = lines.next().unwrap_or_default().to_string();
        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
            .collect();
        Head { start, headers }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn has_token(&self, name: &str, token: &str) -> bool {
        self.get(name).is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    fn serialize(&self) -> String {
        let mut s = format!("{}\r\n", self.start);
        for (n, v) in &self.headers {
            s.push_str(&format!("{n}: {v}\r\n"));
        }
        s.push_str("\r\n");
        s
    }
}

enum Body {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

fn read_head(r: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            return if head.is_empty() { Ok(None) } else { Err(io::ErrorKind::UnexpectedEof.into()) };
        }
        if head.len() + line.len() > 64 * 1024 {
            return Err(io::Error::other("header section too large"));
        }
        let end = line == "\r\n" || line == "\n";
        head.push_str(&line);
        if end && head.trim().len() > 0 {
            return Ok(Some(head));
        }
        if end {
            head.clear(); // stray blank line between messages
        }
    }
}

/// Copies exactly `n` bytes.
fn copy_exact(r: &mut impl Read, w: &mut impl Write, n: u64) -> io::Result<u64> {
    let copied = io::copy(&mut r.take(n), w)?;
    if copied < n {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(copied)
}

/// Writes through to `w`, showing the bytes to `seen` on their way.
struct Tee<'a, W: Write> {
    w: &'a mut W,
    seen: &'a mut dyn FnMut(&[u8]),
}

impl<W: Write> Write for Tee<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.w.write(buf)?;
        (self.seen)(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

/// Copies a chunked body, flushing per chunk so streamed responses stay
/// live. `seen` gets the payload, without the chunk framing.
fn copy_chunked(r: &mut impl BufRead, w: &mut impl Write, seen: &mut dyn FnMut(&[u8])) -> io::Result<u64> {
    let mut total = 0;
    loop {
        let mut line = String::new();
        r.read_line(&mut line)?;
        w.write_all(line.as_bytes())?;
        let size = u64::from_str_radix(line.trim().split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| io::Error::other("bad chunk size"))?;
        if size == 0 {
            loop {
                let mut trailer = String::new();
                r.read_line(&mut trailer)?;
                w.write_all(trailer.as_bytes())?;
                if trailer.trim().is_empty() {
                    break;
                }
            }
            w.flush()?;
            return Ok(total);
        }
        total += copy_exact(r, &mut Tee { w: &mut *w, seen: &mut *seen }, size)?;
        total += copy_exact(r, w, 2)?;
        w.flush()?;
    }
}

/// Copies a body; `seen` gets its payload as it passes.
fn copy_body(body: Body, r: &mut impl BufRead, w: &mut impl Write, seen: &mut dyn FnMut(&[u8])) -> io::Result<u64> {
    let n = match body {
        Body::None => 0,
        Body::Length(n) => copy_exact(r, &mut Tee { w: &mut *w, seen }, n)?,
        Body::Chunked => copy_chunked(r, w, seen)?,
        Body::UntilClose => io::copy(r, &mut Tee { w: &mut *w, seen })?,
    };
    w.flush()?;
    Ok(n)
}

/// Reads a whole request body ahead, as framed, to look inside before it
/// goes on: (framed bytes, payload).
fn hold_body(body: Body, r: &mut impl BufRead) -> io::Result<(Vec<u8>, Vec<u8>)> {
    const LIMIT: usize = 64 << 20;
    let (mut framed, mut payload) = (Vec::new(), Vec::new());
    copy_body(body, r, &mut Capped { buf: &mut framed, limit: LIMIT }, &mut |b| payload.extend_from_slice(b))?;
    Ok((framed, payload))
}

/// A buffer that refuses to grow past `limit`.
struct Capped<'a> {
    buf: &'a mut Vec<u8>,
    limit: usize,
}

impl Write for Capped<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.buf.len() + b.len() > self.limit {
            return Err(io::Error::other("request too large to look inside under a budget"));
        }
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads a whole (de-chunked) body, for the few exchanges that must be rewritten.
fn read_body(body: Body, r: &mut impl BufRead) -> io::Result<Vec<u8>> {
    const LIMIT: u64 = 1 << 20;
    let mut out = Vec::new();
    match body {
        Body::None => {}
        Body::Length(n) if n <= LIMIT => {
            copy_exact(r, &mut out, n)?;
        }
        Body::Length(_) => return Err(io::Error::other("body too large to inspect")),
        Body::UntilClose => {
            r.take(LIMIT).read_to_end(&mut out)?;
        }
        Body::Chunked => loop {
            let mut line = String::new();
            r.read_line(&mut line)?;
            let size = u64::from_str_radix(line.trim().split(';').next().unwrap_or_default().trim(), 16)
                .map_err(|_| io::Error::other("bad chunk size"))?;
            if size == 0 {
                loop {
                    let mut trailer = String::new();
                    if r.read_line(&mut trailer)? == 0 || trailer.trim().is_empty() {
                        break;
                    }
                }
                break;
            }
            if out.len() as u64 + size > LIMIT {
                return Err(io::Error::other("body too large to inspect"));
            }
            copy_exact(r, &mut out, size)?;
            let mut crlf = String::new();
            r.read_line(&mut crlf)?;
        },
    }
    Ok(out)
}

/// Replaces the framing headers of a message whose body we rewrote.
fn set_length(h: &mut Head, len: usize) {
    h.headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-length") && !n.eq_ignore_ascii_case("transfer-encoding"));
    h.headers.push(("Content-Length".into(), len.to_string()));
}

fn request_body(h: &Head) -> Body {
    if h.has_token("transfer-encoding", "chunked") {
        Body::Chunked
    } else {
        match h.get("content-length").and_then(|v| v.parse().ok()) {
            Some(0) | None => Body::None,
            Some(n) => Body::Length(n),
        }
    }
}

fn response_body(method: &str, status: u16, h: &Head) -> Body {
    if method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 || (100..200).contains(&status) {
        Body::None
    } else if h.has_token("transfer-encoding", "chunked") {
        Body::Chunked
    } else {
        match h.get("content-length").and_then(|v| v.parse().ok()) {
            Some(n) => Body::Length(n),
            None => Body::UntilClose,
        }
    }
}

/// HTTP/1.1, one exchange at a time: parse each request head (to inject
/// credentials and spot model calls) and frame bodies so the next head can
/// be found; stream the responses back as they arrive.
fn relay_http<A: Read + Write, B: Read + Write>(
    agent: A,
    remote: B,
    host: &str,
    secrets: &[&Secret],
    vault: Option<&Vault>,
    meter: Option<&Meter>,
) -> Result<(u64, u64, u64, u64)> {
    let mut agent = BufReader::new(agent);
    let mut remote = BufReader::new(remote);
    let (mut up, mut down, mut requests, mut injected) = (0, 0, 0, 0);
    let result = (|| -> io::Result<()> {
        while let Some(raw) = read_head(&mut agent)? {
            let mut req = Head::parse(&raw);
            for (name, value) in req.headers.iter_mut() {
                if secrets.iter().any(|s| s.inject(name, value)) || vault.is_some_and(|v| v.inject_header(name, value)) {
                    injected += 1;
                }
            }
            let method = req.start.split_whitespace().next().unwrap_or_default().to_string();
            let path = req.start.split_whitespace().nth(1).unwrap_or_default().split('?').next().unwrap_or_default().to_string();
            if let Some(v) = vault.filter(|_| method.eq_ignore_ascii_case("POST") && path.ends_with("/oauth/token")) {
                let (n, sent, got, close) = token_exchange(&mut agent, &mut remote, req, v)?;
                (injected, up, down, requests) = (injected + n, up + sent, down + got, requests + 1);
                if close {
                    return Ok(());
                }
                continue;
            }
            // We answer 100-continue ourselves, so the agent sends its body now.
            if req.has_token("expect", "100-continue") {
                req.headers.retain(|(n, _)| !n.eq_ignore_ascii_case("expect"));
                agent.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
                agent.get_mut().flush()?;
            }
            let mut close = req.has_token("connection", "close");
            let post = method.eq_ignore_ascii_case("POST");
            let model = meter.and_then(|m| m.endpoint(host, &path).map(|api| (m, api)));
            // Near the end of a budget, one model call at a time, until it's recorded.
            let _turn = model.and_then(|(m, _)| m.turn());
            // Paid calls whose cost no response reports: refused under a budget.
            let mut refusal = match (meter, post) {
                (Some(m), true) => m.unmeterable(host, &path).and_then(|(why, api)| m.unmetered(host, &path, why, api)),
                _ => None,
            };
            // A request body read ahead, to look inside before it goes on.
            let mut held: Option<Vec<u8>> = None;
            if let (Some((m, api)), None) = (model, &refusal) {
                // Over budget: you may be asked to raise it while the call
                // waits. If the provider hung up on the idle connection
                // meanwhile, the agent's client retries on a new one.
                if !m.admit() {
                    refusal = Some(m.refuse(api));
                } else if api == Api::Openai && post && path.ends_with("/responses") && m.budgeted() {
                    let (framed, payload) = hold_body(request_body(&req), &mut agent)?;
                    if gateway::wants_background(&payload) {
                        refusal = m.unmetered(host, &path, gateway::BACKGROUND, api);
                    }
                    held = Some(framed);
                }
                // Plain responses, so the usage in them can be read.
                req.headers.retain(|(n, _)| !n.eq_ignore_ascii_case("accept-encoding"));
            }
            if let Some((status, reason, body)) = refusal {
                // Answered here, never sent.
                up += raw.len() as u64
                    + match &held {
                        Some(framed) => framed.len() as u64,
                        None => copy_body(request_body(&req), &mut agent, &mut io::sink(), &mut |_| {})?,
                    };
                let resp = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                agent.get_mut().write_all(resp.as_bytes())?;
                agent.get_mut().flush()?;
                (down, requests) = (down + resp.len() as u64, requests + 1);
                if close {
                    return Ok(());
                }
                continue;
            }
            let started = Instant::now();
            let head = req.serialize();
            remote.get_mut().write_all(head.as_bytes())?;
            up += head.len() as u64
                + match held {
                    Some(framed) => {
                        remote.get_mut().write_all(&framed)?;
                        remote.get_mut().flush()?;
                        framed.len() as u64
                    }
                    None => copy_body(request_body(&req), &mut agent, remote.get_mut(), &mut |_| {})?,
                };
            requests += 1;

            loop {
                let Some(raw) = read_head(&mut remote)? else { return Ok(()) };
                let resp = Head::parse(&raw);
                let status: u16 = resp.start.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                agent.get_mut().write_all(raw.as_bytes())?;
                let body = response_body(&method, status, &resp);
                close |= matches!(body, Body::UntilClose) || resp.has_token("connection", "close") || status == 101;
                let interim = (100..200).contains(&status) && status != 101;
                let copied = match model {
                    Some((m, api)) if !interim => {
                        let mut reader = Reader::new(api, resp.get("content-type"), resp.get("content-encoding"));
                        let copied = copy_body(body, &mut remote, agent.get_mut(), &mut |b| reader.feed(b));
                        m.record(host, &path, status, reader, started.elapsed(), copied.is_err());
                        copied?
                    }
                    _ => copy_body(body, &mut remote, agent.get_mut(), &mut |_| {})?,
                };
                down += raw.len() as u64 + copied;
                if !interim {
                    break;
                }
            }
            if close {
                return Ok(());
            }
        }
        Ok(())
    })();
    // An agent hanging up mid-exchange is normal; anything else is worth knowing.
    match result {
        Ok(()) => Ok((up, down, requests, injected)),
        Err(e) if matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) => {
            Ok((up, down, requests, injected))
        }
        Err(e) => Err(e.into()),
    }
}

/// One request to an OAuth token endpoint (login or refresh), rewritten both
/// ways: placeholder refresh token → real on the way out, new real tokens →
/// fresh placeholders on the way back. Returns (tokens unsealed, bytes up,
/// bytes down, close the connection).
fn token_exchange<A: Read + Write, B: Read + Write>(
    agent: &mut BufReader<A>,
    remote: &mut BufReader<B>,
    mut req: Head,
    vault: &Vault,
) -> io::Result<(u64, u64, u64, bool)> {
    if req.has_token("expect", "100-continue") {
        agent.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        agent.get_mut().flush()?;
    }
    // Plain bodies only: we have to read the response.
    req.headers.retain(|(n, _)| !n.eq_ignore_ascii_case("accept-encoding") && !n.eq_ignore_ascii_case("expect"));
    let body = read_body(request_body(&req), agent)?;
    let (body, unsealed) = vault.unseal_json(&body).unwrap_or((body, 0));
    set_length(&mut req, body.len());
    let head = req.serialize();
    remote.get_mut().write_all(head.as_bytes())?;
    remote.get_mut().write_all(&body)?;
    remote.get_mut().flush()?;

    let mut raw = read_head(remote)?.ok_or(io::ErrorKind::UnexpectedEof)?;
    let mut resp = Head::parse(&raw);
    while resp.start.split_whitespace().nth(1).is_some_and(|s| s.starts_with('1')) {
        raw = read_head(remote)?.ok_or(io::ErrorKind::UnexpectedEof)?;
        resp = Head::parse(&raw);
    }
    let status: u16 = resp.start.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = read_body(response_body("POST", status, &resp), remote)?;
    let encoded = resp.get("content-encoding").is_some_and(|e| !e.eq_ignore_ascii_case("identity"));
    let (body, close) = if encoded {
        // Can't look inside, so it can't go to the agent: it might hold real tokens.
        resp = Head::parse("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n");
        (b"agentos: compressed token response, refusing to pass it on".to_vec(), true)
    } else {
        let close = resp.has_token("connection", "close");
        // Not JSON (an error page): no tokens to seal, pass it on.
        (vault.seal_json(&body).map(|(b, _)| b).unwrap_or(body), close)
    };
    resp.headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-encoding"));
    set_length(&mut resp, body.len());
    let head = resp.serialize();
    agent.get_mut().write_all(head.as_bytes())?;
    agent.get_mut().write_all(&body)?;
    agent.get_mut().flush()?;
    Ok((unsealed as u64, head.len() as u64, (raw.len() + body.len()) as u64, close))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// An in-memory duplex: reads from `input`, records writes.
    struct Pipe {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn pipe(input: &str) -> Pipe {
        Pipe { input: Cursor::new(input.as_bytes().to_vec()), output: Vec::new() }
    }

    fn secret() -> Secret {
        let mut s = Secret::new("API_KEY", "api.example.com", "x-api-key", "real-key".into());
        s.placeholder = "PLACEHOLDER".into();
        s
    }

    fn run(requests: &str, responses: &str) -> (String, String, u64, u64) {
        let s = secret();
        let mut agent = pipe(requests);
        let mut remote = pipe(responses);
        let (_, _, n, injected) = relay_http(&mut agent, &mut remote, "api.example.com", &[&s], None, None).unwrap();
        (String::from_utf8(remote.output).unwrap(), String::from_utf8(agent.output).unwrap(), n, injected)
    }

    #[test]
    fn injects_in_the_header_only() {
        let body = r#"{"note":"PLACEHOLDER"}"#;
        let req = format!("POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\nx-api-key: PLACEHOLDER\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let (sent, got, n, injected) = run(&req, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        assert!(sent.contains("x-api-key: real-key\r\n"));
        assert!(sent.ends_with(r#"{"note":"PLACEHOLDER"}"#), "body must not be rewritten: {sent}");
        assert_eq!(sent.matches("real-key").count(), 1);
        assert!(got.ends_with("\r\n\r\nok"));
        assert_eq!((n, injected), (1, 1));
    }

    #[test]
    fn other_headers_and_values_are_left_alone() {
        let req = "GET / HTTP/1.1\r\nx-api-key: something-else\r\nx-other: PLACEHOLDER\r\n\r\n";
        let (sent, _, _, injected) = run(req, "HTTP/1.1 204 No Content\r\n\r\n");
        assert!(!sent.contains("real-key"));
        assert_eq!(injected, 0);
    }

    #[test]
    fn bearer_tokens_and_keep_alive_with_chunked_responses() {
        let mut s = secret();
        s.header = "authorization".into();
        let reqs = "GET /a HTTP/1.1\r\nAuthorization: Bearer PLACEHOLDER\r\n\r\nGET /b HTTP/1.1\r\nAuthorization: Bearer PLACEHOLDER\r\n\r\n";
        let resps = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye";
        let mut agent = pipe(reqs);
        let mut remote = pipe(resps);
        let (_, _, n, injected) = relay_http(&mut agent, &mut remote, "api.example.com", &[&s], None, None).unwrap();
        let sent = String::from_utf8(remote.output).unwrap();
        assert_eq!(sent.matches("Authorization: Bearer real-key\r\n").count(), 2);
        assert_eq!((n, injected), (2, 2));
        let got = String::from_utf8(agent.output).unwrap();
        assert!(got.contains("5\r\nhello\r\n0\r\n\r\n") && got.ends_with("bye"));
    }

    #[test]
    fn token_endpoint_is_rewritten_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), "claude").unwrap();
        let (sealed, _) = vault
            .seal_json(br#"{"accessToken":"sk-ant-oat01-OLDACCESS","refreshToken":"sk-ant-ort01-OLDREFRESH"}"#)
            .unwrap();
        let sealed: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
        let (access, refresh) = (sealed["accessToken"].as_str().unwrap(), sealed["refreshToken"].as_str().unwrap());

        let body = format!(r#"{{"grant_type":"refresh_token","refresh_token":"{refresh}"}}"#);
        let reqs = format!(
            "POST /v1/oauth/token HTTP/1.1\r\nAccept-Encoding: gzip\r\nContent-Length: {}\r\n\r\n{body}GET /api/me HTTP/1.1\r\nAuthorization: Bearer {access}\r\n\r\n",
            body.len()
        );
        let token = r#"{"access_token":"sk-ant-oat01-NEWACCESS","refresh_token":"sk-ant-ort01-NEWREFRESH","expires_in":3600}"#;
        let resps = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{token}HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", token.len());
        let mut agent = pipe(&reqs);
        let mut remote = pipe(&resps);
        let (_, _, n, injected) = relay_http(&mut agent, &mut remote, "api.example.com", &[], Some(&vault), None).unwrap();
        assert_eq!((n, injected), (2, 2));

        let sent = String::from_utf8(remote.output).unwrap();
        assert!(sent.contains("sk-ant-ort01-OLDREFRESH"), "real refresh token goes upstream");
        assert!(!sent.to_ascii_lowercase().contains("accept-encoding"));
        assert!(sent.contains("Authorization: Bearer sk-ant-oat01-OLDACCESS"));

        let got = String::from_utf8(agent.output).unwrap();
        assert!(!got.contains("NEWACCESS") && !got.contains("NEWREFRESH"), "new tokens reach the agent sealed: {got}");
        assert!(got.contains("sk-ant-oat01-agentosplaceholder-") && got.ends_with("ok"));
    }

    #[test]
    fn model_calls_are_metered_and_refused_over_budget() {
        use crate::gateway::{Api, Budget, Endpoint};
        let endpoint = Endpoint { host: "api.example.com".into(), path: "/v1/messages".into(), api: Api::Anthropic };
        let meter = Meter::new(vec![endpoint], Vec::new(), Some(Budget::Tokens(100)), Arc::new(|_| {}));
        let body = r#"{"model":"claude-haiku-4-5","messages":[]}"#;
        let call = format!("POST /v1/messages?beta=true HTTP/1.1\r\nAccept-Encoding: gzip, br\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let reqs = format!("{call}GET /v1/models HTTP/1.1\r\n\r\n{call}");
        let start = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-haiku-4-5\",\"usage\":{\"input_tokens\":120,\"output_tokens\":1}}}\n\n";
        let delta = "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":30}}\n\n";
        let stream = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{start}\r\n{:x}\r\n{delta}\r\n0\r\n\r\n", start.len(), delta.len());
        let resps = format!("{stream}HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{{}}");
        let mut agent = pipe(&reqs);
        let mut remote = pipe(&resps);
        let (_, _, n, _) = relay_http(&mut agent, &mut remote, "api.example.com", &[], None, Some(&meter)).unwrap();
        assert_eq!(n, 3);

        let sent = String::from_utf8(remote.output).unwrap();
        assert_eq!(sent.matches("POST /v1/messages").count(), 1, "the call over budget never goes out: {sent}");
        assert!(!sent.to_ascii_lowercase().contains("accept-encoding"));
        assert!(sent.contains("GET /v1/models"), "other requests pass");
        let got = String::from_utf8(agent.output).unwrap();
        assert!(got.contains("message_delta") && got.contains("HTTP/1.1 400 Bad Request"), "{got}");
        assert!(got.contains("budget is used up (150 of 100 tokens)"), "{got}");
        let t = meter.totals();
        assert_eq!((t.calls, t.usage.input, t.usage.output, t.refused), (1, 120, 30, 1));
    }

    #[test]
    fn unmeterable_calls_are_refused_under_a_budget() {
        use crate::gateway::{Budget, builtin_endpoints};
        let budgeted = Meter::new(builtin_endpoints(), Vec::new(), Some(Budget::Usd(5.0)), Arc::new(|_| {}));
        let free = Meter::new(builtin_endpoints(), Vec::new(), None, Arc::new(|_| {}));
        let post = |path: &str, body: &str| format!("POST {path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";

        // Anthropic's batches: never sent under a budget, sent without one.
        let batch = post("/v1/messages/batches", r#"{"requests":[]}"#);
        let (mut agent, mut remote) = (pipe(&batch), pipe(ok));
        relay_http(&mut agent, &mut remote, "api.anthropic.com", &[], None, Some(&budgeted)).unwrap();
        assert!(remote.output.is_empty(), "nothing goes out");
        let got = String::from_utf8(agent.output).unwrap();
        assert!(got.contains("400 Bad Request") && got.contains("Message Batches are billed when they finish"), "{got}");
        let (mut agent, mut remote) = (pipe(&batch), pipe(ok));
        relay_http(&mut agent, &mut remote, "api.anthropic.com", &[], None, Some(&free)).unwrap();
        assert!(String::from_utf8(remote.output).unwrap().contains("POST /v1/messages/batches"), "no budget: it goes");
        // Reading a batch's results costs nothing more.
        let (mut agent, mut remote) = (pipe("GET /v1/messages/batches/msgbatch_1 HTTP/1.1\r\n\r\n"), pipe(ok));
        relay_http(&mut agent, &mut remote, "api.anthropic.com", &[], None, Some(&budgeted)).unwrap();
        assert!(!remote.output.is_empty());

        // OpenAI's background responses: the body is read ahead to tell.
        let background = post("/v1/responses", r#"{"model":"gpt-5","input":"hi","background":true}"#);
        let (mut agent, mut remote) = (pipe(&background), pipe(ok));
        relay_http(&mut agent, &mut remote, "api.openai.com", &[], None, Some(&budgeted)).unwrap();
        assert!(remote.output.is_empty());
        assert!(String::from_utf8(agent.output).unwrap().contains("background responses are billed when they finish"));
        // A plain one goes, body intact, whether it was sent whole or in chunks.
        let body = r#"{"model":"gpt-5","input":"hi","background":false}"#;
        let chunked = format!("POST /v1/responses HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
        for req in [post("/v1/responses", body), chunked] {
            let (mut agent, mut remote) = (pipe(&req), pipe(ok));
            relay_http(&mut agent, &mut remote, "api.openai.com", &[], None, Some(&budgeted)).unwrap();
            let sent = String::from_utf8(remote.output).unwrap();
            assert!(sent.ends_with(&req[req.find("\r\n\r\n").unwrap() + 4..]), "{sent}");
            assert!(String::from_utf8(agent.output).unwrap().ends_with("{}"));
        }
        let t = budgeted.totals();
        assert_eq!((t.calls, t.refused), (0, 0), "not refusals of the budget itself");
    }

    #[test]
    fn secret_specs() {
        // SAFETY: tests in this module don't read this variable concurrently.
        unsafe { std::env::set_var("AGENTOS_TEST_TOKEN", "tok") };
        let s = Secret::parse("AGENTOS_TEST_TOKEN=api.example.com/x-api-key").unwrap();
        assert_eq!((s.host.as_str(), s.header.as_str(), s.value.as_str()), ("api.example.com", "x-api-key", "tok"));
        assert!(s.placeholder.starts_with("agentos-placeholder-"));
        assert_eq!(Secret::parse("AGENTOS_TEST_TOKEN=api.example.com").unwrap().header, "authorization");
        assert!(Secret::parse("AGENTOS_TEST_TOKEN").is_err());
        assert!(Secret::parse("AGENTOS_UNSET_VAR=x.com").is_err());
    }
}
