//! Signing in to your remote MCP servers, as MCP specifies it (OAuth 2.1):
//! the server's 401 says where its authorization server is, agentos
//! registers itself there as a client, and you approve in a browser that
//! comes back to a loopback address (PKCE, with the server as the token's
//! `resource`). Tokens are kept in the task store's vault, which no sandbox
//! can see; the MCP gateway adds them to the requests it makes for agents,
//! and refreshes them when they expire.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::BufRead;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// How long you have to approve in the browser.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
/// Refreshed this long before it expires.
const EARLY: u64 = 30_000;

/// A sign-in, as kept in the vault (`mcp-NAME.json`, 0600).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tokens {
    /// The MCP server signed in to; another URL in your config needs a new sign-in.
    pub url: String,
    pub issuer: String,
    pub token_endpoint: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
}

/// An HTTP client for MCP servers and their authorization servers: status
/// codes are answers, not errors; no overall timeout (tool calls can be long).
pub fn http() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(15)))
        .build()
        .into()
}

fn path(store_root: &Path, name: &str) -> PathBuf {
    store_root.join("vault").join(format!("mcp-{name}.json"))
}

pub fn load(store_root: &Path, name: &str) -> Option<Tokens> {
    serde_json::from_slice(&crate::sealed::read(store_root, &path(store_root, name)).ok()?).ok()
}

fn save(store_root: &Path, name: &str, t: &Tokens) -> Result<()> {
    let file = path(store_root, name);
    fs::DirBuilder::new().recursive(true).create(file.parent().context("vault")?)?;
    crate::sealed::write(store_root, &file, &serde_json::to_vec_pretty(t)?)
}

/// Forgets a sign-in. Returns whether there was one.
pub fn forget(store_root: &Path, name: &str) -> bool {
    fs::remove_file(path(store_root, name)).is_ok()
}

/// The access token for server `name` at `url`, refreshed first when it's
/// about to expire, or when `stale` (the server just refused it). `None`
/// when you haven't signed in (or did for another URL).
pub fn access_token(store_root: &Path, name: &str, url: &str, stale: bool) -> Result<Option<String>> {
    let Some(t) = load(store_root, name).filter(|t| t.url == url) else { return Ok(None) };
    let expiring = t.expires_at_ms.is_some_and(|at| crate::util::now_ms() + EARLY >= at);
    if !stale && !expiring {
        return Ok(Some(t.access_token));
    }
    if t.refresh_token.is_none() {
        return if expiring { Ok(None) } else { Ok(Some(t.access_token)) };
    }
    // One refresh at a time across tasks: a refresh token may only be good once.
    let lock = fs::OpenOptions::new().create(true).write(true).mode(0o600).open(path(store_root, name).with_extension("lock"))?;
    let _lock = nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusive).map_err(|(_, e)| e)?;
    let Some(now) = load(store_root, name) else { return Ok(None) };
    if now.access_token != t.access_token {
        // Another task refreshed it meanwhile.
        return Ok(Some(now.access_token));
    }
    let fresh = refresh(&http(), &now)?;
    save(store_root, name, &fresh)?;
    Ok(Some(fresh.access_token))
}

fn refresh(http: &ureq::Agent, t: &Tokens) -> Result<Tokens> {
    let refresh_token = t.refresh_token.clone().context("no refresh token")?;
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.clone()),
        ("client_id", t.client_id.clone()),
        ("resource", t.url.clone()),
    ];
    if let Some(s) = &t.client_secret {
        form.push(("client_secret", s.clone()));
    }
    let got = token_request(http, &t.token_endpoint, &form).context("refreshing the sign-in (run `agent connect` again if it was revoked)")?;
    Ok(Tokens { refresh_token: got.refresh_token.or(Some(refresh_token)), ..got_into(t, got.access_token, got.expires_in) })
}

fn got_into(t: &Tokens, access_token: String, expires_in: Option<u64>) -> Tokens {
    Tokens { access_token, expires_at_ms: expires_in.map(|s| crate::util::now_ms() + s * 1000), ..t.clone() }
}

#[derive(Deserialize)]
struct Granted {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

fn token_request(http: &ureq::Agent, endpoint: &str, form: &[(&str, String)]) -> Result<Granted> {
    let mut resp = http
        .post(endpoint)
        .header("Accept", "application/json")
        .send_form(form.iter().map(|(k, v)| (*k, v.as_str())))
        .with_context(|| format!("POST {endpoint}"))?;
    let status = resp.status().as_u16();
    let body = resp.body_mut().read_to_string().unwrap_or_default();
    if status != 200 {
        let v: Value = serde_json::from_str(&body).unwrap_or_default();
        let why = [v["error"].as_str(), v["error_description"].as_str()].into_iter().flatten().collect::<Vec<_>>().join(": ");
        bail!("{endpoint} answered HTTP {status}{}", if why.is_empty() { String::new() } else { format!(" ({why})") });
    }
    serde_json::from_str(&body).with_context(|| format!("{endpoint}: not a token response"))
}

/// Where to sign in for a server.
#[derive(Debug, Clone, PartialEq)]
pub struct Authorization {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub scope: Option<String>,
}

/// `scheme://host[:port]` and the path (no query or fragment).
fn split(url: &str) -> (String, String) {
    let url = url.split(['?', '#']).next().unwrap_or(url);
    let start = url.find("://").map_or(0, |i| i + 3);
    match url[start..].find('/') {
        Some(i) => (url[..start + i].to_string(), url[start + i..].trim_end_matches('/').to_string()),
        None => (url.to_string(), String::new()),
    }
}

/// `key="value"` parameters of a `WWW-Authenticate` header.
fn auth_param(header: &str, key: &str) -> Option<String> {
    let at = header.find(&format!("{key}="))? + key.len() + 1;
    let rest = &header[at..];
    match rest.strip_prefix('"') {
        Some(q) => q.split('"').next().map(str::to_string),
        None => rest.split([',', ' ']).next().map(str::to_string),
    }
}

fn get_json(http: &ureq::Agent, url: &str) -> Option<Value> {
    let mut resp = http.get(url).header("Accept", "application/json").call().ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    serde_json::from_str(&resp.body_mut().read_to_string().ok()?).ok()
}

/// Asks the server, without a token, where to sign in. `None` when it
/// answers without one: it doesn't need a sign-in.
pub fn discover(http: &ureq::Agent, url: &str) -> Result<Option<Authorization>> {
    let probe = json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "agentos", "version": env!("CARGO_PKG_VERSION") } } });
    let resp = http
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .send(probe.to_string().as_bytes())
        .with_context(|| format!("reach {url}"))?;
    let status = resp.status().as_u16();
    if status != 401 && status != 403 {
        return Ok(None);
    }
    let challenge = resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    let (origin, path) = split(url);
    // The protected resource's metadata (RFC 9728): from the 401, or well-known.
    let candidates = auth_param(&challenge, "resource_metadata")
        .into_iter()
        .chain([format!("{origin}/.well-known/oauth-protected-resource{path}"), format!("{origin}/.well-known/oauth-protected-resource")]);
    let resource = candidates.into_iter().find_map(|u| get_json(http, &u));
    let issuer = resource
        .as_ref()
        .and_then(|r| r["authorization_servers"][0].as_str().map(str::to_string))
        // Servers from before that spec: the authorization server is the server's own origin.
        .unwrap_or_else(|| origin.clone());
    let scope = auth_param(&challenge, "scope").or_else(|| {
        let scopes: Vec<&str> = resource.as_ref()?["scopes_supported"].as_array()?.iter().filter_map(Value::as_str).collect();
        (!scopes.is_empty()).then(|| scopes.join(" "))
    });
    // The authorization server's metadata (RFC 8414, or OpenID's).
    let (as_origin, as_path) = split(&issuer);
    let mut metadata = vec![
        format!("{as_origin}/.well-known/oauth-authorization-server{as_path}"),
        format!("{as_origin}/.well-known/openid-configuration{as_path}"),
    ];
    if !as_path.is_empty() {
        metadata.push(format!("{issuer}/.well-known/openid-configuration"));
    }
    let auth = match metadata.iter().find_map(|u| get_json(http, u)) {
        Some(m) => Authorization {
            issuer: m["issuer"].as_str().unwrap_or(&issuer).to_string(),
            authorization_endpoint: m["authorization_endpoint"].as_str().context("the authorization server's metadata has no authorization_endpoint")?.to_string(),
            token_endpoint: m["token_endpoint"].as_str().context("the authorization server's metadata has no token_endpoint")?.to_string(),
            registration_endpoint: m["registration_endpoint"].as_str().map(str::to_string),
            scope,
        },
        None if resource.is_none() => Authorization {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{as_origin}/authorize"),
            token_endpoint: format!("{as_origin}/token"),
            registration_endpoint: Some(format!("{as_origin}/register")),
            scope,
        },
        None => bail!("{url} asks for a sign-in at {issuer}, which doesn't describe itself (no OAuth metadata)"),
    };
    Ok(Some(auth))
}

/// Percent-encodes for a query string.
pub fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let escaped = (b[i] == b'%').then(|| s.get(i + 1..i + 3)).flatten().and_then(|h| u8::from_str_radix(h, 16).ok());
        match (b[i], escaped) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A query parameter of a URL (or of a bare query string).
pub fn query_param(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?').map_or(url, |(_, q)| q).split('#').next().unwrap_or_default();
    query.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| decode(v)))
}

/// Base64url without padding, for PKCE.
fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..=chunk.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn challenge(verifier: &str) -> String {
    b64url(&Sha256::digest(verifier.as_bytes()))
}

/// Opens `url` in your browser: `$BROWSER` if set, else the desktop's.
fn open_browser(url: &str) {
    let mut cmd = match std::env::var("BROWSER") {
        Ok(b) if !b.trim().is_empty() => {
            let mut c = std::process::Command::new("sh");
            c.args(["-c", &format!("{b} \"$1\""), "sh", url]);
            c
        }
        _ => {
            let mut c = std::process::Command::new(if cfg!(target_os = "macos") { "open" } else { "xdg-open" });
            c.arg(url);
            c
        }
    };
    let _ = cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
}

/// Signs in to server `name` at `url`: registers agentos with its
/// authorization server, has you approve in a browser, and keeps the
/// tokens. `tell` shows you each step.
pub fn sign_in(store_root: &Path, name: &str, url: &str, auth: &Authorization, tell: &dyn Fn(&str)) -> Result<Tokens> {
    let http = http();
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| anyhow::anyhow!("listen for the browser's return: {e}"))?;
    let port = server.server_addr().to_ip().context("loopback address")?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let registration = auth.registration_endpoint.as_deref().with_context(|| {
        format!("{} doesn't let clients register themselves, so agentos can't sign in to {name} (yet)", auth.issuer)
    })?;
    let body = json!({
        "client_name": "agentos",
        "redirect_uris": [redirect],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    let mut resp = http
        .post(registration)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .send(body.to_string().as_bytes())
        .with_context(|| format!("register with {registration}"))?;
    let status = resp.status().as_u16();
    let client: Value = serde_json::from_str(&resp.body_mut().read_to_string().unwrap_or_default()).unwrap_or_default();
    let client_id = match client["client_id"].as_str() {
        Some(id) if (200..300).contains(&status) => id.to_string(),
        _ => bail!("{registration} didn't register agentos (HTTP {status})"),
    };
    let client_secret = client["client_secret"].as_str().map(str::to_string);

    let verifier = crate::util::random_hex(32)?;
    let state = crate::util::random_hex(16)?;
    let sep = if auth.authorization_endpoint.contains('?') { '&' } else { '?' };
    let mut link = format!(
        "{}{sep}response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={state}&resource={}",
        auth.authorization_endpoint,
        encode(&client_id),
        encode(&redirect),
        challenge(&verifier),
        encode(url),
    );
    if let Some(scope) = &auth.scope {
        link.push_str(&format!("&scope={}", encode(scope)));
    }
    tell(&format!("open this in a browser to sign in:\n  {link}"));
    tell("(browser on another machine? paste the address it ends up on here)");
    open_browser(&link);

    // The browser comes back here, or you paste where it ended up.
    let (tx, rx) = mpsc::channel::<String>();
    let from_browser = {
        let tx = tx.clone();
        std::thread::spawn(move || {
            while let Ok(Some(req)) = server.recv_timeout(SIGN_IN_TIMEOUT) {
                let back = req.url().to_string();
                let page = "<!doctype html><meta charset=utf-8><title>agentos</title><p>Signed in. You can close this tab and go back to the terminal.";
                let header = tiny_http::Header::from_bytes("Content-Type", "text/html; charset=utf-8").expect("static header");
                let _ = req.respond(tiny_http::Response::from_string(page).with_header(header));
                if back.starts_with("/callback") {
                    let _ = tx.send(back);
                    break;
                }
            }
        })
    };
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if line.contains("code=") || line.contains("error=") {
                let _ = tx.send(line.trim().to_string());
                break;
            }
        }
    });
    let back = rx.recv_timeout(SIGN_IN_TIMEOUT).map_err(|_| anyhow::anyhow!("no answer from the browser in {} minutes", SIGN_IN_TIMEOUT.as_secs() / 60))?;
    drop(from_browser);
    if let Some(err) = query_param(&back, "error") {
        let why = query_param(&back, "error_description").map(|d| format!(": {d}")).unwrap_or_default();
        bail!("the sign-in was refused ({err}{why})");
    }
    if query_param(&back, "state").as_deref() != Some(state.as_str()) {
        bail!("the browser came back from another sign-in (state doesn't match): try again");
    }
    let code = query_param(&back, "code").context("the browser came back without a code")?;
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code),
        ("redirect_uri", redirect),
        ("client_id", client_id.clone()),
        ("code_verifier", verifier),
        ("resource", url.to_string()),
    ];
    if let Some(s) = &client_secret {
        form.push(("client_secret", s.clone()));
    }
    let got = token_request(&http, &auth.token_endpoint, &form)?;
    let tokens = Tokens {
        url: url.to_string(),
        issuer: auth.issuer.clone(),
        token_endpoint: auth.token_endpoint.clone(),
        client_id,
        client_secret,
        access_token: got.access_token,
        refresh_token: got.refresh_token,
        expires_at_ms: got.expires_in.map(|s| crate::util::now_ms() + s * 1000),
    };
    save(store_root, name, &tokens)?;
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_and_urls() {
        // RFC 7636, appendix B.
        assert_eq!(challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(encode("http://127.0.0.1:80/cb?a=b c"), "http%3A%2F%2F127.0.0.1%3A80%2Fcb%3Fa%3Db%20c");
        assert_eq!(query_param("http://127.0.0.1:5/callback?code=a%2Fb+c&state=xyz#frag", "code").as_deref(), Some("a/b c"));
        assert_eq!(query_param("code=1&state=2", "state").as_deref(), Some("2"));
        assert_eq!(split("https://mcp.example.com/v1/mcp/?x=1"), ("https://mcp.example.com".into(), "/v1/mcp".into()));
        assert_eq!(split("http://127.0.0.1:8080"), ("http://127.0.0.1:8080".into(), String::new()));
        let h = r#"Bearer error="invalid_token", resource_metadata="https://x.dev/.well-known/oauth-protected-resource", scope="read write""#;
        assert_eq!(auth_param(h, "resource_metadata").as_deref(), Some("https://x.dev/.well-known/oauth-protected-resource"));
        assert_eq!(auth_param(h, "scope").as_deref(), Some("read write"));
        assert_eq!(auth_param("Bearer realm=x", "scope"), None);
    }

    #[test]
    fn tokens_are_kept_per_server_and_url() {
        let dir = tempfile::tempdir().unwrap();
        let t = Tokens {
            url: "https://mcp.example.com/mcp".into(),
            issuer: "https://auth.example.com".into(),
            token_endpoint: "https://auth.example.com/token".into(),
            client_id: "c".into(),
            client_secret: None,
            access_token: "at".into(),
            refresh_token: None,
            expires_at_ms: None,
        };
        save(dir.path(), "tracker", &t).unwrap();
        assert_eq!(access_token(dir.path(), "tracker", &t.url, false).unwrap().as_deref(), Some("at"));
        assert_eq!(access_token(dir.path(), "tracker", "https://other.example.com/mcp", false).unwrap(), None, "another URL: sign in again");
        assert_eq!(access_token(dir.path(), "other", &t.url, false).unwrap(), None);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(path(dir.path(), "tracker")).unwrap().permissions().mode() & 0o777, 0o600);
        // Expired, with nothing to refresh it with: you sign in again.
        save(dir.path(), "tracker", &Tokens { expires_at_ms: Some(1), ..t.clone() }).unwrap();
        assert_eq!(access_token(dir.path(), "tracker", &t.url, false).unwrap(), None);
        assert!(forget(dir.path(), "tracker") && !forget(dir.path(), "tracker"));
    }
}
