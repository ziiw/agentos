//! Signing in to agentd's console with your identity provider (OpenID Connect).
//!
//! ```toml
//! [console.oidc]                                   # your config only
//! issuer = "https://accounts.example.com"
//! client_id = "agentd"
//! client_secret = "AGENTD_OIDC_SECRET"             # the variable that holds it
//! public_url = "https://agentd.example.com"        # where people reach agentd
//!
//! [console.oidc.roles]                             # who gets what; no entry, no entry
//! "alice@example.com" = "admin"
//! "group:platform" = "approver"
//! "domain:example.com" = "viewer"
//! "group:contractors" = { role = "viewer", projects = ["~/code/app"] }
//! ```
//!
//! `/login` sends the browser to the provider (authorization code flow with
//! PKCE, a `state` and a `nonce`, and a cookie that ties the sign-in to the
//! browser that began it). `/oidc/callback` exchanges the code, checks the ID
//! token (signature against the provider's published keys, issuer, audience,
//! expiry, nonce: RS256 and ES256 only, whatever the token's header asks
//! for), maps the person to a role, and hands the console a session token of
//! its own, as the link `agent serve` prints does. Nothing else about the
//! console's tokens changes: this only gives out ones for people your provider
//! vouches for.

use crate::users::Role;
use anyhow::{Context, Result, bail};
use ring::rsa::PublicKeyComponents;
use ring::signature::{ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// How long a sign-in may take between `/login` and the callback.
const LOGIN_TTL: Duration = Duration::from_secs(600);
/// Sign-ins begun and not finished that are remembered at once.
const MAX_PENDING: usize = 500;
/// How long a provider's description and keys are trusted before a refetch.
const CACHE_TTL: Duration = Duration::from_secs(3600);
/// A provider is asked for its keys again at most this often (an unknown key id).
const REFETCH_AFTER: Duration = Duration::from_secs(30);
/// Slack for clocks that disagree.
const SKEW_SECS: u64 = 60;

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer: String,
    pub client_id: String,
    /// The environment variable (or `[secret_commands]` entry) holding the client secret; none: a public client (PKCE alone).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Where people reach agentd: the provider sends them back to `{public_url}/oidc/callback`.
    pub public_url: String,
    #[serde(default)]
    pub scopes: Option<String>,
    /// How long a sign-in lasts (default 12h).
    #[serde(default)]
    pub session: Option<String>,
    /// Which claim lists a person's groups (default "groups").
    #[serde(default)]
    pub groups_claim: Option<String>,
    /// Whether an email address counts only when the provider says it's verified (default yes).
    #[serde(default = "yes")]
    pub require_verified_email: bool,
    #[serde(default)]
    pub roles: BTreeMap<String, Grant>,
}

/// What a match in `roles` gives: a role, or a role on some projects only.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Grant {
    Role(String),
    Limited {
        role: String,
        #[serde(default)]
        projects: Vec<String>,
    },
}

impl Grant {
    fn parts(&self) -> Result<(Role, &[String])> {
        match self {
            Grant::Role(r) => Ok((Role::parse(r)?, &[])),
            Grant::Limited { role, projects } => Ok((Role::parse(role)?, projects)),
        }
    }
}

/// Whether `url` is somewhere we may talk to: https, or this machine.
fn reachable(url: &str) -> bool {
    crate::attest::valid_witness(url).is_ok()
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if !reachable(&self.issuer) || self.issuer.contains(['?', '#']) {
            bail!("[console.oidc] issuer must be an https:// address (http:// only for this machine), without a query: {:?}", self.issuer);
        }
        if self.client_id.trim().is_empty() {
            bail!("[console.oidc] client_id is empty");
        }
        if let Some(var) = &self.client_secret {
            if var.is_empty() || !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                bail!("[console.oidc] client_secret is the name of an environment variable holding it, e.g. \"AGENTD_OIDC_SECRET\"");
            }
        }
        if !reachable(&self.public_url) || self.public_url.contains(['?', '#']) {
            bail!("[console.oidc] public_url must be where people reach agentd, https:// (http:// only for this machine): {:?}", self.public_url);
        }
        let ttl = self.session_ttl()?;
        if ttl < Duration::from_secs(300) || ttl > Duration::from_secs(30 * 86400) {
            bail!("[console.oidc] session lasts from 5 minutes to 30 days");
        }
        if self.roles.is_empty() {
            bail!("[console.oidc] roles is empty: nobody could sign in. Name who gets a role: \"alice@example.com\" = \"admin\", \"group:platform\" = \"approver\"");
        }
        for (who, grant) in &self.roles {
            let ok = match who.split_once(':') {
                Some(("group" | "domain" | "sub", rest)) => !rest.is_empty(),
                Some(_) => false,
                None => who.contains('@') && !who.starts_with('@') && !who.ends_with('@'),
            };
            if !ok {
                bail!("[console.oidc.roles] {who:?}: an email address, or group:NAME, domain:example.com or sub:ID");
            }
            let (_, projects) = grant.parts().with_context(|| format!("[console.oidc.roles] {who:?}"))?;
            if let Some(bad) = projects.iter().find(|p| !(p.starts_with('/') || p.starts_with("~/"))) {
                bail!("[console.oidc.roles] {who:?}: project {bad:?}: use an absolute path or ~/…");
            }
        }
        Ok(())
    }

    pub fn session_ttl(&self) -> Result<Duration> {
        match &self.session {
            Some(s) => humantime::parse_duration(s).with_context(|| format!("[console.oidc] session {s:?}: expected e.g. 12h")),
            None => Ok(Duration::from_secs(12 * 3600)),
        }
    }

    fn redirect_uri(&self) -> String {
        format!("{}/oidc/callback", self.public_url.trim_end_matches('/'))
    }

    /// Whether the cookie that ties a sign-in to its browser should be marked secure.
    pub fn secure(&self) -> bool {
        self.public_url.starts_with("https://")
    }
}

// ---- base64url, and the keys of a JWKS ----

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.len() % 4 == 1 {
        return None;
    }
    let (mut out, mut acc, mut bits) = (Vec::with_capacity(s.len() * 3 / 4), 0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

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

#[derive(Debug, Clone, PartialEq)]
pub enum Key {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// An uncompressed P-256 point: 0x04, x, y.
    Ec { point: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Jwk {
    pub kid: Option<String>,
    /// The algorithm the key says it's for, if it says.
    pub alg: Option<String>,
    pub key: Key,
}

/// The signing keys in a JWKS document. Keys of kinds we don't verify, or
/// meant for encryption, are left out.
pub fn parse_jwks(doc: &Value) -> Vec<Jwk> {
    let field = |k: &Value, name: &str| k[name].as_str().and_then(b64url_decode);
    doc["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|k| k["use"].as_str().is_none_or(|u| u == "sig"))
        .filter_map(|k| {
            let key = match k["kty"].as_str()? {
                "RSA" => {
                    let (n, e) = (field(k, "n")?, field(k, "e")?);
                    // (ring wants 2048 bits or more, and says so when it verifies.)
                    Key::Rsa { n, e }
                }
                "EC" if k["crv"].as_str() == Some("P-256") => {
                    let (x, y) = (field(k, "x")?, field(k, "y")?);
                    if x.len() != 32 || y.len() != 32 {
                        return None;
                    }
                    Key::Ec { point: [&[4u8][..], &x, &y].concat() }
                }
                _ => return None,
            };
            Some(Jwk { kid: k["kid"].as_str().map(str::to_string), alg: k["alg"].as_str().map(str::to_string), key })
        })
        .collect()
}

// ---- the ID token ----

/// Who the provider says someone is.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub groups: Vec<String>,
}

impl Identity {
    /// What to call them in a journal.
    pub fn name(&self) -> String {
        format!("sso:{}", self.email.as_deref().unwrap_or(&self.sub))
    }
}

/// Checks an ID token and says who it's about. Only RS256 and ES256 are
/// accepted, whatever the token's header says it is (`none`, or an HMAC
/// keyed with a public key, are the classic ways around a check like this),
/// and the key must be of the kind the algorithm needs.
pub fn verify_id_token(jwt: &str, cfg: &Config, keys: &[Jwk], nonce: &str, now: u64) -> Result<Identity, String> {
    let bad = |why: &str| Err(format!("the identity provider's token was refused: {why}"));
    let parts: Vec<&str> = jwt.split('.').collect();
    let [head, payload, signature] = parts.as_slice() else { return bad("it isn't a signed token") };
    let (Some(header), Some(claims)) = (
        b64url_decode(head).and_then(|b| serde_json::from_slice::<Value>(&b).ok()),
        b64url_decode(payload).and_then(|b| serde_json::from_slice::<Value>(&b).ok()),
    ) else {
        return bad("it can't be read");
    };
    let Some(signature) = b64url_decode(signature) else { return bad("its signature can't be read") };
    let alg = header["alg"].as_str().unwrap_or("");
    if alg != "RS256" && alg != "ES256" {
        return bad(&format!("it's signed with {:?}, and agentd accepts RS256 and ES256", alg));
    }
    let kid = header["kid"].as_str();
    // The key it names, or the only one of its kind when it names none.
    let of_kind = |k: &&Jwk| matches!((alg, &k.key), ("RS256", Key::Rsa { .. }) | ("ES256", Key::Ec { .. })) && k.alg.as_deref().is_none_or(|a| a == alg);
    let candidates: Vec<&Jwk> = match kid {
        Some(kid) => keys.iter().filter(|k| k.kid.as_deref() == Some(kid)).filter(of_kind).collect(),
        None => keys.iter().filter(of_kind).collect(),
    };
    let [key] = candidates.as_slice() else {
        return bad(if candidates.is_empty() { "it's signed with a key the provider doesn't publish" } else { "it doesn't say which of the provider's keys signed it" });
    };
    let message = format!("{head}.{payload}");
    let verified = match &key.key {
        Key::Rsa { n, e } => PublicKeyComponents { n, e }.verify(&RSA_PKCS1_2048_8192_SHA256, message.as_bytes(), &signature).is_ok(),
        Key::Ec { point } => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point).verify(message.as_bytes(), &signature).is_ok(),
    };
    if !verified {
        return bad("its signature isn't the provider's");
    }
    // Signed by the provider. Is it for this sign-in?
    if claims["iss"].as_str() != Some(cfg.issuer.as_str()) {
        return bad("it comes from another issuer");
    }
    let audience: Vec<&str> = match &claims["aud"] {
        Value::String(a) => vec![a.as_str()],
        Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audience.contains(&cfg.client_id.as_str()) {
        return bad("it isn't for agentd (its audience is someone else)");
    }
    if audience.len() > 1 && claims["azp"].as_str() != Some(cfg.client_id.as_str()) {
        return bad("it was issued to several parties, not to agentd");
    }
    let Some(exp) = claims["exp"].as_u64() else { return bad("it has no expiry") };
    if exp + SKEW_SECS < now {
        return bad("it has expired");
    }
    if claims["iat"].as_u64().is_some_and(|iat| iat > now + 5 * SKEW_SECS) {
        return bad("it was issued in the future");
    }
    if claims["nbf"].as_u64().is_some_and(|nbf| nbf > now + SKEW_SECS) {
        return bad("it isn't valid yet");
    }
    if claims["nonce"].as_str() != Some(nonce) {
        return bad("it isn't the answer to this sign-in (wrong nonce)");
    }
    let Some(sub) = claims["sub"].as_str().filter(|s| !s.is_empty()) else { return bad("it doesn't say who it's about") };
    let groups_claim = cfg.groups_claim.as_deref().unwrap_or("groups");
    Ok(Identity {
        sub: sub.to_string(),
        email: claims["email"].as_str().map(str::to_string),
        email_verified: match &claims["email_verified"] {
            Value::Bool(b) => *b,
            Value::String(s) => s == "true",
            _ => false,
        },
        groups: claims[groups_claim].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect(),
    })
}

/// The role (and the projects it's limited to, as written; none: all) that
/// `roles` gives this person. The strongest match wins; of equal ones, a
/// role that isn't limited beats one that is, and limited ones add up.
pub fn grant(cfg: &Config, id: &Identity) -> Result<Option<(Role, Vec<String>)>, String> {
    let email = id.email.as_deref().map(str::to_ascii_lowercase);
    // An address the provider doesn't vouch for says nothing about who someone is.
    let email = email.filter(|_| id.email_verified || !cfg.require_verified_email);
    let mut best: Option<(Role, Vec<String>, bool)> = None;
    for (who, grant) in &cfg.roles {
        let matches = match who.split_once(':') {
            Some(("sub", v)) => id.sub == v,
            Some(("group", v)) => id.groups.iter().any(|g| g == v),
            Some(("domain", v)) => email.as_deref().and_then(|e| e.rsplit_once('@')).is_some_and(|(_, d)| d == v.to_ascii_lowercase()),
            _ => email.as_deref() == Some(&who.to_ascii_lowercase()),
        };
        if !matches {
            continue;
        }
        let (role, projects) = grant.parts().map_err(|e| format!("{e:#}"))?;
        let limited = !projects.is_empty();
        best = Some(match best {
            None => (role, projects.to_vec(), limited),
            Some((r, _, _)) if role > r => (role, projects.to_vec(), limited),
            Some((r, p, was_limited)) if role == r => match (was_limited, limited) {
                (false, _) => (r, p, false),
                (true, false) => (r, Vec::new(), false),
                (true, true) => (r, p.into_iter().chain(projects.iter().cloned()).collect(), true),
            },
            Some(keep) => keep,
        });
    }
    Ok(best.map(|(role, mut projects, _)| {
        projects.sort();
        projects.dedup();
        (role, projects)
    }))
}

// ---- the provider ----

#[derive(Debug, Clone)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    /// Whether the token endpoint takes the client's login in the form instead of a Basic header.
    secret_in_form: bool,
}

struct Cached {
    discovery: Discovery,
    discovered: Instant,
    keys: Vec<Jwk>,
    fetched: Instant,
}

static PROVIDERS: LazyLock<Mutex<HashMap<String, Cached>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

struct Pending {
    nonce: String,
    verifier: String,
    /// The value of the cookie the browser that began it was given.
    browser: String,
    at: Instant,
}

static PENDING: LazyLock<Mutex<HashMap<String, Pending>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn client() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .into()
}

fn get_json(http: &ureq::Agent, url: &str) -> Result<Value> {
    let mut resp = http.get(url).header("Accept", "application/json").call().with_context(|| format!("fetch {url}"))?;
    let status = resp.status().as_u16();
    if status != 200 {
        bail!("{url} answered HTTP {status}");
    }
    let body = resp.body_mut().with_config().limit(1024 * 1024).read_to_string().with_context(|| format!("read {url}"))?;
    serde_json::from_str(&body).with_context(|| format!("{url}: not JSON"))
}

fn discover(http: &ureq::Agent, cfg: &Config) -> Result<Discovery> {
    let url = format!("{}/.well-known/openid-configuration", cfg.issuer.trim_end_matches('/'));
    let doc = get_json(http, &url)?;
    // A provider that names another issuer than the one you configured isn't that issuer.
    if doc["issuer"].as_str() != Some(cfg.issuer.as_str()) {
        bail!("{url} says its issuer is {:?}, not {:?}", doc["issuer"].as_str().unwrap_or(""), cfg.issuer);
    }
    let endpoint = |name: &str| -> Result<String> {
        let u = doc[name].as_str().with_context(|| format!("{url} has no {name}"))?;
        if !reachable(u) {
            bail!("{url}: {name} {u:?} isn't https");
        }
        Ok(u.to_string())
    };
    if let Some(algs) = doc["id_token_signing_alg_values_supported"].as_array() {
        if !algs.iter().filter_map(Value::as_str).any(|a| a == "RS256" || a == "ES256") {
            bail!("{url}: the provider signs ID tokens in neither RS256 nor ES256");
        }
    }
    let methods: Vec<&str> = doc["token_endpoint_auth_methods_supported"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    Ok(Discovery {
        authorization_endpoint: endpoint("authorization_endpoint")?,
        token_endpoint: endpoint("token_endpoint")?,
        jwks_uri: endpoint("jwks_uri")?,
        secret_in_form: !methods.is_empty() && !methods.contains(&"client_secret_basic") && methods.contains(&"client_secret_post"),
    })
}

/// The provider's description and keys, from the cache while they're fresh.
/// `want_kid`: a key id the cache doesn't have makes it look again (but not
/// more than every half minute).
fn provider(http: &ureq::Agent, cfg: &Config, want_kid: Option<&str>) -> Result<(Discovery, Vec<Jwk>)> {
    let mut cache = PROVIDERS.lock().unwrap_or_else(|p| p.into_inner());
    let stale = cache.get(&cfg.issuer).is_none_or(|c| c.discovered.elapsed() > CACHE_TTL);
    if stale {
        let discovery = discover(http, cfg)?;
        let keys = parse_jwks(&get_json(http, &discovery.jwks_uri)?);
        cache.insert(cfg.issuer.clone(), Cached { discovery, discovered: Instant::now(), keys, fetched: Instant::now() });
    } else if let Some(c) = cache.get_mut(&cfg.issuer) {
        let missing = want_kid.is_some_and(|kid| !c.keys.iter().any(|k| k.kid.as_deref() == Some(kid)));
        if (missing && c.fetched.elapsed() > REFETCH_AFTER) || c.fetched.elapsed() > CACHE_TTL {
            if let Ok(doc) = get_json(http, &c.discovery.jwks_uri) {
                c.keys = parse_jwks(&doc);
            }
            c.fetched = Instant::now();
        }
    }
    let c = cache.get(&cfg.issuer).context("the provider's description is gone")?;
    Ok((c.discovery.clone(), c.keys.clone()))
}

fn random(bytes: usize) -> Result<String> {
    Ok(crate::util::random_hex(bytes)?)
}

/// Starts a sign-in: where to send the browser, and the value of the cookie
/// to give it (the callback wants it back).
pub fn begin(cfg: &Config) -> Result<(String, String)> {
    let http = client();
    let (discovery, _) = provider(&http, cfg, None)?;
    let (state, nonce, verifier, browser) = (random(24)?, random(24)?, random(24)?, random(24)?);
    {
        let mut pending = PENDING.lock().unwrap_or_else(|p| p.into_inner());
        pending.retain(|_, p| p.at.elapsed() < LOGIN_TTL);
        if pending.len() >= MAX_PENDING {
            bail!("too many sign-ins are waiting: try again in a few minutes");
        }
        pending.insert(state.clone(), Pending { nonce: nonce.clone(), verifier: verifier.clone(), browser: browser.clone(), at: Instant::now() });
    }
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    let sep = if discovery.authorization_endpoint.contains('?') { '&' } else { '?' };
    let enc = crate::oauth::encode;
    let url = format!(
        "{}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        discovery.authorization_endpoint,
        enc(&cfg.client_id),
        enc(&cfg.redirect_uri()),
        enc(cfg.scopes.as_deref().unwrap_or("openid email profile")),
        state,
        nonce,
        challenge
    );
    Ok((url, browser))
}

/// Compares without telling how much matched.
fn same(a: &str, b: &str) -> bool {
    Sha256::digest(a.as_bytes()).iter().zip(Sha256::digest(b.as_bytes()).iter()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Finishes a sign-in: the callback's query, and the cookie the browser sent
/// back. Who the provider says they are, or why not (text fit to show them).
pub fn finish(cfg: &Config, secret: Option<&str>, query: &str, browser_cookie: Option<&str>, now: u64) -> Result<Identity, String> {
    let param = |k: &str| crate::oauth::query_param(query, k);
    // A sign-in can be finished once, whatever happens next.
    let pending = param("state").and_then(|s| PENDING.lock().unwrap_or_else(|p| p.into_inner()).remove(&s));
    if let Some(error) = param("error") {
        let said = param("error_description").map(|d| format!(": {}", crate::approvals::sanitize(&d, 200))).unwrap_or_default();
        return Err(format!("the identity provider didn't sign you in ({}{said})", crate::approvals::sanitize(&error, 60)));
    }
    let Some(pending) = pending.filter(|p| p.at.elapsed() < LOGIN_TTL) else {
        return Err("this sign-in is unknown, was used already, or took too long: start again".into());
    };
    if !browser_cookie.is_some_and(|c| same(c, &pending.browser)) {
        return Err("this sign-in was begun in another browser: start again from this one".into());
    }
    let Some(code) = param("code").filter(|c| !c.is_empty()) else { return Err("the identity provider sent no code".into()) };
    let http = client();
    let (discovery, _) = provider(&http, cfg, None).map_err(|e| format!("can't reach the identity provider: {e:#}"))?;
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code),
        ("redirect_uri", cfg.redirect_uri()),
        ("code_verifier", pending.verifier.clone()),
    ];
    let mut request = http.post(&discovery.token_endpoint).header("Accept", "application/json");
    match secret {
        Some(secret) if discovery.secret_in_form => {
            form.push(("client_id", cfg.client_id.clone()));
            form.push(("client_secret", secret.to_string()));
        }
        Some(secret) => {
            let login = format!("{}:{}", crate::oauth::encode(&cfg.client_id), crate::oauth::encode(secret));
            request = request.header("Authorization", format!("Basic {}", crate::util::base64(login.as_bytes())));
        }
        None => form.push(("client_id", cfg.client_id.clone())),
    }
    let mut response = request.send_form(form.iter().map(|(k, v)| (*k, v.as_str()))).map_err(|e| format!("can't reach the identity provider's token endpoint: {e}"))?;
    let status = response.status().as_u16();
    let body = response.body_mut().with_config().limit(1024 * 1024).read_to_string().unwrap_or_default();
    let answer: Value = serde_json::from_str(&body).unwrap_or_default();
    if status != 200 {
        let why = answer["error"].as_str().unwrap_or("no reason given");
        return Err(format!("the identity provider's token endpoint refused the code (HTTP {status}: {})", crate::approvals::sanitize(why, 80)));
    }
    let Some(id_token) = answer["id_token"].as_str() else { return Err("the identity provider's answer has no ID token".into()) };
    // Which key signed it? (read before the check, to fetch keys again if it's a new one)
    let kid = id_token.split('.').next().and_then(b64url_decode).and_then(|h| serde_json::from_slice::<Value>(&h).ok()).and_then(|h| h["kid"].as_str().map(str::to_string));
    let (_, keys) = provider(&http, cfg, kid.as_deref()).map_err(|e| format!("can't reach the identity provider: {e:#}"))?;
    verify_id_token(id_token, cfg, &keys, &pending.nonce, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use serde_json::json;

    /// Two 2048-bit RSA keys (PKCS#1) made for these tests, and for nothing else.
    const RSA_KEY: &[u8] = include_bytes!("../tests/oidc-test-rsa.der");
    const OTHER_RSA_KEY: &[u8] = include_bytes!("../tests/oidc-test-rsa-other.der");

    const NOW: u64 = 1_800_000_000;

    fn config() -> Config {
        let toml = r#"
            issuer = "https://idp.example.com"
            client_id = "agentd"
            public_url = "https://agentd.example.com"
            [roles]
            "alice@example.com" = "admin"
            "group:platform" = "approver"
            "domain:example.com" = "viewer"
            "group:contractors" = { role = "viewer", projects = ["~/code/app"] }
            "sub:svc-1" = { role = "approver", projects = ["/srv/a"] }
        "#;
        toml::from_str(toml).unwrap()
    }

    struct Signer {
        rsa: RsaKeyPair,
        ec: EcdsaKeyPair,
    }

    /// (n, e) of a PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }.
    fn rsa_components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
        fn read(der: &[u8]) -> (&[u8], &[u8]) {
            let (len, header) = if der[1] & 0x80 == 0 {
                (der[1] as usize, 2)
            } else {
                let n = (der[1] & 0x7f) as usize;
                (der[2..2 + n].iter().fold(0usize, |a, b| a << 8 | *b as usize), 2 + n)
            };
            (&der[header..header + len], &der[header + len..])
        }
        let (sequence, _) = read(der);
        let (n, rest) = read(sequence);
        let (e, _) = read(rest);
        let strip = |v: &[u8]| v.iter().skip_while(|b| **b == 0).copied().collect::<Vec<u8>>();
        (strip(n), strip(e))
    }

    fn signer() -> Signer {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        Signer { rsa: RsaKeyPair::from_der(RSA_KEY).unwrap(), ec: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap() }
    }

    impl Signer {
        fn jwks(&self) -> Vec<Jwk> {
            let (n, e) = rsa_components(self.rsa.public().as_ref());
            vec![
                Jwk { kid: Some("rsa-1".into()), alg: Some("RS256".into()), key: Key::Rsa { n, e } },
                Jwk { kid: Some("ec-1".into()), alg: None, key: Key::Ec { point: self.ec.public_key().as_ref().to_vec() } },
            ]
        }

        /// A token with this header and these claims, signed as `alg` says (with the key that goes with it;
        /// "forged" as the key id means the other RSA key, which the provider doesn't publish).
        fn token(&self, header: Value, claims: Value) -> String {
            let signing_input = format!("{}.{}", b64url(header.to_string().as_bytes()), b64url(claims.to_string().as_bytes()));
            let rng = SystemRandom::new();
            let signature = match header["alg"].as_str().unwrap_or("") {
                "RS256" => {
                    let other = RsaKeyPair::from_der(OTHER_RSA_KEY).unwrap();
                    let key = if header["kid"] == "forged" { &other } else { &self.rsa };
                    let mut sig = vec![0u8; key.public().modulus_len()];
                    key.sign(&RSA_PKCS1_SHA256, &rng, signing_input.as_bytes(), &mut sig).unwrap();
                    sig
                }
                "ES256" => self.ec.sign(&rng, signing_input.as_bytes()).unwrap().as_ref().to_vec(),
                _ => b"not a signature".to_vec(),
            };
            format!("{signing_input}.{}", b64url(&signature))
        }
    }

    fn claims() -> Value {
        json!({ "iss": "https://idp.example.com", "aud": "agentd", "sub": "u-1", "exp": NOW + 600, "iat": NOW - 5, "nonce": "n-123", "email": "Alice@Example.com", "email_verified": true, "groups": ["platform"] })
    }

    fn rs256() -> Value {
        json!({ "alg": "RS256", "kid": "rsa-1" })
    }

    #[test]
    fn base64url_both_ways() {
        for (plain, enc) in [("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"), ("foob", "Zm9vYg"), ("fooba", "Zm9vYmE"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(b64url(plain.as_bytes()), enc);
            assert_eq!(b64url_decode(enc).unwrap(), plain.as_bytes());
        }
        assert_eq!(b64url_decode("Zg==").unwrap(), b"f", "padding is allowed");
        assert_eq!(b64url_decode("-_-_").unwrap(), [0xfb, 0xff, 0xbf]);
        for bad in ["Z", "Zg=a", "a+b/", "a b", "é"] {
            assert!(b64url_decode(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_good_token_says_who_it_is_about() {
        let s = signer();
        let keys = s.jwks();
        for header in [rs256(), json!({ "alg": "ES256", "kid": "ec-1" }), json!({ "alg": "ES256" })] {
            let id = verify_id_token(&s.token(header.clone(), claims()), &config(), &keys, "n-123", NOW).unwrap_or_else(|e| panic!("{header}: {e}"));
            assert_eq!((id.sub.as_str(), id.email.as_deref(), id.email_verified, id.groups.as_slice()), ("u-1", Some("Alice@Example.com"), true, &["platform".to_string()][..]));
            assert_eq!(id.name(), "sso:Alice@Example.com");
        }
        // The audience may be a list that includes us, if we're the authorized party.
        let mut c = claims();
        c["aud"] = json!(["other", "agentd"]);
        c["azp"] = json!("agentd");
        assert!(verify_id_token(&s.token(rs256(), c.clone()), &config(), &keys, "n-123", NOW).is_ok());
        c["azp"] = json!("someone-else");
        assert!(verify_id_token(&s.token(rs256(), c), &config(), &keys, "n-123", NOW).unwrap_err().contains("several parties"));
        // A little clock skew either way is fine; a lot isn't.
        let mut c = claims();
        c["exp"] = json!(NOW - 30);
        assert!(verify_id_token(&s.token(rs256(), c), &config(), &keys, "n-123", NOW).is_ok());
    }

    #[test]
    fn a_token_that_isnt_for_this_sign_in_is_refused() {
        let s = signer();
        let keys = s.jwks();
        let check = |header: Value, tweak: &dyn Fn(&mut Value), nonce: &str| {
            let mut c = claims();
            tweak(&mut c);
            verify_id_token(&s.token(header, c), &config(), &keys, nonce, NOW).unwrap_err()
        };
        let none = |_: &mut Value| {};
        assert!(check(rs256(), &|c| c["iss"] = json!("https://evil.example.com"), "n-123").contains("another issuer"));
        assert!(check(rs256(), &|c| c["iss"] = json!("https://idp.example.com/"), "n-123").contains("another issuer"), "to the letter");
        assert!(check(rs256(), &|c| c["aud"] = json!("someone-else"), "n-123").contains("audience"));
        assert!(check(rs256(), &|c| c["aud"] = json!(["a", "b"]), "n-123").contains("audience"));
        assert!(check(rs256(), &|c| c["aud"] = json!(7), "n-123").contains("audience"));
        assert!(check(rs256(), &|c| c["exp"] = json!(NOW - 61), "n-123").contains("expired"));
        assert!(check(rs256(), &|c| c["exp"] = json!("soon"), "n-123").contains("no expiry"));
        assert!(check(rs256(), &|c| { c.as_object_mut().unwrap().remove("exp"); }, "n-123").contains("no expiry"));
        assert!(check(rs256(), &|c| c["iat"] = json!(NOW + 3600), "n-123").contains("future"));
        assert!(check(rs256(), &|c| c["nbf"] = json!(NOW + 3600), "n-123").contains("isn't valid yet"));
        assert!(check(rs256(), &none, "another-nonce").contains("wrong nonce"));
        assert!(check(rs256(), &|c| { c.as_object_mut().unwrap().remove("nonce"); }, "n-123").contains("wrong nonce"));
        assert!(check(rs256(), &|c| c["sub"] = json!(""), "n-123").contains("who it's about"));
    }

    #[test]
    fn a_token_that_isnt_the_providers_is_refused() {
        let s = signer();
        let keys = s.jwks();
        let c = claims();
        let refused = |jwt: String| verify_id_token(&jwt, &config(), &keys, "n-123", NOW).unwrap_err();
        // alg none, and the HMAC-with-the-public-key trick, and anything else.
        for alg in ["none", "HS256", "HS512", "RS512", "PS256", "ES384", "", "rs256"] {
            let err = refused(s.token(json!({ "alg": alg, "kid": "rsa-1" }), c.clone()));
            assert!(err.contains("agentd accepts RS256 and ES256"), "{alg}: {err}");
        }
        // Edited after signing.
        let good = s.token(rs256(), c.clone());
        let mut parts: Vec<String> = good.split('.').map(str::to_string).collect();
        let mut edited = c.clone();
        edited["sub"] = json!("admin");
        parts[1] = b64url(edited.to_string().as_bytes());
        assert!(refused(parts.join(".")).contains("signature isn't the provider's"));
        // Signed by a key the provider doesn't publish, under the name of one it does.
        let mut as_published = json!({ "alg": "RS256", "kid": "rsa-1" });
        let forged = {
            let signing_input = format!("{}.{}", b64url(as_published.to_string().as_bytes()), b64url(c.to_string().as_bytes()));
            let other = RsaKeyPair::from_der(OTHER_RSA_KEY).unwrap();
            let mut sig = vec![0u8; other.public().modulus_len()];
            other.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), signing_input.as_bytes(), &mut sig).unwrap();
            format!("{signing_input}.{}", b64url(&sig))
        };
        assert!(refused(forged).contains("signature isn't the provider's"));
        as_published["kid"] = json!("forged");
        assert!(refused(s.token(as_published, c.clone())).contains("key the provider doesn't publish"));
        // A key the provider doesn't publish.
        assert!(refused(s.token(json!({ "alg": "RS256", "kid": "who" }), c.clone())).contains("key the provider doesn't publish"));
        // The key's kind has to be the algorithm's.
        assert!(refused(s.token(json!({ "alg": "RS256", "kid": "ec-1" }), c.clone())).contains("key the provider doesn't publish"));
        assert!(refused(s.token(json!({ "alg": "ES256", "kid": "rsa-1" }), c.clone())).contains("key the provider doesn't publish"));
        // No kid, and more than one key of the kind: it can't be told which.
        let mut twice = s.jwks();
        twice.push(twice[0].clone());
        let err = verify_id_token(&s.token(json!({ "alg": "RS256" }), c.clone()), &config(), &twice, "n-123", NOW).unwrap_err();
        assert!(err.contains("doesn't say which"), "{err}");
        // A key that says it's for another algorithm isn't used for this one.
        let mut keys = s.jwks();
        keys[0].alg = Some("RS512".into());
        assert!(verify_id_token(&s.token(rs256(), c.clone()), &config(), &keys, "n-123", NOW).is_err());
        // Not tokens at all.
        for junk in ["", "a.b", "a.b.c.d", "x.y.z", "...", &format!("{}.{}.", b64url(b"{}"), b64url(b"{}"))] {
            assert!(verify_id_token(junk, &config(), &keys, "n-123", NOW).is_err(), "{junk:?}");
        }
    }

    #[test]
    fn jwks_keep_only_signing_keys_we_can_verify() {
        let doc = json!({ "keys": [
            { "kty": "RSA", "kid": "a", "use": "sig", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "noparts" },
            { "kty": "EC", "kid": "p384", "crv": "P-384", "x": "AA", "y": "AA" },
            { "kty": "EC", "kid": "short", "crv": "P-256", "x": "AA", "y": "AA" },
            { "kty": "oct", "kid": "hmac", "k": "AAAA" },
            { "kty": "EC", "kid": "ok", "crv": "P-256", "x": b64url(&[1u8; 32]), "y": b64url(&[2u8; 32]) }
        ] });
        let kids: Vec<_> = parse_jwks(&doc).into_iter().map(|k| k.kid.unwrap()).collect();
        assert_eq!(kids, ["a", "ok"]);
        assert!(parse_jwks(&json!({})).is_empty() && parse_jwks(&json!({ "keys": 3 })).is_empty());
    }

    fn who(sub: &str, email: Option<&str>, verified: bool, groups: &[&str]) -> Identity {
        Identity { sub: sub.into(), email: email.map(str::to_string), email_verified: verified, groups: groups.iter().map(|g| g.to_string()).collect() }
    }

    #[test]
    fn roles_come_from_who_the_provider_says_someone_is() {
        let cfg = config();
        let got = |id: Identity| grant(&cfg, &id).unwrap();
        // By address (any case), by group, by the address's domain.
        assert_eq!(got(who("1", Some("ALICE@example.com"), true, &[])), Some((Role::Admin, vec![])));
        assert_eq!(got(who("2", Some("bob@example.com"), true, &["platform"])), Some((Role::Approver, vec![])));
        assert_eq!(got(who("3", Some("carol@Example.COM"), true, &[])), Some((Role::Viewer, vec![])));
        // The strongest match wins.
        assert_eq!(got(who("4", Some("alice@example.com"), true, &["platform"])).unwrap().0, Role::Admin);
        // A limited role carries its projects, ~ and all.
        assert_eq!(got(who("5", None, false, &["contractors"])), Some((Role::Viewer, vec!["~/code/app".to_string()])));
        assert_eq!(got(who("svc-1", None, false, &[])), Some((Role::Approver, vec!["/srv/a".to_string()])));
        // Equal roles: an unlimited one beats a limited one…
        assert_eq!(got(who("6", Some("dan@example.com"), true, &["contractors"])), Some((Role::Viewer, vec![])));
        // …and limited ones add up.
        let mut two: Config = config();
        two.roles.insert("group:b".into(), Grant::Limited { role: "viewer".into(), projects: vec!["~/code/lib".into()] });
        assert_eq!(grant(&two, &who("7", None, false, &["contractors", "b"])).unwrap(), Some((Role::Viewer, vec!["~/code/app".to_string(), "~/code/lib".to_string()])));
        // Nobody else gets anything.
        assert_eq!(got(who("8", Some("eve@evil.example"), true, &[])), None);
        assert_eq!(got(who("9", None, false, &[])), None);
        assert_eq!(got(who("10", Some("eve@evil.example"), true, &["platform-team", "Platform"])), None, "groups match to the letter");
        assert_eq!(got(who("11", Some("alice@example.com.evil.example"), true, &[])), None);
        assert_eq!(got(who("12", Some("alice@evil.example"), true, &[])), None);
        // An address the provider doesn't vouch for is no address at all…
        assert_eq!(got(who("13", Some("alice@example.com"), false, &[])), None);
        // …unless you say you trust it.
        let mut lax = config();
        lax.require_verified_email = false;
        assert_eq!(grant(&lax, &who("13", Some("alice@example.com"), false, &[])).unwrap().unwrap().0, Role::Admin);
        // …but a group or an id doesn't depend on it.
        assert_eq!(got(who("14", Some("bob@evil.example"), false, &["platform"])).unwrap().0, Role::Approver);
    }

    #[test]
    fn the_configuration_is_checked() {
        let ok = |toml: &str| toml::from_str::<Config>(toml).map_err(anyhow::Error::from).and_then(|c| c.validate().map(|_| c));
        let base = |extra: &str| format!("issuer = \"https://idp.example.com\"\nclient_id = \"agentd\"\npublic_url = \"https://agentd.example.com\"\n{extra}\n[roles]\n\"a@b.example\" = \"admin\"\n");
        assert!(ok(&base("")).is_ok());
        assert!(ok(&base("client_secret = \"AGENTD_OIDC_SECRET\"\nsession = \"1h\"")).is_ok());
        assert_eq!(ok(&base("")).unwrap().session_ttl().unwrap(), Duration::from_secs(12 * 3600));
        assert_eq!(ok(&base("")).unwrap().redirect_uri(), "https://agentd.example.com/oidc/callback");
        let local = ok(&base("").replace("https://idp.example.com", "http://127.0.0.1:9000").replace("https://agentd.example.com", "http://localhost:7777"));
        assert!(local.is_ok() && !local.unwrap().secure(), "this machine may be http");
        for (bad, why) in [
            (base("").replace("https://idp.example.com", "http://idp.example.com"), "issuer"),
            (base("").replace("https://idp.example.com", "https://idp.example.com?x=1"), "issuer"),
            (base("").replace("https://agentd.example.com", "http://agentd.example.com"), "public_url"),
            (base("").replace("client_id = \"agentd\"", "client_id = \" \""), "client_id"),
            (base("client_secret = \"$SECRET\""), "client_secret"),
            (base("session = \"1m\""), "session lasts"),
            (base("session = \"90d\""), "session lasts"),
            (base("session = \"soon\""), "session"),
            ("issuer = \"https://i.example\"\nclient_id = \"a\"\npublic_url = \"https://a.example\"\n".to_string(), "roles is empty"),
            (base("").replace("\"a@b.example\" = \"admin\"", "\"nobody\" = \"admin\""), "an email address"),
            (base("").replace("\"a@b.example\" = \"admin\"", "\"team:x\" = \"admin\""), "an email address"),
            (base("").replace("\"a@b.example\" = \"admin\"", "\"group:\" = \"admin\""), "an email address"),
            (base("").replace("\"a@b.example\" = \"admin\"", "\"a@b.example\" = \"root\""), "isn't a role"),
            (base("").replace("\"a@b.example\" = \"admin\"", "\"a@b.example\" = { role = \"viewer\", projects = [\"relative\"] }"), "absolute path"),
            (base("extra = 1"), "unknown field"),
        ] {
            let err = ok(&bad).map(|_| ()).unwrap_err();
            assert!(format!("{err:#}").contains(why), "{why}: {err:#}\n{bad}");
        }
    }

    #[test]
    fn a_sign_in_can_be_finished_once_and_only_by_the_browser_that_began_it() {
        let cfg = config();
        let put = |state: &str, browser: &str, age: Duration| {
            PENDING.lock().unwrap().insert(
                state.to_string(),
                Pending { nonce: "n".into(), verifier: "v".into(), browser: browser.into(), at: Instant::now().checked_sub(age).unwrap_or_else(Instant::now) },
            );
        };
        // (everything here fails before the provider would be asked)
        assert!(finish(&cfg, None, "state=unknown&code=c", Some("x"), NOW).unwrap_err().contains("unknown, was used already"));
        put("s1", "browser-1", Duration::ZERO);
        assert!(finish(&cfg, None, "state=s1&code=c", Some("someone-else"), NOW).unwrap_err().contains("another browser"));
        assert!(finish(&cfg, None, "state=s1&code=c", Some("browser-1"), NOW).unwrap_err().contains("unknown, was used already"), "a failed try uses it up");
        put("s2", "browser-2", Duration::ZERO);
        assert!(finish(&cfg, None, "state=s2&code=c", None, NOW).unwrap_err().contains("another browser"), "no cookie, no sign-in");
        put("s3", "browser-3", LOGIN_TTL + Duration::from_secs(1));
        assert!(finish(&cfg, None, "state=s3&code=c", Some("browser-3"), NOW).unwrap_err().contains("took too long"));
        put("s4", "browser-4", Duration::ZERO);
        let err = finish(&cfg, None, "state=s4&error=access_denied&error_description=No%20thanks%3Cscript%3E", Some("browser-4"), NOW).unwrap_err();
        assert!(err.contains("access_denied") && err.contains("No thanks"), "{err}");
        assert!(PENDING.lock().unwrap().get("s4").is_none(), "an error ends it too");
        put("s5", "browser-5", Duration::ZERO);
        assert!(finish(&cfg, None, "state=s5", Some("browser-5"), NOW).unwrap_err().contains("no code"));
    }
}
