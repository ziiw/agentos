//! Model gateway: what each model call costs, measured on the wire, and the
//! task's budget enforced there.
//!
//! Model API calls are relayed by the credential broker, which terminates
//! TLS for the hosts it holds credentials for, and for model APIs too when
//! the task has a budget. The gateway reads the token counts the provider
//! itself reports in each response, so the agent can't under-report them,
//! prices them, and journals every call. Once the budget is used up, further
//! model calls are answered with an error instead of reaching the provider.
//!
//! A call's cost is only known once it's done, so the call that crosses the
//! budget completes: a task can end slightly over.
//!
//! Every metered call also goes into a ledger in the task store, shared by
//! all tasks, for budgets across them: per day, week or month, for all your
//! tasks or one project's.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Api {
    /// The Messages API (`usage` with cache reads and writes).
    Anthropic,
    /// Chat Completions and Responses (`usage` with cached input details).
    Openai,
}

/// Where model calls go: requests to this host and path are metered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    /// The exact path, or a prefix when it ends with `*`. The query is ignored.
    pub path: String,
    pub api: Api,
}

impl Endpoint {
    /// `https://HOST/PATH`; a trailing `*` matches any path under it.
    pub fn parse(url: &str, api: Api) -> Result<Endpoint> {
        let rest = url.strip_prefix("https://").with_context(|| format!("{url}: model endpoints are https:// URLs"))?;
        let (host, path) = match rest.split_once('/') {
            Some((h, p)) => (h, format!("/{p}")),
            None => (rest, "/".to_string()),
        };
        if host.is_empty() || host.contains([':', '@', '*']) {
            bail!("{url}: expected https://HOST/PATH (port 443)");
        }
        Ok(Endpoint { host: host.to_ascii_lowercase(), path, api })
    }

    fn matches(&self, host: &str, path: &str) -> bool {
        self.host == host
            && match self.path.strip_suffix('*') {
                Some(prefix) => path.starts_with(prefix),
                None => path == self.path,
            }
    }
}

/// The model APIs every task's gateway knows about.
pub fn builtin_endpoints() -> Vec<Endpoint> {
    [
        ("api.anthropic.com", "/v1/messages", Api::Anthropic),
        ("api.openai.com", "/v1/responses", Api::Openai),
        ("api.openai.com", "/v1/chat/completions", Api::Openai),
        ("api.openai.com", "/v1/completions", Api::Openai),
    ]
    .map(|(host, path, api)| Endpoint { host: host.into(), path: path.into(), api })
    .to_vec()
}

/// Tokens, as the provider reported them for one call or a whole task.
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    /// Input tokens not read from the prompt cache.
    pub input: u64,
    pub output: u64,
    #[serde(default)]
    pub cache_read: u64,
    /// Written to the 5-minute prompt cache.
    #[serde(default)]
    pub cache_write: u64,
    /// Written to the 1-hour prompt cache.
    #[serde(default)]
    pub cache_write_1h: u64,
    /// Server-side web searches (billed per search).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub web_searches: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Usage {
    /// Every token the model processed: what a token budget counts.
    pub fn tokens(&self) -> u64 {
        self.input + self.output + self.cache_read + self.cache_write + self.cache_write_1h
    }

    fn add(&mut self, o: &Usage) {
        self.input += o.input;
        self.output += o.output;
        self.cache_read += o.cache_read;
        self.cache_write += o.cache_write;
        self.cache_write_1h += o.cache_write_1h;
        self.web_searches += o.web_searches;
    }
}

/// USD per million tokens. Cache prices default to Anthropic's multipliers
/// of the input price: reads 0.1×, 5-minute writes 1.25×, 1-hour writes 2×.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Price {
    pub input: f64,
    pub output: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_1h: Option<f64>,
}

impl Price {
    const fn claude(input: f64, output: f64, cache_read: f64) -> Price {
        Price { input, output, cache_read: Some(cache_read), cache_write: None, cache_write_1h: None }
    }

    /// Fast mode (`usage.speed: "fast"`) doubles every rate.
    pub fn cost(&self, u: &Usage, fast: bool) -> f64 {
        let per_token = if fast { 2e-6 } else { 1e-6 };
        let tokens = u.input as f64 * self.input
            + u.output as f64 * self.output
            + u.cache_read as f64 * self.cache_read.unwrap_or(self.input * 0.1)
            + u.cache_write as f64 * self.cache_write.unwrap_or(self.input * 1.25)
            + u.cache_write_1h as f64 * self.cache_write_1h.unwrap_or(self.input * 2.0);
        // $10 per 1,000 searches.
        tokens * per_token + u.web_searches as f64 * 0.01
    }
}

/// Claude API list prices: (model id, input, output, cache read), USD per
/// million tokens, from platform.claude.com/docs/en/about-claude/pricing
/// (October 2026). An id matches itself and its dated snapshots.
const CLAUDE_PRICES: &[(&str, Price)] = &[
    ("claude-fable-5-1", Price::claude(10.0, 50.0, 0.25)),
    ("claude-mythos-5-1", Price::claude(10.0, 50.0, 0.25)),
    ("claude-fable-5", Price::claude(10.0, 50.0, 1.0)),
    ("claude-mythos-5", Price::claude(10.0, 50.0, 1.0)),
    ("claude-opus-5-5", Price::claude(4.0, 20.0, 0.20)),
    ("claude-opus-5", Price::claude(5.0, 25.0, 0.50)),
    ("claude-opus-4-8", Price::claude(5.0, 25.0, 0.50)),
    ("claude-opus-4-7", Price::claude(5.0, 25.0, 0.50)),
    ("claude-opus-4-6", Price::claude(5.0, 25.0, 0.50)),
    ("claude-opus-4-5", Price::claude(5.0, 25.0, 0.50)),
    ("claude-opus-4-1", Price::claude(15.0, 75.0, 1.50)),
    ("claude-opus-4-0", Price::claude(15.0, 75.0, 1.50)),
    ("claude-opus-4", Price::claude(15.0, 75.0, 1.50)),
    ("claude-sonnet-5-5", Price::claude(2.0, 10.0, 0.20)),
    ("claude-sonnet-5", Price::claude(2.0, 10.0, 0.20)),
    ("claude-sonnet-4-6", Price::claude(3.0, 15.0, 0.30)),
    ("claude-sonnet-4-5", Price::claude(3.0, 15.0, 0.30)),
    ("claude-sonnet-4-0", Price::claude(3.0, 15.0, 0.30)),
    ("claude-sonnet-4", Price::claude(3.0, 15.0, 0.30)),
    ("claude-haiku-4-5", Price::claude(1.0, 5.0, 0.10)),
    ("claude-3-5-haiku", Price::claude(0.80, 4.0, 0.08)),
];

/// What a model with no known price is counted at: the highest rates above,
/// so a budget errs on the safe side.
const UNKNOWN: Price = Price::claude(10.0, 50.0, 1.0);

/// `claude-opus-4` matches `claude-opus-4` and `claude-opus-4-20250514`,
/// but not `claude-opus-4-1`. A user-configured `gpt-5*` matches by prefix.
fn model_matches(pattern: &str, model: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        return model.starts_with(prefix);
    }
    match model.strip_prefix(pattern) {
        Some("") => true,
        Some(rest) => {
            let snapshot = rest.strip_prefix('-').or_else(|| rest.strip_prefix('@')).unwrap_or("");
            snapshot.len() >= 8 && snapshot.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// The price of `model`: yours first (from `[prices]`), then the built-in
/// table. `None` when it isn't known.
pub fn price(model: &str, yours: &[(String, Price)]) -> Option<Price> {
    yours
        .iter()
        .find(|(pattern, _)| model_matches(pattern, model))
        .map(|(_, p)| *p)
        .or_else(|| CLAUDE_PRICES.iter().find(|(id, _)| model_matches(id, model)).map(|(_, p)| *p))
}

/// How much a task may spend on model calls.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Budget {
    /// Every token processed (input, output, cache reads and writes).
    Tokens(u64),
    /// Dollars at list prices.
    Usd(f64),
}

impl FromStr for Budget {
    type Err = String;

    /// `2usd`, `$2`, `2$`, `0.50usd`; `500k`, `2M`, `1500000` (tokens).
    fn from_str(s: &str) -> Result<Budget, String> {
        let bad = || format!("{s}: expected dollars like 2usd or $2, or tokens like 500k or 2M");
        let t = s.trim().to_ascii_lowercase();
        let positive = |n: &str| n.trim().parse::<f64>().ok().filter(|v| v.is_finite() && *v > 0.0);
        if let Some(n) = t.strip_prefix('$').or_else(|| t.strip_suffix('$')).or_else(|| t.strip_suffix("usd")) {
            return positive(n).map(Budget::Usd).ok_or_else(bad);
        }
        let t = t.strip_suffix("tokens").unwrap_or(&t).trim();
        let (n, scale) = match t.as_bytes().last() {
            Some(b'k') => (&t[..t.len() - 1], 1e3),
            Some(b'm') => (&t[..t.len() - 1], 1e6),
            _ => (t, 1.0),
        };
        positive(n).map(|v| Budget::Tokens((v * scale).round() as u64)).filter(|b| *b != Budget::Tokens(0)).ok_or_else(bad)
    }
}

impl fmt::Display for Budget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Budget::Usd(v) => write!(f, "{}", usd(*v)),
            Budget::Tokens(n) => write!(f, "{} tokens", tokens(*n)),
        }
    }
}

/// `$0.84`, `$0.031`, `$12.40`.
pub fn usd(v: f64) -> String {
    if v > 0.0 && v < 0.1 { format!("${v:.3}") } else { format!("${v:.2}") }
}

/// `950`, `12.3k`, `1.24M`.
pub fn tokens(n: u64) -> String {
    match n {
        0..1_000 => n.to_string(),
        1_000..1_000_000 => format!("{}k", trim_zero(format!("{:.1}", n as f64 / 1e3))),
        _ => format!("{}M", trim_zero(format!("{:.2}", n as f64 / 1e6))),
    }
}

fn trim_zero(s: String) -> String {
    if s.contains('.') { s.trim_end_matches('0').trim_end_matches('.').to_string() } else { s }
}

/// One model call, as journaled.
#[derive(Debug, Clone, Serialize)]
pub struct Call {
    pub host: String,
    pub path: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub usage: Usage,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fast: bool,
    pub cost_usd: f64,
    /// Set when the model's price isn't known: counted at the highest rates.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub assumed_price: bool,
    /// The response was cut short (the agent hung up mid-stream): the
    /// provider may have billed more than this.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
    pub ms: u64,
}

/// A task's model use so far.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Totals {
    pub calls: u64,
    pub usage: Usage,
    pub cost_usd: f64,
    /// Calls to models with no known price, counted at the highest rates.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub assumed: u64,
    /// Successful model calls whose usage couldn't be read (not counted).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unmetered: u64,
    /// Model calls refused because the budget was used up.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refused: u64,
}

impl Totals {
    /// "412k tokens · $0.84" (≤ when some calls had to be priced at the highest rates).
    pub fn describe(&self) -> String {
        let bound = if self.assumed > 0 { "≤ " } else { "" };
        format!("{} tokens · {bound}{}", tokens(self.usage.tokens()), usd(self.cost_usd))
    }

    /// How much of `budget` is used, 1.0 being all of it.
    pub fn fraction(&self, budget: Budget) -> f64 {
        match budget {
            Budget::Tokens(n) => self.usage.tokens() as f64 / n as f64,
            Budget::Usd(v) => self.cost_usd / v,
        }
    }

    /// "$0.62 of $0.50", "1.2M of 1M tokens".
    pub fn against(&self, budget: Budget) -> String {
        match budget {
            Budget::Tokens(n) => format!("{} of {} tokens", tokens(self.usage.tokens()), tokens(n)),
            Budget::Usd(v) => format!("{} of {}", usd(self.cost_usd), usd(v)),
        }
    }
}

/// What the gateway reports, as it happens.
pub enum Event<'a> {
    Call(&'a Call, &'a Totals),
    /// A successful model call without readable usage.
    Unmetered { host: &'a str, why: &'a str },
    /// 80% of the budget used.
    Nearly(&'a Totals),
    /// The budget is used up: model calls are refused from now on.
    Exhausted(&'a Totals),
    /// A budget shared with other tasks is used up (a sentence saying which).
    Over(&'a str),
    Refused(&'a Totals),
}

pub type Observer = Arc<dyn Fn(Event) + Send + Sync>;

/// One task's meter: endpoints, prices, budget and running totals.
pub struct Meter {
    endpoints: Vec<Endpoint>,
    prices: Vec<(String, Price)>,
    budget: Option<Budget>,
    observer: Observer,
    spend: Option<Spend>,
    state: Mutex<State>,
}

/// Where a task's calls go in the ledger, and the shared budgets it answers to.
pub struct Spend {
    pub ledger: Arc<Ledger>,
    pub task: String,
    pub project: PathBuf,
    pub budgets: Vec<Periodic>,
}

#[derive(Default)]
struct State {
    totals: Totals,
    nearly: bool,
    exhausted: bool,
    /// A shared budget ran out during this task (and it was said).
    over: bool,
}

impl Meter {
    pub fn new(endpoints: Vec<Endpoint>, prices: Vec<(String, Price)>, budget: Option<Budget>, observer: Observer) -> Meter {
        Meter { endpoints, prices, budget, observer, spend: None, state: Mutex::new(State::default()) }
    }

    /// Records calls in the ledger, and enforces the shared budgets too.
    pub fn with_spend(mut self, spend: Spend) -> Meter {
        self.spend = Some(spend);
        self
    }

    /// The shared budget that's used up, if one is.
    fn over(&self) -> Option<String> {
        let spend = self.spend.as_ref()?;
        spend.ledger.over(&spend.budgets, crate::util::now_ms())
    }

    pub fn budget(&self) -> Option<Budget> {
        self.budget
    }

    /// The hosts model calls go to.
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.endpoints.iter().map(|e| e.host.clone()).collect();
        hosts.dedup();
        hosts
    }

    /// The API spoken at `host` + `path`, if that's a model call.
    pub fn endpoint(&self, host: &str, path: &str) -> Option<Api> {
        self.endpoints.iter().find(|e| e.matches(host, path)).map(|e| e.api)
    }

    pub fn totals(&self) -> Totals {
        self.state.lock().map(|s| s.totals.clone()).unwrap_or_default()
    }

    /// This task's budget, or one it shares, is used up.
    pub fn exhausted(&self) -> bool {
        self.state.lock().is_ok_and(|s| s.exhausted) || self.over().is_some()
    }

    /// Counts a refused call and returns the response for the agent: an
    /// error in the API's own format, one clients don't retry.
    pub fn refuse(&self, api: Api) -> (u16, &'static str, String) {
        let totals = {
            let Ok(mut s) = self.state.lock() else { return (400, "Bad Request", String::new()) };
            s.totals.refused += 1;
            s.totals.clone()
        };
        (self.observer)(Event::Refused(&totals));
        let own = self.state.lock().is_ok_and(|s| s.exhausted);
        let message = match (own, self.over()) {
            (false, Some(over)) => format!("agentos: {over}; this task's work so far is held for review"),
            _ => {
                let spent = self.budget.map(|b| totals.against(b)).unwrap_or_default();
                format!("agentos: this task's budget is used up ({spent}); its work so far is held for review")
            }
        };
        let body = match api {
            Api::Anthropic => json!({ "type": "error", "error": { "type": "invalid_request_error", "message": message } }),
            Api::Openai => json!({ "error": { "message": message, "type": "invalid_request_error", "code": "budget_exhausted" } }),
        };
        (400, "Bad Request", body.to_string())
    }

    /// Records a finished call from what `reader` saw of its response.
    pub fn record(&self, host: &str, path: &str, status: u16, reader: Reader, took: Duration, partial: bool) {
        let seen = match reader.finish() {
            Ok(seen) => seen,
            // Errors (4xx/5xx) carry no usage and cost nothing.
            Err(_) if !(200..300).contains(&status) => return,
            Err(why) => {
                if let Ok(mut s) = self.state.lock() {
                    s.totals.unmetered += 1;
                }
                (self.observer)(Event::Unmetered { host, why });
                return;
            }
        };
        let known = seen.model.as_deref().and_then(|m| price(m, &self.prices));
        let cost = known.unwrap_or(UNKNOWN).cost(&seen.usage, seen.fast);
        let call = Call {
            host: host.to_string(),
            path: path.to_string(),
            status,
            model: seen.model,
            usage: seen.usage,
            fast: seen.fast,
            cost_usd: cost,
            assumed_price: known.is_none(),
            partial,
            ms: took.as_millis() as u64,
        };
        let (totals, nearly, exhausted) = {
            let Ok(mut s) = self.state.lock() else { return };
            s.totals.calls += 1;
            s.totals.usage.add(&call.usage);
            s.totals.cost_usd += cost;
            s.totals.assumed += call.assumed_price as u64;
            let used = self.budget.map(|b| s.totals.fraction(b)).unwrap_or(0.0);
            let exhausted = used >= 1.0 && !s.exhausted;
            let nearly = used >= 0.8 && !s.nearly && !exhausted;
            s.exhausted |= exhausted;
            s.nearly |= nearly || exhausted;
            (s.totals.clone(), nearly, exhausted)
        };
        (self.observer)(Event::Call(&call, &totals));
        if nearly {
            (self.observer)(Event::Nearly(&totals));
        }
        if exhausted {
            (self.observer)(Event::Exhausted(&totals));
        }
        if let Some(spend) = &self.spend {
            let entry = Entry {
                ts_ms: crate::util::now_ms(),
                task: spend.task.clone(),
                project: spend.project.display().to_string(),
                usd: cost,
                tokens: call.usage.tokens(),
            };
            let _ = spend.ledger.add(&entry);
            if let Some(over) = self.over() {
                let first = self.state.lock().is_ok_and(|mut s| !std::mem::replace(&mut s.over, true));
                if first {
                    (self.observer)(Event::Over(&over));
                }
            }
        }
    }
}

/// How often a shared budget starts over, in your local time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    Day,
    Week,
    Month,
}

impl Period {
    pub const ALL: [Period; 3] = [Period::Day, Period::Week, Period::Month];

    /// Its key under [limits].
    pub fn key(self) -> &'static str {
        match self {
            Period::Day => "daily",
            Period::Week => "weekly",
            Period::Month => "monthly",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Period::Day => "today",
            Period::Week => "this week",
            Period::Month => "this month",
        }
    }

    fn resets(self) -> &'static str {
        match self {
            Period::Day => "at midnight",
            Period::Week => "on Monday",
            Period::Month => "on the 1st",
        }
    }

    /// When the current period began (local midnight; weeks start on Monday).
    pub fn start(self, now_ms: u64) -> u64 {
        // SAFETY: localtime_r and mktime only read and write the tm we own.
        unsafe {
            let t = (now_ms / 1000) as libc::time_t;
            let mut tm: libc::tm = std::mem::zeroed();
            libc::localtime_r(&t, &mut tm);
            tm.tm_sec = 0;
            tm.tm_min = 0;
            tm.tm_hour = 0;
            match self {
                Period::Day => {}
                Period::Week => tm.tm_mday -= (tm.tm_wday + 6) % 7,
                Period::Month => tm.tm_mday = 1,
            }
            tm.tm_isdst = -1;
            (libc::mktime(&mut tm).max(0) as u64) * 1000
        }
    }
}

/// A budget shared by tasks: all of yours, or one project's.
#[derive(Debug, Clone, PartialEq)]
pub struct Periodic {
    pub amount: Budget,
    pub period: Period,
    /// `None`: all your tasks.
    pub project: Option<PathBuf>,
}

impl Periodic {
    fn scope(&self) -> String {
        match &self.project {
            None => "all your tasks".into(),
            Some(p) => format!("this project ({})", crate::util::display_path(p)),
        }
    }
}

/// One metered call, in the ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub ts_ms: u64,
    pub task: String,
    pub project: String,
    pub usd: f64,
    pub tokens: u64,
}

/// What every task spent on model calls: one JSON line per call, a file per
/// (UTC) month, in the task store. Read incrementally: each file is parsed
/// once, then only what other tasks added since.
pub struct Ledger {
    dir: PathBuf,
    read: Mutex<HashMap<String, (u64, Vec<Entry>)>>,
}

fn month(ms: u64) -> String {
    crate::util::rfc3339(ms)[..7].to_string()
}

impl Ledger {
    /// The task store's ledger, and whether it was just created (empty).
    pub fn open(store_root: &Path) -> anyhow::Result<(Ledger, bool)> {
        let dir = store_root.join("ledger");
        let fresh = match std::fs::create_dir(&dir) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(e).with_context(|| format!("create {}", dir.display())),
        };
        Ok((Ledger { dir, read: Mutex::new(HashMap::new()) }, fresh))
    }

    pub fn add(&self, e: &Entry) -> anyhow::Result<()> {
        let path = self.dir.join(format!("{}.jsonl", month(e.ts_ms)));
        let file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        let mut f = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive).map_err(|(_, e)| e)?;
        f.write_all(format!("{}\n", serde_json::to_string(e)?).as_bytes())?;
        Ok(())
    }

    /// Spent since `since_ms` (USD, tokens): by everyone, or in one project.
    pub fn spent(&self, since_ms: u64, project: Option<&Path>) -> (f64, u64) {
        let now = crate::util::now_ms();
        let mut months = vec![month(since_ms)];
        // Every month from then to now (a period is at most a month long).
        if month(now) != months[0] {
            months.push(month(now));
        }
        let project = project.map(|p| p.display().to_string());
        let Ok(mut read) = self.read.lock() else { return (0.0, 0) };
        let (mut usd, mut tokens) = (0.0, 0);
        for m in months {
            let (offset, entries) = read.entry(m.clone()).or_default();
            if let Ok(mut f) = std::fs::File::open(self.dir.join(format!("{m}.jsonl"))) {
                let mut more = String::new();
                if f.seek(SeekFrom::Start(*offset)).is_ok() && f.read_to_string(&mut more).is_ok() {
                    // Only whole lines: another task may be halfway through one.
                    let complete = more.rfind('\n').map_or(0, |i| i + 1);
                    *offset += complete as u64;
                    entries.extend(more[..complete].lines().filter_map(|l| serde_json::from_str::<Entry>(l).ok()));
                }
            }
            for e in entries.iter().filter(|e| e.ts_ms >= since_ms && project.as_ref().is_none_or(|p| *p == e.project)) {
                usd += e.usd;
                tokens += e.tokens;
            }
        }
        (usd, tokens)
    }

    fn used(&self, b: &Periodic, now_ms: u64) -> (f64, u64) {
        self.spent(b.period.start(now_ms), b.project.as_deref())
    }

    /// The first of `budgets` that's used up, in a sentence.
    pub fn over(&self, budgets: &[Periodic], now_ms: u64) -> Option<String> {
        budgets.iter().find_map(|b| {
            let (usd, tokens) = self.used(b, now_ms);
            let (done, spent) = match b.amount {
                Budget::Usd(v) => (usd >= v, format!("{} of {}", usd_str(usd), usd_str(v))),
                Budget::Tokens(n) => (tokens >= n, format!("{} of {} tokens", tokens_str(tokens), tokens_str(n))),
            };
            done.then(|| format!("{}'s budget for {} is used up ({spent}); it resets {}", b.period.label(), b.scope(), b.period.resets()))
        })
    }

    /// Where each budget stands: "today $0.30 of $0.50 (all your tasks)".
    pub fn status(&self, budgets: &[Periodic], now_ms: u64) -> Vec<String> {
        budgets
            .iter()
            .map(|b| {
                let (usd, tokens) = self.used(b, now_ms);
                let spent = match b.amount {
                    Budget::Usd(v) => format!("{} of {}", usd_str(usd), usd_str(v)),
                    Budget::Tokens(n) => format!("{} of {} tokens", tokens_str(tokens), tokens_str(n)),
                };
                format!("{} {spent} ({})", b.period.label(), b.scope())
            })
            .collect()
    }
}

fn usd_str(v: f64) -> String {
    usd(v)
}

fn tokens_str(n: u64) -> String {
    tokens(n)
}

/// What a response said about its own cost.
#[derive(Debug, Default, PartialEq)]
pub struct Seen {
    pub model: Option<String>,
    pub usage: Usage,
    pub fast: bool,
}

#[derive(Debug, PartialEq)]
enum Mode {
    /// Not decided yet: no body bytes so far.
    Sniff,
    Json,
    Sse,
    Unreadable(&'static str),
}

/// Reads a model API response as it streams past, for its usage. Bounded:
/// a JSON body is kept up to 16 MB, an event-stream line up to 1 MB.
pub struct Reader {
    api: Api,
    mode: Mode,
    buf: Vec<u8>,
    /// Skipping the rest of an oversized event-stream line.
    skipping: bool,
    seen: Seen,
    found: bool,
}

const JSON_LIMIT: usize = 16 << 20;
const LINE_LIMIT: usize = 1 << 20;

impl Reader {
    pub fn new(api: Api, content_type: Option<&str>, content_encoding: Option<&str>) -> Reader {
        let ct = content_type.unwrap_or("").to_ascii_lowercase();
        let mode = if content_encoding.is_some_and(|e| !e.trim().eq_ignore_ascii_case("identity")) {
            Mode::Unreadable("the response is compressed")
        } else if ct.contains("event-stream") {
            Mode::Sse
        } else if ct.contains("json") {
            Mode::Json
        } else {
            Mode::Sniff
        };
        Reader { api, mode, buf: Vec::new(), skipping: false, seen: Seen::default(), found: false }
    }

    pub fn feed(&mut self, mut bytes: &[u8]) {
        if self.mode == Mode::Sniff {
            let Some(first) = bytes.iter().position(|b| !b.is_ascii_whitespace()) else { return };
            self.mode = if bytes[first] == b'{' { Mode::Json } else { Mode::Sse };
            bytes = &bytes[first..];
        }
        match self.mode {
            Mode::Json => {
                if self.buf.len() + bytes.len() > JSON_LIMIT {
                    self.mode = Mode::Unreadable("the response is too large to read");
                    self.buf = Vec::new();
                } else {
                    self.buf.extend_from_slice(bytes);
                }
            }
            Mode::Sse => {
                for part in bytes.split_inclusive(|b| *b == b'\n') {
                    let complete = part.ends_with(b"\n");
                    if !self.skipping {
                        if self.buf.len() + part.len() > LINE_LIMIT {
                            self.buf.clear();
                            self.skipping = true;
                        } else {
                            self.buf.extend_from_slice(part);
                        }
                    }
                    if complete {
                        if !self.skipping {
                            let line = std::mem::take(&mut self.buf);
                            self.event_line(&line);
                        }
                        self.skipping = false;
                    }
                }
            }
            Mode::Sniff | Mode::Unreadable(_) => {}
        }
    }

    /// One `data:` line of an event stream. Only lines that mention usage
    /// are worth parsing (most are content deltas).
    fn event_line(&mut self, line: &[u8]) {
        let Some(data) = line.strip_prefix(b"data:") else { return };
        if !data.windows(7).any(|w| w == b"\"usage\"") {
            return;
        }
        if let Ok(v) = serde_json::from_slice::<Value>(data) {
            self.observe(&v);
        }
    }

    fn observe(&mut self, v: &Value) {
        let found = match self.api {
            Api::Anthropic => anthropic(&mut self.seen, v),
            Api::Openai => openai(&mut self.seen, v),
        };
        self.found |= found;
    }

    pub fn finish(mut self) -> std::result::Result<Seen, &'static str> {
        match self.mode {
            Mode::Json => {
                let buf = std::mem::take(&mut self.buf);
                if let Ok(v) = serde_json::from_slice::<Value>(&buf) {
                    self.observe(&v);
                }
            }
            Mode::Sse if !self.buf.is_empty() && !self.skipping => {
                let line = std::mem::take(&mut self.buf);
                self.event_line(&line);
            }
            Mode::Unreadable(why) => return Err(why),
            _ => {}
        }
        if self.found { Ok(self.seen) } else { Err("no usage in the response") }
    }
}

fn count(v: &Value) -> Option<u64> {
    v.as_u64()
}

/// A Messages API response (`usage`, `model`) or stream event:
/// `message_start` carries the input side, `message_delta` the final
/// (cumulative) counts.
fn anthropic(seen: &mut Seen, v: &Value) -> bool {
    let (usage, model) = match v["type"].as_str() {
        Some("message_start") => (&v["message"]["usage"], &v["message"]["model"]),
        _ => (&v["usage"], &v["model"]),
    };
    if !usage.is_object() {
        return false;
    }
    if let Some(m) = model.as_str() {
        seen.model = Some(m.to_string());
    }
    let u = &mut seen.usage;
    if let Some(n) = count(&usage["input_tokens"]) {
        u.input = n;
    }
    if let Some(n) = count(&usage["output_tokens"]) {
        u.output = n;
    }
    if let Some(n) = count(&usage["cache_read_input_tokens"]) {
        u.cache_read = n;
    }
    let split = &usage["cache_creation"];
    match (count(&split["ephemeral_5m_input_tokens"]), count(&split["ephemeral_1h_input_tokens"])) {
        (Some(m5), h1) if split.is_object() => (u.cache_write, u.cache_write_1h) = (m5, h1.unwrap_or(0)),
        _ => {
            if let Some(total) = count(&usage["cache_creation_input_tokens"]) {
                u.cache_write = total.saturating_sub(u.cache_write_1h);
            }
        }
    }
    if let Some(n) = count(&usage["server_tool_use"]["web_search_requests"]) {
        u.web_searches = n;
    }
    if let Some(speed) = usage["speed"].as_str() {
        seen.fast = speed == "fast";
    }
    true
}

/// A Chat Completions or Responses API body or stream event (the usage is
/// in the last chunk, or in `response.completed`). Input counts include
/// cached tokens there.
fn openai(seen: &mut Seen, v: &Value) -> bool {
    let (usage, model) = if v["response"]["usage"].is_object() { (&v["response"]["usage"], &v["response"]["model"]) } else { (&v["usage"], &v["model"]) };
    if !usage.is_object() {
        return false;
    }
    if let Some(m) = model.as_str() {
        seen.model = Some(m.to_string());
    }
    let input = count(&usage["input_tokens"]).or_else(|| count(&usage["prompt_tokens"])).unwrap_or(0);
    let cached = count(&usage["input_tokens_details"]["cached_tokens"])
        .or_else(|| count(&usage["prompt_tokens_details"]["cached_tokens"]))
        .unwrap_or(0)
        .min(input);
    let output = count(&usage["output_tokens"]).or_else(|| count(&usage["completion_tokens"])).unwrap_or(0);
    seen.usage = Usage { input: input - cached, output, cache_read: cached, ..Usage::default() };
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(api: Api, content_type: &str, body: &str, chunk: usize) -> std::result::Result<Seen, &'static str> {
        let mut r = Reader::new(api, Some(content_type), None);
        for piece in body.as_bytes().chunks(chunk) {
            r.feed(piece);
        }
        r.finish()
    }

    #[test]
    fn anthropic_json_and_stream() {
        let body = r#"{"id":"msg_1","type":"message","model":"claude-sonnet-5-5","content":[],"usage":{"input_tokens":12,"cache_creation_input_tokens":300,"cache_read_input_tokens":5000,"cache_creation":{"ephemeral_5m_input_tokens":100,"ephemeral_1h_input_tokens":200},"output_tokens":40,"server_tool_use":{"web_search_requests":2}}}"#;
        let seen = read(Api::Anthropic, "application/json", body, 7).unwrap();
        assert_eq!(seen.model.as_deref(), Some("claude-sonnet-5-5"));
        assert_eq!(seen.usage, Usage { input: 12, output: 40, cache_read: 5000, cache_write: 100, cache_write_1h: 200, web_searches: 2 });

        let stream = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-5-5\",\"usage\":{\"input_tokens\":30,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":20000,\"output_tokens\":1,\"speed\":\"fast\"}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"the word usage, quoted: \\\"usage\\\"\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":512}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        for chunk in [1, 5, 64, 4096] {
            let seen = read(Api::Anthropic, "text/event-stream", stream, chunk).unwrap();
            assert_eq!(seen.model.as_deref(), Some("claude-opus-5-5"));
            assert_eq!(seen.usage, Usage { input: 30, output: 512, cache_read: 20000, ..Usage::default() }, "chunk {chunk}");
            assert!(seen.fast);
        }
        // Content type missing (or wrong): sniffed.
        assert_eq!(read(Api::Anthropic, "text/html", stream, 3).unwrap().usage.output, 512);
        assert_eq!(read(Api::Anthropic, "text/html", body, 3).unwrap().usage.input, 12);
    }

    #[test]
    fn unreadable_responses() {
        assert!(read(Api::Anthropic, "application/json", r#"{"type":"error","error":{"type":"overloaded_error"}}"#, 9).is_err());
        let mut r = Reader::new(Api::Anthropic, Some("application/json"), Some("gzip"));
        r.feed(b"\x1f\x8b...");
        assert_eq!(r.finish().err(), Some("the response is compressed"));
        // An oversized line is skipped, not buffered; the stream goes on.
        let huge = format!("data: {{\"usage\":\"{}\"}}\ndata: {{\"usage\":{{\"input_tokens\":3,\"output_tokens\":4}}}}\n", "x".repeat(LINE_LIMIT + 10));
        assert_eq!(read(Api::Anthropic, "text/event-stream", &huge, 8192).unwrap().usage.output, 4);
    }

    #[test]
    fn openai_shapes() {
        let chat = r#"{"model":"gpt-x","usage":{"prompt_tokens":1000,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":800}}}"#;
        let seen = read(Api::Openai, "application/json", chat, 11).unwrap();
        assert_eq!(seen.usage, Usage { input: 200, output: 50, cache_read: 800, ..Usage::default() });

        let stream = concat!(
            "data: {\"model\":\"gpt-x\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n",
            "data: {\"model\":\"gpt-x\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2}}\n\n",
            "data: [DONE]\n\n",
        );
        assert_eq!(read(Api::Openai, "text/event-stream", stream, 4).unwrap().usage, Usage { input: 10, output: 2, ..Usage::default() });

        let responses = concat!(
            "event: response.created\n",
            "data: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-y\",\"usage\":null}}\n\n",
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-y\",\"usage\":{\"input_tokens\":90,\"input_tokens_details\":{\"cached_tokens\":60},\"output_tokens\":7}}}\n\n",
        );
        let seen = read(Api::Openai, "text/event-stream", responses, 13).unwrap();
        assert_eq!((seen.model.as_deref(), seen.usage.input, seen.usage.cache_read, seen.usage.output), (Some("gpt-y"), 30, 60, 7));
    }

    #[test]
    fn prices() {
        let p = |m: &str| price(m, &[]);
        assert_eq!(p("claude-opus-5-5"), Some(Price::claude(4.0, 20.0, 0.20)));
        assert_eq!(p("claude-opus-5"), Some(Price::claude(5.0, 25.0, 0.50)));
        assert_eq!(p("claude-opus-4-20250514"), Some(Price::claude(15.0, 75.0, 1.50)), "dated snapshot");
        assert_eq!(p("claude-opus-4-1@20250805"), Some(Price::claude(15.0, 75.0, 1.50)));
        assert_eq!(p("claude-haiku-4-5-20251001").map(|x| x.input), Some(1.0));
        assert_eq!(p("claude-opus-5-6"), None, "a new version isn't priced as an old one");
        assert_eq!(p("gpt-x"), None);
        let yours = vec![("gpt-*".to_string(), Price { input: 1.0, output: 8.0, cache_read: Some(0.25), cache_write: None, cache_write_1h: None })];
        assert_eq!(price("gpt-x", &yours).map(|x| x.output), Some(8.0));

        // Sonnet 5.5: $2 in, $10 out, cache reads 0.2, writes 2.5 (5m) and 4 (1h).
        let s = Price::claude(2.0, 10.0, 0.20);
        let u = Usage { input: 1_000_000, output: 100_000, cache_read: 1_000_000, cache_write: 1_000_000, cache_write_1h: 1_000_000, web_searches: 3 };
        assert!((s.cost(&u, false) - (2.0 + 1.0 + 0.2 + 2.5 + 4.0 + 0.03)).abs() < 1e-9);
        let u = Usage { input: 1_000_000, ..Usage::default() };
        assert!((s.cost(&u, true) - 4.0).abs() < 1e-9, "fast mode doubles");
    }

    #[test]
    fn budgets_parse() {
        for (s, b) in [("2usd", Budget::Usd(2.0)), ("$0.5", Budget::Usd(0.5)), ("3$", Budget::Usd(3.0)), ("2.50 USD", Budget::Usd(2.5))] {
            assert_eq!(s.parse::<Budget>(), Ok(b), "{s}");
        }
        for (s, n) in [("500k", 500_000), ("2M", 2_000_000), ("1.5m", 1_500_000), ("1200", 1200), ("300k tokens", 300_000)] {
            assert_eq!(s.parse::<Budget>(), Ok(Budget::Tokens(n)), "{s}");
        }
        for s in ["", "lots", "$", "-2usd", "0", "0usd", "2 euros", "1e999usd"] {
            assert!(s.parse::<Budget>().is_err(), "{s}");
        }
        assert_eq!(Budget::Usd(2.0).to_string(), "$2.00");
        assert_eq!(Budget::Tokens(1_500_000).to_string(), "1.5M tokens");
        assert_eq!((tokens(950), tokens(12_340), tokens(1_000_000), tokens(1_240_000)), ("950".into(), "12.3k".into(), "1M".into(), "1.24M".into()));
    }

    #[test]
    fn meter_enforces_the_budget() {
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = events.clone();
        let observer: Observer = Arc::new(move |e| {
            let name = match e {
                Event::Call(c, _) => format!("call {:.2}", c.cost_usd),
                Event::Unmetered { .. } => "unmetered".into(),
                Event::Nearly(_) => "nearly".into(),
                Event::Exhausted(_) => "exhausted".into(),
                Event::Over(text) => format!("over: {text}"),
                Event::Refused(t) => format!("refused {}", t.refused),
            };
            log.lock().unwrap().push(name);
        });
        let meter = Meter::new(builtin_endpoints(), Vec::new(), Some(Budget::Usd(1.0)), observer);
        assert_eq!(meter.endpoint("api.anthropic.com", "/v1/messages"), Some(Api::Anthropic));
        assert_eq!(meter.endpoint("api.anthropic.com", "/v1/messages/count_tokens"), None);
        assert_eq!(meter.endpoint("evil.example", "/v1/messages"), None);

        // $0.45 per call on Sonnet 5.5: 100k in ($0.20) + 25k out ($0.25).
        let body = r#"{"type":"message","model":"claude-sonnet-5-5","usage":{"input_tokens":100000,"output_tokens":25000}}"#;
        let call = |status: u16, body: &str| {
            let mut r = Reader::new(Api::Anthropic, Some("application/json"), None);
            r.feed(body.as_bytes());
            meter.record("api.anthropic.com", "/v1/messages", status, r, Duration::from_millis(5), false);
        };
        call(200, body);
        assert!(!meter.exhausted());
        call(529, r#"{"type":"error"}"#);
        call(200, body);
        assert!(!meter.exhausted(), "$0.90 of $1.00");
        call(200, r#"{"type":"message","content":[]}"#);
        call(200, body);
        assert!(meter.exhausted(), "$1.35 of $1.00");
        let (status, _, refusal) = meter.refuse(Api::Anthropic);
        assert_eq!(status, 400);
        assert!(refusal.contains("invalid_request_error") && refusal.contains("$1.35 of $1.00"), "{refusal}");
        let t = meter.totals();
        assert_eq!((t.calls, t.unmetered, t.refused, t.usage.tokens()), (3, 1, 1, 375_000));
        assert_eq!(*events.lock().unwrap(), ["call 0.45", "call 0.45", "nearly", "unmetered", "call 0.45", "exhausted", "refused 1"]);

        // Unknown models count at the highest rates.
        let meter = Meter::new(builtin_endpoints(), Vec::new(), Some(Budget::Tokens(10)), Arc::new(|_| {}));
        let mut r = Reader::new(Api::Openai, None, None);
        r.feed(br#"{"model":"mystery","usage":{"prompt_tokens":1000000,"completion_tokens":0}}"#);
        meter.record("api.openai.com", "/v1/responses", 200, r, Duration::ZERO, false);
        let t = meter.totals();
        assert_eq!((t.assumed, t.cost_usd), (1, 10.0));
        assert!(t.describe().contains("≤ $10.00") && meter.exhausted());
    }

    #[test]
    fn shared_budgets_count_every_task() {
        let dir = tempfile::tempdir().unwrap();
        let (ledger, fresh) = Ledger::open(dir.path()).unwrap();
        assert!(fresh && !Ledger::open(dir.path()).unwrap().1, "fresh only the first time");
        let ledger = Arc::new(ledger);
        let (app, site) = (PathBuf::from("/home/you/code/app"), PathBuf::from("/home/you/code/site"));
        let now = crate::util::now_ms();
        let entry = |task: &str, project: &Path, usd: f64, ts_ms: u64| Entry { ts_ms, task: task.into(), project: project.display().to_string(), usd, tokens: 1000 };
        ledger.add(&entry("a", &app, 0.30, now)).unwrap();
        ledger.add(&entry("b", &site, 0.25, now)).unwrap();
        ledger.add(&entry("old", &app, 9.0, Period::Month.start(now).saturating_sub(86_400_000))).unwrap();
        let (usd, tokens) = ledger.spent(Period::Day.start(now), None);
        assert!((usd - 0.55).abs() < 1e-9 && tokens == 2000);
        assert!((ledger.spent(Period::Day.start(now), Some(&app)).0 - 0.30).abs() < 1e-9);

        let all = Periodic { amount: Budget::Usd(0.50), period: Period::Day, project: None };
        let mine = Periodic { amount: Budget::Usd(1.0), period: Period::Day, project: Some(app.clone()) };
        let over = ledger.over(&[mine.clone(), all.clone()], now).unwrap();
        assert!(over.starts_with("today's budget for all your tasks is used up ($0.55 of $0.50)") && over.ends_with("at midnight"), "{over}");
        assert!(ledger.over(&[mine.clone()], now).is_none());
        assert_eq!(ledger.status(&[mine], now), ["today $0.30 of $1.00 (this project (/home/you/code/app))"]);

        // A meter: its calls go in the ledger, and a shared budget refuses the next.
        let events = Arc::new(Mutex::new(Vec::new()));
        let log = events.clone();
        let observer: Observer = Arc::new(move |e| {
            if let Event::Over(text) = e {
                log.lock().unwrap().push(text.to_string());
            }
        });
        let budgets = vec![Periodic { amount: Budget::Usd(1.0), period: Period::Day, project: None }];
        let meter = Meter::new(builtin_endpoints(), Vec::new(), None, observer).with_spend(Spend { ledger: ledger.clone(), task: "c".into(), project: app, budgets });
        assert!(!meter.exhausted());
        let mut r = Reader::new(Api::Anthropic, Some("application/json"), None);
        r.feed(br#"{"type":"message","model":"claude-sonnet-5-5","usage":{"input_tokens":100000,"output_tokens":25000}}"#);
        meter.record("api.anthropic.com", "/v1/messages", 200, r, Duration::ZERO, false);
        assert!(meter.exhausted(), "$0.55 + $0.45 = $1.00 today");
        assert!(meter.refuse(Api::Anthropic).2.contains("today's budget for all your tasks is used up ($1.00 of $1.00)"));
        assert_eq!(events.lock().unwrap().len(), 1);
    }

    #[test]
    fn periods_start_where_you_expect() {
        let now = crate::util::now_ms();
        let (day, week, month) = (Period::Day.start(now), Period::Week.start(now), Period::Month.start(now));
        assert!(day <= now && now - day < 25 * 3_600_000);
        assert!(week <= day && day - week < 7 * 25 * 3_600_000);
        assert!(month <= day && day - month < 31 * 25 * 3_600_000);
        assert_eq!(Period::Day.start(day), day, "midnight is the start of its own day");
    }

    #[test]
    fn endpoints() {
        let e = Endpoint::parse("https://httpbin.org/base64/*", Api::Anthropic).unwrap();
        assert!(e.matches("httpbin.org", "/base64/eyJ9") && !e.matches("httpbin.org", "/get"));
        assert!(Endpoint::parse("http://x.com/v1", Api::Openai).is_err());
        assert!(Endpoint::parse("https://x.com:8443/v1", Api::Openai).is_err());
        assert_eq!(Endpoint::parse("https://OpenRouter.ai/api/v1/chat/completions", Api::Openai).unwrap().host, "openrouter.ai");
    }
}
