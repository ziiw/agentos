//! Your side of a running task, on its owner socket: what you granted while it ran, and taking it back.

use crate::*;

/// What you granted while a task ran (folders, hosts): you can take it back.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct Given {
    /// "folder" or "host".
    pub(crate) kind: String,
    /// A folder's path, or `host` / `host:port`.
    pub(crate) target: String,
    /// "read" or "write", for a folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) access: Option<String>,
    #[serde(default)]
    pub(crate) revoked: bool,
}

pub(crate) type GivenList = Arc<Mutex<Vec<Given>>>;

pub(crate) fn give(given: &GivenList, kind: &str, target: &str, access: Option<&str>) {
    if let Ok(mut g) = given.lock() {
        if !g.iter().any(|x| x.kind == kind && x.target == target && !x.revoked) {
            g.push(Given { kind: kind.into(), target: target.into(), access: access.map(String::from), revoked: false });
        }
    }
}

pub(crate) fn taken_back(given: &GivenList, kind: &str, target: &str) -> bool {
    given.lock().is_ok_and(|g| g.iter().any(|x| x.kind == kind && x.target == target && x.revoked))
}

/// Your side of a running task, on its owner socket: what you granted while
/// it ran, and taking it back.
pub(crate) struct Owner {
    pub(crate) given: GivenList,
    pub(crate) allow: Option<proxy::LiveAllowlist>,
    pub(crate) asker: Option<Arc<Asker>>,
    pub(crate) attacher: Arc<sandbox::Attacher>,
    pub(crate) proxy: Option<proxy::Handle>,
    pub(crate) meter: Option<Arc<Meter>>,
    pub(crate) task: String,
    pub(crate) journal: Journal,
    pub(crate) err: Paint,
}

impl Owner {
    pub(crate) fn handle(&self, call: Call) -> Reply {
        match call {
            Call::Given => Reply::answer(self.given.lock().map(|g| serde_json::to_string(&*g).unwrap_or_default()).unwrap_or_default()),
            Call::Revoke { target } => self.revoke(&target),
            Call::Raise { to, by } => self.raise(&to, &approvals::sanitize(&by, 40)),
            _ => Reply::error("this socket is the task owner's: given, revoke and raise only"),
        }
    }

    /// Raises the task's own budget: a model call waiting on it goes on.
    pub(crate) fn raise(&self, to: &str, by: &str) -> Reply {
        let Some(m) = &self.meter else {
            return Reply::error(format!("task {}'s model calls aren't metered: it has no budget to raise", self.task));
        };
        let to: Budget = match to.parse() {
            Ok(b) => b,
            Err(e) => return Reply::error(e),
        };
        match m.raise(to) {
            Ok(from) => {
                let _ = self.journal.append("budget.raised", json!({ "scope": "task", "what": "this task's budget", "from": from, "to": to, "by": by }));
                say(format!("{} the budget was raised to {to} (from {from}, {})", self.err.cyan("agent ▸"), render::by(by)));
                Reply::answer(format!("task {}'s budget is now {to} (was {from})", self.task))
            }
            Err(e) => Reply::error(format!("can't raise task {}'s budget to {to}: {e}", self.task)),
        }
    }

    pub(crate) fn revoke(&self, target: &str) -> Reply {
        let target = target.trim();
        let target = if target.len() > 1 { target.trim_end_matches('/') } else { target };
        let Ok(mut given) = self.given.lock() else { return Reply::error("internal: lock poisoned") };
        let matches = |g: &Given| !g.revoked && (g.target == target || (g.kind == "host" && format!("{}:443", g.target) == target));
        let Some(g) = given.iter_mut().find(|g| matches(g)) else {
            return Reply::error(format!("nothing granted while the task ran matches {target} (`agent revoke` lists them)"));
        };
        let mut closed = 0;
        if g.kind == "folder" {
            if let Err(e) = self.attacher.detach(Path::new(&g.target)) {
                return Reply::error(format!("couldn't take back {}: {e:#}", g.target));
            }
        } else {
            let (host, port) = match g.target.rsplit_once(':').and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?))) {
                Some((h, p)) => (h.to_string(), p),
                None => (g.target.clone(), 443),
            };
            if let Some(Ok(mut a)) = self.allow.as_ref().map(|a| a.write()) {
                a.remove(&g.target);
            }
            if let Some(a) = &self.asker {
                a.refuse(&Request::host(&host, port));
            }
            closed = self.proxy.as_ref().map_or(0, |p| p.close(&host, port));
        }
        g.revoked = true;
        let _ = self.journal.append("grant.revoked", json!({ "kind": g.kind, "target": g.target, "closed": closed }));
        let shown = if g.kind == "folder" { display_path(Path::new(&g.target)) } else { g.target.clone() };
        say(format!("{} you took back {shown}", self.err.cyan("agent ▸")));
        let also = match closed {
            0 => String::new(),
            n => format!(" and closed {}", plural(n, "open connection")),
        };
        Reply::answer(format!("took back {shown}{also}"))
    }
}

/// Raises a budget your tasks share until its period resets: the one for
/// all of them, or (`mine`) the project's at `cwd`. Returns what to say.
pub(crate) fn raise_shared(store: &Store, home: &Path, cwd: &Path, period: gateway::Period, mine: bool, to: Budget, by: &str) -> Result<String> {
    let settings = config::load(store.root(), cwd, home)?;
    let Some((_, amount, _)) = settings.periodic.iter().find(|(p, _, m)| *p == period && *m == mine) else {
        let whose = if mine { "this project's .agentos.toml (trusted)" } else { "your config" };
        bail!("there's no {} budget to raise: set `{}` under [limits] in {whose}", period.key(), period.key());
    };
    let budget = Periodic { amount: *amount, period, project: mine.then(|| approvals::project_root(cwd, home)) };
    let ledger = open_ledger(store, home)?;
    let from = ledger.raise(&budget, to, by, util::now_ms()).map_err(|e| anyhow::anyhow!("can't raise {} to {to}: {e}", budget.what()))?;
    Ok(format!("{} is now {to} (was {from}), until it resets {}", budget.what(), period.resets()))
}
