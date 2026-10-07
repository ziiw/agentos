//! The agent's side: what it asks agentos from inside its sandbox (through `agent mcp`).

use crate::*;

/// Answers what the agent asks agentos from inside its sandbox (through
/// `agent mcp`): what it has, and more when you agree.
pub(crate) struct Control {
    pub(crate) task_id: String,
    pub(crate) store_root: PathBuf,
    pub(crate) home: PathBuf,
    pub(crate) cwd: PathBuf,
    /// The task store, your config and agent definitions: never offered.
    pub(crate) private: Vec<PathBuf>,
    pub(crate) hidden: Vec<PathBuf>,
    pub(crate) grants: Arc<Mutex<Vec<Grant>>>,
    /// The proxy's allowlist, when the task has one.
    pub(crate) allow: Option<proxy::LiveAllowlist>,
    pub(crate) net: Net,
    pub(crate) asker: Option<Arc<Asker>>,
    /// Your rules, which answer before you're asked.
    pub(crate) rules: Option<Arc<policy::Policy>>,
    /// Why nobody can be asked, when there's no asker.
    pub(crate) no_asker: &'static str,
    pub(crate) attacher: Arc<sandbox::Attacher>,
    pub(crate) landlock: bool,
    pub(crate) journal: Journal,
    pub(crate) meter: Option<Arc<Meter>>,
    pub(crate) outbox: bool,
    /// Your MCP servers, reachable through agentos.
    pub(crate) mcp: Vec<String>,
    /// What you granted while it ran, and what you took back.
    pub(crate) given: GivenList,
    pub(crate) taint: Arc<taint::Taint>,
    pub(crate) err: Paint,
}

impl Control {
    pub(crate) fn handle(&self, call: Call) -> Reply {
        match call {
            Call::Info => Reply::answer(self.info()),
            Call::Network { host, port, reason } => self.network(&host, port.unwrap_or(443), &reason),
            Call::Path { path, write, reason } => self.path(&path, write, &reason),
            Call::Mcp { .. } => Reply::error("MCP sessions are relayed, not answered"),
            Call::Given | Call::Revoke { .. } | Call::Raise { .. } => Reply::error("only the user can do that, from outside the sandbox"),
        }
    }

    pub(crate) fn info(&self) -> String {
        let mut out = vec![format!("This is agentos task {}.", self.task_id)];
        let mut grants = self.grants.lock().map(|g| g.clone()).unwrap_or_default();
        grants.retain(|g| !taken_back(&self.given, "folder", &g.path.display().to_string()));
        let list = |access: Access| grants.iter().filter(|g| g.access == access).map(|g| g.path.display().to_string()).collect::<Vec<_>>().join(", ");
        let (rw, ro) = (list(Access::Rw), list(Access::Ro));
        if !rw.is_empty() {
            out.push(format!("You can read and change: {rw}. Your changes are held for the user's review, not applied directly."));
        }
        if !ro.is_empty() {
            out.push(format!("You can read: {ro}."));
        }
        out.push(format!("System folders (/usr, /etc, …) are read-only. The rest of {} is hidden, apart from your own home.", self.home.display()));
        out.push(match (&self.allow, self.net) {
            (Some(allow), _) => {
                let hosts = allow.read().map(|a| a.describe()).unwrap_or_default();
                let others = if self.asker.is_some() { "the user is asked about others when you connect" } else { "others are refused" };
                format!("Network: HTTPS only, through the proxy in $HTTPS_PROXY, to {hosts}; {others}.")
            }
            (None, Net::Host) => "Network: unrestricted.".to_string(),
            (None, _) => "Network: none in this task.".to_string(),
        });
        if self.outbox {
            out.push("git push works, but your pushes are held until the user reviews them.".into());
        }
        if !self.mcp.is_empty() {
            out.push(format!(
                "The user's MCP servers, run by agentos outside the sandbox: {}. Read-only tools run directly; the user is asked before the others.",
                self.mcp.join(", ")
            ));
        }
        if let Some(m) = &self.meter {
            let t = m.totals();
            out.push(match m.budget() {
                Some(b) => format!("Budget for model calls: {} used.", t.against(b)),
                None => format!("Model calls so far: {}.", t.describe()),
            });
        }
        out.push(if self.asker.is_some() {
            "Need more? request_path_access or request_network_access, with a reason: the user decides.".to_string()
        } else {
            format!("Nobody can approve requests for more in this task: {}.", self.no_asker)
        });
        out.join("\n")
    }

    /// Asks you, and journals the request and your answer.
    /// Your rules answer first; then you're asked.
    pub(crate) fn ask(&self, kind: Kind, target: &str, reason: &str, question: Question) -> std::result::Result<approvals::Decision, Reply> {
        let reason = approvals::sanitize(reason, 300);
        let req = Request { kind, target: approvals::sanitize(target, 200), reason: Some(reason.clone()), taint: None };
        let label = match kind {
            Kind::Host => "host",
            Kind::Read => "read",
            Kind::Write => "write",
            Kind::Tool => "tool",
            Kind::Budget => "budget",
        };
        let record_rule = |decision: &str, rule: Option<&str>| {
            let mut data = json!({ "kind": label, "target": req.target, "reason": reason, "decision": decision });
            if let Some(rule) = rule {
                data["rule"] = json!(rule);
            }
            let _ = self.journal.append("agent.request", data);
        };
        let record = |decision: &str| record_rule(decision, None);
        match self.rules.as_ref().map(|r| r.decide(&question.with_reason(&reason))) {
            Some(Verdict::Permit(rule)) => {
                record_rule("rule", Some(&rule));
                return Ok(approvals::Decision::Once);
            }
            Some(Verdict::Forbid(rule)) => {
                record_rule("forbidden", Some(&rule));
                let (who, name) = policy::whose(&rule);
                let who = if who == "your" { "the user's" } else { who };
                return Err(Reply::answer(format!(
                    "Denied by {who} rules (\u{201c}{name}\u{201d}). Carry on without it, and don't try to get it another way."
                )));
            }
            _ => {}
        }
        let Some(asker) = &self.asker else {
            record("nobody to ask");
            say(format!("{} the agent asked for {} ({}), but {}", self.err.yellow("agent:"), req.target, label, self.no_asker));
            return Err(Reply::answer(format!("Not granted: nobody can approve requests in this task ({}). Tell the user what you need instead.", self.no_asker)));
        };
        let (decision, _) = asker.ask(&req, |s| self.err.cyan(s));
        record(decision.label());
        match decision {
            d if d.allows() => Ok(d),
            approvals::Decision::Timeout => Err(Reply::answer("No answer from the user in time. You can ask again later, or carry on without it.")),
            _ => Err(Reply::answer("Denied: the user said no. Carry on without it, and don't try to get it another way.")),
        }
    }

    pub(crate) fn network(&self, host: &str, port: u16, reason: &str) -> Reply {
        let Some(allow) = &self.allow else {
            return Reply::answer(match self.net {
                Net::Host => "The network isn't restricted in this task: just connect.",
                _ => "This task has no network at all. The user can rerun it with --allow HOST.",
            });
        };
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.contains(['*', '/', ':', ' ', '@']) {
            return Reply::error(format!("{host:?} isn't a host name; give one like pypi.org, and the port separately"));
        }
        let entry = approvals::entry(&host, port);
        if let Err(e) = Allowlist::parse(&[entry.clone()]) {
            return Reply::error(format!("{e:#}"));
        }
        if taken_back(&self.given, "host", &entry) {
            return Reply::answer(format!("Not granted: the user took {entry} back from this task. Carry on without it."));
        }
        if allow.read().is_ok_and(|a| a.allows(&host, port)) {
            return Reply::answer(format!("{entry} is already allowed: connect to it over HTTPS (through $HTTPS_PROXY)."));
        }
        match self.ask(Kind::Host, &entry, reason, Question::connect(&host, port)) {
            Ok(decision) => {
                if let Ok(mut a) = allow.write() {
                    let _ = a.add(&entry);
                }
                give(&self.given, "host", &entry, None);
                let always = if decision == approvals::Decision::Always { ", and for later tasks in this project" } else { "" };
                Reply::answer(format!("Granted: you can reach {entry} now{always}."))
            }
            Err(reply) => reply,
        }
    }

    pub(crate) fn path(&self, asked: &str, write: bool, reason: &str) -> Reply {
        let named = match control::resolve(asked, &self.home, &self.cwd) {
            Ok(p) => p,
            Err(e) => return Reply::error(format!("{e:#}")),
        };
        let grants = self.grants.lock().map(|g| g.clone()).unwrap_or_default();
        let rules = PathRules { home: &self.home, private: &self.private, hidden: &self.hidden, grants: &grants, landlock: self.landlock };
        // Off limits by name (whether or not it exists), then for what it
        // really is, symlinks resolved.
        let (path, verdict) = match control::forbidden(&named, &rules) {
            Some(why) => (named, Err(why)),
            None => match fs::canonicalize(&named) {
                Ok(path) => {
                    let verdict = control::check_path(&path, write, &rules);
                    (path, verdict)
                }
                Err(_) => return Reply::error(format!("{} doesn't exist", named.display())),
            },
        };
        let shown = display_path(&path);
        if taken_back(&self.given, "folder", &path.display().to_string()) {
            return Reply::answer(format!("Not granted: the user took {} back from this task. Carry on without it.", path.display()));
        }
        match verdict {
            Err(why) => {
                let kind = if write { "write" } else { "read" };
                let _ = self.journal.append("agent.request", json!({ "kind": kind, "target": shown, "reason": approvals::sanitize(reason, 300), "decision": "impossible", "why": why }));
                return Reply::answer(format!("Not possible: {why}."));
            }
            Ok(PathVerdict::AlreadyWritable) => return Reply::answer(format!("You can already read and change {}.", path.display())),
            Ok(PathVerdict::AlreadyReadable) if !write => return Reply::answer(format!("You can already read {}.", path.display())),
            Ok(_) => {}
        }
        if let Err(reply) = self.ask(if write { Kind::Write } else { Kind::Read }, &shown, reason, Question::path(write, &path)) {
            return reply;
        }
        // A folder outside the project is input the agent shouldn't trust.
        if !path.starts_with(&self.cwd) {
            self.taint.mark(taint::Source::File, &shown);
        }
        match self.grant(&path, write) {
            Ok(()) if write => Reply::answer(format!(
                "Granted: you can now read and change {} (at that path). Your changes there are held for the user's review, like the rest.",
                path.display()
            )),
            Ok(()) => Reply::answer(format!("Granted: you can now read {} (at that path).", path.display())),
            Err(e) => {
                let _ = self.journal.append("grant.failed", json!({ "path": path, "error": format!("{e:#}") }));
                say(format!("{} couldn't add {shown} to the sandbox: {e:#}", self.err.yellow("agent: warning:")));
                Reply::error(format!("The user agreed, but agentos couldn't add {}: {e:#}", path.display()))
            }
        }
    }

    /// Mounts `path` into the running sandbox and records the grant (with a
    /// layer of its own when writable, so its changes are held like the rest).
    pub(crate) fn grant(&self, path: &Path, write: bool) -> Result<()> {
        let store = Store::open_at(&self.store_root)?;
        let mut task = store.load(&self.task_id)?;
        let mut grants = self.grants.lock().map_err(|_| anyhow::anyhow!("grants lock poisoned"))?;
        let layer = write.then(|| grants.iter().filter_map(|g| g.layer).max().map_or(0, |n| n + 1));
        let kind = match layer {
            Some(n) => {
                fs::create_dir_all(task.layer_upper(n))?;
                fs::create_dir_all(task.layer_work(n))?;
                Mount::Overlay { upper: task.layer_upper(n), work: task.layer_work(n) }
            }
            None => Mount::ReadOnly,
        };
        if let Err(e) = self.attacher.attach(&GrantMount { path: path.to_path_buf(), kind }) {
            if let Some(n) = layer {
                let _ = fs::remove_dir_all(task.layer_upper(n).parent().unwrap_or(Path::new("/nonexistent")));
            }
            return Err(e);
        }
        let access = if write { Access::Rw } else { Access::Ro };
        grants.push(Grant { path: path.to_path_buf(), access, layer });
        // On disk at once: `agent diff` must see the new layer even if this
        // process dies before the task ends.
        task.meta.grants = grants.clone();
        task.save()?;
        self.journal.append("grant.added", json!({ "path": path, "access": access, "layer": layer }))?;
        give(&self.given, "folder", &path.display().to_string(), Some(if write { "write" } else { "read" }));
        say(format!("{} {} {}", self.err.cyan("agent ▸"), if write { "now read-write:" } else { "now readable:" }, display_path(path)));
        Ok(())
    }
}
