//! Your rules for what agents may do without asking: Cedar policies in
//! `policy.cedar`, next to your config.
//!
//! They answer the questions agentos would otherwise ask you. A `forbid`
//! that matches refuses, and wins over everything, your allowlist included;
//! a `permit` that matches allows without asking; when nothing matches,
//! you're asked as before. Deterministic code decides, never a model.
//!
//! ```cedar
//! @id("read code")
//! permit (principal, action == Action::"read", resource)
//! when { resource.path like "~/code/*" };
//!
//! @id("no paste sites")
//! forbid (principal, action == Action::"connect", resource)
//! when { resource.name like "*paste*" };
//!
//! @id("issues in our repo")
//! permit (principal, action == Action::"call", resource == Tool::"github.create_issue")
//! when { context.args has repo && context.args.repo == "agentos" };
//! ```
//!
//! What a rule sees:
//! - principal `Agent::"claude"` (the agent's name; `Agent::"command"` for `agent run`);
//! - actions `Action::"connect"`, `"read"`, `"write"` (folders asked for
//!   mid-task) and `"call"` (tools of your MCP servers);
//! - resources `Host::"pypi.org"` {name, port}, `Path::"/home/you/code/lib"`
//!   {path}, `Tool::"github.create_issue"` {server, name};
//! - context {agent, task, project, reason (the agent's own words, when it
//!   asked), args (a tool call's arguments)}.
//!
//! `"~/…"` in a string means your home folder.
//!
//! A project can ship rules too, in `.agentos.cedar` at its root. They can
//! only forbid, so they apply to every task there without your review (a
//! `permit` in one is refused, and so is a file that doesn't parse: a
//! protection the project asked for is never silently dropped).

use anyhow::{Context as _, Result};
use cedar_policy::{Authorizer, Context, Decision, Effect, Entities, EntityId, EntityTypeName, EntityUid, PolicyId, PolicySet, Request};
use serde_json::{Map, Value, json};
use std::path::Path;
use std::str::FromStr;

/// Next to your config.toml.
pub const FILE: &str = "policy.cedar";
/// A project's own rules, at its root.
pub const PROJECT_FILE: &str = ".agentos.cedar";
/// Prefix of a project rule's id, once combined with yours.
const PROJECT: &str = "project:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Connect,
    Read,
    Write,
    Call,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::Connect => "connect",
            Action::Read => "read",
            Action::Write => "write",
            Action::Call => "call",
        }
    }

    pub fn parse(s: &str) -> Option<Action> {
        [Action::Connect, Action::Read, Action::Write, Action::Call].into_iter().find(|a| a.name() == s)
    }
}

/// What a rule is asked about.
#[derive(Debug, Clone)]
pub struct Question {
    pub action: Action,
    kind: &'static str,
    id: String,
    attrs: Value,
    reason: Option<String>,
    args: Option<Value>,
}

impl Question {
    pub fn connect(host: &str, port: u16) -> Question {
        Question { action: Action::Connect, kind: "Host", id: host.to_string(), attrs: json!({ "name": host, "port": port }), reason: None, args: None }
    }

    pub fn path(write: bool, path: &Path) -> Question {
        let p = path.display().to_string();
        let action = if write { Action::Write } else { Action::Read };
        Question { action, kind: "Path", id: p.clone(), attrs: json!({ "path": p }), reason: None, args: None }
    }

    pub fn call(server: &str, tool: &str, args: &Value) -> Question {
        Question {
            action: Action::Call,
            kind: "Tool",
            id: format!("{server}.{tool}"),
            attrs: json!({ "server": server, "name": tool }),
            reason: None,
            args: Some(args.clone()),
        }
    }

    pub fn with_reason(mut self, reason: &str) -> Question {
        self.reason = Some(reason.to_string());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A permit matched, and no forbid: the rule's name.
    Permit(String),
    /// A forbid matched.
    Forbid(String),
    /// No rule matched: ask, as before.
    Undecided,
}

/// Your rules, for one task.
pub struct Policy {
    set: PolicySet,
    agent: String,
    task: String,
    project: String,
}

/// Your rules, if you wrote any. A file that doesn't parse is an error, not
/// something to skip: rules you wrote must never be silently ignored.
pub fn load(path: &Path, home: &Path) -> Result<Option<PolicySet>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let home = home.display().to_string();
    let text = text.replace("\"~/", &format!("\"{home}/")).replace("\"~\"", &format!("\"{home}\""));
    let set = PolicySet::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e:?}", path.display()))?;
    Ok(Some(set))
}

/// A project's rules, which may only forbid.
pub fn load_project(path: &Path, home: &Path) -> Result<PolicySet> {
    let set = load(path, home)?.with_context(|| format!("{}: no such file", path.display()))?;
    if set.templates().next().is_some() {
        anyhow::bail!("{}: templates aren't supported in project rules", path.display());
    }
    if let Some(p) = set.policies().find(|p| p.effect() == Effect::Permit) {
        anyhow::bail!(
            "{}: project rules can only forbid, and \u{201c}{}\u{201d} permits; only your own rules ({FILE}) can allow",
            path.display(),
            rule_name(&set, p.id())
        );
    }
    Ok(set)
}

/// Your rules and a project's, in one set.
pub fn combine(yours: Option<PolicySet>, project: Option<PolicySet>) -> Result<Option<PolicySet>> {
    let Some(project) = project else { return Ok(yours) };
    let mut set = yours.unwrap_or_default();
    for policy in project.policies() {
        set.add(policy.new_id(PolicyId::new(format!("{PROJECT}{}", policy.id()))))
            .map_err(|e| anyhow::anyhow!("combining the project's rules with yours: {e}"))?;
    }
    Ok(Some(set))
}

/// A rule's name: its `@id("…")`, else "rule N" in file order; a project's
/// rules start with "project: ".
pub fn rule_name(set: &PolicySet, id: &PolicyId) -> String {
    let raw = id.to_string();
    let (prefix, raw) = match raw.strip_prefix(PROJECT) {
        Some(rest) => ("project: ", rest.to_string()),
        None => ("", raw),
    };
    if let Some(name) = set.annotation(id, "id") {
        return format!("{prefix}{name}");
    }
    match raw.strip_prefix("policy").and_then(|n| n.parse::<usize>().ok()) {
        Some(n) => format!("{prefix}rule {}", n + 1),
        None => format!("{prefix}{raw}"),
    }
}

/// Whose rule it is, and its own name: ("your", name) or ("the project's", name).
pub fn whose(rule: &str) -> (&'static str, &str) {
    match rule.strip_prefix("project: ") {
        Some(name) => ("the project's", name),
        None => ("your", rule),
    }
}

/// Every rule: (name, "permit" or "forbid"), yours then the project's, in
/// file order.
pub fn rules(set: &PolicySet) -> Vec<(String, &'static str)> {
    let mut out: Vec<((bool, usize), String, &'static str)> = set
        .policies()
        .map(|p| {
            let effect = if p.effect() == Effect::Forbid { "forbid" } else { "permit" };
            let id = p.id().to_string();
            let project = id.starts_with(PROJECT);
            // policy0, policy1, …, policy10: file order.
            let n = id.trim_start_matches(PROJECT).strip_prefix("policy").and_then(|n| n.parse::<usize>().ok()).unwrap_or(usize::MAX);
            ((project, n), rule_name(set, p.id()), effect)
        })
        .collect();
    out.sort_by_key(|(key, _, _)| *key);
    out.into_iter().map(|(_, name, effect)| (name, effect)).collect()
}

/// Cedar has no null and no floating point: drop the first, spell the second.
fn cedar_json(v: &Value) -> Option<Value> {
    match v {
        Value::Null => None,
        Value::Number(n) if n.as_i64().is_none() => Some(Value::String(n.to_string())),
        Value::Array(items) => Some(Value::Array(items.iter().filter_map(cedar_json).collect())),
        Value::Object(map) => Some(Value::Object(map.iter().filter_map(|(k, v)| Some((k.clone(), cedar_json(v)?))).collect())),
        other => Some(other.clone()),
    }
}

impl Policy {
    pub fn new(set: PolicySet, agent: &str, task: &str, project: &Path) -> Policy {
        Policy { set, agent: agent.to_string(), task: task.to_string(), project: project.display().to_string() }
    }

    pub fn decide(&self, q: &Question) -> Verdict {
        // Built from parts, so a path or host never needs escaping.
        let uid = |kind: &str, id: &str| EntityTypeName::from_str(kind).map(|t| EntityUid::from_type_name_and_id(t, EntityId::new(id)));
        let (Ok(principal), Ok(action), Ok(resource)) = (uid("Agent", &self.agent), uid("Action", q.action.name()), uid(q.kind, &q.id)) else {
            return Verdict::Undecided;
        };
        let mut context = Map::new();
        context.insert("agent".into(), json!(self.agent));
        context.insert("task".into(), json!(self.task));
        context.insert("project".into(), json!(self.project));
        if let Some(r) = &q.reason {
            context.insert("reason".into(), json!(r));
        }
        if let Some(args) = q.args.as_ref().and_then(cedar_json) {
            context.insert("args".into(), args);
        }
        // Arguments Cedar can't represent: decide on the rest.
        let context = Context::from_json_value(Value::Object(context.clone()), None).or_else(|_| {
            context.remove("args");
            Context::from_json_value(Value::Object(context), None)
        });
        let entities = Entities::from_json_value(json!([{ "uid": { "type": q.kind, "id": q.id }, "attrs": q.attrs, "parents": [] }]), None);
        let (Ok(context), Ok(entities)) = (context, entities) else { return Verdict::Undecided };
        let Ok(request) = Request::new(principal, action, resource, context, None) else { return Verdict::Undecided };
        let response = Authorizer::new().is_authorized(&request, &self.set, &entities);
        let first = response.diagnostics().reason().next().map(|id| rule_name(&self.set, id));
        match (response.decision(), first) {
            (Decision::Allow, Some(rule)) => Verdict::Permit(rule),
            // Denied *because of* a policy: only a forbid does that.
            (Decision::Deny, Some(rule)) => Verdict::Forbid(rule),
            _ => Verdict::Undecided,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
        @id("read code")
        permit (principal, action == Action::"read", resource)
        when { resource.path like "~/code/*" };

        forbid (principal, action == Action::"read", resource)
        when { resource.path like "~/code/secret*" };

        @id("no paste sites")
        forbid (principal, action == Action::"connect", resource)
        when { resource.name like "*paste*" };

        @id("pypi for claude")
        permit (principal == Agent::"claude", action == Action::"connect", resource == Host::"pypi.org");

        @id("issues in our repo")
        permit (principal, action == Action::"call", resource == Tool::"github.create_issue")
        when { context.args has repo && context.args.repo == "agentos" };
    "#;

    fn policy(agent: &str) -> Policy {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE);
        std::fs::write(&path, RULES).unwrap();
        let set = load(&path, Path::new("/home/you")).unwrap().unwrap();
        Policy::new(set, agent, "t1", Path::new("/home/you/code/app"))
    }

    #[test]
    fn rules_answer_or_leave_it_to_you() {
        let p = policy("claude");
        let read = |path: &str| p.decide(&Question::path(false, Path::new(path)));
        assert_eq!(read("/home/you/code/lib"), Verdict::Permit("read code".into()));
        assert_eq!(read("/home/you/code/secrets/keys"), Verdict::Forbid("rule 2".into()), "forbid wins");
        assert_eq!(read("/home/you/notes"), Verdict::Undecided);
        assert_eq!(p.decide(&Question::path(true, Path::new("/home/you/code/lib"))), Verdict::Undecided, "reading isn't writing");

        assert_eq!(p.decide(&Question::connect("pastebin.com", 443)), Verdict::Forbid("no paste sites".into()));
        assert_eq!(p.decide(&Question::connect("pypi.org", 443)), Verdict::Permit("pypi for claude".into()));
        assert_eq!(policy("codex").decide(&Question::connect("pypi.org", 443)), Verdict::Undecided, "per agent");

        let call = |args: Value| p.decide(&Question::call("github", "create_issue", &args));
        assert_eq!(call(json!({ "repo": "agentos", "title": "x", "labels": null, "weight": 0.5 })), Verdict::Permit("issues in our repo".into()));
        assert_eq!(call(json!({ "repo": "other" })), Verdict::Undecided);
        assert_eq!(call(json!({})), Verdict::Undecided, "a rule that can't be evaluated doesn't match");
        assert_eq!(rules(&p.set).len(), 5);
        assert_eq!(rules(&p.set)[1], ("rule 2".to_string(), "forbid"));
    }

    #[test]
    fn project_rules_only_tighten() {
        let dir = tempfile::tempdir().unwrap();
        let (yours, theirs) = (dir.path().join(FILE), dir.path().join(PROJECT_FILE));
        std::fs::write(&yours, "@id(\"pypi\")\npermit (principal, action == Action::\"connect\", resource == Host::\"pypi.org\");").unwrap();
        std::fs::write(&theirs, "@id(\"never prod\")\nforbid (principal, action == Action::\"connect\", resource) when { resource.name like \"*.prod.example\" };\nforbid (principal, action == Action::\"connect\", resource == Host::\"pypi.org\");").unwrap();
        let home = Path::new("/home/you");
        let set = combine(load(&yours, home).unwrap(), Some(load_project(&theirs, home).unwrap())).unwrap().unwrap();
        let p = Policy::new(set, "claude", "t", home);
        assert_eq!(p.decide(&Question::connect("db.prod.example", 443)), Verdict::Forbid("project: never prod".into()));
        assert_eq!(p.decide(&Question::connect("pypi.org", 443)), Verdict::Forbid("project: rule 2".into()), "the project's forbid beats your permit");
        assert_eq!(whose("project: never prod"), ("the project's", "never prod"));
        assert_eq!(whose("pypi"), ("your", "pypi"));
        let names: Vec<String> = rules(&p.set).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["pypi", "project: never prod", "project: rule 2"]);

        std::fs::write(&theirs, "forbid (principal, action, resource == Host::\"x\");\npermit (principal, action, resource);").unwrap();
        assert!(load_project(&theirs, home).unwrap_err().to_string().contains("can only forbid"));
        std::fs::write(&theirs, "forbid (principal, action, resource").unwrap();
        assert!(load_project(&theirs, home).is_err(), "a broken file isn't skipped");
        assert!(combine(None, None).unwrap().is_none());
    }

    #[test]
    fn a_broken_file_is_an_error_and_no_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(&dir.path().join(FILE), Path::new("/h")).unwrap().is_none());
        std::fs::write(dir.path().join(FILE), "permit (principal, action, resource").unwrap();
        assert!(load(&dir.path().join(FILE), Path::new("/h")).is_err());
    }
}
