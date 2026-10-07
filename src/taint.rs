//! Taint: whether a task has read something it shouldn't trust.
//!
//! An agent can be steered by any text it reads, so a task that has read
//! untrusted input is treated differently from one that hasn't. agentos
//! marks a task tainted when it sees one of:
//!
//! - **web**: the task connected to a host that isn't one of its own model
//!   APIs, a brokered credential's host or a package registry (those, and
//!   whatever you add under `[taint] trusted`, don't count);
//! - **tool**: a result came back from an MCP server that reaches outside
//!   your machine (every remote server, unless you say `taint = false`; a
//!   local one if you say `taint = true`);
//! - **file**: you let it read a folder outside its project, mid-task.
//!
//! Taint never goes away within a task. It is context for your rules
//! (`context.tainted`, `context.taint`), and by default a tainted task is
//! asked before every tool call that isn't read-only, whatever the config
//! or an earlier "always" said. Only a rule you wrote can permit such a
//! call without asking.

use crate::journal::Journal;
use serde_json::json;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Web,
    Tool,
    File,
}

impl Source {
    pub fn name(self) -> &'static str {
        match self {
            Source::Web => "web",
            Source::Tool => "tool",
            Source::File => "file",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Source::Web => "web pages",
            Source::Tool => "tool results",
            Source::File => "files outside the project",
        }
    }
}

/// Hosts whose content doesn't taint a task by default: package registries.
pub const TRUSTED_HOSTS: &[&str] = &[
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "crates.io",
    "index.crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "sum.golang.org",
];

/// Journaled in full up to this many details per source; after that, the
/// task is just as tainted, only not every instance is written down.
const JOURNALED: usize = 20;

pub struct Taint {
    journal: Option<Journal>,
    /// Hosts that don't taint: exact names, or `*.suffix`.
    trusted: Vec<String>,
    marks: Mutex<Vec<(Source, String)>>,
}

impl Taint {
    pub fn new(journal: Option<Journal>, mut trusted: Vec<String>) -> Taint {
        trusted.extend(TRUSTED_HOSTS.iter().map(|h| h.to_string()));
        Taint { journal, trusted, marks: Mutex::new(Vec::new()) }
    }

    pub fn is_trusted(&self, host: &str) -> bool {
        self.trusted.iter().any(|t| match t.strip_prefix("*.") {
            Some(suffix) => host.strip_suffix(suffix).is_some_and(|rest| rest.ends_with('.')),
            None => t == host,
        })
    }

    /// The task reached `host`: tainted unless it's a trusted one.
    pub fn web(&self, host: &str) {
        if !self.is_trusted(host) {
            self.mark(Source::Web, host);
        }
    }

    /// Records `detail` (a host, a server, a path) as a source of taint.
    pub fn mark(&self, source: Source, detail: &str) {
        let Ok(mut marks) = self.marks.lock() else { return };
        let entry = (source, detail.to_string());
        if marks.contains(&entry) {
            return;
        }
        let first = marks.is_empty();
        let seen = marks.iter().filter(|(s, _)| *s == source).count();
        marks.push(entry);
        if seen < JOURNALED {
            if let Some(journal) = &self.journal {
                let _ = journal.append("taint.marked", json!({ "source": source.name(), "detail": detail, "first": first }));
            }
        }
    }

    pub fn is_tainted(&self) -> bool {
        self.marks.lock().is_ok_and(|m| !m.is_empty())
    }

    /// The kinds of source seen so far, in a fixed order.
    pub fn sources(&self) -> Vec<&'static str> {
        let marks = self.marks.lock().map(|m| m.clone()).unwrap_or_default();
        [Source::Web, Source::Tool, Source::File].into_iter().filter(|s| marks.iter().any(|(m, _)| m == s)).map(Source::name).collect()
    }

    /// "web pages (evil.example, x.org), tool results (linear)": what the
    /// task read, for the prompt and the summary.
    pub fn describe(&self) -> Option<String> {
        let marks = self.marks.lock().ok()?.clone();
        let parts: Vec<String> = [Source::Web, Source::Tool, Source::File]
            .into_iter()
            .filter_map(|source| {
                let details: Vec<&str> = marks.iter().filter(|(s, _)| *s == source).map(|(_, d)| d.as_str()).collect();
                if details.is_empty() {
                    return None;
                }
                let shown = details.iter().take(3).copied().collect::<Vec<_>>().join(", ");
                let more = if details.len() > 3 { format!(", +{} more", details.len() - 3) } else { String::new() };
                Some(format!("{} ({shown}{more})", source.noun()))
            })
            .collect();
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taint(trusted: &[&str]) -> (Taint, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path().join("journal.jsonl"));
        (Taint::new(Some(journal), trusted.iter().map(|s| s.to_string()).collect()), dir)
    }

    #[test]
    fn hosts_taint_unless_trusted() {
        let (t, _dir) = taint(&["api.anthropic.com", "*.corp.example"]);
        assert!(!t.is_tainted());
        for host in ["pypi.org", "api.anthropic.com", "git.corp.example"] {
            t.web(host);
        }
        assert!(!t.is_tainted(), "registries, your model API and your trusted hosts don't taint");
        t.web("corp.example.evil.com");
        assert!(t.is_tainted());
        t.web("evil.com");
        t.mark(Source::Tool, "linear");
        assert_eq!(t.sources(), ["web", "tool"]);
        assert_eq!(t.describe().as_deref(), Some("web pages (corp.example.evil.com, evil.com); tool results (linear)"));
        t.web("evil.com");
        assert_eq!(t.marks.lock().unwrap().len(), 3, "once each");
    }

    #[test]
    fn a_wildcard_needs_a_subdomain() {
        let (t, _dir) = taint(&["*.corp.example"]);
        assert!(!t.is_trusted("corp.example"));
        assert!(!t.is_trusted("xcorp.example"));
        assert!(t.is_trusted("a.b.corp.example"));
    }
}
