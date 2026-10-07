//! Held tool calls: the second half of the outbox.
//!
//! A call to one of your MCP servers that changes things and whose result
//! the agent doesn't need (create an issue, post a message) can be held
//! instead of run: `tools = { create_issue = "hold" }` in your config, a
//! server's `hold = true` for all its tools that aren't read-only, or [h]
//! when you're asked. The agent is told it's queued. The call is stored in
//! the task, shown by `agent diff` with its arguments, and run by `agent
//! commit` from outside the sandbox with your credentials, together with
//! the task's files and held pushes. `agent rollback` drops it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Held {
    /// Order of arrival; calls are released in this order.
    pub seq: u32,
    pub server: String,
    pub tool: String,
    pub args: Value,
    pub at_ms: u64,
}

impl Held {
    /// `server.tool`
    pub fn target(&self) -> String {
        format!("{}.{}", self.server, self.tool)
    }
}

fn dir(task_dir: &Path) -> PathBuf {
    task_dir.join("held-calls")
}

fn file(task_dir: &Path, seq: u32) -> PathBuf {
    dir(task_dir).join(format!("{seq:04}.json"))
}

/// Stores a call, returning it with its place in the queue.
pub fn hold(task_dir: &Path, server: &str, tool: &str, args: &Value) -> Result<Held> {
    fs::create_dir_all(dir(task_dir)).context("create held-calls")?;
    let seq = pending(task_dir)?.last().map_or(1, |h| h.seq + 1);
    let held = Held { seq, server: server.to_string(), tool: tool.to_string(), args: args.clone(), at_ms: crate::util::now_ms() };
    let tmp = dir(task_dir).join(format!(".{seq:04}.tmp"));
    fs::write(&tmp, serde_json::to_vec_pretty(&held)?)?;
    fs::rename(&tmp, file(task_dir, seq))?;
    Ok(held)
}

/// The calls still held, in order.
pub fn pending(task_dir: &Path) -> Result<Vec<Held>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir(task_dir)) {
        Ok(e) => e,
        Err(_) => return Ok(out),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let raw = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            out.push(serde_json::from_slice::<Held>(&raw).with_context(|| format!("{}: corrupt", path.display()))?);
        }
    }
    out.sort_by_key(|h| h.seq);
    Ok(out)
}

/// Forgets a call: it ran, or you dropped it.
pub fn remove(task_dir: &Path, seq: u32) {
    let _ = fs::remove_file(file(task_dir, seq));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn calls_queue_in_order_and_leave_when_done() {
        let dir = tempfile::tempdir().unwrap();
        assert!(pending(dir.path()).unwrap().is_empty());
        let a = hold(dir.path(), "tracker", "create_issue", &json!({ "title": "one" })).unwrap();
        let b = hold(dir.path(), "chat", "post", &json!({ "text": "two" })).unwrap();
        assert_eq!((a.seq, b.seq), (1, 2));
        let all = pending(dir.path()).unwrap();
        assert_eq!(all.iter().map(Held::target).collect::<Vec<_>>(), ["tracker.create_issue", "chat.post"]);
        assert_eq!(all[0].args["title"], "one");
        remove(dir.path(), 1);
        let c = hold(dir.path(), "chat", "post", &json!({})).unwrap();
        assert_eq!(c.seq, 3, "numbers aren't reused while later calls wait");
        assert_eq!(pending(dir.path()).unwrap().len(), 2);
    }
}
