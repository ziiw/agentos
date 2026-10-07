//! Append-only, hash-chained event log ("flight recorder") for a task.
//!
//! Each event commits to the hash of the one before it, so any edit, removal
//! or reordering of past events breaks the chain. The journal lives outside
//! the sandbox, so the agent can't reach it; anchoring the chain head
//! somewhere the *user* can't rewrite either (TPM, remote witness) is a later
//! phase.

use crate::util::{hex, now_ms};
use anyhow::{Context, Result};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub ts_ms: u64,
    pub kind: String,
    pub data: Value,
    pub prev: String,
    pub hash: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Integrity {
    Intact { events: usize, head: String },
    Broken { line: usize, reason: String },
}

#[derive(Clone)]
pub struct Journal {
    path: PathBuf,
}

/// `v` with object keys sorted at every level: the form that is hashed and
/// written. (serde_json sorts keys by default, but a dependency can turn on
/// its `preserve_order` feature, so the journal doesn't rely on that.)
fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<&String, Value> = map.iter().map(|(k, v)| (k, canonical(v))).collect();
            Value::Object(sorted.into_iter().map(|(k, v)| (k.clone(), v)).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn digest(seq: u64, ts_ms: u64, kind: &str, data: &Value, prev: &str) -> String {
    let body = canonical(&json!({ "seq": seq, "ts_ms": ts_ms, "kind": kind, "data": data })).to_string();
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(body.as_bytes());
    hex(&h.finalize())
}

impl Journal {
    pub fn new(path: PathBuf) -> Self {
        Journal { path }
    }

    fn lines(&self) -> Result<Vec<String>> {
        match fs::read_to_string(&self.path) {
            Ok(s) => Ok(s.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e).with_context(|| format!("read {}", self.path.display())),
        }
    }

    pub fn read(&self) -> Result<Vec<Event>> {
        self.lines()?
            .iter()
            .enumerate()
            .map(|(i, l)| serde_json::from_str(l).with_context(|| format!("journal line {}", i + 1)))
            .collect()
    }

    /// Appends an event. Safe to call from several threads or processes at
    /// once (the egress proxy reports from its own threads): the file is
    /// locked from reading the chain head to writing the new event.
    pub fn append(&self, kind: &str, data: Value) -> Result<Event> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("open {}", self.path.display()))?;
        let mut f = Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, e)| e).context("lock journal")?;
        let mut content = String::new();
        f.read_to_string(&mut content)?;
        // Only the last event matters for chaining; agents can log hundreds of tool calls.
        let (seq, prev) = match content.lines().rev().find(|l| !l.trim().is_empty()) {
            Some(line) => {
                let last: Event = serde_json::from_str(line).context("journal: unparseable last event")?;
                (last.seq + 1, last.hash)
            }
            None => (0, GENESIS.to_string()),
        };
        let ts_ms = now_ms();
        let data = canonical(&data);
        let hash = digest(seq, ts_ms, kind, &data, &prev);
        let event = Event { seq, ts_ms, kind: kind.to_string(), data, prev, hash };
        writeln!(f, "{}", serde_json::to_string(&event)?)?;
        f.sync_data()?;
        Ok(event)
    }

    pub fn verify(&self) -> Result<Integrity> {
        let mut prev = GENESIS.to_string();
        let lines = self.lines()?;
        for (i, line) in lines.iter().enumerate() {
            let broken = |reason: &str| Integrity::Broken { line: i + 1, reason: reason.into() };
            let Ok(e) = serde_json::from_str::<Event>(line) else {
                return Ok(broken("unparseable event"));
            };
            if e.seq != i as u64 {
                return Ok(broken("sequence gap (event removed or reordered)"));
            }
            if e.prev != prev {
                return Ok(broken("does not chain to the previous event"));
            }
            if digest(e.seq, e.ts_ms, &e.kind, &e.data, &e.prev) != e.hash {
                return Ok(broken("contents don't match their hash (event was edited)"));
            }
            prev = e.hash;
        }
        Ok(Integrity::Intact { events: lines.len(), head: prev })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let j = Journal::new(path.clone());
        j.append("task.created", json!({ "command": ["sh"] })).unwrap();
        j.append("task.exited", json!({ "exit_code": 0 })).unwrap();
        assert!(matches!(j.verify().unwrap(), Integrity::Intact { events: 2, .. }));

        let tampered = fs::read_to_string(&path).unwrap().replace("\"exit_code\":0", "\"exit_code\":1");
        fs::write(&path, tampered).unwrap();
        assert!(matches!(j.verify().unwrap(), Integrity::Broken { line: 2, .. }));
    }

    #[test]
    fn concurrent_appends_keep_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path().join("events.jsonl"));
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let j = j.clone();
                std::thread::spawn(move || {
                    for i in 0..25 {
                        j.append("tick", json!({ "t": t, "i": i })).unwrap();
                    }
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        assert!(matches!(j.verify().unwrap(), Integrity::Intact { events: 200, .. }));
    }

    #[test]
    fn hashes_are_independent_of_key_order() {
        // An event written before agentos sorted keys itself (serde_json did).
        let data = json!({ "b": 1, "a": { "y": [{ "q": 1, "p": 2 }], "x": true } });
        let old = {
            let body = r#"{"data":{"a":{"x":true,"y":[{"p":2,"q":1}]},"b":1},"kind":"k","seq":0,"ts_ms":5}"#;
            let mut h = Sha256::new();
            h.update(GENESIS.as_bytes());
            h.update(b"\n");
            h.update(body.as_bytes());
            hex(&h.finalize())
        };
        assert_eq!(digest(0, 5, "k", &data, GENESIS), old);
        assert_eq!(canonical(&data).to_string(), r#"{"a":{"x":true,"y":[{"p":2,"q":1}]},"b":1}"#);
    }

    #[test]
    fn floats_read_back_exactly() {
        // Costs are sums of products like 3000 × 2e-6: their shortest decimal
        // form only parses back to the same number with exact float parsing,
        // and the chain hashes the re-serialized value.
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path().join("events.jsonl"));
        let mut total = 0.0;
        for i in 0..400u64 {
            total += (3000 + i * 7) as f64 * 2e-6 + 40000.0 * 0.2e-6 + (1500 + i) as f64 * 10e-6;
            j.append("model.call", json!({ "cost_usd": total, "third": (i as f64) / 3.0, "tiny": 1e-7 * i as f64 })).unwrap();
        }
        assert!(matches!(j.verify().unwrap(), Integrity::Intact { events: 400, .. }));
    }

    #[test]
    fn dropping_an_event_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let j = Journal::new(path.clone());
        for i in 0..3 {
            j.append("tick", json!({ "i": i })).unwrap();
        }
        let kept: Vec<String> = fs::read_to_string(&path).unwrap().lines().skip(1).map(String::from).collect();
        fs::write(&path, kept.join("\n")).unwrap();
        assert!(matches!(j.verify().unwrap(), Integrity::Broken { line: 1, .. }));
    }
}
