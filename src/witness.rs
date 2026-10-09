//! A witness you can run: it keeps the receipts agentos machines send it.
//!
//! ```bash
//! agent witness serve --listen 0.0.0.0:7979 --dir /var/lib/agentos-witness --trust 3f2a9c1e
//! ```
//!
//! and on the machines whose tasks it should witness, in their config:
//!
//! ```toml
//! [journal]
//! witness = "https://witness.example.com/receipts"
//! ```
//!
//! A receipt is a machine's signed statement of where a task's journal stood.
//! A witness is somewhere else that holds the statement, so rewriting a
//! journal later (and signing the rewrite) can't also rewrite the witness's
//! copy. This one checks each receipt's signature, takes receipts only from
//! the keys you name (`--trust`, if you do), appends each to a log that is
//! itself hash-chained, and refuses a second, different history for the same
//! task from the same key at the same point: two receipts that disagree about
//! where one journal stood is exactly what rewriting leaves behind.
//!
//! `GET /receipts/TASK` lists what it holds for a task (that is what
//! `agent attest --verify … --witness URL` asks), `GET /head` is the log's
//! head (note it somewhere: it commits to everything the witness has taken),
//! and `agent witness check` re-verifies the whole log.

use crate::attest::{Receipt, Signed, key_id};
use crate::util::{hex, now_ms};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

/// A receipt is a few hundred bytes; this is generous.
const MAX_BODY: u64 = 64 * 1024;

/// One receipt as the log keeps it, chained to the one before.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    /// When this witness took it (its own clock).
    pub at_ms: u64,
    pub receipt: Receipt,
    pub signature: String,
    pub prev: String,
    pub hash: String,
}

/// What an entry's hash covers: all of it but the hash itself.
fn entry_hash(seq: u64, at_ms: u64, receipt: &Receipt, signature: &str, prev: &str) -> String {
    let receipt = serde_json::to_string(receipt).unwrap_or_default();
    hex(&Sha256::digest(format!("agentos-witness/1\n{seq}\n{at_ms}\n{receipt}\n{signature}\n{prev}\n").as_bytes()))
}

/// The hash a log starts from.
fn genesis() -> String {
    "0".repeat(64)
}

/// Why a receipt isn't taken.
#[derive(Debug, PartialEq)]
pub enum Refusal {
    /// Not a receipt, or its signature isn't the key's (400).
    Bad(String),
    /// Not from a key this witness takes receipts from (403).
    Untrusted(String),
    /// Disagrees with a receipt it holds (409).
    Conflict(String),
}

#[derive(Debug, PartialEq)]
pub enum Accepted {
    New { seq: u64, head: String },
    /// It already had this very receipt.
    Duplicate { seq: u64, head: String },
}

/// Whether `key` (a receipt's, hex) is one of `trust`: a key id, a prefix of at least 8, or the whole key.
pub fn trusted(key: &str, trust: &[String]) -> bool {
    trust.is_empty() || {
        let id = key_id(key);
        trust.iter().any(|t| {
            let t = t.to_ascii_lowercase();
            t == key.to_ascii_lowercase() || (t.len() >= 8 && id.starts_with(&t))
        })
    }
}

pub struct Log {
    path: PathBuf,
    entries: Vec<Entry>,
    /// Entries by (key, task), for telling when a key vouches for two histories.
    by_task: HashMap<(String, String), Vec<usize>>,
}

impl Log {
    /// The log in `dir`, made if there isn't one. A log whose chain doesn't hold is an error: it's not to be added to.
    pub fn open(dir: &Path) -> Result<Log> {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).with_context(|| format!("create {}", dir.display()))?;
        let path = dir.join("log.jsonl");
        let entries = match fs::read_to_string(&path) {
            Ok(text) => parse(&text).with_context(|| format!("{} doesn't hold together", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        let mut by_task: HashMap<(String, String), Vec<usize>> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            by_task.entry((e.receipt.key.clone(), e.receipt.task.clone())).or_default().push(i);
        }
        Ok(Log { path, entries, by_task })
    }

    /// How many receipts it holds, and the hash that commits to all of them.
    pub fn head(&self) -> (usize, String) {
        (self.entries.len(), self.entries.last().map_or_else(genesis, |e| e.hash.clone()))
    }

    pub fn for_task(&self, task: &str) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.receipt.task == task).collect()
    }

    pub fn accept(&mut self, signed: Signed, trust: &[String]) -> std::result::Result<Accepted, Refusal> {
        signed.check().map_err(Refusal::Bad)?;
        let r = &signed.receipt;
        let name_ok = |s: &str| !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !name_ok(&r.task) {
            return Err(Refusal::Bad("the receipt's task id isn't an id".into()));
        }
        if !trusted(&r.key, trust) {
            return Err(Refusal::Untrusted(format!("key {} isn't one this witness takes receipts from", key_id(&r.key))));
        }
        let held = self.by_task.get(&(r.key.clone(), r.task.clone())).cloned().unwrap_or_default();
        for &i in &held {
            let e = &self.entries[i];
            // The same journal head again (a re-issue, a retry) vouches for nothing new.
            if e.signature == signed.signature || (e.receipt.events == r.events && e.receipt.head == r.head) {
                return Ok(Accepted::Duplicate { seq: e.seq, head: self.head().1 });
            }
            if e.receipt.events == r.events && e.receipt.head != r.head {
                return Err(Refusal::Conflict(format!(
                    "key {} already vouched for a different history of task {} at event {}: two receipts that disagree about where one journal stood",
                    key_id(&r.key),
                    r.task,
                    r.events
                )));
            }
        }
        let (seq, prev, at_ms) = (self.entries.len() as u64, self.head().1, now_ms());
        let entry = Entry { seq, at_ms, hash: entry_hash(seq, at_ms, r, &signed.signature, &prev), receipt: signed.receipt, signature: signed.signature, prev };
        let line = serde_json::to_string(&entry).map_err(|e| Refusal::Bad(e.to_string()))? + "\n";
        let mut file = fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&self.path).map_err(|e| Refusal::Bad(format!("can't write the log: {e}")))?;
        file.write_all(line.as_bytes()).and_then(|_| file.sync_data()).map_err(|e| Refusal::Bad(format!("can't write the log: {e}")))?;
        let head = entry.hash.clone();
        self.by_task.entry((entry.receipt.key.clone(), entry.receipt.task.clone())).or_default().push(self.entries.len());
        self.entries.push(entry);
        Ok(Accepted::New { seq, head })
    }
}

/// Reads a log's text and checks that it holds together: the chain, and every receipt's signature.
fn parse(text: &str) -> Result<Vec<Entry>> {
    let mut entries: Vec<Entry> = Vec::new();
    for (n, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let e: Entry = serde_json::from_str(line).with_context(|| format!("line {}: not an entry", n + 1))?;
        let prev = entries.last().map_or_else(genesis, |p| p.hash.clone());
        if e.seq != entries.len() as u64 || e.prev != prev {
            bail!("line {}: it doesn't follow the one before", n + 1);
        }
        if e.hash != entry_hash(e.seq, e.at_ms, &e.receipt, &e.signature, &e.prev) {
            bail!("line {}: it was changed after it was written", n + 1);
        }
        Signed { receipt: e.receipt.clone(), signature: e.signature.clone() }.check().map_err(|why| anyhow::anyhow!("line {}: {why}", n + 1))?;
        entries.push(e);
    }
    Ok(entries)
}

/// What a witness says about a receipt you hold.
#[derive(Debug, PartialEq)]
pub enum Held {
    /// It holds this very receipt.
    Yes { seq: u64, at_ms: u64 },
    /// It holds another history of this task from this key at the same point: the one you hold, or the one it holds, is a rewrite.
    Different { seq: u64, events: usize },
    No,
}

/// Asks the witness at `url` (the address receipts are posted to) what it holds for `signed`'s task.
pub fn ask(url: &str, signed: &Signed) -> std::result::Result<Held, String> {
    crate::attest::valid_witness(url)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .build()
        .into();
    let mut response = agent.get(&format!("{}/{}", url.trim_end_matches('/'), signed.receipt.task)).header("Accept", "application/json").call().map_err(|e| e.to_string())?;
    if response.status().as_u16() != 200 {
        return Err(format!("the witness answered {}", response.status()));
    }
    let body = response.body_mut().with_config().limit(4 * 1024 * 1024).read_to_string().map_err(|e| e.to_string())?;
    let held: Vec<Entry> = serde_json::from_str(&body).map_err(|_| "the witness didn't answer with a list of receipts".to_string())?;
    // (it is asked, not believed: an entry only counts if its receipt's signature checks)
    let held: Vec<Entry> = held.into_iter().filter(|e| Signed { receipt: e.receipt.clone(), signature: e.signature.clone() }.check().is_ok()).collect();
    if let Some(e) = held.iter().find(|e| e.signature == signed.signature) {
        return Ok(Held::Yes { seq: e.seq, at_ms: e.at_ms });
    }
    Ok(match held.iter().find(|e| e.receipt.key == signed.receipt.key && e.receipt.events == signed.receipt.events && e.receipt.head != signed.receipt.head) {
        Some(e) => Held::Different { seq: e.seq, events: e.receipt.events },
        None => Held::No,
    })
}

/// `agent witness check`: how many receipts, and the head, or why the log doesn't hold.
pub fn check(dir: &Path) -> Result<(usize, String)> {
    let log = Log::open(dir)?;
    Ok(log.head())
}

fn reply(request: Request, status: u16, body: Value) {
    let json = Header::from_bytes("Content-Type", "application/json").expect("static header");
    let _ = request.respond(Response::from_data(body.to_string().into_bytes()).with_status_code(StatusCode(status)).with_header(json));
}

fn handle(mut request: Request, log: &Mutex<Log>, trust: &[String]) {
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("").trim_end_matches('/').to_string();
    match (request.method().clone(), path.as_str()) {
        (Method::Post, "" | "/receipts") => {
            let mut body = String::new();
            if request.as_reader().take(MAX_BODY + 1).read_to_string(&mut body).is_err() || body.len() as u64 > MAX_BODY {
                return reply(request, 413, json!({ "error": "a receipt is a few hundred bytes" }));
            }
            let Ok(signed) = serde_json::from_str::<Signed>(&body) else { return reply(request, 400, json!({ "error": "not a receipt" })) };
            let outcome = log.lock().unwrap_or_else(|p| p.into_inner()).accept(signed, trust);
            match outcome {
                Ok(Accepted::New { seq, head }) => reply(request, 200, json!({ "ok": true, "seq": seq, "head": head })),
                Ok(Accepted::Duplicate { seq, head }) => reply(request, 200, json!({ "ok": true, "duplicate": true, "seq": seq, "head": head })),
                Err(Refusal::Bad(why)) => reply(request, 400, json!({ "error": why })),
                Err(Refusal::Untrusted(why)) => reply(request, 403, json!({ "error": why })),
                Err(Refusal::Conflict(why)) => reply(request, 409, json!({ "error": why })),
            }
        }
        (Method::Get, "/head") => {
            let (count, head) = log.lock().unwrap_or_else(|p| p.into_inner()).head();
            reply(request, 200, json!({ "entries": count, "head": head }));
        }
        (Method::Get, "/log") => {
            let guard = log.lock().unwrap_or_else(|p| p.into_inner());
            let text: String = guard.entries.iter().filter_map(|e| serde_json::to_string(e).ok()).map(|l| l + "\n").collect();
            let header = Header::from_bytes("Content-Type", "application/x-ndjson").expect("static header");
            let _ = request.respond(Response::from_data(text.into_bytes()).with_header(header));
        }
        (Method::Get, p) if p.starts_with("/receipts/") => {
            let task = &p["/receipts/".len()..];
            let held: Vec<Value> = log.lock().unwrap_or_else(|p| p.into_inner()).for_task(task).into_iter().map(|e| json!(e)).collect();
            reply(request, 200, json!(held));
        }
        (Method::Get, "") => {
            let (count, head) = log.lock().unwrap_or_else(|p| p.into_inner()).head();
            let header = Header::from_bytes("Content-Type", "text/plain; charset=utf-8").expect("static header");
            let _ = request.respond(Response::from_data(format!("agentos witness: {count} receipts, head {head}\n").into_bytes()).with_header(header));
        }
        _ => reply(request, 404, json!({ "error": "not found" })),
    }
}

/// Serves until it is stopped.
pub fn serve(listen: &str, dir: &Path, trust: Vec<String>) -> Result<()> {
    let log = Arc::new(Mutex::new(Log::open(dir)?));
    let server = Server::http(listen).map_err(|e| anyhow::anyhow!("listen on {listen}: {e}"))?;
    let (count, head) = log.lock().unwrap_or_else(|p| p.into_inner()).head();
    println!("agent ▸ witness on http://{} · {count} receipts held (head {}) · {}", server.server_addr(), &head[..12], dir.display());
    println!("  {}", if trust.is_empty() { "taking receipts from any key (--trust KEY limits it)".to_string() } else { format!("taking receipts from {} key(s) only", trust.len()) });
    let trust = Arc::new(trust);
    for request in server.incoming_requests() {
        let (log, trust) = (log.clone(), trust.clone());
        std::thread::spawn(move || handle(request, &log, &trust));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::Identity;
    use crate::journal::Journal;

    /// A task whose journal has these events, and the receipt for it from `id`.
    fn receipt_for(id: &Identity, task: &str, events: usize, tag: &str) -> Signed {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path().join("events.jsonl"));
        for i in 0..events {
            j.append("test.event", json!({ "i": i, "tag": tag })).unwrap();
        }
        id.issue(task, &j).unwrap()
    }

    #[test]
    fn a_witness_keeps_receipts_in_a_chain_that_holds() {
        let keys = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(keys.path()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path()).unwrap();
        assert_eq!(log.head(), (0, genesis()));
        let first = receipt_for(&id, "aaaa1111", 3, "x");
        let Accepted::New { seq: 0, head: h0 } = log.accept(first.clone(), &[]).unwrap() else { panic!("new") };
        // The same receipt again is known, and adds nothing.
        assert_eq!(log.accept(first.clone(), &[]).unwrap(), Accepted::Duplicate { seq: 0, head: h0.clone() });
        assert_eq!(log.head(), (1, h0.clone()));
        // The same journal head signed again later (a re-issue) is no news either.
        let dir2 = tempfile::tempdir().unwrap();
        let j = Journal::new(dir2.path().join("events.jsonl"));
        j.append("test.event", json!({ "i": 0 })).unwrap();
        let (a, b) = (id.issue("dddd4444", &j).unwrap(), {
            std::thread::sleep(std::time::Duration::from_millis(5));
            id.issue("dddd4444", &j).unwrap()
        });
        assert_ne!(a.signature, b.signature, "a later signature of the same head");
        let Accepted::New { seq: 1, head: h1 } = log.accept(a, &[]).unwrap() else { panic!("new") };
        assert_eq!(log.accept(b, &[]).unwrap(), Accepted::Duplicate { seq: 1, head: h1 });
        // A later receipt of the same task (the journal grew) is fine.
        let Accepted::New { seq: 2, head: h1 } = log.accept(receipt_for(&id, "aaaa1111", 5, "x"), &[]).unwrap() else { panic!("new") };
        assert_ne!(h0, h1);
        assert_eq!(log.for_task("aaaa1111").len(), 2);
        assert_eq!(log.for_task("bbbb2222").len(), 0);
        // It reads back as it was written, and its head is the same.
        let again = Log::open(dir.path()).unwrap();
        assert_eq!(again.head(), (3, h1.clone()));
        assert_eq!(check(dir.path()).unwrap(), (3, h1));
    }

    #[test]
    fn a_key_cannot_vouch_for_two_histories_of_one_task() {
        let keys = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(keys.path()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path()).unwrap();
        log.accept(receipt_for(&id, "aaaa1111", 4, "the truth"), &[]).unwrap();
        // The same task, the same number of events, another history: what rewriting leaves behind.
        let Err(Refusal::Conflict(why)) = log.accept(receipt_for(&id, "aaaa1111", 4, "a rewrite"), &[]) else { panic!("conflict") };
        assert!(why.contains("different history") && why.contains("event 4"), "{why}");
        assert_eq!(log.head().0, 1, "and it was not kept");
        // Another task, or more events, or another key, is not a conflict.
        log.accept(receipt_for(&id, "cccc3333", 4, "other task"), &[]).unwrap();
        log.accept(receipt_for(&id, "aaaa1111", 6, "a rewrite"), &[]).unwrap();
        let other_keys = tempfile::tempdir().unwrap();
        let other = Identity::load_or_create(other_keys.path()).unwrap();
        log.accept(receipt_for(&other, "aaaa1111", 4, "another machine's"), &[]).unwrap();
    }

    #[test]
    fn only_signed_receipts_from_keys_you_trust_are_taken() {
        let keys = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(keys.path()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path()).unwrap();
        let good = receipt_for(&id, "aaaa1111", 3, "x");
        // A changed receipt isn't the key's.
        let mut forged = good.clone();
        forged.receipt.events = 99;
        assert!(matches!(log.accept(forged, &[]), Err(Refusal::Bad(_))));
        // A receipt can be perfectly signed and still not be about a task id.
        let odd_task = receipt_for(&id, "has space!", 1, "x");
        assert!(matches!(log.accept(odd_task, &[]), Err(Refusal::Bad(why)) if why.contains("task id")));
        // Trust: by id, by prefix, by the whole key; not by a short prefix or another key.
        let (id16, full) = (id.key_id(), id.public_hex());
        for yes in [id16.clone(), id16[..8].to_string(), full.clone(), id16.to_uppercase()] {
            assert!(trusted(&full, &[yes.clone()]), "{yes}");
        }
        for no in [id16[..4].to_string(), "0".repeat(16), String::new()] {
            assert!(!trusted(&full, &[no.clone()]), "{no:?}");
        }
        assert!(trusted(&full, &[]), "no list: anyone");
        assert!(matches!(log.accept(good.clone(), &["deadbeefdeadbeef".to_string()]), Err(Refusal::Untrusted(_))));
        assert!(log.accept(good, &[id16]).is_ok());
    }

    #[test]
    fn a_log_that_was_changed_does_not_open() {
        let keys = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(keys.path()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path()).unwrap();
        for (task, n) in [("aaaa1111", 2), ("bbbb2222", 3), ("cccc3333", 4)] {
            log.accept(receipt_for(&id, task, n, "x"), &[]).unwrap();
        }
        let path = dir.path().join("log.jsonl");
        let original = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = original.lines().collect();
        // An edit, a missing line, lines swapped, a line from another log.
        for (broken, why) in [
            (original.replacen("bbbb2222", "bbbb2223", 1), "line 2"),
            ([lines[0], lines[2]].join("\n"), "line 2: it doesn't follow"),
            ([lines[1], lines[0], lines[2]].join("\n"), "line 1"),
            (original.replacen("\"events\":4", "\"events\":5", 1), "line 3"),
        ] {
            fs::write(&path, broken).unwrap();
            let err = format!("{:#}", Log::open(dir.path()).err().expect("should not open"));
            assert!(err.contains(why), "{why}: {err}");
        }
        fs::write(&path, &original).unwrap();
        assert!(Log::open(dir.path()).is_ok());
    }
}
