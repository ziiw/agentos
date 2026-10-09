//! Receipts: a signed statement of where a task's journal stood, and a
//! witness for it.
//!
//! The journal is tamper-evident against the agent, which can't reach it.
//! Against *you* (or whoever has your machine) it isn't: rewrite a whole
//! chain and it verifies. A receipt closes part of that gap. When a task ends,
//! agentos signs its journal's head (the hash that commits to every event) with
//! this machine's key, and can post the signed receipt to a witness you run
//! or trust. Anyone holding a receipt, wherever they got it, can later check
//! that a journal they're shown still contains the history it vouches for:
//! changing that history afterwards means changing the receipt, which
//! means the key's signature, and the witness's copy.
//!
//! The key is an Ed25519 key made on first use and kept in the task store,
//! which no sandbox can see. Or, with `[journal] key = "tpm"`, an ECDSA key
//! the machine's TPM holds (`tpm.rs`): it signs but can't be copied, so a copy
//! of the store can't forge receipts. A receipt can also carry the TPM's PCRs,
//! the measurements of what the machine booted.

use crate::journal::{Integrity, Journal};
use crate::util::{hex, now_ms};
use anyhow::{Context, Result, bail};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1, ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// What the signature covers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub v: u32,
    pub task: String,
    /// The journal's head hash, and how many events it commits to.
    pub head: String,
    pub events: usize,
    /// `agent --version`, as the machine that signed it ran it.
    pub agentos: String,
    pub at_ms: u64,
    /// The signing key, hex: a receipt carries the key to check it with, which
    /// only means something once you know whose key that is (see `key_id`).
    pub key: String,
    /// How it was signed: "ed25519" (a key in the store) or "ecdsa-p256" (a key in a TPM).
    #[serde(default = "ed25519", skip_serializing_if = "is_ed25519")]
    pub alg: String,
    /// The TPM's PCRs (sha256) when the task ended, if you asked for them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pcrs: BTreeMap<u32, String>,
}

fn ed25519() -> String {
    "ed25519".into()
}

fn is_ed25519(alg: &String) -> bool {
    alg == "ed25519"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed {
    pub receipt: Receipt,
    /// Hex.
    pub signature: String,
}

impl Receipt {
    /// The bytes that are signed: spelled out, so no JSON detail can change them.
    /// (A receipt with neither a TPM key nor PCRs is the first version, byte for byte.)
    fn message(&self) -> Vec<u8> {
        if self.v == 1 {
            return format!(
                "agentos-receipt/{}\ntask={}\nhead={}\nevents={}\nagentos={}\nat_ms={}\nkey={}\n",
                self.v, self.task, self.head, self.events, self.agentos, self.at_ms, self.key
            )
            .into_bytes();
        }
        let pcrs: Vec<String> = self.pcrs.iter().map(|(i, v)| format!("{i}:{v}")).collect();
        format!(
            "agentos-receipt/{}\ntask={}\nhead={}\nevents={}\nagentos={}\nat_ms={}\nkey={}\nalg={}\npcrs={}\n",
            self.v,
            self.task,
            self.head,
            self.events,
            self.agentos,
            self.at_ms,
            self.key,
            self.alg,
            pcrs.join(",")
        )
        .into_bytes()
    }
}

/// A short name for a public key (hex): what you compare, or tell a verifier to trust.
pub fn key_id(public_hex: &str) -> String {
    hex(&Sha256::digest(unhex(public_hex))).chars().take(16).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).filter_map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()).collect()
}

/// Which key signs a task's receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyKind {
    /// An Ed25519 key in the task store.
    #[default]
    File,
    /// An ECDSA key the TPM holds.
    Tpm,
}

impl KeyKind {
    pub fn parse(s: &str) -> Result<KeyKind> {
        match s {
            "file" => Ok(KeyKind::File),
            "tpm" => Ok(KeyKind::Tpm),
            other => bail!("{other:?}: receipts are signed with a \"file\" key or a \"tpm\" key"),
        }
    }
}

/// This machine's signing key.
pub enum Identity {
    File(Ed25519KeyPair),
    Tpm(crate::tpm::Key),
}

impl Identity {
    /// The key in the store, made on first use (private to you).
    pub fn load_or_create(store_root: &Path) -> Result<Identity> {
        Identity::open(store_root, KeyKind::File)
    }

    /// The key of this kind: a file key is made on first use in `store_root/identity/`
    /// (private to you); a TPM key is made in the TPM, with its wrapped blobs kept there.
    pub fn open(store_root: &Path, kind: KeyKind) -> Result<Identity> {
        match kind {
            KeyKind::File => Identity::file(store_root),
            KeyKind::Tpm => Ok(Identity::Tpm(crate::tpm::Key::load_or_create(store_root).context("the TPM key")?)),
        }
    }

    fn file(store_root: &Path) -> Result<Identity> {
        let dir = store_root.join("identity");
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let path = dir.join("ed25519.pk8");
        let pkcs8 = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| anyhow::anyhow!("couldn't make a signing key"))?;
                let tmp = dir.join(format!(".ed25519.{}.tmp", std::process::id()));
                let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
                file.write_all(doc.as_ref())?;
                file.sync_all()?;
                // Whoever links it first wins, so tasks starting together share one key.
                let linked = fs::hard_link(&tmp, &path);
                let _ = fs::remove_file(&tmp);
                match linked {
                    Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e).with_context(|| format!("write {}", path.display())),
                    _ => {}
                }
                fs::read(&path)?
            }
        };
        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| anyhow::anyhow!("{} isn't a signing key", path.display()))?;
        Ok(Identity::File(pair))
    }

    pub fn alg(&self) -> &'static str {
        match self {
            Identity::File(_) => "ed25519",
            Identity::Tpm(_) => "ecdsa-p256",
        }
    }

    pub fn public_hex(&self) -> String {
        match self {
            Identity::File(pair) => hex(pair.public_key().as_ref()),
            Identity::Tpm(key) => hex(&key.point),
        }
    }

    pub fn key_id(&self) -> String {
        key_id(&self.public_hex())
    }

    /// Signs where `journal` stands now: it must verify.
    pub fn issue(&self, task: &str, journal: &Journal) -> Result<Signed> {
        self.issue_with(task, journal, BTreeMap::new())
    }

    /// The same, with these PCRs in the receipt.
    pub fn issue_with(&self, task: &str, journal: &Journal, pcrs: BTreeMap<u32, String>) -> Result<Signed> {
        let (events, head) = match journal.verify()? {
            Integrity::Intact { events, head } => (events, head),
            Integrity::Broken { line, reason } => bail!("the journal is broken at line {line} ({reason}); not signing it"),
        };
        let receipt = Receipt {
            // The first version stays what it was for a file key and no PCRs.
            v: if matches!(self, Identity::File(_)) && pcrs.is_empty() { 1 } else { 2 },
            task: task.to_string(),
            head,
            events,
            agentos: concat!(env!("CARGO_PKG_VERSION"), " (", env!("AGENTOS_REV"), ")").to_string(),
            at_ms: now_ms(),
            key: self.public_hex(),
            alg: self.alg().to_string(),
            pcrs,
        };
        let signature = match self {
            Identity::File(pair) => hex(pair.sign(&receipt.message()).as_ref()),
            Identity::Tpm(key) => hex(&key.sign(&receipt.message())?),
        };
        Ok(Signed { receipt, signature })
    }
}

impl Signed {
    /// Whether the signature is the embedded key's over the receipt.
    pub fn check(&self) -> Result<(), String> {
        let key = unhex(&self.receipt.key);
        let signature = unhex(&self.signature);
        let message = self.receipt.message();
        // (the algorithm is signed too, but a receipt must not pick how it's checked)
        let verified = match (self.receipt.v, self.receipt.alg.as_str()) {
            (1 | 2, "ed25519") => UnparsedPublicKey::new(&ED25519, key).verify(&message, &signature),
            (2, "ecdsa-p256") => UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key).verify(&message, &signature),
            (v, alg) => return Err(format!("a version {v} receipt signed with {alg:?}: not something this agentos checks")),
        };
        verified.map_err(|_| "the signature doesn't match the receipt".to_string())
    }

    /// Whether `journal` still contains the history this receipt vouches
    /// for: an intact chain, with the head the receipt names at the event it
    /// says. The journal may have grown since (a commit, a push).
    pub fn check_journal(&self, journal: &Journal) -> Result<usize, String> {
        match journal.verify().map_err(|e| format!("{e:#}"))? {
            Integrity::Broken { line, reason } => return Err(format!("the journal is broken at line {line}: {reason}")),
            Integrity::Intact { .. } => {}
        }
        let events = journal.read().map_err(|e| format!("{e:#}"))?;
        match events.get(self.receipt.events.wrapping_sub(1)) {
            Some(e) if e.hash == self.receipt.head => Ok(events.len() - self.receipt.events),
            Some(_) => Err(format!("event {} isn't the one the receipt vouches for: the history was rewritten", self.receipt.events.saturating_sub(1))),
            None => Err(format!("the journal has {} events; the receipt vouches for {}", events.len(), self.receipt.events)),
        }
    }
}

pub fn receipt_path(task_dir: &Path) -> PathBuf {
    task_dir.join("receipt.json")
}

/// Posts a signed receipt to a witness. Returns the status it answered.
pub fn witness(url: &str, signed: &Signed) -> Result<u16, String> {
    let body = serde_json::to_vec(signed).map_err(|e| e.to_string())?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .build()
        .into();
    let response = agent.post(url).header("Content-Type", "application/json").send(&body[..]).map_err(|e| e.to_string())?;
    Ok(response.status().as_u16())
}

/// A witness address you can send a receipt to: https, or this machine.
pub fn valid_witness(url: &str) -> Result<(), String> {
    let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"].iter().any(|p| url.strip_prefix(p).is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/'])));
    if url.starts_with("https://") && url.len() > "https://".len() || local {
        Ok(())
    } else {
        Err(format!("{url:?}: a witness is an https:// address (http:// only for this machine)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn journal_of(dir: &Path, n: usize) -> Journal {
        let j = Journal::new(dir.join("events.jsonl"));
        for i in 0..n {
            j.append("test.event", json!({ "i": i })).unwrap();
        }
        j
    }

    #[test]
    fn a_receipt_vouches_for_the_history_it_names() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(dir.path()).unwrap();
        // The same key every time, kept private.
        assert_eq!(Identity::load_or_create(dir.path()).unwrap().public_hex(), id.public_hex());
        assert_eq!(fs::metadata(dir.path().join("identity/ed25519.pk8")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(id.key_id(), key_id(&id.public_hex()));

        let j = journal_of(dir.path(), 4);
        let signed = id.issue("abcd1234", &j).unwrap();
        assert_eq!((signed.receipt.events, signed.receipt.task.as_str()), (4, "abcd1234"));
        signed.check().unwrap();
        assert_eq!(signed.check_journal(&j), Ok(0));
        // A journal that grew afterwards still holds the vouched history.
        j.append("commit", json!({})).unwrap();
        assert_eq!(signed.check_journal(&j), Ok(1));

        // Any change to the receipt breaks the signature…
        for tamper in [
            |s: &mut Signed| s.receipt.head = "0".repeat(64),
            |s: &mut Signed| s.receipt.events += 1,
            |s: &mut Signed| s.receipt.task = "other".into(),
            |s: &mut Signed| s.receipt.at_ms += 1,
        ] {
            let mut forged = signed.clone();
            tamper(&mut forged);
            assert!(forged.check().is_err());
        }
        // …and so does signing it with another key and keeping the first one's name.
        let other_dir = tempfile::tempdir().unwrap();
        let other = Identity::load_or_create(other_dir.path()).unwrap();
        let mut swapped = other.issue("abcd1234", &j).unwrap();
        swapped.receipt.key = id.public_hex();
        assert!(swapped.check().is_err());

        // A rewritten history is caught even when its chain is whole.
        let rewritten = tempfile::tempdir().unwrap();
        let fake = Journal::new(rewritten.path().join("events.jsonl"));
        for i in 0..4 {
            fake.append("test.event", json!({ "i": i + 100 })).unwrap();
        }
        assert!(signed.check_journal(&fake).unwrap_err().contains("history was rewritten"));
        let shorter_dir = tempfile::tempdir().unwrap();
        let shorter = journal_of(shorter_dir.path(), 2);
        assert!(signed.check_journal(&shorter).unwrap_err().contains("vouches for 4"));
    }

    #[test]
    fn a_first_version_receipt_is_what_it_always_was() {
        // Receipts made before TPM keys and PCRs existed still verify: their signed bytes are fixed.
        let receipt = Receipt {
            v: 1,
            task: "abcd1234".into(),
            head: "ff".repeat(32),
            events: 4,
            agentos: "0.0.1 (abc)".into(),
            at_ms: 1_700_000_000_000,
            key: "11".repeat(32),
            alg: "ed25519".into(),
            pcrs: BTreeMap::new(),
        };
        let want = format!("agentos-receipt/1\ntask=abcd1234\nhead={}\nevents=4\nagentos=0.0.1 (abc)\nat_ms=1700000000000\nkey={}\n", "ff".repeat(32), "11".repeat(32));
        assert_eq!(String::from_utf8(receipt.message()).unwrap(), want);
        // …and in JSON, a receipt without the new fields reads as ed25519 with no PCRs, and is written the same way.
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("alg") && !json.contains("pcrs"), "{json}");
        let old: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!((old.alg.as_str(), old.pcrs.len()), ("ed25519", 0));
    }

    #[test]
    fn a_receipt_from_a_tpm_key_with_pcrs() {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        // A key of ring's stands in for the TPM's: the same algorithm, the same DER signature.
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let receipt = Receipt {
            v: 2,
            task: "abcd1234".into(),
            head: "ee".repeat(32),
            events: 9,
            agentos: "0.0.1 (abc)".into(),
            at_ms: 1_700_000_000_000,
            key: hex(pair.public_key().as_ref()),
            alg: "ecdsa-p256".into(),
            pcrs: BTreeMap::from([(0, "00".repeat(32)), (7, "ab".repeat(32))]),
        };
        let signed = Signed { signature: hex(pair.sign(&rng, &receipt.message()).unwrap().as_ref()), receipt: receipt.clone() };
        signed.check().unwrap();
        assert!(String::from_utf8(receipt.message()).unwrap().ends_with(&format!("alg=ecdsa-p256\npcrs=0:{},7:{}\n", "00".repeat(32), "ab".repeat(32))));
        // The same JSON round trip keeps what is signed.
        let again: Signed = serde_json::from_str(&serde_json::to_string(&signed).unwrap()).unwrap();
        again.check().unwrap();
        assert_eq!(again.receipt.pcrs.len(), 2);
        // The PCRs, the algorithm and the version are all signed.
        for tamper in [
            (|s: &mut Signed| s.receipt.pcrs.insert(7, "cd".repeat(32)).map(|_| ())) as fn(&mut Signed) -> Option<()>,
            |s| s.receipt.pcrs.remove(&0).map(|_| ()),
            |s| {
                s.receipt.alg = "ed25519".into();
                Some(())
            },
            |s| {
                s.receipt.v = 1;
                Some(())
            },
            |s| {
                s.receipt.events += 1;
                Some(())
            },
        ] {
            let mut forged = signed.clone();
            tamper(&mut forged);
            assert!(forged.check().is_err());
        }
        // A receipt can't choose a way of being checked this agentos doesn't know.
        let mut odd = signed.clone();
        odd.receipt.alg = "rsa".into();
        assert!(odd.check().unwrap_err().contains("not something this agentos checks"));
        let mut v3 = signed.clone();
        v3.receipt.v = 3;
        assert!(v3.check().is_err());
    }

    #[test]
    fn a_broken_journal_is_not_signed() {
        let dir = tempfile::tempdir().unwrap();
        let j = journal_of(dir.path(), 3);
        let text = fs::read_to_string(dir.path().join("events.jsonl")).unwrap().replace("\"i\":1", "\"i\":9");
        fs::write(dir.path().join("events.jsonl"), text).unwrap();
        let err = Identity::load_or_create(dir.path()).unwrap().issue("t", &j).unwrap_err();
        assert!(err.to_string().contains("not signing it"), "{err:#}");
    }

    #[test]
    fn witnesses_are_https_or_this_machine() {
        for ok in ["https://witness.example.com/receipts", "http://127.0.0.1:8080/r", "http://localhost/r", "http://[::1]:9/"] {
            assert!(valid_witness(ok).is_ok(), "{ok}");
        }
        for bad in ["http://witness.example.com/r", "https://", "http://127.0.0.1.evil.example/r", "ftp://x", "witness"] {
            assert!(valid_witness(bad).is_err(), "{bad}");
        }
    }
}
