//! A registry of agent packages: a static `index.json` anyone can host.
//!
//! ```toml
//! [registry]                                       # your config only
//! url = "https://agents.example.com/index.json"
//! ```
//!
//! ```json
//! { "packages": { "local-aider": {
//!     "version": "0.1.0",
//!     "description": "Aider, with a model on this machine",
//!     "url": "local-aider-0.1.0.tar.gz",
//!     "sha256": "…the tarball's…" } } }
//! ```
//!
//! `agent install local-aider` fetches the tarball, checks it against the
//! index's hash, unpacks it into a folder of its own and puts it through the
//! same review as a package from disk: you read what it asks for and say yes.
//! The index is as trustworthy as the host it's fetched from; the hash makes
//! sure the tarball is the one that index named.

use crate::util::hex;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_INDEX: u64 = 4 * 1024 * 1024;
const MAX_TARBALL: u64 = 32 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct Index {
    pub packages: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    pub version: String,
    #[serde(default)]
    pub description: String,
    /// Absolute, or relative to the index.
    pub url: String,
    /// The tarball's sha256, hex.
    pub sha256: String,
    /// The package's own digest (what `agent install` shows), if the index vouches for it.
    #[serde(default)]
    pub digest: Option<String>,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(std::time::Duration::from_secs(15)))
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .build()
        .into()
}

/// An address agentos fetches from: https, or this machine (for testing).
pub fn valid_url(url: &str) -> Result<(), String> {
    crate::attest::valid_witness(url).map_err(|e| e.replace("a witness is", "a registry is"))
}

fn get(url: &str, limit: u64) -> Result<Vec<u8>> {
    valid_url(url).map_err(anyhow::Error::msg)?;
    let mut response = agent().get(url).call().with_context(|| format!("fetch {url}"))?;
    if response.status().as_u16() != 200 {
        bail!("{url}: the server answered {}", response.status());
    }
    response.body_mut().with_config().limit(limit).read_to_vec().with_context(|| format!("read {url} (at most {} MB)", limit / 1024 / 1024))
}

pub fn index(url: &str) -> Result<Index> {
    let raw = get(url, MAX_INDEX)?;
    serde_json::from_slice(&raw).with_context(|| format!("{url}: not a registry index"))
}

/// `entry.url` as an address: relative ones are resolved against the index.
pub fn resolve(index_url: &str, entry: &Entry) -> String {
    if entry.url.contains("://") {
        entry.url.clone()
    } else {
        let base = index_url.rsplit_once('/').map_or(index_url, |(b, _)| b);
        format!("{base}/{}", entry.url.trim_start_matches('/'))
    }
}

/// Fetches and unpacks a package into `into` (an empty folder of ours),
/// returning the folder that holds its `agentos-package.toml`.
pub fn fetch(index_url: &str, entry: &Entry, into: &Path) -> Result<PathBuf> {
    let url = resolve(index_url, entry);
    let tarball = get(&url, MAX_TARBALL)?;
    let got = hex(&Sha256::digest(&tarball));
    if !got.eq_ignore_ascii_case(entry.sha256.trim()) {
        bail!("{url} isn't the tarball the index names (sha256 {got}, the index says {}): nothing was unpacked", entry.sha256);
    }
    let file = into.join("package.tar.gz");
    fs::write(&file, &tarball)?;
    let dir = into.join("files");
    fs::create_dir_all(&dir)?;
    // tar refuses absolute names and `..`; links and special files are refused below.
    let status = Command::new("tar")
        .args(["-xzf"])
        .arg(&file)
        .arg("-C")
        .arg(&dir)
        .args(["--no-same-owner", "--no-same-permissions"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("run tar")?;
    if !status.status.success() {
        bail!("couldn't unpack {url}: {}", String::from_utf8_lossy(&status.stderr).lines().next().unwrap_or("tar failed"));
    }
    refuse_links(&dir)?;
    let top: Vec<PathBuf> = fs::read_dir(&dir)?.flatten().map(|e| e.path()).collect();
    match top.as_slice() {
        _ if dir.join(crate::packages::MANIFEST).is_file() => Ok(dir),
        [only] if only.is_dir() && only.join(crate::packages::MANIFEST).is_file() => Ok(only.clone()),
        _ => bail!("{url} has no {} at its top (or in the one folder it holds)", crate::packages::MANIFEST),
    }
}

/// A tarball can carry hard links to files elsewhere on your machine: any
/// file that isn't only ours is refused (symlinks and special files are
/// refused by the package review).
fn refuse_links(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)?.flatten() {
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.is_dir() {
            refuse_links(&entry.path())?;
        } else if meta.is_file() && meta.nlink() > 1 {
            bail!("{} is a hard link, which a package can't contain", entry.path().strip_prefix(dir).unwrap_or(&entry.path()).display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_urls_follow_the_index() {
        let entry = |url: &str| Entry { version: "1".into(), description: String::new(), url: url.into(), sha256: String::new(), digest: None };
        assert_eq!(resolve("https://a.example/agents/index.json", &entry("x-1.tar.gz")), "https://a.example/agents/x-1.tar.gz");
        assert_eq!(resolve("https://a.example/agents/index.json", &entry("/x.tar.gz")), "https://a.example/agents/x.tar.gz");
        assert_eq!(resolve("https://a.example/index.json", &entry("https://cdn.example/x.tar.gz")), "https://cdn.example/x.tar.gz");
    }

    #[test]
    fn a_registry_is_https_or_this_machine() {
        assert!(valid_url("https://agents.example.com/index.json").is_ok() && valid_url("http://127.0.0.1:8080/index.json").is_ok());
        assert!(valid_url("http://agents.example.com/index.json").unwrap_err().contains("a registry is"));
    }

    #[test]
    fn indexes_parse() {
        let i: Index = serde_json::from_str(r#"{"packages":{"a":{"version":"1","url":"a.tgz","sha256":"00"},"b":{"version":"2","description":"B","url":"b.tgz","sha256":"11","digest":"ff"}}}"#).unwrap();
        assert_eq!(i.packages.len(), 2);
        assert_eq!(i.packages["b"].digest.as_deref(), Some("ff"));
        assert!(serde_json::from_str::<Index>(r#"{"packages":{"a":{"version":"1"}}}"#).is_err());
    }
}
