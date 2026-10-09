//! Agent packages: an agent that ships with what it runs, and says what it
//! needs.
//!
//! A package is a directory with an `agentos-package.toml`:
//!
//! ```toml
//! [package]
//! name = "local-aider"
//! version = "0.1.0"
//! description = "Aider, with a model on this machine"
//!
//! [agent]                                # an agent file (see profiles.rs)
//! run = ["{pkg}/bin/run", "{task}"]      # {pkg} is where the package is installed
//! allow = ["pypi.org"]
//! local = [11434]
//!
//! [agent.secrets]
//! OPENAI_API_KEY = "api.openai.com"
//! ```
//!
//! `[agent]` *is* the agent file that `agent install` writes, so what you
//! review is what's enforced: there's no second list of permissions that
//! could drift from the real one. The package's files are copied to a
//! folder agents can't write (and are granted read-only to the agent), their
//! hashes are recorded, and both the files and the agent file are checked
//! against what you approved before every run.

use crate::profiles::AgentFile;
use crate::util::hex;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const MANIFEST: &str = "agentos-package.toml";
/// Written next to the files at install: what was approved.
const RECORD: &str = ".agentos-installed.json";
const MAX_FILES: usize = 2000;
const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    name: String,
    version: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    package: Meta,
    agent: toml::Table,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileInfo {
    pub sha256: String,
    pub exec: bool,
    pub size: u64,
}

/// What `agent install` shows before it installs anything.
#[derive(Debug)]
pub struct Review {
    pub name: String,
    pub version: String,
    pub description: String,
    /// sha256 over every file's path, content and executable bit: the same
    /// package has the same digest everywhere.
    pub digest: String,
    pub files: BTreeMap<String, FileInfo>,
    pub bytes: u64,
    /// What the agent gets, a line each, as the review shows it.
    pub permissions: Vec<String>,
    agent: toml::Table,
}

/// What was approved at install, kept with the files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub name: String,
    pub version: String,
    pub description: String,
    pub digest: String,
    pub files: BTreeMap<String, FileInfo>,
    pub permissions: Vec<String>,
    pub agent_file_sha256: String,
    pub installed_at_ms: u64,
}

/// Where packages are installed: outside the task store, which no sandbox
/// can see, since the agent's own files must be visible to it.
pub fn packages_root(home: &Path) -> PathBuf {
    if let Some(p) = std::env::var_os("AGENTOS_PACKAGES") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".local/share"));
    base.join("agentos-packages")
}

pub fn valid_name(name: &str) -> Result<()> {
    let ok = name.len() <= 64
        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c))
        && !name.contains("..");
    if !ok {
        bail!("{name:?} isn't a package name: lowercase letters, digits, - _ . (64 at most), starting with a letter or digit");
    }
    if name == "claude" {
        bail!("claude is built in; a package can't take its name");
    }
    Ok(())
}

pub fn sha256(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Reads and checks a package directory.
pub fn review(dir: &Path) -> Result<Review> {
    let manifest = dir.join(MANIFEST);
    let text = fs::read_to_string(&manifest).with_context(|| format!("{}: no {MANIFEST} (is this an agent package?)", dir.display()))?;
    let parsed: ManifestFile = toml::from_str(&text).with_context(|| format!("{}: invalid package", manifest.display()))?;
    let Meta { name, version, description } = parsed.package;
    valid_name(&name)?;
    if version.is_empty() || version.len() > 64 || version.contains(|c: char| c.is_whitespace() || c.is_control()) {
        bail!("{}: version {version:?} isn't a version", manifest.display());
    }
    let agent = parsed.agent;
    if agent.contains_key("package") {
        bail!("{}: [agent] package is set by `agent install`, not by the package", manifest.display());
    }
    let def: AgentFile = toml::Value::Table(agent.clone()).try_into().with_context(|| format!("{}: [agent]", manifest.display()))?;
    crate::proxy::Allowlist::parse(&def.allow).with_context(|| format!("{}: [agent] allow", manifest.display()))?;
    if def.local.contains(&0) {
        bail!("{}: [agent] local: 0 isn't a port", manifest.display());
    }
    if def.run.is_empty() || def.run[0].is_empty() {
        bail!("{}: [agent] run is empty", manifest.display());
    }

    let mut files = BTreeMap::new();
    let mut bytes = 0;
    walk(dir, dir, &mut files, &mut bytes)?;
    for program in [Some(&def.run), def.interactive.as_ref()].into_iter().flatten().filter_map(|c| c.first()) {
        if let Some(path) = program.strip_prefix("{pkg}/") {
            match files.get(path) {
                Some(f) if f.exec => {}
                Some(_) => bail!("{}: {path} is the agent's program but isn't executable (chmod +x)", dir.display()),
                None => bail!("{}: the agent runs {program}, which isn't in the package", dir.display()),
            }
        }
    }
    let digest = digest(&files);
    let permissions = permissions(&def);
    Ok(Review { name, version, description, digest, files, bytes, permissions, agent })
}

fn walk(root: &Path, dir: &Path, files: &mut BTreeMap<String, FileInfo>, bytes: &mut u64) -> Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let rel = path.strip_prefix(root)?.to_str().map(str::to_owned).with_context(|| format!("{}: not a UTF-8 name", path.display()))?;
        if rel.contains(|c: char| c.is_control()) {
            bail!("{rel:?}: control characters in a file name");
        }
        // Not part of a package: version control, and the record of an install.
        if dir == root && (rel == ".git" || rel == RECORD) {
            continue;
        }
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            bail!("{rel}: symlinks aren't allowed in a package (they could point anywhere on your machine)");
        } else if meta.is_dir() {
            walk(root, &path, files, bytes)?;
        } else if meta.is_file() {
            *bytes += meta.len();
            if files.len() >= MAX_FILES || *bytes > MAX_BYTES {
                bail!("a package is at most {MAX_FILES} files and {} MB", MAX_BYTES / 1024 / 1024);
            }
            let data = fs::read(&path).with_context(|| format!("read {rel}"))?;
            files.insert(rel, FileInfo { sha256: sha256(&data), exec: meta.permissions().mode() & 0o111 != 0, size: meta.len() });
        } else {
            bail!("{rel}: only files and folders are allowed in a package");
        }
    }
    Ok(())
}

fn digest(files: &BTreeMap<String, FileInfo>) -> String {
    let mut h = Sha256::new();
    for (path, f) in files {
        h.update(format!("{path}\0{}\0{}\n", f.sha256, if f.exec { "x" } else { "-" }));
    }
    hex(&h.finalize())
}

/// What the agent gets, in words, a line each.
fn permissions(def: &AgentFile) -> Vec<String> {
    let mut lines = vec![format!("{:<13}{}", "runs", def.run.join(" "))];
    if let Some(i) = &def.interactive {
        lines.push(format!("{:<13}{}", "interactive", i.join(" ")));
    }
    if !def.allow.is_empty() {
        lines.push(format!("{:<13}{}", "network", def.allow.join(", ")));
    }
    for (var, target) in &def.secrets {
        lines.push(format!("{:<13}{var} → {target} (a placeholder in the sandbox; your real value, when set, is added on the wire)", "secret"));
    }
    for port in &def.local {
        lines.push(format!("{:<13}127.0.0.1:{port} (a server on your machine)", "your machine"));
    }
    for path in &def.ro {
        let risk = credentials_in(path).map(|what| format!("  ← {what}")).unwrap_or_default();
        lines.push(format!("{:<13}{path} (read-only){risk}", "reads"));
    }
    for name in &def.pass_env {
        lines.push(format!("{:<13}${name} (from your environment, when set)", "passes"));
    }
    for (k, v) in &def.env {
        lines.push(format!("{:<13}{k}={v}", "sets"));
    }
    for m in &def.models {
        lines.push(format!("{:<13}{} ({:?}, counted against budgets)", "meters", m.url, m.api));
    }
    lines
}

/// Whether reading `path` would expose your home or the credentials in it.
fn credentials_in(path: &str) -> Option<String> {
    let relative = match path.strip_prefix("~/") {
        Some(rest) => rest.trim_end_matches('/'),
        None if path == "~" || path == "~/" => "",
        None => return None,
    };
    if relative.is_empty() {
        return Some("your whole home folder, credentials included".into());
    }
    crate::control::SENSITIVE
        .iter()
        .find(|s| relative == **s || relative.starts_with(&format!("{s}/")) || s.starts_with(&format!("{relative}/")))
        .map(|s| format!("~/{s} holds credentials"))
}

/// The agent file for an installed package: `[agent]` with `{pkg}` filled in.
fn render_agent(review: &Review, target: &Path) -> Result<String> {
    fn fill(v: &mut toml::Value, pkg: &str) {
        match v {
            toml::Value::String(s) => *s = s.replace("{pkg}", pkg),
            toml::Value::Array(a) => a.iter_mut().for_each(|x| fill(x, pkg)),
            toml::Value::Table(t) => t.iter_mut().for_each(|(_, x)| fill(x, pkg)),
            _ => {}
        }
    }
    let mut table = review.agent.clone();
    table.insert("package".into(), toml::Value::String(review.name.clone()));
    let mut value = toml::Value::Table(table);
    fill(&mut value, &target.display().to_string());
    Ok(format!(
        "# Installed by `agent install` from package {} {}. Changing this file makes agentos refuse to run\n# the agent until the package is installed again: what you approved is what runs.\n{}",
        review.name,
        review.version,
        toml::to_string(&value).context("write the agent file")?
    ))
}

fn read_record(dir: &Path) -> Option<Record> {
    serde_json::from_slice(&fs::read(dir.join(RECORD)).ok()?).ok()
}

/// What is installed under this name, if anything.
pub fn installed(home: &Path, name: &str) -> Option<Record> {
    read_record(&packages_root(home).join(name))
}

/// Copies the reviewed package to its place, checks the copy against the
/// review, writes the agent file and the record. Replaces an installed
/// version of the same name.
pub fn install(review: &Review, source: &Path, home: &Path, agents_dir: &Path) -> Result<PathBuf> {
    let root = packages_root(home);
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    let target = root.join(&review.name);
    let agent_file = agents_dir.join(format!("{}.toml", review.name));
    if let Ok(text) = fs::read_to_string(&agent_file) {
        let ours = toml::from_str::<AgentFile>(&text).ok().and_then(|d| d.package);
        if ours.as_deref() != Some(review.name.as_str()) {
            bail!("{} is an agent file of yours with that name; rename or remove it first", agent_file.display());
        }
    }

    let staging = root.join(format!(".{}.installing", review.name));
    if staging.exists() {
        crate::util::force_remove_dir_all(&staging)?;
    }
    for (rel, info) in &review.files {
        let (from, to) = (source.join(rel), staging.join(rel));
        fs::create_dir_all(to.parent().unwrap_or(&staging))?;
        let data = fs::read(&from).with_context(|| format!("read {}", from.display()))?;
        // The package could change between the review and now.
        if sha256(&data) != info.sha256 {
            crate::util::force_remove_dir_all(&staging)?;
            bail!("{rel} changed while it was being installed; nothing was installed");
        }
        fs::write(&to, &data)?;
        fs::set_permissions(&to, fs::Permissions::from_mode(if info.exec { 0o755 } else { 0o644 }))?;
    }
    let text = render_agent(review, &target)?;
    let record = Record {
        name: review.name.clone(),
        version: review.version.clone(),
        description: review.description.clone(),
        digest: review.digest.clone(),
        files: review.files.clone(),
        permissions: review.permissions.clone(),
        agent_file_sha256: sha256(text.as_bytes()),
        installed_at_ms: crate::util::now_ms(),
    };
    fs::write(staging.join(RECORD), serde_json::to_vec_pretty(&record)?)?;
    if target.exists() {
        crate::util::force_remove_dir_all(&target)?;
    }
    fs::rename(&staging, &target)?;
    fs::create_dir_all(agents_dir)?;
    let tmp = agent_file.with_extension("toml.tmp");
    fs::write(&tmp, &text)?;
    fs::rename(&tmp, &agent_file)?;
    Ok(target)
}

/// What differs from what was approved, one problem a line (none: it's intact).
pub fn problems(dir: &Path, record: &Record) -> Vec<String> {
    let mut current = BTreeMap::new();
    let mut bytes = 0;
    if let Err(e) = walk(dir, dir, &mut current, &mut bytes) {
        return vec![format!("{e:#}")];
    }
    let mut out = Vec::new();
    for (path, info) in &record.files {
        match current.get(path) {
            None => out.push(format!("{path} is gone")),
            Some(now) if now != info => out.push(format!("{path} changed")),
            Some(_) => {}
        }
    }
    out.extend(current.keys().filter(|p| !record.files.contains_key(*p)).map(|p| format!("{p} was added")));
    out
}

/// Before a run: the package's files and its agent file are what you approved.
pub fn verify(name: &str, agent_file: &Path, home: &Path) -> Result<()> {
    let dir = packages_root(home).join(name);
    let record = read_record(&dir).with_context(|| {
        format!("agent '{name}' comes from a package that isn't installed here any more ({}): `agent install` it again", dir.display())
    })?;
    let reinstall = format!("`agent packages` shows what, then `agent install` the package again, or `agent uninstall {name}`");
    let current = fs::read(agent_file).with_context(|| format!("read {}", agent_file.display()))?;
    if sha256(&current) != record.agent_file_sha256 {
        bail!("{} changed since you installed package {name}: {reinstall}", agent_file.display());
    }
    let problems = problems(&dir, &record);
    if !problems.is_empty() {
        bail!("package {name} changed since you installed it ({}): {reinstall}", problems.join("; "));
    }
    Ok(())
}

/// Every installed package.
pub fn list(home: &Path) -> Vec<(Record, PathBuf)> {
    let root = packages_root(home);
    let mut out: Vec<(Record, PathBuf)> = fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| read_record(&e.path()).map(|r| (r, e.path())))
        .collect();
    out.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    out
}

/// Removes a package and the agent file it wrote.
pub fn uninstall(name: &str, home: &Path, agents_dir: &Path) -> Result<()> {
    valid_name(name)?;
    let dir = packages_root(home).join(name);
    let agent_file = agents_dir.join(format!("{name}.toml"));
    let ours = fs::read_to_string(&agent_file)
        .ok()
        .and_then(|t| toml::from_str::<AgentFile>(&t).ok())
        .is_some_and(|d| d.package.as_deref() == Some(name));
    if !dir.exists() && !ours {
        return Err(anyhow!("no package named {name} is installed (see `agent packages`)"));
    }
    if dir.exists() {
        crate::util::force_remove_dir_all(&dir)?;
    }
    if ours {
        fs::remove_file(&agent_file)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(dir: &Path, extra: &str) {
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::write(dir.join("bin/run"), "#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(dir.join("bin/run"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(dir.join("README"), "a stand-in\n").unwrap();
        fs::write(
            dir.join(MANIFEST),
            format!(
                "[package]\nname = \"stand-in\"\nversion = \"0.1.0\"\ndescription = \"test\"\n\n[agent]\nrun = [\"{{pkg}}/bin/run\", \"{{task}}\"]\nallow = [\"pypi.org\"]\nlocal = [11434]\n{extra}\n[agent.secrets]\nOPENAI_API_KEY = \"api.openai.com\"\n"
            ),
        )
        .unwrap();
    }

    struct Env {
        _dir: tempfile::TempDir,
        src: PathBuf,
        home: PathBuf,
        agents: PathBuf,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let (src, home) = (root.join("src"), root.join("home"));
        fs::create_dir_all(&home).unwrap();
        package(&src, "");
        let agents = root.join("agents");
        Env { _dir: dir, src, home, agents }
    }

    // The tests share the process environment: each uses its own AGENTOS_PACKAGES via `home`
    // (the default root is under home), so none of them sets it.

    #[test]
    fn a_package_that_reads_credentials_says_so() {
        assert_eq!(credentials_in("~/.ssh").as_deref(), Some("~/.ssh holds credentials"));
        assert_eq!(credentials_in("~/.ssh/id_ed25519").as_deref(), Some("~/.ssh holds credentials"));
        assert_eq!(credentials_in("~/.config").as_deref(), Some("~/.config/gh holds credentials"), "a folder that contains one");
        assert!(credentials_in("~").unwrap().contains("whole home"));
        assert!(credentials_in("~/.gitconfig").is_none() && credentials_in("~/code/app").is_none() && credentials_in("/etc/hosts").is_none());
    }

    #[test]
    fn names() {
        for ok in ["aider", "local-aider", "a1_b.c"] {
            assert!(valid_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Aider", "-x", "a b", "a/b", "..", "a..b", "claude", &"x".repeat(65)] {
            assert!(valid_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_review_says_what_the_agent_gets() {
        let e = env();
        let r = review(&e.src).unwrap();
        assert_eq!((r.name.as_str(), r.version.as_str(), r.files.len()), ("stand-in", "0.1.0", 3));
        let text = r.permissions.join("\n");
        for expected in ["runs         {pkg}/bin/run {task}", "network      pypi.org", "OPENAI_API_KEY → api.openai.com", "127.0.0.1:11434"] {
            assert!(text.contains(expected), "{expected} in\n{text}");
        }
        // The same files, the same digest; any change to one, another.
        assert_eq!(r.digest, review(&e.src).unwrap().digest);
        fs::write(e.src.join("README"), "changed\n").unwrap();
        assert_ne!(r.digest, review(&e.src).unwrap().digest);
        fs::set_permissions(e.src.join("bin/run"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(review(&e.src).unwrap_err().to_string().contains("isn't executable"));
    }

    #[test]
    fn bad_packages_are_refused() {
        let e = env();
        let manifest = fs::read_to_string(e.src.join(MANIFEST)).unwrap();
        let broken = |text: &str| {
            fs::write(e.src.join(MANIFEST), text).unwrap();
            review(&e.src).err().map(|e| format!("{e:#}")).unwrap_or_default()
        };
        assert!(broken(&manifest.replace("stand-in", "Stand In")).contains("isn't a package name"));
        assert!(broken(&manifest.replace("[agent]", "[agent]\npackage = \"x\"")).contains("set by `agent install`"));
        assert!(broken(&manifest.replace("{pkg}/bin/run", "{pkg}/bin/missing")).contains("isn't in the package"));
        assert!(broken(&manifest.replace("pypi.org", "not a host")).contains("allow"));
        assert!(broken(&manifest.replace("local = [11434]", "local = [0]")).contains("isn't a port"));
        assert!(broken(&manifest.replace("allow =", "alow =")).contains("alow"));
        fs::write(e.src.join(MANIFEST), &manifest).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", e.src.join("link")).unwrap();
        assert!(review(&e.src).unwrap_err().to_string().contains("symlinks aren't allowed"));
        fs::remove_file(e.src.join("link")).unwrap();
        fs::remove_file(e.src.join(MANIFEST)).unwrap();
        assert!(review(&e.src).unwrap_err().to_string().contains("is this an agent package"));
    }

    #[test]
    fn installing_pins_what_you_approved() {
        let e = env();
        let target = {
            let r = review(&e.src).unwrap();
            install(&r, &e.src, &e.home, &e.agents).unwrap()
        };
        assert!(target.join("bin/run").is_file());
        // The agent file is the manifest's [agent], with {pkg} filled in and the package marked.
        let agent_file = e.agents.join("stand-in.toml");
        let text = fs::read_to_string(&agent_file).unwrap();
        assert!(text.contains(&format!("{}/bin/run", target.display())) && text.contains("package = \"stand-in\""), "{text}");
        let def: AgentFile = toml::from_str(&text).unwrap();
        assert_eq!((def.local, def.allow, def.secrets.len()), (vec![11434], vec!["pypi.org".to_string()], 1));
        verify("stand-in", &agent_file, &e.home).unwrap();
        assert_eq!(list(&e.home).len(), 1);

        // A changed file, an added one, a widened agent file: each is caught.
        fs::write(target.join("README"), "edited\n").unwrap();
        assert!(verify("stand-in", &agent_file, &e.home).unwrap_err().to_string().contains("README changed"));
        fs::write(target.join("README"), "a stand-in\n").unwrap();
        verify("stand-in", &agent_file, &e.home).unwrap();
        fs::write(target.join("extra"), "x").unwrap();
        assert!(verify("stand-in", &agent_file, &e.home).unwrap_err().to_string().contains("extra was added"));
        fs::remove_file(target.join("extra")).unwrap();
        fs::write(&agent_file, text.replace("pypi.org", "evil.example")).unwrap();
        assert!(verify("stand-in", &agent_file, &e.home).unwrap_err().to_string().contains("changed since you installed package stand-in"));
        fs::write(&agent_file, &text).unwrap();

        // Installing again replaces it; an agent file of someone else's with that name is left alone.
        let r = review(&e.src).unwrap();
        install(&r, &e.src, &e.home, &e.agents).unwrap();
        verify("stand-in", &agent_file, &e.home).unwrap();
        fs::write(&agent_file, "run = [\"mine\"]\n").unwrap();
        assert!(install(&r, &e.src, &e.home, &e.agents).unwrap_err().to_string().contains("an agent file of yours"));
        fs::write(&agent_file, &text).unwrap();

        uninstall("stand-in", &e.home, &e.agents).unwrap();
        assert!(!target.exists() && !agent_file.exists() && list(&e.home).is_empty());
        assert!(uninstall("stand-in", &e.home, &e.agents).is_err());
    }
}
