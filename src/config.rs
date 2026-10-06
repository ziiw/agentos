//! Configuration files.
//!
//! - `~/.config/agentos/config.toml` is yours and applies to every task.
//! - `.agentos.toml` in a project (the current directory or a parent, below
//!   `$HOME`) travels with the project, so it's only applied once you've
//!   reviewed it with `agent trust`, and again after every change, including
//!   a change an agent commits. Otherwise an agent could widen its own
//!   permissions for the next run.
//!
//! ```toml
//! [network]
//! allow = ["@pypi", "api.github.com"]     # presets: @pypi @npm @crates @github @go
//!
//! [files]
//! hide = [".env"]                         # in a project file: relative to the project
//! ro = ["~/.cargo"]                       # in a project file: inside the project only
//!
//! [secrets]                               # your file only: a cloned repo must never
//! GITHUB_TOKEN = "api.github.com"         # decide where your tokens go
//! OPENAI_API_KEY = "api.openai.com/authorization"
//!
//! [limits]                                # defaults for every task
//! memory = "8G"
//! cpus = 4
//! pids = 4096
//! ```

use crate::util::hex;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const PROJECT_FILE: &str = ".agentos.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    network: Network,
    #[serde(default)]
    files: Files,
    #[serde(default)]
    secrets: BTreeMap<String, String>,
    #[serde(default)]
    limits: crate::limits::Limits,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Files {
    #[serde(default)]
    hide: Vec<String>,
    #[serde(default)]
    ro: Vec<String>,
}

/// What the config files add to a task.
#[derive(Debug, Default)]
pub struct Settings {
    pub allow: Vec<String>,
    /// Existing paths only: a pattern like `.env` needn't exist everywhere.
    pub hide: Vec<PathBuf>,
    pub ro: Vec<PathBuf>,
    /// `(NAME, HOST[/HEADER])`, brokered when NAME is set in your environment.
    pub secrets: Vec<(String, String)>,
    /// Things to tell you before the task starts (e.g. an untrusted project file).
    pub notes: Vec<String>,
    /// Default resource limits (a project's override yours).
    pub limits: crate::limits::Limits,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Trust {
    Trusted,
    New,
    Changed,
}

pub fn user_config_path(home: &Path) -> PathBuf {
    if let Some(p) = std::env::var_os("AGENTOS_CONFIG") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".config"));
    base.join("agentos").join("config.toml")
}

/// The nearest `.agentos.toml` from `cwd` upwards, stopping before `$HOME` and `/`.
pub fn find_project_config(cwd: &Path, home: &Path) -> Option<PathBuf> {
    cwd.ancestors()
        .take_while(|dir| *dir != home && *dir != Path::new("/"))
        .map(|dir| dir.join(PROJECT_FILE))
        .find(|p| p.is_file())
}

pub fn load(store_root: &Path, cwd: &Path, home: &Path) -> Result<Settings> {
    let mut settings = Settings::default();
    let user = user_config_path(home);
    if user.is_file() {
        apply(&mut settings, parse(&user)?, &user, None, home)?;
    }
    if let Some(project) = find_project_config(cwd, home) {
        let shown = crate::util::display_path(&project);
        match trust_state(store_root, &project)? {
            Trust::Trusted => {
                let dir = project.parent().context("project config has no directory")?.to_path_buf();
                apply(&mut settings, parse(&project)?, &project, Some(&dir), home)?;
            }
            Trust::New => settings.notes.push(format!("ignoring {shown}: review it, then run `agent trust` to apply it")),
            Trust::Changed => settings.notes.push(format!(
                "ignoring {shown}: it changed since you trusted it; review it, then run `agent trust` again"
            )),
        }
    }
    Ok(settings)
}

fn parse(path: &Path) -> Result<ConfigFile> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("{}: invalid config", path.display()))
}

/// `project`: the project directory when applying a project file.
fn apply(s: &mut Settings, file: ConfigFile, path: &Path, project: Option<&Path>, home: &Path) -> Result<()> {
    let shown = path.display();
    crate::proxy::Allowlist::parse(&file.network.allow).with_context(|| format!("{shown}: [network] allow"))?;
    s.allow.extend(file.network.allow);

    let resolve = |entry: &str| -> Result<PathBuf> {
        let expanded = match entry.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None if entry == "~" => home.to_path_buf(),
            None => PathBuf::from(entry),
        };
        match project {
            Some(dir) => {
                let p = crate::util::absolutize(&dir.join(expanded))?;
                if !p.starts_with(dir) {
                    bail!("{shown}: {entry} is outside the project; only your own config can grant paths elsewhere");
                }
                Ok(p)
            }
            None if expanded.is_absolute() => Ok(expanded),
            None => bail!("{shown}: {entry}: use an absolute path or ~/…"),
        }
    };
    for entry in &file.files.hide {
        let p = resolve(entry)?;
        if let Ok(p) = fs::canonicalize(&p) {
            s.hide.push(p);
        }
    }
    for entry in &file.files.ro {
        let p = resolve(entry)?;
        s.ro.push(fs::canonicalize(&p).with_context(|| format!("{shown}: ro {entry}: no such file or directory"))?);
    }

    file.limits.validate().with_context(|| format!("{shown}: [limits]"))?;
    s.limits = file.limits.or(&s.limits);

    if project.is_some() && !file.secrets.is_empty() {
        bail!("{shown}: [secrets] only belongs in your own config, never in a project's");
    }
    s.secrets.extend(file.secrets);
    Ok(())
}

/// Validates a project file the way it would be applied, without applying it.
pub fn check_project(path: &Path, home: &Path) -> Result<()> {
    let dir = path.parent().context("project config has no directory")?;
    apply(&mut Settings::default(), parse(path)?, path, Some(dir), home)
}

fn trust_db(store_root: &Path) -> PathBuf {
    store_root.join("trusted.json")
}

fn digest(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(hex(&Sha256::digest(&bytes)))
}

fn trusted(store_root: &Path) -> Result<BTreeMap<String, String>> {
    match fs::read(trust_db(store_root)) {
        Ok(raw) => serde_json::from_slice(&raw).context("trusted.json is corrupt"),
        Err(_) => Ok(BTreeMap::new()),
    }
}

pub fn trust_state(store_root: &Path, config: &Path) -> Result<Trust> {
    let key = fs::canonicalize(config)?.display().to_string();
    Ok(match trusted(store_root)?.get(&key) {
        None => Trust::New,
        Some(hash) if *hash == digest(config)? => Trust::Trusted,
        Some(_) => Trust::Changed,
    })
}

/// Records the current contents of `config` as reviewed. The trust database
/// lives in the task store, which no sandbox can see.
pub fn trust(store_root: &Path, config: &Path) -> Result<String> {
    let mut db = trusted(store_root)?;
    let hash = digest(config)?;
    db.insert(fs::canonicalize(config)?.display().to_string(), hash.clone());
    let tmp = trust_db(store_root).with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(&db)?)?;
    fs::rename(&tmp, trust_db(store_root))?;
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Env {
        _dir: tempfile::TempDir,
        home: PathBuf,
        store: PathBuf,
        project: PathBuf,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let (home, store) = (root.join("home"), root.join("store"));
        let project = home.join("code/app");
        fs::create_dir_all(project.join("src")).unwrap();
        fs::create_dir_all(&store).unwrap();
        Env { _dir: dir, home, store, project }
    }

    fn settings(e: &Env) -> Result<Settings> {
        load(&e.store, &e.project.join("src"), &e.home)
    }

    #[test]
    fn project_config_needs_trust_and_retrust_after_changes() {
        let e = env();
        fs::write(e.project.join(".env"), "SECRET=1").unwrap();
        let cfg = e.project.join(PROJECT_FILE);
        fs::write(&cfg, "[network]\nallow = [\"@pypi\"]\n[files]\nhide = [\".env\", \"missing\"]\n").unwrap();

        let s = settings(&e).unwrap();
        assert!(s.allow.is_empty() && s.notes[0].contains("agent trust"), "untrusted file must be ignored");

        trust(&e.store, &cfg).unwrap();
        let s = settings(&e).unwrap();
        assert_eq!(s.allow, vec!["@pypi"]);
        assert_eq!(s.hide, vec![e.project.join(".env")], "missing paths are skipped");

        fs::write(&cfg, "[network]\nallow = [\"@pypi\", \"evil.example\"]\n").unwrap();
        let s = settings(&e).unwrap();
        assert!(s.allow.is_empty() && s.notes[0].contains("changed"));
    }

    #[test]
    fn project_config_cannot_reach_outside_or_name_secrets() {
        let e = env();
        let cfg = e.project.join(PROJECT_FILE);
        fs::create_dir_all(e.home.join(".ssh")).unwrap();
        for bad in ["[files]\nro = [\"~/.ssh\"]\n", "[files]\nro = [\"../../.ssh\"]\n", "[secrets]\nGITHUB_TOKEN = \"evil.example\"\n"] {
            fs::write(&cfg, bad).unwrap();
            trust(&e.store, &cfg).unwrap();
            assert!(settings(&e).is_err(), "should refuse: {bad}");
        }
    }

    #[test]
    fn user_config_applies_without_trust() {
        let e = env();
        let user = e.home.join(".config/agentos/config.toml");
        fs::create_dir_all(user.parent().unwrap()).unwrap();
        fs::write(&user, "[network]\nallow = [\"api.github.com\"]\n[secrets]\nGITHUB_TOKEN = \"api.github.com\"\n").unwrap();
        // SAFETY: no other test in this module reads these variables.
        unsafe {
            std::env::remove_var("AGENTOS_CONFIG");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        let s = settings(&e).unwrap();
        assert_eq!(s.allow, vec!["api.github.com"]);
        assert_eq!(s.secrets, vec![("GITHUB_TOKEN".to_string(), "api.github.com".to_string())]);
        assert!(fs::write(&user, "[network]\nallow = [\"not a host\"]\n").is_ok() && settings(&e).is_err());
    }
}
