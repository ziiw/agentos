//! On-disk task store.
//!
//! ```text
//! $AGENTOS_HOME/tasks/<id>/
//!   task.json        metadata and status
//!   events.jsonl     hash-chained journal
//!   layers/<n>/      overlay upper + work dir for the n-th writable grant
//!   rootfs/          mount point for the sandbox root
//! ```

use crate::changes::Layer;
use crate::journal::Journal;
use crate::util::{self, now_ms};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Ro,
    Rw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub path: PathBuf,
    pub access: Access,
    /// Index of the overlay layer holding this grant's writes (rw grants only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Net {
    /// Private network namespace with only loopback.
    None,
    /// Share the host network.
    Host,
    /// Private namespace whose only way out is the egress proxy, which
    /// lets through the task's allowlist (`--allow`).
    Proxy,
}

impl FromStr for Net {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "none" => Ok(Net::None),
            "host" => Ok(Net::Host),
            _ => Err(format!("unknown network mode '{s}' (expected none or host; use --allow HOST for an allowlist)")),
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Net::None => "none",
            Net::Host => "host",
            Net::Proxy => "proxy",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Running,
    /// The agent finished; its changes are waiting for review.
    Exited,
    /// The sandbox could not be set up.
    Failed,
    /// Every change was committed.
    Committed,
    /// Every change was rolled back.
    Discarded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMeta {
    pub id: String,
    /// What to call the task in listings, e.g. "claude: add a test for greet".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Agent profile, when started with `agent do`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub hidden: Vec<PathBuf>,
    pub net: Net,
    /// Hosts the egress proxy lets through (`Net::Proxy`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Names of environment variables passed in. Values are never stored.
    pub env: Vec<String>,
    pub status: Status,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub supervisor_pid: Option<u32>,
}

pub struct NewTask {
    pub title: Option<String>,
    pub agent: Option<String>,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub grants: Vec<Grant>,
    pub hidden: Vec<PathBuf>,
    pub net: Net,
    pub allow: Vec<String>,
    pub env: Vec<String>,
}

pub struct Task {
    pub meta: TaskMeta,
    pub dir: PathBuf,
}

impl Task {
    pub fn id(&self) -> &str {
        &self.meta.id
    }

    pub fn journal(&self) -> Journal {
        Journal::new(self.dir.join("events.jsonl"))
    }

    pub fn rootfs_dir(&self) -> PathBuf {
        self.dir.join("rootfs")
    }

    fn layers_dir(&self) -> PathBuf {
        self.dir.join("layers")
    }

    pub fn layer_upper(&self, n: usize) -> PathBuf {
        self.layers_dir().join(n.to_string()).join("upper")
    }

    pub fn layer_work(&self, n: usize) -> PathBuf {
        self.layers_dir().join(n.to_string()).join("work")
    }

    pub fn layers(&self) -> Vec<Layer> {
        self.meta
            .grants
            .iter()
            .filter_map(|g| g.layer.map(|n| Layer { index: n, source: g.path.clone(), upper: self.layer_upper(n) }))
            .filter(|l| l.upper.is_dir())
            .collect()
    }

    /// True while the supervising `agent run` process is still alive.
    pub fn is_live(&self) -> bool {
        self.meta.status == Status::Running
            && self.meta.supervisor_pid.is_some_and(|pid| {
                nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok()
            })
    }

    /// Status for display: a task stuck in `running` whose supervisor is gone crashed.
    pub fn status_label(&self) -> String {
        match self.meta.status {
            Status::Running if !self.is_live() => "crashed".into(),
            Status::Exited => format!("exited {}", self.meta.exit_code.unwrap_or(-1)),
            s => format!("{s:?}").to_lowercase(),
        }
    }

    /// Whether the task still holds changes that can be committed or rolled back.
    pub fn is_open(&self) -> bool {
        match self.meta.status {
            Status::Exited | Status::Failed => true,
            Status::Running => !self.is_live(),
            Status::Committed | Status::Discarded => false,
        }
    }

    pub fn save(&self) -> Result<()> {
        let tmp = self.dir.join("task.json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&self.meta)?)?;
        fs::rename(&tmp, self.dir.join("task.json"))?;
        Ok(())
    }

    /// Frees the overlay layers and sandbox mount point once nothing is pending.
    /// Metadata and the journal stay for the audit trail.
    pub fn release_storage(&self) -> Result<()> {
        util::force_remove_dir_all(&self.layers_dir())?;
        util::force_remove_dir_all(&self.rootfs_dir())?;
        Ok(())
    }
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    /// `$AGENTOS_HOME`, else `$XDG_DATA_HOME/agentos`, else `~/.local/share/agentos`.
    pub fn open() -> Result<Store> {
        let root = if let Some(p) = std::env::var_os("AGENTOS_HOME") {
            PathBuf::from(p)
        } else if let Some(p) = std::env::var_os("XDG_DATA_HOME") {
            PathBuf::from(p).join("agentos")
        } else {
            let home = std::env::var_os("HOME").context("HOME is not set")?;
            PathBuf::from(home).join(".local/share/agentos")
        };
        let tasks = root.join("tasks");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&tasks)
            .with_context(|| format!("create {}", tasks.display()))?;
        Ok(Store { root: fs::canonicalize(&root)? })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn tasks_dir(&self) -> PathBuf {
        self.root.join("tasks")
    }

    /// The persistent home of an agent profile: its login, settings and
    /// history live here instead of in your real home, and nothing outside
    /// the sandbox ever executes from it.
    pub fn agent_home(&self, agent: &str) -> Result<PathBuf> {
        let dir = self.root.join("homes").join(agent);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("create {}", dir.display()))?;
        Ok(dir)
    }

    pub fn create(&self, new: NewTask) -> Result<Task> {
        let (id, dir) = loop {
            let id = util::random_hex(4)?;
            let dir = self.tasks_dir().join(&id);
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => break (id, dir),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e).with_context(|| format!("create {}", dir.display())),
            }
        };
        let mut grants = new.grants;
        let mut next_layer = 0;
        for g in grants.iter_mut().filter(|g| g.access == Access::Rw) {
            g.layer = Some(next_layer);
            next_layer += 1;
        }
        let task = Task {
            meta: TaskMeta {
                id,
                title: new.title,
                agent: new.agent,
                command: new.command,
                cwd: new.cwd,
                grants,
                hidden: new.hidden,
                net: new.net,
                allow: new.allow,
                env: new.env,
                status: Status::Running,
                started_at_ms: now_ms(),
                ended_at_ms: None,
                exit_code: None,
                supervisor_pid: Some(std::process::id()),
            },
            dir,
        };
        for n in 0..next_layer {
            fs::create_dir_all(task.layer_upper(n))?;
            fs::create_dir_all(task.layer_work(n))?;
        }
        fs::create_dir_all(task.rootfs_dir())?;
        task.save()?;
        Ok(task)
    }

    pub fn load(&self, id: &str) -> Result<Task> {
        let dir = self.tasks_dir().join(id);
        let raw = fs::read(dir.join("task.json")).with_context(|| format!("task {id} not found"))?;
        Ok(Task { meta: serde_json::from_slice(&raw).with_context(|| format!("task {id}: bad task.json"))?, dir })
    }

    /// All tasks, oldest first.
    pub fn list(&self) -> Result<Vec<Task>> {
        let mut tasks = Vec::new();
        for entry in fs::read_dir(self.tasks_dir())? {
            let entry = entry?;
            if let Some(id) = entry.file_name().to_str() {
                if let Ok(t) = self.load(id) {
                    tasks.push(t);
                }
            }
        }
        tasks.sort_by_key(|t| t.meta.started_at_ms);
        Ok(tasks)
    }

    /// Resolves `None`/`"last"` to the most recent task, otherwise an id prefix.
    pub fn resolve(&self, selector: Option<&str>) -> Result<Task> {
        let mut tasks = self.list()?;
        match selector {
            None | Some("last") => tasks.pop().context("no tasks yet — start one with `agent run`"),
            Some(prefix) => {
                let mut hits: Vec<Task> = tasks.into_iter().filter(|t| t.id().starts_with(prefix)).collect();
                match hits.len() {
                    1 => Ok(hits.remove(0)),
                    0 => bail!("no task matching '{prefix}' (see `agent ls`)"),
                    n => bail!("'{prefix}' matches {n} tasks; use more characters"),
                }
            }
        }
    }
}
