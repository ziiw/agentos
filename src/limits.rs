//! Resource limits: memory, CPU and process count for a task, enforced by
//! the kernel (cgroup v2).
//!
//! Unprivileged users get cgroups through their systemd instance, so a task
//! with limits re-runs itself inside a transient scope
//! (`systemd-run --user --scope`) that carries them. That needs a systemd
//! user session: a normal login has one, a container usually doesn't.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::{Command, Stdio};

/// Set inside the scope, so the re-run doesn't re-run again.
pub const IN_SCOPE: &str = "AGENTOS_IN_SCOPE";

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    /// `512M`, `4G`, … (no swap on top).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// CPUs' worth of time, e.g. 1.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<f32>,
    /// Processes and threads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids: Option<u32>,
}

impl Limits {
    pub fn is_empty(&self) -> bool {
        self.memory.is_none() && self.cpus.is_none() && self.pids.is_none()
    }

    /// Fills unset fields from `other` (flags over project over your config).
    pub fn or(self, other: &Limits) -> Limits {
        Limits {
            memory: self.memory.or_else(|| other.memory.clone()),
            cpus: self.cpus.or(other.cpus),
            pids: self.pids.or(other.pids),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(m) = &self.memory {
            let digits = m.trim_end_matches(['K', 'M', 'G', 'T', 'k', 'm', 'g', 't']);
            if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) || digits.len() + 1 < m.len() {
                bail!("--memory {m}: expected a size like 512M or 4G");
            }
        }
        if self.cpus.is_some_and(|c| !(c > 0.0)) {
            bail!("--cpus must be more than 0");
        }
        if self.pids == Some(0) {
            bail!("--pids must be more than 0");
        }
        Ok(())
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(m) = &self.memory {
            parts.push(format!("memory {m}"));
        }
        if let Some(c) = self.cpus {
            parts.push(format!("cpus {c}"));
        }
        if let Some(p) = self.pids {
            parts.push(format!("pids {p}"));
        }
        parts.join(" · ")
    }

    fn properties(&self) -> Vec<String> {
        let mut props = Vec::new();
        if let Some(m) = &self.memory {
            props.push(format!("MemoryMax={}", m.to_ascii_uppercase()));
            props.push("MemorySwapMax=0".into());
        }
        if let Some(c) = self.cpus {
            props.push(format!("CPUQuota={}%", (c * 100.0).round() as u32));
        }
        if let Some(p) = self.pids {
            props.push(format!("TasksMax={p}"));
        }
        props
    }
}

/// Whether this user can get a systemd scope (and so cgroup limits).
pub fn available() -> bool {
    Command::new("systemd-run")
        .args(["--user", "--scope", "--quiet", "--collect", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Replaces this process with the same command line, run inside a scope
/// that carries `limits`. Only returns on failure.
pub fn reexec_in_scope(limits: &Limits) -> Result<std::convert::Infallible> {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new("systemd-run");
    cmd.args(["--user", "--scope", "--quiet", "--collect"]);
    for p in limits.properties() {
        cmd.arg(format!("--property={p}"));
    }
    cmd.arg("--").arg(std::env::current_exe()?).args(std::env::args_os().skip(1));
    cmd.env(IN_SCOPE, serde_json::to_string(limits)?);
    let err = cmd.exec();
    bail!("systemd-run: {err}")
}

/// The limits this process runs under, when it's the re-run inside a scope.
pub fn current() -> Option<Limits> {
    serde_json::from_str(&std::env::var(IN_SCOPE).ok()?).ok()
}

/// This process's cgroup directory.
fn cgroup_dir() -> Option<std::path::PathBuf> {
    let line = fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = line.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(std::path::Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}

/// The scope's name, for the journal.
pub fn scope_name() -> Option<String> {
    Some(cgroup_dir()?.file_name()?.to_string_lossy().into_owned())
}

/// How many times the kernel killed something here for exceeding memory.
pub fn oom_kills() -> u64 {
    let Some(dir) = cgroup_dir() else { return 0 };
    fs::read_to_string(dir.join("memory.events"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("oom_kill ").and_then(|n| n.trim().parse().ok()))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_and_properties() {
        let l = Limits { memory: Some("512m".into()), cpus: Some(1.5), pids: Some(256) };
        l.validate().unwrap();
        assert_eq!(l.properties(), vec!["MemoryMax=512M", "MemorySwapMax=0", "CPUQuota=150%", "TasksMax=256"]);
        assert_eq!(l.describe(), "memory 512m · cpus 1.5 · pids 256");
        for bad in ["lots", "4GB", "G", "-1G"] {
            assert!(Limits { memory: Some(bad.into()), ..Default::default() }.validate().is_err(), "{bad}");
        }
        assert!(Limits { cpus: Some(0.0), ..Default::default() }.validate().is_err());
        let merged = Limits { memory: Some("1G".into()), ..Default::default() }.or(&Limits { memory: Some("8G".into()), pids: Some(64), cpus: None });
        assert_eq!((merged.memory.as_deref(), merged.pids), (Some("1G"), Some(64)));
    }
}
