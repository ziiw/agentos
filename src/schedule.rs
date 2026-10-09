//! Agents that live for days: tasks that start themselves.
//!
//! agentd is the long-lived part. A `[schedule.NAME]` in your config says what
//! to run, where, and how often; agentd starts it as it would from the
//! console, each run its own task with its own sandbox, journal and review, and
//! remembers when it last did. Restart agentd, or the machine, and the
//! schedules carry on from where they were: a run that came due meanwhile
//! happens once, as soon as agentd is back.
//!
//! ```toml
//! [schedule.triage]                       # your config only
//! every = "24h"
//! project = "~/code/app"                  # one of the folders agentd may start tasks in
//! task = "Look at the open issues and write a summary in TRIAGE.md"
//! budget = "2usd"                         # a task nobody is watching deserves a budget
//! timeout = "30m"
//! ```

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Not more often than this (a run that started every few seconds is a loop, not a schedule).
const MIN_EVERY: Duration = Duration::from_secs(60);

/// What a schedule may not be quicker than; `AGENTOS_MIN_SCHEDULE` (a duration) lowers it for tests.
pub fn min_every() -> Duration {
    std::env::var("AGENTOS_MIN_SCHEDULE").ok().and_then(|v| humantime::parse_duration(&v).ok()).unwrap_or(MIN_EVERY)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    #[serde(skip)]
    pub name: String,
    /// A duration: `30m`, `6h`, `1d`.
    pub every: String,
    /// One of the folders agentd may start tasks in.
    pub project: String,
    pub task: String,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub budget: Option<String>,
    #[serde(default)]
    pub timeout: Option<String>,
}

impl Schedule {
    pub fn interval(&self) -> Result<Duration> {
        let every = humantime::parse_duration(self.every.trim()).with_context(|| format!("every = {:?}: expected a duration like 30m, 6h or 1d", self.every))?;
        if every < min_every() {
            bail!("every = {:?}: not more often than every {}", self.every, humantime::format_duration(min_every()));
        }
        Ok(every)
    }

    /// What can be checked without starting anything.
    pub fn validate(&self) -> Result<()> {
        let ok = !self.name.is_empty() && self.name.len() <= 40 && self.name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        if !ok {
            bail!("{:?} isn't a schedule name: lowercase letters, digits, - and _", self.name);
        }
        self.interval()?;
        if self.task.trim().is_empty() || self.task.len() > 20_000 {
            bail!("task: describe it (up to 20,000 characters)");
        }
        if self.project.trim().is_empty() {
            bail!("project: a folder");
        }
        if let Some(b) = &self.budget {
            b.parse::<crate::gateway::Budget>().map_err(|e| anyhow::anyhow!("budget {e}"))?;
        }
        if let Some(t) = &self.timeout {
            humantime::parse_duration(t).with_context(|| format!("timeout = {t:?}: expected e.g. 30m or 2h"))?;
        }
        Ok(())
    }
}

/// A hook: an address that starts a task when something is sent to it (a CI
/// failure, an alert, a chat message), the event's own words in the task.
///
/// ```toml
/// [hook.ci-failed]                        # your config only
/// project = "~/code/app"
/// task = "CI failed. Find out why and fix it. The event: {event}"
/// token = "CI_HOOK_TOKEN"                 # a variable (or a [secret_commands] entry) with the hook's secret
/// budget = "2usd"
/// ```
///
/// `POST /api/hooks/ci-failed` with the token (`Authorization: Bearer …`,
/// `X-Agentos-Token` or `X-Gitlab-Token`) starts it. The token opens this hook and
/// nothing else of agentd. What came in is untrusted: the task starts tainted.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hook {
    #[serde(skip)]
    pub name: String,
    pub project: String,
    /// Where `{event}` goes; without it the event is added after the task.
    pub task: String,
    /// The variable holding the hook's token, in agentd's environment or a `[secret_commands]` entry.
    pub token: String,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub budget: Option<String>,
    #[serde(default)]
    pub timeout: Option<String>,
    /// Events closer together than this are refused (default 1m).
    #[serde(default)]
    pub min_interval: Option<String>,
}

impl Hook {
    pub fn min_interval(&self) -> Result<Duration> {
        match &self.min_interval {
            None => Ok(Duration::from_secs(60)),
            Some(v) => humantime::parse_duration(v.trim()).with_context(|| format!("min_interval = {v:?}: expected a duration like 30s or 5m")),
        }
    }

    pub fn validate(&self) -> Result<()> {
        // Same rules as a schedule for the name, task, folder, budget and timeout.
        Schedule {
            name: self.name.clone(),
            every: "1h".into(),
            project: self.project.clone(),
            task: self.task.clone(),
            agent: self.agent.clone(),
            budget: self.budget.clone(),
            timeout: self.timeout.clone(),
        }
        .validate()?;
        crate::keychain::validate(&self.token, &["x".to_string()]).map_err(|e| anyhow::anyhow!("token: {e}"))?;
        self.min_interval()?;
        Ok(())
    }

    /// The task for an event: its words, cleaned and cut to a size an agent can be handed.
    pub fn task_for(&self, event: &str) -> String {
        let clean: String = event.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\t')).take(8000).collect();
        if self.task.contains("{event}") { self.task.replace("{event}", clean.trim()) } else { format!("{}\n\nEvent received:\n{}", self.task, clean.trim()) }
    }
}

/// What agentd remembers of a hook.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HookState {
    pub last_fire_ms: u64,
    pub last_task: Option<String>,
    pub fired: u64,
    pub refused: u64,
}

fn hooks_path(root: &Path) -> PathBuf {
    root.join("hooks.json")
}

pub fn load_hooks(root: &Path) -> BTreeMap<String, HookState> {
    fs::read(hooks_path(root)).ok().and_then(|raw| serde_json::from_slice(&raw).ok()).unwrap_or_default()
}

pub fn save_hooks(root: &Path, states: &BTreeMap<String, HookState>) -> Result<()> {
    let tmp = hooks_path(root).with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(states)?)?;
    fs::rename(&tmp, hooks_path(root)).context("save hooks.json")
}

/// What agentd remembers of a schedule, across restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    /// When agentd first saw it: the first run comes one interval later.
    pub first_seen_ms: u64,
    pub last_start_ms: u64,
    pub last_task: Option<String>,
    pub runs: u64,
    /// Times a run came due while the last one was still going.
    pub skipped: u64,
    pub last_error: Option<String>,
}

impl State {
    pub fn new(now_ms: u64) -> State {
        State { first_seen_ms: now_ms, ..State::default() }
    }

    /// When the next run is due.
    pub fn next_ms(&self, every: Duration) -> u64 {
        self.last_start_ms.max(self.first_seen_ms) + every.as_millis() as u64
    }

    pub fn due(&self, now_ms: u64, every: Duration) -> bool {
        now_ms >= self.next_ms(every)
    }
}

fn path(root: &Path) -> PathBuf {
    root.join("schedules.json")
}

pub fn load(root: &Path) -> BTreeMap<String, State> {
    fs::read(path(root)).ok().and_then(|raw| serde_json::from_slice(&raw).ok()).unwrap_or_default()
}

pub fn save(root: &Path, states: &BTreeMap<String, State>) -> Result<()> {
    let tmp = path(root).with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(states)?)?;
    fs::rename(&tmp, path(root)).context("save schedules.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(every: &str) -> Schedule {
        Schedule { name: "triage".into(), every: every.into(), project: "~/code/app".into(), task: "summarize".into(), agent: None, budget: Some("2usd".into()), timeout: Some("30m".into()) }
    }

    #[test]
    fn a_hook_hands_the_event_to_the_task_cleaned_and_cut() {
        let hook = Hook {
            name: "ci".into(),
            project: "~/code/app".into(),
            task: "CI failed: {event}. Fix it.".into(),
            token: "CI_HOOK_TOKEN".into(),
            agent: None,
            budget: None,
            timeout: None,
            min_interval: None,
        };
        hook.validate().unwrap();
        assert_eq!(hook.min_interval().unwrap(), Duration::from_secs(60));
        assert_eq!(hook.task_for("  {\"build\": \"red\"}\n"), "CI failed: {\"build\": \"red\"}. Fix it.");
        assert_eq!(hook.task_for("a\u{1b}[2Jb\0c"), "CI failed: a[2Jbc. Fix it.", "no terminal escapes or NULs reach the agent's prompt");
        assert_eq!(hook.task_for(&"x".repeat(50_000)).len(), "CI failed: . Fix it.".len() + 8000);
        let appended = Hook { task: "Look at CI.".into(), ..hook.clone() };
        assert_eq!(appended.task_for("red"), "Look at CI.\n\nEvent received:\nred");
        for bad in [Hook { token: "not a var".into(), ..hook.clone() }, Hook { min_interval: Some("soon".into()), ..hook.clone() }, Hook { name: "Bad Name".into(), ..hook.clone() }, Hook { task: " ".into(), ..hook }] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn intervals_and_their_floor() {
        assert_eq!(schedule("6h").interval().unwrap(), Duration::from_secs(6 * 3600));
        assert!(schedule("6h").validate().is_ok());
        for bad in ["often", "10s", "0s", ""] {
            assert!(schedule(bad).interval().is_err(), "{bad}");
        }
    }

    #[test]
    fn what_cannot_be_started_is_refused_up_front() {
        let mut s = schedule("1h");
        for (mutate, says) in [
            (Box::new(|s: &mut Schedule| s.name = "Bad Name".into()) as Box<dyn Fn(&mut Schedule)>, "isn't a schedule name"),
            (Box::new(|s: &mut Schedule| s.task = "  ".into()), "describe it"),
            (Box::new(|s: &mut Schedule| s.budget = Some("lots".into())), "budget"),
            (Box::new(|s: &mut Schedule| s.timeout = Some("soon".into())), "timeout"),
            (Box::new(|s: &mut Schedule| s.project = String::new()), "project"),
        ] {
            let before = s.clone();
            mutate(&mut s);
            assert!(s.validate().unwrap_err().to_string().contains(says), "{says}");
            s = before;
        }
    }

    #[test]
    fn a_schedule_runs_an_interval_after_it_was_first_seen_and_after_each_start() {
        let every = Duration::from_secs(3600);
        let mut state = State::new(1_000_000);
        assert!(!state.due(1_000_000, every), "not the moment it appears");
        assert!(!state.due(1_000_000 + 3_599_999, every));
        assert!(state.due(1_000_000 + 3_600_000, every));
        // Agentd was off for a day: one run is due, once it's back.
        assert!(state.due(1_000_000 + 86_400_000, every));
        state.last_start_ms = 1_000_000 + 86_400_000;
        assert!(!state.due(1_000_000 + 86_400_000 + 1000, every), "and then the interval starts over");
        assert_eq!(state.next_ms(every), 1_000_000 + 86_400_000 + 3_600_000);
    }

    #[test]
    fn what_agentd_remembers_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).is_empty());
        let mut states = BTreeMap::new();
        states.insert("triage".to_string(), State { first_seen_ms: 5, last_start_ms: 9, last_task: Some("abcd1234".into()), runs: 3, skipped: 1, last_error: None });
        save(dir.path(), &states).unwrap();
        assert_eq!(load(dir.path()), states);
        fs::write(path(dir.path()), "not json").unwrap();
        assert!(load(dir.path()).is_empty(), "a damaged file starts over rather than stopping agentd");
    }
}
