use agentos::approvals::{self, Asker, Kind, Request};
use agentos::attest;
use agentos::broker::{self, Broker, Secret};
use agentos::changes::{self, Summary};
use agentos::config;
use agentos::display;
use agentos::control::{self, Call, PathRules, PathVerdict, Reply};
use agentos::doctor::{self, Level};
use agentos::gateway::{self, Budget, Endpoint, Ledger, Meter, Periodic, Price, Spend};
use agentos::journal::{Integrity, Journal};
use agentos::keychain;
use agentos::limits::{self, Limits};
use agentos::outbox;
use agentos::policy::{self, Question, Verdict};
use agentos::profiles::{self, AgentEvent, Output};
use agentos::proxy::{self, Allowlist, NetEvent};
use agentos::sandbox::{self, GrantMount, Mount, RunMount};
use agentos::taint;
use agentos::store::{Access, Grant, Net, NewTask, Status, Store, Task};
use agentos::util::{self, display_path};
use agentos::vault::Vault;
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use nix::fcntl::OFlag;
use render::Paint;
use serde_json::json;
use std::fs;
use std::io::{BufRead, BufReader, IsTerminal};
use std::os::fd::{AsRawFd, OwnedFd};
use std::thread;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

mod admin;
mod agent_control;
mod cli;
mod owner;
mod plan;
mod render;
mod review;
mod task;
mod web;

use admin::*;
use agent_control::*;
use cli::*;
use owner::*;
use plan::*;
use review::*;
use task::*;

/// Set when a task is started for you (by agentd's console), for the journal.
const STARTED_BY: &str = "AGENTOS_STARTED_BY";

/// Environment variables an agent inherits by default. Anything else (API
/// keys, tokens) must be passed explicitly with --env.
const PASS_ENV: &[&str] = &[
    "PATH", "TERM", "COLORTERM", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ", "NO_COLOR", "USER",
    "LOGNAME", "SHELL", "EDITOR", "VISUAL",
];

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("{} {e:#}", Paint::stderr().red("agent:"));
            ExitCode::from(2)
        }
    }
}

fn dispatch(cli: Cli) -> Result<i32> {
    // Inside a sandbox: no task store there, just the control socket.
    if let Command::Mcp { server } = &cli.command {
        let socket = Path::new(control::SOCKET);
        match server {
            None => agentos::mcp::serve_stdio(socket)?,
            Some(name) => agentos::mcp::relay_stdio(socket, name)?,
        }
        return Ok(0);
    }
    let store = Store::open()?;
    match cli.command {
        Command::Do(args) => cmd_do(&store, args),
        Command::Run(args) => cmd_run(&store, args),
        Command::Ls => cmd_ls(&store),
        Command::Diff { task, paths, stat, all } => cmd_diff(&store, task.as_deref(), &paths, stat, all),
        Command::Commit { task, paths, force, all, no_push } => cmd_commit(&store, task.as_deref(), &paths, force, all, no_push),
        Command::Push { task, force } => cmd_push(&store, task.as_deref(), force),
        Command::Rollback { task, paths } => cmd_rollback(&store, task.as_deref(), &paths),
        Command::Log { task, json } => cmd_log(&store, task.as_deref(), json),
        Command::Logs { task, follow } => cmd_logs(&store, task.as_deref(), follow),
        Command::Wait { task } => cmd_wait(&store, task.as_deref()),
        Command::Stop { task } => cmd_stop(&store, task.as_deref()),
        Command::Doctor => cmd_doctor(&store),
        Command::Trust { path } => cmd_trust(&store, path),
        Command::Agents => cmd_agents(&store),
        Command::Schedules => cmd_schedules(&store),
        Command::Hooks => cmd_hooks(&store),
        Command::Screen { task, output } => cmd_screen(&store, task.as_deref(), output),
        Command::Attest { task, verify, journal, trust, public } => cmd_attest(&store, task.as_deref(), verify, journal, trust, public),
        Command::Install { dir, yes, digest } => cmd_install(&store, dir, yes, digest),
        Command::Search { text } => cmd_search(&store, text.as_deref()),
        Command::Registry { command } => cmd_registry(command),
        Command::Uninstall { name } => cmd_uninstall(&name),
        Command::Packages => cmd_packages(),
        Command::Approvals { revoke } => cmd_approvals(&store, revoke),
        Command::Users { command } => cmd_users(&store, command),
        Command::Serve { listen, notify } => web::serve(&store, &listen, notify),
        Command::Vault { action, agent } => cmd_vault(&store, &action, &agent),
        Command::Policy { command } => cmd_policy(command),
        Command::Spend => cmd_spend(&store),
        Command::Raise { amount, task, today, this_week, this_month, project } => {
            let period = [(today, gateway::Period::Day), (this_week, gateway::Period::Week), (this_month, gateway::Period::Month)]
                .into_iter()
                .find_map(|(on, p)| on.then_some(p));
            cmd_raise(&store, amount, task, period, project)
        }
        Command::Revoke { target, task } => cmd_revoke(&store, target, task),
        Command::Connect { name, forget } => cmd_connect(&store, name, forget),
        Command::Mcp { .. } => unreachable!(),
    }
}

fn home_dir() -> Result<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    Ok(fs::canonicalize(&home).unwrap_or(home))
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}
