//! agentos: a transactional, capability-scoped runtime for AI agents.
//!
//! Every agent task runs as a transaction: it sees only the paths it was
//! granted, its writes land in an overlay instead of your real files, and
//! everything it did is recorded in a hash-chained journal. When the task
//! ends you review the diff and commit or roll back — all of it or per path.

pub mod approvals;
pub mod broker;
pub mod changes;
pub mod config;
pub mod control;
pub mod doctor;
pub mod gateway;
pub mod held;
pub mod journal;
pub mod limits;
pub mod mcp;
pub mod oauth;
pub mod outbox;
pub mod policy;
pub mod profiles;
pub mod proxy;
pub mod sandbox;
pub mod store;
pub mod taint;
pub mod util;
pub mod vault;
