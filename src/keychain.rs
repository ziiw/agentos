//! Where a secret's real value comes from: your environment, or a command of
//! yours that prints it (your OS keychain, a password manager).
//!
//! ```toml
//! [secret_commands]                                       # your config only
//! ANTHROPIC_API_KEY = ["secret-tool", "lookup", "service", "anthropic"]
//! GITHUB_TOKEN = ["security", "find-generic-password", "-s", "github", "-w"]
//! OPENAI_API_KEY = ["op", "read", "op://Private/OpenAI/credential"]
//! ```
//!
//! The command runs as you, outside any sandbox, only when a task needs the
//! secret and your environment doesn't already have it. What it prints is the
//! value (without its final newline); it goes where the variable's value would
//! have: to the credential broker, never into the sandbox, never into the
//! journal.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Variable name → the command that prints its value.
pub type Commands = BTreeMap<String, Vec<String>>;

/// Long enough to unlock a keyring or approve a prompt on your phone.
const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OUTPUT: u64 = 64 * 1024;

/// `NAME` in your environment, else what its command prints. `Ok(None)`: not
/// set, and no command for it. `Err`: the command failed; the reason never
/// includes what it printed.
pub fn lookup(name: &str, commands: &Commands) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() || !commands.contains_key(name) => return Ok(Some(v)),
        _ => {}
    }
    commands.get(name).map(|argv| run(argv, TIMEOUT)).transpose()
}

/// Checks a `[secret_commands]` entry as written in a config file.
pub fn validate(name: &str, argv: &[String]) -> Result<(), String> {
    let mut chars = name.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("{name:?} isn't a variable name"));
    }
    match argv.first() {
        Some(program) if !program.is_empty() => Ok(()),
        _ => Err(format!("{name}: needs a command, like [\"secret-tool\", \"lookup\", \"service\", \"{}\"]", name.to_ascii_lowercase())),
    }
}

/// Reads a pipe to its end (or `MAX_OUTPUT`) on a thread of its own.
fn drain(pipe: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.take(MAX_OUTPUT).read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

fn run(argv: &[String], timeout: Duration) -> Result<String, String> {
    let path = argv.first().ok_or("no command")?;
    // What the messages call it: `keychain-get`, not /home/you/bin/keychain-get.
    let program = path.rsplit('/').next().unwrap_or(path);
    let mut child = Command::new(path)
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("can't run {program}: {e}"))?;
    let out = drain(child.stdout.take().ok_or("no stdout")?);
    let err = drain(child.stderr.take().ok_or("no stderr")?);

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program} didn't answer within {}s", timeout.as_secs()));
            }
            Err(e) => return Err(format!("{program}: {e}")),
        }
    };
    // Both pipes close once it has exited; a process it left running can keep
    // them open, which isn't worth waiting for.
    let grace = Duration::from_secs(2);
    let (Ok(stdout), Ok(stderr)) = (out.recv_timeout(grace), err.recv_timeout(grace)) else {
        return Err(format!("{program} left a process running that keeps its output open"));
    };
    if !status.success() {
        let why = String::from_utf8_lossy(&stderr).lines().next().unwrap_or_default().trim().chars().take(120).collect::<String>();
        let why = if why.is_empty() { String::new() } else { format!(": {why}") };
        return Err(match status.code() {
            Some(code) => format!("{program} exited {code}{why}"),
            None => format!("{program} was killed{why}"),
        });
    }
    let value = String::from_utf8_lossy(&stdout).trim_end_matches(['\n', '\r']).to_string();
    if value.is_empty() { Err(format!("{program} printed nothing")) } else { Ok(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Commands {
        BTreeMap::from([("AGENTOS_KEYCHAIN_TEST".to_string(), vec!["sh".to_string(), "-c".to_string(), script.to_string()])])
    }

    #[test]
    fn a_command_supplies_what_the_environment_lacks() {
        let value = |script: &str| lookup("AGENTOS_KEYCHAIN_TEST", &sh(script));
        assert_eq!(value("echo s3cret"), Ok(Some("s3cret".into())), "the final newline is not part of it");
        assert_eq!(value("printf 'a b\\nc\\n\\n'"), Ok(Some("a b\nc".into())), "only trailing newlines go");
        assert_eq!(lookup("AGENTOS_KEYCHAIN_TEST", &Commands::new()), Ok(None), "no variable, no command: not set");
    }

    #[test]
    fn the_environment_wins_unless_it_is_empty() {
        // SAFETY: only these tests read these variables.
        unsafe {
            std::env::set_var("AGENTOS_KEYCHAIN_SET", "from-env");
            std::env::set_var("AGENTOS_KEYCHAIN_EMPTY", "");
        }
        let commands = BTreeMap::from([
            ("AGENTOS_KEYCHAIN_SET".to_string(), vec!["echo".to_string(), "from-command".to_string()]),
            ("AGENTOS_KEYCHAIN_EMPTY".to_string(), vec!["echo".to_string(), "from-command".to_string()]),
        ]);
        assert_eq!(lookup("AGENTOS_KEYCHAIN_SET", &commands), Ok(Some("from-env".into())));
        assert_eq!(lookup("AGENTOS_KEYCHAIN_EMPTY", &commands), Ok(Some("from-command".into())));
        assert_eq!(lookup("AGENTOS_KEYCHAIN_EMPTY", &Commands::new()), Ok(Some(String::new())), "an empty variable is still what it was");
    }

    #[test]
    fn failures_are_explained_without_the_output() {
        let err = |script: &str| lookup("AGENTOS_KEYCHAIN_TEST", &sh(script)).unwrap_err();
        assert_eq!(err("echo leaked-value; echo not found >&2; exit 3"), "sh exited 3: not found");
        assert_eq!(err("exit 1"), "sh exited 1");
        assert_eq!(err("true"), "sh printed nothing");
        assert_eq!(err("echo; echo"), "sh printed nothing");
        let missing = BTreeMap::from([("AGENTOS_KEYCHAIN_TEST".to_string(), vec!["agentos-no-such-program".to_string()])]);
        assert!(lookup("AGENTOS_KEYCHAIN_TEST", &missing).unwrap_err().starts_with("can't run agentos-no-such-program"));
    }

    #[test]
    fn a_command_that_hangs_is_stopped() {
        let started = Instant::now();
        let argv = vec!["sleep".to_string(), "30".to_string()];
        assert_eq!(run(&argv, Duration::from_millis(200)), Err("sleep didn't answer within 0s".into()));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn entries_are_checked() {
        assert!(validate("ANTHROPIC_API_KEY", &["secret-tool".into()]).is_ok());
        for (name, argv) in [("1BAD", vec!["x".to_string()]), ("A-B", vec!["x".into()]), ("", vec!["x".into()]), ("OK", vec![]), ("OK", vec![String::new()])] {
            assert!(validate(name, &argv).is_err(), "{name} {argv:?}");
        }
    }
}
