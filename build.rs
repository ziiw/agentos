// Embeds the git commit in `agent --version`, so it's always clear which
// build is running.
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=AGENTOS_REV");
    if let Some(rev) = std::env::var("AGENTOS_REV").ok().filter(|r| !r.is_empty() && r != "unknown") {
        println!("cargo:rustc-env=AGENTOS_REV={rev}");
        return;
    }
    let rev = Command::new("git")
        .args(["-c", "safe.directory=*", "rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=AGENTOS_REV={rev}");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
}
