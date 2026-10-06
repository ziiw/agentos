//! `agent doctor`: can this machine run agent sandboxes?

use crate::sandbox::enter_user_namespace;
use crate::util::force_remove_dir_all;
use nix::mount::{MsFlags, mount};
use nix::sched::CloneFlags;
use nix::sys::statfs::statfs;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Gid, Uid, fork};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
}

fn check(name: &'static str, level: Level, detail: impl Into<String>) -> Check {
    Check { name, level, detail: detail.into() }
}

pub fn run(store_root: &Path) -> Vec<Check> {
    let store = store_fs(store_root);
    // The probe mounts an overlay inside the store, so a bad store would only
    // produce a second, misleading failure.
    let sandbox = if store.level == Level::Fail {
        check("sandbox", Level::Fail, "not tested until the task store is fixed")
    } else {
        sandbox(store_root)
    };
    let userns = userns_policy(sandbox.level == Level::Ok);
    vec![kernel(), user(), userns, store, sandbox, landlock(), seccomp(), limits()]
}

fn kernel() -> Check {
    let release = nix::sys::utsname::uname().map(|u| u.release().to_string_lossy().into_owned()).unwrap_or_default();
    let mut nums = release.split(|c: char| !c.is_ascii_digit()).filter_map(|s| s.parse::<u32>().ok());
    let version = (nums.next().unwrap_or(0), nums.next().unwrap_or(0));
    if version >= (5, 11) {
        check("kernel", Level::Ok, release)
    } else {
        check("kernel", Level::Fail, format!("{release}: need 5.11+ for unprivileged overlayfs"))
    }
}

fn user() -> Check {
    if Uid::effective().is_root() {
        check("user", Level::Fail, "running as root; run agents as a normal user")
    } else {
        check("user", Level::Ok, format!("uid {}", Uid::effective()))
    }
}

/// `probe_ok`: the live sandbox probe worked, which is what actually counts;
/// the sysctls only explain a failure.
fn userns_policy(probe_ok: bool) -> Check {
    let read = |p: &str| fs::read_to_string(p).ok().map(|s| s.trim().to_string());
    if read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() == Some("1") {
        return if probe_ok {
            check("user namespaces", Level::Ok, "restricted by AppArmor, allowed for agent by its profile")
        } else {
            check(
                "user namespaces",
                Level::Fail,
                "AppArmor blocks unprivileged user namespaces (Ubuntu 23.10+); install the profile from README.md",
            )
        };
    }
    if read("/proc/sys/kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return check("user namespaces", Level::Fail, "disabled: sysctl kernel.unprivileged_userns_clone=1");
    }
    if read("/proc/sys/user/max_user_namespaces").as_deref() == Some("0") {
        return check("user namespaces", Level::Fail, "disabled: sysctl user.max_user_namespaces=0");
    }
    check("user namespaces", Level::Ok, "allowed")
}

fn store_fs(root: &Path) -> Check {
    const OVERLAYFS_MAGIC: i64 = 0x794c7630;
    match statfs(root) {
        Ok(st) if st.filesystem_type().0 as i64 == OVERLAYFS_MAGIC => check(
            "task store",
            Level::Fail,
            format!("{} is on overlayfs (a container root?); set AGENTOS_HOME to a real filesystem", root.display()),
        ),
        Ok(_) => check("task store", Level::Ok, root.display().to_string()),
        Err(e) => check("task store", Level::Fail, format!("{}: {e}", root.display())),
    }
}

/// End-to-end probe: enter a user namespace and write through an overlay.
fn sandbox(root: &Path) -> Check {
    let name = "sandbox";
    let dir = root.join(format!("doctor-{}", std::process::id()));
    let [lower, upper, work, merged] = ["lower", "upper", "work", "merged"].map(|d| dir.join(d));
    for d in [&lower, &upper, &work, &merged] {
        if let Err(e) = fs::create_dir_all(d) {
            return check(name, Level::Fail, format!("{}: {e}", d.display()));
        }
    }
    let (uid, gid) = (Uid::current(), Gid::current());
    let code = match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let code = if enter_user_namespace(CloneFlags::CLONE_NEWNS, uid, gid).is_err() {
                10
            } else {
                let opts = format!("lowerdir={},upperdir={},workdir={},userxattr", lower.display(), upper.display(), work.display());
                if mount(Some("overlay"), &merged, Some("overlay"), MsFlags::empty(), Some(opts.as_str())).is_err() {
                    11
                } else if fs::write(merged.join("probe"), "ok").is_err() {
                    12
                } else {
                    0
                }
            };
            unsafe { libc::_exit(code) }
        }
        Ok(ForkResult::Parent { child }) => match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => code,
            _ => -1,
        },
        Err(e) => return check(name, Level::Fail, format!("fork: {e}")),
    };
    let landed = upper.join("probe").exists();
    let _ = force_remove_dir_all(&dir);
    match code {
        0 if landed => check(name, Level::Ok, "unprivileged namespaces + overlayfs work"),
        10 => check(name, Level::Fail, "can't create a user namespace"),
        11 => check(name, Level::Fail, "can't mount overlayfs in a user namespace (kernel 5.11+, store on ext4/xfs/btrfs)"),
        12 => check(name, Level::Fail, "overlay mounted but writes fail"),
        _ => check(name, Level::Fail, format!("probe failed (code {code})")),
    }
}

fn limits() -> Check {
    if crate::limits::available() {
        check("limits", Level::Ok, "--memory/--cpus/--pids through systemd user scopes")
    } else {
        check("limits", Level::Warn, "no systemd user session: --memory/--cpus/--pids can't be enforced here")
    }
}

fn seccomp() -> Check {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    if status.lines().any(|l| l.starts_with("Seccomp:")) {
        check("seccomp", Level::Ok, "available")
    } else {
        check("seccomp", Level::Warn, "not available: sandboxes run without a syscall filter")
    }
}

fn landlock() -> Check {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    let abi = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<libc::c_void>(), 0usize, LANDLOCK_CREATE_RULESET_VERSION)
    };
    if abi > 0 {
        check("landlock", Level::Ok, format!("ABI v{abi}"))
    } else {
        check("landlock", Level::Warn, "not available: sandboxes still isolate via namespaces, without the second layer")
    }
}
