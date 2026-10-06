//! The process sandbox.
//!
//! ```text
//! supervisor (agent run)      stays on the host, writes the journal
//!  └─ A  new user/mount/pid/ipc/uts(/net) namespaces, uid/gid maps
//!      └─ B  pid 1: assembles the root, pivots, applies Landlock, reaps
//!          ├─ F  (with --allow) relays 127.0.0.1 to the egress proxy socket
//!          └─ C  execs the agent command
//! ```
//!
//! The agent's root is an empty tmpfs that gets: read-only system dirs, a
//! private /dev, /proc, /tmp, a private empty $HOME, and only the paths it was
//! granted. Writable grants are overlayfs mounts whose upper dir lives in the
//! task store, so nothing the agent writes touches the real tree until it is
//! committed. Everything runs unprivileged via user namespaces.

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use nix::sys::prctl;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction, signal};
use nix::sys::statvfs::{FsFlags, statvfs};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Gid, Pid, Uid, chdir, execve, fork, pipe2, pivot_root, sethostname};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs;
use crate::proxy;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};
use std::thread;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

/// Where the egress proxy's socket appears inside the sandbox.
const PROXY_SOCKET: &str = "/run/agentos/proxy.sock";

/// Host directories every agent can read (never write).
const SYSTEM_DIRS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt", "/nix", "/sys"];
const DEV_NODES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

pub enum Mount {
    /// Writable, transactional: writes go to `upper`, `source` is never touched.
    Overlay { upper: PathBuf, work: PathBuf },
    ReadOnly,
}

pub struct GrantMount {
    /// Canonical host path, mounted at the same path inside the sandbox.
    pub path: PathBuf,
    pub kind: Mount,
}

pub struct RunMount {
    pub src: PathBuf,
    pub name: String,
    pub writable: bool,
}

pub struct Spec {
    /// Empty directory used as the sandbox root mount point.
    pub rootfs: PathBuf,
    pub grants: Vec<GrantMount>,
    /// Paths to blank out even though a grant would expose them.
    pub hide: Vec<PathBuf>,
    /// Like `hide`, but silent: the task store must never be visible.
    pub mask: Vec<PathBuf>,
    pub isolate_net: bool,
    /// Host path of the egress proxy's unix socket. When set, the agent's
    /// only way out is through it (see `proxy.rs`).
    pub proxy: Option<PathBuf>,
    /// Host files or directories exposed as /run/agentos/<name>: the task
    /// CA (read-only), the git outbox (writable), …
    pub run_mounts: Vec<RunMount>,
    pub hostname: String,
    pub home: PathBuf,
    /// Directory mounted read-write as $HOME (an agent's persistent home).
    /// Without one, $HOME is an empty tmpfs.
    pub home_source: Option<PathBuf>,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    pub argv: Vec<String>,
}

/// What the sandbox actually achieved, sent back to the supervisor for the journal.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub landlock: String,
    #[serde(default)]
    pub seccomp: String,
    pub proc: String,
    pub devpts: bool,
    pub cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The sandbox's namespace parent (process A), while it runs: killing it
/// takes down everything inside, since pid 1 dies with it.
static SANDBOX_PID: AtomicI32 = AtomicI32::new(0);
/// Why the sandbox was cut short: 0 not, 1 stopped (signal), 2 timed out.
static STOPPED: AtomicU8 = AtomicU8::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// `agent stop`, SIGTERM or a closed terminal.
    Stopped,
    Timeout,
}

/// Ends the running sandbox, if any. Safe from a signal handler.
pub fn stop(why: Stop) {
    let pid = SANDBOX_PID.load(Ordering::SeqCst);
    if pid <= 0 {
        return;
    }
    let _ = STOPPED.compare_exchange(0, if why == Stop::Timeout { 2 } else { 1 }, Ordering::SeqCst, Ordering::SeqCst);
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

/// Why the last sandbox was cut short, if it was.
pub fn stopped() -> Option<Stop> {
    match STOPPED.load(Ordering::SeqCst) {
        1 => Some(Stop::Stopped),
        2 => Some(Stop::Timeout),
        _ => None,
    }
}

extern "C" fn on_terminate(_: libc::c_int) {
    stop(Stop::Stopped);
}

/// Whether `path` is under a system dir every sandbox already sees read-only.
pub fn is_system_path(path: &Path) -> bool {
    SYSTEM_DIRS.iter().any(|d| path.starts_with(d))
}

/// Runs `spec.argv` in the sandbox, with its stdout redirected to `stdout`
/// if given. `on_ready` is called once setup has finished (or failed), while
/// the agent runs; the call returns the agent's exit status.
pub fn run(spec: &Spec, stdout: Option<OwnedFd>, on_ready: impl FnOnce(&Report)) -> Result<i32> {
    if spec.argv.is_empty() {
        bail!("no command to run");
    }
    let (uid, gid) = (Uid::current(), Gid::current());
    if uid.is_root() {
        bail!("refusing to run an agent as root; agentos sandboxes are built on unprivileged user namespaces");
    }
    let (report_rx, report_tx) = pipe2(OFlag::O_CLOEXEC)?;

    // Ctrl-C belongs to the agent; the supervisor must survive it to record the outcome.
    let prev_int = unsafe { signal(Signal::SIGINT, SigHandler::SigIgn)? };
    let prev_quit = unsafe { signal(Signal::SIGQUIT, SigHandler::SigIgn)? };
    // SIGTERM (agent stop) and SIGHUP (terminal gone) end the sandbox, and
    // the supervisor lives on to record it.
    let terminate = SigAction::new(SigHandler::Handler(on_terminate), SaFlags::SA_RESTART, SigSet::empty());
    let prev_term = unsafe { sigaction(Signal::SIGTERM, &terminate)? };
    let prev_hup = unsafe { sigaction(Signal::SIGHUP, &terminate)? };

    let result = match unsafe { fork() }? {
        ForkResult::Child => {
            drop(report_rx);
            let code = namespace_parent(spec, uid, gid, report_tx, stdout);
            unsafe { libc::_exit(code) }
        }
        ForkResult::Parent { child } => {
            SANDBOX_PID.store(child.as_raw(), Ordering::SeqCst);
            drop(report_tx);
            drop(stdout);
            let mut raw = String::new();
            let _ = fs::File::from(report_rx).read_to_string(&mut raw);
            let report = serde_json::from_str(raw.trim()).unwrap_or_else(|_| Report {
                error: Some("sandbox exited before finishing setup".into()),
                ..Default::default()
            });
            on_ready(&report);
            let code = wait_for(child);
            SANDBOX_PID.store(0, Ordering::SeqCst);
            code
        }
    };

    unsafe {
        signal(Signal::SIGINT, prev_int)?;
        signal(Signal::SIGQUIT, prev_quit)?;
        sigaction(Signal::SIGTERM, &prev_term)?;
        sigaction(Signal::SIGHUP, &prev_hup)?;
    }
    result
}

/// Enters a new user namespace (plus `flags`) mapping only the caller's own
/// uid/gid — no setuid helpers, no subordinate id ranges.
pub fn enter_user_namespace(flags: CloneFlags, uid: Uid, gid: Gid) -> Result<()> {
    unshare(flags | CloneFlags::CLONE_NEWUSER)
        .context("unshare: unprivileged user namespaces unavailable (run `agent doctor`)")?;
    fs::write("/proc/self/setgroups", "deny").context("write setgroups")?;
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n")).context("write uid_map")?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n")).context("write gid_map")?;
    Ok(())
}

/// Process A: creates the namespaces, then forks pid 1 of the new pid namespace.
fn namespace_parent(spec: &Spec, uid: Uid, gid: Gid, report_tx: OwnedFd, stdout: Option<OwnedFd>) -> i32 {
    let _ = prctl::set_pdeathsig(Signal::SIGKILL);
    let mut flags = CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWUTS;
    if spec.isolate_net {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    if let Err(e) = enter_user_namespace(flags, uid, gid) {
        return send_failure(&report_tx, e);
    }
    let mut warnings = Vec::new();
    if let Err(e) = sethostname(&spec.hostname) {
        warnings.push(format!("hostname: {e}"));
    }
    if spec.isolate_net {
        if let Err(e) = bring_up_loopback() {
            warnings.push(format!("loopback: {e:#}"));
        }
    }
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let code = sandbox_init(spec, warnings, report_tx, stdout);
            unsafe { libc::_exit(code) }
        }
        Ok(ForkResult::Parent { child }) => {
            drop(report_tx);
            drop(stdout);
            wait_for(child).unwrap_or(125)
        }
        Err(e) => send_failure(&report_tx, e.into()),
    }
}

/// Process B (pid 1): builds the root, applies Landlock, runs the agent and
/// reaps orphans. When B exits the kernel kills everything left in the namespace.
fn sandbox_init(spec: &Spec, warnings: Vec<String>, report_tx: OwnedFd, stdout: Option<OwnedFd>) -> i32 {
    let _ = prctl::set_pdeathsig(Signal::SIGKILL);
    let mut report = Report { warnings, ..Default::default() };
    if let Err(e) = build_root(spec, &mut report) {
        return send_failure_with(&report_tx, report, e);
    }
    let cwd = if spec.cwd.is_dir() {
        spec.cwd.clone()
    } else {
        report.warnings.push(format!("{} is not granted; starting in $HOME", spec.cwd.display()));
        spec.home.clone()
    };
    report.cwd = cwd.display().to_string();
    report.landlock = apply_landlock(spec);
    report.seccomp = match apply_seccomp() {
        Ok(()) => "enforced".into(),
        Err(e) => {
            report.warnings.push(format!("seccomp filter not applied: {e:#}"));
            format!("error: {e:#}")
        }
    };

    let mut proxy_env = Vec::new();
    if spec.proxy.is_some() {
        match TcpListener::bind("127.0.0.1:0").and_then(|l| Ok((l.local_addr()?.port(), l))) {
            Ok((port, listener)) => match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    // Hold nothing the supervisor waits on to reach EOF.
                    drop(report_tx);
                    drop(stdout);
                    forward(listener)
                }
                Ok(ForkResult::Parent { .. }) => {
                    report.proxy_port = Some(port);
                    let url = format!("http://127.0.0.1:{port}");
                    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
                        proxy_env.push((name.to_string(), url.clone()));
                    }
                    for name in ["NO_PROXY", "no_proxy"] {
                        proxy_env.push((name.to_string(), "localhost,127.0.0.1,::1".to_string()));
                    }
                }
                Err(e) => report.warnings.push(format!("proxy forwarder: {e}")),
            },
            Err(e) => report.warnings.push(format!("proxy forwarder: {e}")),
        }
    }
    send_report(&report_tx, &report);
    drop(report_tx);

    match unsafe { fork() } {
        Ok(ForkResult::Child) => exec_agent(spec, &cwd, stdout.as_ref(), &proxy_env),
        Ok(ForkResult::Parent { child }) => {
            drop(stdout);
            reap_until(child)
        }
        Err(e) => {
            eprintln!("agent: fork: {e}");
            125
        }
    }
}

fn build_root(spec: &Spec, report: &mut Report) -> Result<()> {
    let root = spec.rootfs.as_path();
    let inside = |p: &Path| root.join(p.strip_prefix("/").unwrap_or(p));
    let dir = |p: &str| -> Result<PathBuf> {
        let d = inside(Path::new(p));
        fs::create_dir_all(&d).with_context(|| format!("mkdir {}", d.display()))?;
        Ok(d)
    };

    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>).context("make mounts private")?;
    tmpfs(root, "0755").context("root tmpfs")?;

    for sys in SYSTEM_DIRS {
        let src = Path::new(sys);
        match fs::symlink_metadata(src) {
            Ok(m) if m.file_type().is_symlink() => symlink(fs::read_link(src)?, inside(src))?,
            Ok(m) if m.is_dir() => bind_ro(src, &dir(sys)?)?,
            _ => {}
        }
    }

    // A private /dev with just the safe nodes.
    let dev = dir("/dev")?;
    tmpfs(&dev, "0755")?;
    for node in DEV_NODES {
        let target = dev.join(node);
        fs::File::create(&target)?;
        if let Err(e) = bind(&Path::new("/dev").join(node), &target) {
            report.warnings.push(format!("/dev/{node}: {e:#}"));
        }
    }
    fs::create_dir(dev.join("pts"))?;
    match mount(Some("devpts"), &dev.join("pts"), Some("devpts"), MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC, Some("newinstance,ptmxmode=0666,mode=0620")) {
        Ok(()) => {
            symlink("pts/ptmx", dev.join("ptmx"))?;
            report.devpts = true;
        }
        Err(e) => report.warnings.push(format!("devpts: {e}")),
    }
    fs::create_dir(dev.join("shm"))?;
    tmpfs(&dev.join("shm"), "1777")?;
    for (name, target) in [("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"), ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2")] {
        symlink(target, dev.join(name))?;
    }

    // Scratch space: private, empty and thrown away with the sandbox.
    tmpfs(&dir("/tmp")?, "1777")?;
    tmpfs(&dir("/run")?, "0755")?;
    tmpfs(&dir("/var")?, "0755")?;
    let var_tmp = dir("/var/tmp")?;
    fs::set_permissions(&var_tmp, fs::Permissions::from_mode(0o1777))?;
    if Path::new("/run/systemd/resolve").is_dir() {
        bind_ro(Path::new("/run/systemd/resolve"), &dir("/run/systemd/resolve")?)?;
    }
    if let Some(sock) = &spec.proxy {
        let target = dir("/run/agentos")?.join("proxy.sock");
        fs::File::create(&target)?;
        bind(sock, &target).context("proxy socket")?;
    }
    for m in &spec.run_mounts {
        let target = dir("/run/agentos")?.join(&m.name);
        if m.src.is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            fs::File::create(&target)?;
        }
        if m.writable { bind(&m.src, &target) } else { bind_ro(&m.src, &target) }
            .with_context(|| format!("/run/agentos/{}", m.name))?;
    }

    // $HOME starts empty; grants are mounted shallowest-first so nested
    // grants (and grants inside $HOME) land on top of their parents.
    enum Step<'a> {
        Home,
        Grant(&'a GrantMount),
    }
    let mut steps: Vec<(&Path, Step)> = spec.grants.iter().map(|g| (g.path.as_path(), Step::Grant(g))).collect();
    if !spec.grants.iter().any(|g| g.path == spec.home) {
        steps.push((spec.home.as_path(), Step::Home));
    }
    steps.sort_by_key(|(p, _)| p.components().count());
    for (path, step) in steps {
        let target = inside(path);
        match step {
            Step::Home => {
                fs::create_dir_all(&target)?;
                match &spec.home_source {
                    Some(src) => bind(src, &target).context("agent home")?,
                    None => tmpfs(&target, "0700").context("home tmpfs")?,
                }
            }
            Step::Grant(g) => mount_grant(g, &target).with_context(|| format!("grant {}", g.path.display()))?,
        }
    }

    for path in &spec.hide {
        if let Err(e) = blank_out(&inside(path)) {
            report.warnings.push(format!("hide {}: {e:#}", path.display()));
        }
    }
    for path in &spec.mask {
        if inside(path).exists() {
            blank_out(&inside(path)).with_context(|| format!("mask {}", path.display()))?;
        }
    }

    // /proc for the new pid namespace. Mounting it needs an unobstructed
    // /proc elsewhere in the namespace (unprivileged containers mask theirs),
    // so fall back to the host's, which is weaker: it shows host processes.
    let proc_dir = dir("/proc")?;
    let pflags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    match mount(Some("proc"), &proc_dir, Some("proc"), pflags, None::<&str>) {
        Ok(()) => report.proc = "private".into(),
        Err(e) => {
            mount(Some("/proc"), &proc_dir, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>).context("bind /proc")?;
            report.proc = "host".into();
            report.warnings.push(format!("private /proc unavailable ({e}); host processes are visible"));
        }
    }

    chdir(root)?;
    fs::create_dir(".oldroot")?;
    pivot_root(".", ".oldroot").context("pivot_root")?;
    chdir("/")?;
    umount2("/.oldroot", MntFlags::MNT_DETACH).context("detach old root")?;
    fs::remove_dir("/.oldroot")?;
    if let Err(e) = mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY, None::<&str>) {
        report.warnings.push(format!("read-only root: {e}"));
    }
    Ok(())
}

fn mount_grant(g: &GrantMount, target: &Path) -> Result<()> {
    if g.path.is_dir() {
        fs::create_dir_all(target)?;
    } else {
        fs::create_dir_all(target.parent().context("grant has no parent")?)?;
        fs::File::create(target)?;
    }
    match &g.kind {
        Mount::ReadOnly => bind_ro(&g.path, target),
        Mount::Overlay { upper, work } => {
            for p in [&g.path, upper, work] {
                if p.as_os_str().as_bytes().iter().any(|b| matches!(b, b',' | b':' | b'\\')) {
                    bail!("{}: paths containing ',', ':' or '\\' can't be overlay-mounted yet", p.display());
                }
            }
            // userxattr: unprivileged overlay keeps its metadata in user.overlay.* xattrs.
            let opts = format!("lowerdir={},upperdir={},workdir={},userxattr", g.path.display(), upper.display(), work.display());
            mount(Some("overlay"), target, Some("overlay"), MsFlags::empty(), Some(opts.as_str())).context("mount overlay")?;
            Ok(())
        }
    }
}

fn tmpfs(target: &Path, mode: &str) -> Result<()> {
    mount(Some("tmpfs"), target, Some("tmpfs"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV, Some(format!("mode={mode}").as_str()))
        .with_context(|| format!("tmpfs {}", target.display()))?;
    Ok(())
}

fn bind(src: &Path, dst: &Path) -> Result<()> {
    mount(Some(src), dst, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
        .with_context(|| format!("bind {} -> {}", src.display(), dst.display()))?;
    Ok(())
}

fn bind_ro(src: &Path, dst: &Path) -> Result<()> {
    bind(src, dst)?;
    make_readonly(dst).with_context(|| format!("make {} read-only", dst.display()))
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const AT_RECURSIVE: libc::c_uint = 0x8000;

fn make_readonly(path: &Path) -> Result<()> {
    // mount_setattr(2) (Linux 5.12+) makes the whole subtree read-only at once.
    let c = CString::new(path.as_os_str().as_bytes())?;
    let attr = MountAttr { attr_set: MOUNT_ATTR_RDONLY, attr_clr: 0, propagation: 0, userns_fd: 0 };
    let rc = unsafe {
        libc::syscall(libc::SYS_mount_setattr, libc::AT_FDCWD, c.as_ptr(), AT_RECURSIVE, &attr as *const MountAttr, size_of::<MountAttr>())
    };
    if rc == 0 {
        return Ok(());
    }
    // Older kernels: remount the top mount only, keeping the flags the kernel
    // locked when the mount crossed into our user namespace.
    let st = statvfs(path)?;
    let mut flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
    for (have, want) in [
        (FsFlags::ST_NOSUID, MsFlags::MS_NOSUID),
        (FsFlags::ST_NODEV, MsFlags::MS_NODEV),
        (FsFlags::ST_NOEXEC, MsFlags::MS_NOEXEC),
        (FsFlags::ST_NOATIME, MsFlags::MS_NOATIME),
        (FsFlags::ST_NODIRATIME, MsFlags::MS_NODIRATIME),
        (FsFlags::ST_RELATIME, MsFlags::MS_RELATIME),
    ] {
        if st.flags().contains(have) {
            flags |= want;
        }
    }
    mount(None::<&str>, path, None::<&str>, flags, None::<&str>)?;
    Ok(())
}

/// Covers a dir with an empty read-only tmpfs, or a file with /dev/null.
fn blank_out(target: &Path) -> Result<()> {
    let m = fs::symlink_metadata(target).context("not visible in the sandbox")?;
    if m.is_dir() {
        let flags = MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
        mount(Some("tmpfs"), target, Some("tmpfs"), flags, Some("mode=0755,size=0")).context("tmpfs")?;
    } else {
        bind_ro(Path::new("/dev/null"), target)?;
    }
    Ok(())
}

/// Syscalls an agent has no business making: kernel interfaces with a long
/// record of exploits (bpf, io_uring, keyrings, userfaultfd, perf) and ways
/// to rearrange its own sandbox (new namespaces, mounts, modules).
const DENIED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_open_by_handle_at,
];

/// clone(2) flags that create namespaces (NEWNS … NEWNET, NEWTIME).
const NAMESPACE_FLAGS: &[u64] = &[0x0002_0000, 0x0200_0000, 0x0400_0000, 0x0800_0000, 0x1000_0000, 0x2000_0000, 0x4000_0000, 0x80];
/// ioctls that push input into a terminal: a sandboxed process sharing your
/// tty could otherwise type commands into your shell.
const TIOCSTI: u64 = 0x5412;
const TIOCLINUX: u64 = 0x541C;

fn apply_seccomp() -> Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;

    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let rule = |arg: u8, len, op, value| -> Result<SeccompRule> {
        Ok(SeccompRule::new(vec![SeccompCondition::new(arg, len, op, value)?])?)
    };
    let mut deny: BTreeMap<i64, Vec<SeccompRule>> = DENIED_SYSCALLS.iter().map(|&s| (s as i64, Vec::new())).collect();
    // Plain fork and thread creation stay allowed; namespace flags don't.
    deny.insert(
        libc::SYS_clone as i64,
        NAMESPACE_FLAGS.iter().map(|&f| rule(0, SeccompCmpArgLen::Qword, SeccompCmpOp::MaskedEq(f), f)).collect::<Result<_>>()?,
    );
    deny.insert(
        libc::SYS_ioctl as i64,
        [TIOCSTI, TIOCLINUX].iter().map(|&req| rule(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, req)).collect::<Result<_>>()?,
    );
    let deny: BpfProgram =
        SeccompFilter::new(deny, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM as u32), arch)?.try_into()?;
    // clone3 passes its flags in memory, out of a filter's reach. ENOSYS makes
    // libc fall back to clone(2), which is filtered above.
    let clone3: BpfProgram = SeccompFilter::new(
        BTreeMap::from([(libc::SYS_clone3 as i64, Vec::new())]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )?
    .try_into()?;
    prctl::set_no_new_privs()?;
    seccompiler::apply_filter(&clone3)?;
    seccompiler::apply_filter(&deny)?;
    Ok(())
}

fn apply_landlock(spec: &Spec) -> String {
    use landlock::{ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, path_beneath_rules};
    let abi = ABI::V5;
    let mut writable: Vec<PathBuf> = ["/tmp", "/var/tmp", "/dev", "/proc", "/run"].iter().map(PathBuf::from).collect();
    writable.push(spec.home.clone());
    writable.extend(spec.grants.iter().filter(|g| matches!(g.kind, Mount::Overlay { .. })).map(|g| g.path.clone()));
    writable.retain(|p| p.exists());

    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.create())
        .and_then(|r| r.add_rules(path_beneath_rules(["/"], AccessFs::from_read(abi))))
        .and_then(|r| r.add_rules(path_beneath_rules(&writable, AccessFs::from_all(abi))))
        .and_then(|r| r.restrict_self());
    match status {
        Ok(s) => match s.ruleset {
            RulesetStatus::FullyEnforced => "enforced".into(),
            RulesetStatus::PartiallyEnforced => "partially enforced (older kernel ABI)".into(),
            RulesetStatus::NotEnforced => "unavailable (kernel without Landlock)".into(),
        },
        Err(e) => format!("error: {e}"),
    }
}

/// Process F, inside the sandbox: relays 127.0.0.1 connections to the
/// egress proxy's socket. Dies with the sandbox.
fn forward(listener: TcpListener) -> ! {
    for tcp in listener.incoming().flatten() {
        thread::spawn(move || {
            if let Ok(unix) = UnixStream::connect(PROXY_SOCKET) {
                proxy::pump(tcp, unix);
            }
        });
    }
    unsafe { libc::_exit(0) }
}

/// Process C: becomes the agent.
fn exec_agent(spec: &Spec, cwd: &Path, stdout: Option<&OwnedFd>, extra_env: &[(String, String)]) -> ! {
    if let Some(fd) = stdout {
        unsafe { libc::dup2(fd.as_raw_fd(), 1) };
    }
    unsafe {
        // Ignored signals survive execve; give the agent normal defaults
        // (Rust's runtime ignores SIGPIPE, which would break shell pipelines).
        for sig in [Signal::SIGINT, Signal::SIGQUIT, Signal::SIGPIPE] {
            let _ = signal(sig, SigHandler::SigDfl);
        }
    }
    let _ = prctl::set_no_new_privs();
    let _ = chdir(cwd);

    let path_var = spec.env.iter().find(|(k, _)| k == "PATH").map(|(_, v)| v.as_str()).unwrap_or("/usr/bin:/bin");
    let program = resolve_program(&spec.argv[0], path_var);
    let to_c = |s: &str| CString::new(s).unwrap_or_default();
    let argv: Vec<CString> = spec.argv.iter().map(|a| to_c(a)).collect();
    let env: Vec<CString> = spec.env.iter().chain(extra_env).map(|(k, v)| to_c(&format!("{k}={v}"))).collect();
    let err = execve(&CString::new(program.as_os_str().as_bytes()).unwrap_or_default(), &argv, &env).unwrap_err();
    eprintln!("agent: {}: {}", spec.argv[0], if err == Errno::ENOENT { "command not found in the sandbox".to_string() } else { err.to_string() });
    unsafe { libc::_exit(if err == Errno::ENOENT { 127 } else { 126 }) }
}

fn resolve_program(name: &str, path_var: &str) -> PathBuf {
    if name.contains('/') {
        return PathBuf::from(name);
    }
    path_var
        .split(':')
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join(name))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
        .unwrap_or_else(|| PathBuf::from(name))
}

fn bring_up_loopback() -> Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(Errno::last()).context("socket");
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, b) in b"lo".iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        let res = if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            Err(Errno::last()).context("SIOCGIFFLAGS")
        } else {
            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            if libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &ifr) < 0 { Err(Errno::last()).context("SIOCSIFFLAGS") } else { Ok(()) }
        };
        libc::close(fd);
        res
    }
}

fn exit_code(status: WaitStatus) -> Option<i32> {
    match status {
        WaitStatus::Exited(_, code) => Some(code),
        WaitStatus::Signaled(_, sig, _) => Some(128 + sig as i32),
        _ => None,
    }
}

fn wait_for(pid: Pid) -> Result<i32> {
    loop {
        match waitpid(pid, None) {
            Ok(status) => {
                if let Some(code) = exit_code(status) {
                    return Ok(code);
                }
            }
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e).context("waitpid"),
        }
    }
}

/// As pid 1, reap every orphan, but return as soon as the agent itself exits.
fn reap_until(main: Pid) -> i32 {
    loop {
        match waitpid(None::<Pid>, None) {
            Ok(status) if status.pid() == Some(main) => {
                if let Some(code) = exit_code(status) {
                    return code;
                }
            }
            Ok(_) | Err(Errno::EINTR) => continue,
            Err(_) => return 125,
        }
    }
}

fn send_report(tx: &OwnedFd, report: &Report) {
    if let Ok(json) = serde_json::to_string(report) {
        let _ = fs::File::from(tx.try_clone().expect("dup report pipe")).write_all(json.as_bytes());
    }
}

fn send_failure(tx: &OwnedFd, err: anyhow::Error) -> i32 {
    send_failure_with(tx, Report::default(), err)
}

fn send_failure_with(tx: &OwnedFd, mut report: Report, err: anyhow::Error) -> i32 {
    report.error = Some(format!("{err:#}"));
    send_report(tx, &report);
    125
}
