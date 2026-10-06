//! Reading and applying a task's transaction.
//!
//! A writable grant is an overlayfs mount: the real directory is the read-only
//! lower layer and everything the agent writes lands in an upper directory we
//! own. The upper dir *is* the changeset:
//!
//! - a regular file, dir or symlink is an addition or modification,
//! - a 0:0 character device ("whiteout") is a deletion,
//! - a directory with the `overlay.opaque` xattr replaced the lower directory
//!   wholesale (e.g. `rm -rf build && mkdir build`): lower entries missing
//!   from it are deletions.
//!
//! Committing copies entries into the real tree and retires them from the
//! upper dir, so whatever is left is exactly what is still pending.

use crate::util::{force_remove_dir_all, mtime_ms};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::ffi::{CString, OsString};
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

const OPAQUE_XATTRS: [&str; 2] = ["user.overlay.opaque", "trusted.overlay.opaque"];

pub struct Layer {
    pub index: usize,
    /// The real directory (overlay lower layer).
    pub source: PathBuf,
    /// Where the agent's writes landed (overlay upper layer).
    pub upper: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Entry {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone)]
pub struct Change {
    pub kind: Kind,
    pub entry: Entry,
    pub layer: usize,
    /// Path relative to the grant.
    pub rel: PathBuf,
    /// Absolute path on the host.
    pub path: PathBuf,
    /// Location inside the upper dir.
    pub upper: PathBuf,
    /// A deletion implied by an opaque parent dir (no whiteout of its own).
    pub implied: bool,
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Summary {
    pub added: usize,
    pub modified: usize,
    pub deleted: usize,
}

impl Summary {
    pub fn of(changes: &[Change]) -> Summary {
        let mut s = Summary::default();
        for c in changes {
            match c.kind {
                Kind::Added => s.added += 1,
                Kind::Modified => s.modified += 1,
                Kind::Deleted => s.deleted += 1,
            }
        }
        s
    }

    pub fn total(&self) -> usize {
        self.added + self.modified + self.deleted
    }
}

/// Lists every pending change, parents before children.
pub fn scan(layers: &[Layer]) -> Result<Vec<Change>> {
    let mut out = Vec::new();
    for layer in layers {
        walk(layer, Path::new(""), &mut out).with_context(|| format!("scan {}", layer.upper.display()))?;
    }
    Ok(out)
}

/// Keeps the changes at or under any of `filters` (all of them if empty).
pub fn select(changes: Vec<Change>, filters: &[PathBuf]) -> Vec<Change> {
    if filters.is_empty() {
        return changes;
    }
    changes.into_iter().filter(|c| filters.iter().any(|f| c.path.starts_with(f))).collect()
}

/// Changes whose real path was modified on the host after `since_ms`, i.e.
/// while the agent was working on its own copy.
pub fn conflicts(changes: &[Change], since_ms: u64) -> Vec<&Change> {
    changes
        .iter()
        .filter(|c| fs::symlink_metadata(&c.path).is_ok_and(|m| mtime_ms(&m) > since_ms))
        .collect()
}

/// Applies `selected` to the real filesystem and removes them from the transaction.
pub fn commit(layers: &[Layer], selected: &[Change]) -> Result<()> {
    for c in selected {
        apply(c).with_context(|| format!("commit {}", c.path.display()))?;
    }
    // Must run before retiring entries: an opaque dir only stops being opaque
    // once all its implied deletions have reached the real tree.
    for layer in layers {
        settle_opaque(&layer.upper, &layer.source)?;
    }
    for c in selected {
        let layer = layers.iter().find(|l| l.index == c.layer).context("change from unknown layer")?;
        retire(layer, c)?;
    }
    for layer in layers {
        prune(&layer.upper, &layer.source)?;
    }
    Ok(())
}

/// Discards pending changes at or under each target path. Returns how many
/// targets had something to discard.
pub fn rollback(layers: &[Layer], changes: &[Change], targets: &[PathBuf]) -> Result<usize> {
    let mut discarded = 0;
    for target in targets {
        let Some(layer) = layers
            .iter()
            .filter(|l| target.starts_with(&l.source))
            .max_by_key(|l| l.source.components().count())
        else {
            bail!("{}: not inside a writable grant of this task", target.display());
        };
        let rel = target.strip_prefix(&layer.source)?;
        if rel.as_os_str().is_empty() {
            for entry in fs::read_dir(&layer.upper)? {
                force_remove_dir_all(&entry?.path())?;
            }
            discarded += 1;
        } else if fs::symlink_metadata(layer.upper.join(rel)).is_ok() {
            force_remove_dir_all(&layer.upper.join(rel))?;
            discarded += 1;
        } else if let Some(c) = changes.iter().find(|c| c.implied && target.starts_with(&c.path)) {
            let parent = c.path.parent().unwrap_or(&c.path);
            bail!(
                "{}: deleted because the agent replaced {}; roll back that directory instead",
                target.display(),
                parent.display()
            );
        } else {
            bail!("{}: no pending changes", target.display());
        }
        prune(&layer.upper, &layer.source)?;
    }
    Ok(discarded)
}

/// Number of non-directory entries under `path` (for describing deleted dirs).
pub fn count_files(path: &Path) -> usize {
    let Ok(entries) = fs::read_dir(path) else { return 0 };
    entries
        .flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => count_files(&e.path()),
            _ => 1,
        })
        .sum()
}

fn walk(layer: &Layer, rel: &Path, out: &mut Vec<Change>) -> Result<()> {
    for name in sorted_names(&layer.upper.join(rel))? {
        let r = rel.join(&name);
        let up = layer.upper.join(&r);
        let um = fs::symlink_metadata(&up)?;
        let lm = fs::symlink_metadata(layer.source.join(&r)).ok();
        let change = |kind, entry| change(layer, r.clone(), kind, entry, false);

        if is_whiteout(&um) {
            if let Some(lm) = &lm {
                out.push(change(Kind::Deleted, entry_of(lm)));
            }
            continue;
        }
        let ue = entry_of(&um);
        match &lm {
            None => out.push(change(Kind::Added, ue)),
            Some(lm) if lm.is_dir() && ue == Entry::Dir => {
                if is_opaque(&up) {
                    for gone in sorted_names(&layer.source.join(&r))? {
                        if fs::symlink_metadata(up.join(&gone)).is_err() {
                            let lm = fs::symlink_metadata(layer.source.join(&r).join(&gone))?;
                            out.push(self::change(layer, r.join(&gone), Kind::Deleted, entry_of(&lm), true));
                        }
                    }
                }
            }
            Some(lm) if lm.is_dir() || ue == Entry::Dir => {
                // The entry changed type (file <-> dir).
                out.push(change(Kind::Deleted, entry_of(lm)));
                out.push(change(Kind::Added, ue));
            }
            Some(lm) => {
                if differs(&up, &um, &layer.source.join(&r), lm)? {
                    out.push(change(Kind::Modified, ue));
                }
            }
        }
        if ue == Entry::Dir {
            walk(layer, &r, out)?;
        }
    }
    Ok(())
}

fn change(layer: &Layer, rel: PathBuf, kind: Kind, entry: Entry, implied: bool) -> Change {
    Change {
        kind,
        entry,
        layer: layer.index,
        path: layer.source.join(&rel),
        upper: layer.upper.join(&rel),
        rel,
        implied,
    }
}

fn sorted_names(dir: &Path) -> io::Result<Vec<OsString>> {
    let mut names = fs::read_dir(dir)?.map(|e| e.map(|e| e.file_name())).collect::<io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}

fn entry_of(m: &Metadata) -> Entry {
    let t = m.file_type();
    if t.is_symlink() {
        Entry::Symlink
    } else if t.is_dir() {
        Entry::Dir
    } else if t.is_file() {
        Entry::File
    } else {
        Entry::Other
    }
}

fn is_whiteout(m: &Metadata) -> bool {
    m.file_type().is_char_device() && m.rdev() == 0
}

fn is_opaque(path: &Path) -> bool {
    let Ok(p) = CString::new(path.as_os_str().as_bytes()) else { return false };
    OPAQUE_XATTRS.iter().any(|name| {
        let n = CString::new(*name).unwrap();
        let mut buf = [0u8; 8];
        let len = unsafe { libc::lgetxattr(p.as_ptr(), n.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        len == 1 && buf[0] == b'y'
    })
}

fn clear_opaque(path: &Path) {
    let Ok(p) = CString::new(path.as_os_str().as_bytes()) else { return };
    for name in OPAQUE_XATTRS {
        let n = CString::new(name).unwrap();
        unsafe { libc::lremovexattr(p.as_ptr(), n.as_ptr()) };
    }
}

/// True if some directory above `rel` in the upper layer is opaque.
fn under_opaque(upper: &Path, rel: &Path) -> bool {
    rel.ancestors().skip(1).filter(|a| !a.as_os_str().is_empty()).any(|a| is_opaque(&upper.join(a)))
}

/// Overlayfs copies a file up on any write-open, even if nothing changes, so
/// compare type, permissions and contents rather than trusting presence.
fn differs(up: &Path, um: &Metadata, low: &Path, lm: &Metadata) -> Result<bool> {
    let (ut, lt) = (um.file_type(), lm.file_type());
    if ut.is_symlink() || lt.is_symlink() {
        return Ok(!(ut.is_symlink() && lt.is_symlink()) || fs::read_link(up)? != fs::read_link(low)?);
    }
    if !(ut.is_file() && lt.is_file()) {
        return Ok(true);
    }
    if um.permissions().mode() & 0o7777 != lm.permissions().mode() & 0o7777 || um.len() != lm.len() {
        return Ok(true);
    }
    Ok(!same_contents(up, low)?)
}

fn same_contents(a: &Path, b: &Path) -> io::Result<bool> {
    let (mut fa, mut fb) = (fs::File::open(a)?, fs::File::open(b)?);
    let (mut ba, mut bb) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
    loop {
        let na = read_full(&mut fa, &mut ba)?;
        let nb = read_full(&mut fb, &mut bb)?;
        if na != nb || ba[..na] != bb[..nb] {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
    }
}

fn read_full(f: &mut fs::File, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn apply(c: &Change) -> Result<()> {
    let ensure_parent = || -> io::Result<()> {
        match c.path.parent() {
            Some(p) => fs::create_dir_all(p),
            None => Ok(()),
        }
    };
    match (c.kind, c.entry) {
        (Kind::Deleted, Entry::Dir) => ignore_missing(fs::remove_dir_all(&c.path))?,
        (Kind::Deleted, _) => ignore_missing(fs::remove_file(&c.path))?,
        (_, Entry::Dir) => {
            fs::create_dir_all(&c.path)?;
            fs::set_permissions(&c.path, fs::symlink_metadata(&c.upper)?.permissions())?;
        }
        (_, Entry::Symlink) => {
            ensure_parent()?;
            ignore_missing(fs::remove_file(&c.path))?;
            symlink(fs::read_link(&c.upper)?, &c.path)?;
        }
        (_, Entry::File) => {
            ensure_parent()?;
            let name = c.path.file_name().context("no file name")?.to_string_lossy();
            let tmp = c.path.with_file_name(format!(".{name}.agentos-commit"));
            fs::copy(&c.upper, &tmp)?;
            fs::rename(&tmp, &c.path)?;
        }
        (_, Entry::Other) => bail!("special files (fifos, sockets, devices) can't be committed"),
    }
    Ok(())
}

fn ignore_missing(r: io::Result<()>) -> io::Result<()> {
    match r {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

fn retire(layer: &Layer, c: &Change) -> Result<()> {
    // Inside a still-opaque dir an entry must stay in the upper layer, or the
    // overlay would read its absence as a deletion.
    if c.implied || under_opaque(&layer.upper, &c.rel) {
        return Ok(());
    }
    let Ok(m) = fs::symlink_metadata(&c.upper) else { return Ok(()) };
    let remove = match c.kind {
        Kind::Deleted => is_whiteout(&m),
        // Directories go once they're empty (see prune).
        _ => !m.is_dir(),
    };
    if remove {
        fs::remove_file(&c.upper)?;
    }
    Ok(())
}

/// Clears the opaque mark from upper dirs whose lower counterpart no longer
/// has entries the upper dir lacks.
fn settle_opaque(upper: &Path, lower: &Path) -> Result<()> {
    for name in sorted_names(upper)? {
        let up = upper.join(&name);
        if fs::symlink_metadata(&up)?.is_dir() {
            settle_opaque(&up, &lower.join(&name))?;
        }
    }
    if is_opaque(upper) {
        let all_present = match sorted_names(lower) {
            Ok(names) => names.iter().all(|n| fs::symlink_metadata(upper.join(n)).is_ok()),
            Err(_) => true,
        };
        if all_present {
            clear_opaque(upper);
        }
    }
    Ok(())
}

/// Removes upper entries that no longer represent a change: empty dirs and
/// files identical to the real ones (no-op copy-ups, or entries an opaque dir
/// held on to until it settled).
fn prune(upper: &Path, lower: &Path) -> Result<()> {
    prune_in(upper, lower, false)
}

fn prune_in(upper: &Path, lower: &Path, in_opaque: bool) -> Result<()> {
    for name in sorted_names(upper)? {
        let (up, low) = (upper.join(&name), lower.join(&name));
        let um = fs::symlink_metadata(&up)?;
        let lm = fs::symlink_metadata(&low).ok();
        if um.is_dir() {
            let opaque = is_opaque(&up);
            prune_in(&up, &low, in_opaque || opaque)?;
            let empty = fs::read_dir(&up)?.next().is_none();
            if empty && !opaque && lm.is_some_and(|m| m.is_dir()) {
                fs::remove_dir(&up)?;
            }
        } else if !in_opaque && !is_whiteout(&um) {
            if let Some(lm) = lm {
                if !lm.is_dir() && !differs(&up, &um, &low, &lm)? {
                    fs::remove_file(&up)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        layer: Layer,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let layer = Layer { index: 0, source: dir.path().join("lower"), upper: dir.path().join("upper") };
        fs::create_dir_all(&layer.source).unwrap();
        fs::create_dir_all(&layer.upper).unwrap();
        Fixture { _dir: dir, layer }
    }

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn kinds(changes: &[Change]) -> Vec<(Kind, String)> {
        changes.iter().map(|c| (c.kind, c.rel.display().to_string())).collect()
    }

    fn whiteout(path: &Path) -> bool {
        let p = CString::new(path.as_os_str().as_bytes()).unwrap();
        unsafe { libc::mknod(p.as_ptr(), libc::S_IFCHR, 0) == 0 }
    }

    fn set_opaque(path: &Path) -> bool {
        let p = CString::new(path.as_os_str().as_bytes()).unwrap();
        let n = CString::new("user.overlay.opaque").unwrap();
        unsafe { libc::lsetxattr(p.as_ptr(), n.as_ptr(), b"y".as_ptr().cast(), 1, 0) == 0 }
    }

    #[test]
    fn scan_ignores_noop_copy_ups_and_commit_retires_entries() {
        let f = fixture();
        let (lo, up) = (&f.layer.source, &f.layer.upper);
        write(&lo.join("same.txt"), "unchanged");
        write(&lo.join("notes.txt"), "line1\n");
        write(&up.join("same.txt"), "unchanged");
        write(&up.join("notes.txt"), "line1\nline2\n");
        write(&up.join("src/new.rs"), "fn new() {}");

        let changes = scan(std::slice::from_ref(&f.layer)).unwrap();
        assert_eq!(
            kinds(&changes),
            vec![(Kind::Modified, "notes.txt".into()), (Kind::Added, "src".into()), (Kind::Added, "src/new.rs".into())]
        );

        let picked = select(changes, &[lo.join("notes.txt")]);
        commit(std::slice::from_ref(&f.layer), &picked).unwrap();
        assert_eq!(fs::read_to_string(lo.join("notes.txt")).unwrap(), "line1\nline2\n");
        assert_eq!(
            kinds(&scan(std::slice::from_ref(&f.layer)).unwrap()),
            vec![(Kind::Added, "src".into()), (Kind::Added, "src/new.rs".into())]
        );

        let rest = scan(std::slice::from_ref(&f.layer)).unwrap();
        commit(std::slice::from_ref(&f.layer), &rest).unwrap();
        assert_eq!(fs::read_to_string(lo.join("src/new.rs")).unwrap(), "fn new() {}");
        assert!(scan(std::slice::from_ref(&f.layer)).unwrap().is_empty());
    }

    #[test]
    fn whiteouts_are_deletions() {
        let f = fixture();
        write(&f.layer.source.join("old/a"), "keep?");
        if !whiteout(&f.layer.upper.join("old")) {
            eprintln!("skipping: creating whiteouts needs CAP_MKNOD");
            return;
        }
        let changes = scan(std::slice::from_ref(&f.layer)).unwrap();
        assert_eq!(kinds(&changes), vec![(Kind::Deleted, "old".into())]);
        assert_eq!(changes[0].entry, Entry::Dir);
        commit(std::slice::from_ref(&f.layer), &changes).unwrap();
        assert!(!f.layer.source.join("old").exists());
        assert!(scan(std::slice::from_ref(&f.layer)).unwrap().is_empty());
    }

    #[test]
    fn opaque_dirs_survive_partial_commits() {
        let f = fixture();
        let (lo, up) = (&f.layer.source, &f.layer.upper);
        write(&lo.join("src/main.rs"), "old main");
        write(&up.join("src/other.rs"), "new file");
        if !set_opaque(&up.join("src")) {
            eprintln!("skipping: filesystem lacks user xattrs");
            return;
        }
        let layers = std::slice::from_ref(&f.layer);
        assert_eq!(
            kinds(&scan(layers).unwrap()),
            vec![(Kind::Deleted, "src/main.rs".into()), (Kind::Added, "src/other.rs".into())]
        );

        // Commit only the addition: the deletion of main.rs must stay pending
        // and the committed file must not turn into a phantom deletion.
        commit(layers, &select(scan(layers).unwrap(), &[lo.join("src/other.rs")])).unwrap();
        assert!(lo.join("src/main.rs").exists() && lo.join("src/other.rs").exists());
        assert_eq!(kinds(&scan(layers).unwrap()), vec![(Kind::Deleted, "src/main.rs".into())]);

        commit(layers, &scan(layers).unwrap()).unwrap();
        assert!(!lo.join("src/main.rs").exists());
        assert!(scan(layers).unwrap().is_empty());
        assert!(!up.join("src").exists(), "settled opaque dir should be pruned");
    }

    #[test]
    fn rollback_of_a_path_keeps_the_rest() {
        let f = fixture();
        write(&f.layer.upper.join("a.txt"), "a");
        write(&f.layer.upper.join("b.txt"), "b");
        let layers = std::slice::from_ref(&f.layer);
        let changes = scan(layers).unwrap();
        rollback(layers, &changes, &[f.layer.source.join("a.txt")]).unwrap();
        assert_eq!(kinds(&scan(layers).unwrap()), vec![(Kind::Added, "b.txt".into())]);
        assert!(rollback(layers, &changes, &[f.layer.source.join("a.txt")]).is_err());
    }
}
