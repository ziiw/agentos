use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    to_ms(SystemTime::now())
}

pub fn to_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn mtime_ms(meta: &fs::Metadata) -> u64 {
    meta.modified().map(to_ms).unwrap_or(0)
}

pub fn rfc3339(ms: u64) -> String {
    humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_millis(ms)).to_string()
}

pub fn ago(ms: u64) -> String {
    let s = now_ms().saturating_sub(ms) / 1000;
    match s {
        0..=59 => format!("{s}s ago"),
        60..=3599 => format!("{}m ago", s / 60),
        3600..=86399 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86400),
    }
}

pub fn duration(ms: u64) -> String {
    match ms {
        0..=999 => format!("{ms}ms"),
        1000..=59_999 => format!("{:.1}s", ms as f64 / 1000.0),
        _ => format!("{}m{}s", ms / 60_000, (ms % 60_000) / 1000),
    }
}

/// Shows paths under $HOME as `~/...`.
pub fn display_path(p: &Path) -> String {
    if let Some(home) = std::env::var_os("HOME") {
        if let Ok(rest) = p.strip_prefix(&home) {
            return if rest.as_os_str().is_empty() {
                "~".into()
            } else {
                format!("~/{}", rest.display())
            };
        }
    }
    p.display().to_string()
}

/// Makes `p` absolute against the current directory and resolves `.`/`..`
/// lexically. Unlike `canonicalize`, works for paths that don't exist on the
/// host yet (e.g. a file the agent created).
pub fn absolutize(p: &Path) -> io::Result<PathBuf> {
    let base = if p.is_absolute() { PathBuf::new() } else { std::env::current_dir()? };
    let mut out = PathBuf::new();
    for c in base.join(p).components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    Ok(out)
}

/// `remove_dir_all` that also copes with overlayfs work dirs, which the
/// kernel leaves behind with mode 000.
pub fn force_remove_dir_all(path: &Path) -> io::Result<()> {
    fn unlock(p: &Path) {
        if let Ok(m) = fs::symlink_metadata(p) {
            if m.is_dir() {
                let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
                if let Ok(entries) = fs::read_dir(p) {
                    for e in entries.flatten() {
                        unlock(&e.path());
                    }
                }
            }
        }
    }
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.is_dir() => {
            unlock(path);
            fs::remove_dir_all(path)
        }
        Ok(_) => fs::remove_file(path),
    }
}

pub fn random_hex(bytes: usize) -> io::Result<String> {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(hex(&buf))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The bytes a hex string spells; none if it isn't hex.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}

/// Standard base64, with padding (RFC 4648).
pub fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= chunk.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_both_ways() {
        assert_eq!(unhex(&hex(&[0, 1, 0xab, 0xff])), Some(vec![0, 1, 0xab, 0xff]));
        for bad in ["a", "zz", "0x12", "é1", "12 "] {
            assert_eq!(unhex(bad), None, "{bad:?}");
        }
        assert_eq!(unhex(""), Some(vec![]));
    }

    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (plain, encoded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("user:pw", "dXNlcjpwdw==")] {
            assert_eq!(base64(plain.as_bytes()), encoded);
        }
    }
}
