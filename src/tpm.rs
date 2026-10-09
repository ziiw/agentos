//! The machine's TPM, through tpm2-tools: a key that signs receipts and never
//! leaves it, and the PCRs that say what the machine booted.
//!
//! ```toml
//! [journal]                               # your config only
//! key = "tpm"                             # sign receipts with a key the TPM holds (default: "file")
//! pcrs = [0, 2, 4, 7]                     # and put these PCRs (sha256) in each receipt
//! ```
//!
//! The signing key is an ECDSA P-256 key made inside the TPM under its owner
//! hierarchy: its private part leaves only wrapped by that TPM, so a copy of
//! the task store (a backup, a stolen disk) can't sign anything, which a file
//! key can. The wrapped blobs are kept in the store; each signing loads them
//! into the TPM, signs, and flushes. Anyone can check a receipt without a TPM:
//! it carries the public key.
//!
//! The PCRs in a receipt are what the TPM held when the task ended: the
//! measurements of firmware, boot loader, kernel and policy. They are only
//! evidence of what the machine booted if you know what good values are
//! (`agent attest --verify --expect-pcr 7=…`).
//!
//! The TPM is reached as the tools reach it: `TPM2TOOLS_TCTI` if set (a
//! software TPM for tests), else `/dev/tpmrm0`, which a user in the `tss`
//! group may open.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A tpm2-tools program that doesn't answer in this long is stuck.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Runs a tpm2-tools program in `dir` and returns what it printed.
fn run(dir: &Path, tool: &str, args: &[&str]) -> Result<String> {
    let mut child = Command::new(tool)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!("{tool} isn't installed (tpm2-tools)"),
            _ => anyhow::anyhow!("couldn't start {tool}: {e}"),
        })?;
    let reader = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.by_ref().take(1 << 20).read_to_end(&mut buf);
            buf
        })
    };
    let (out, err) = (reader(Box::new(child.stdout.take().unwrap())), reader(Box::new(child.stderr.take().unwrap())));
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{tool} didn't answer in {} seconds", TIMEOUT.as_secs());
            }
        }
    };
    let (out, err) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
    if !status.success() {
        // The tools' last line says what went wrong; the rest is a trace.
        let said = String::from_utf8_lossy(&err);
        let why = said.lines().rev().find(|l| l.starts_with("ERROR")).or_else(|| said.lines().last()).unwrap_or("no reason given");
        bail!("{tool}: {}", crate::approvals::sanitize(why, 300));
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Whether there is a TPM to talk to, and if not, why.
pub fn check() -> Result<(), String> {
    let dir = std::env::temp_dir();
    run(&dir, "tpm2_getrandom", &["--hex", "4"]).map(|_| ()).map_err(|e| format!("{e:#}"))
}

/// A private working folder, gone when dropped.
struct Work(PathBuf);

impl Work {
    fn new(parent: &Path) -> Result<Work> {
        let dir = parent.join(format!("run-{}", crate::util::random_hex(6)?));
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        Ok(Work(dir))
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Everything in the TPM that this process loaded is let go. (Behind a
/// resource manager, `/dev/tpmrm0`, that is only this process's; a bare
/// software TPM has three slots for everyone.)
fn flush(dir: &Path) {
    let _ = run(dir, "tpm2_flushcontext", &["--transient-object"]);
}

/// Makes the owner's primary key: the same one each time on one TPM, so the
/// wrapped blobs below load under it.
fn primary(dir: &Path) -> Result<()> {
    run(dir, "tpm2_createprimary", &["-C", "o", "-G", "ecc256", "-g", "sha256", "-c", "primary.ctx"])?;
    flush(dir);
    Ok(())
}

/// Only one tpm2-tools sequence at a time, across processes: they share a few object slots.
struct Lock {
    _file: fs::File,
}

impl Lock {
    fn take(dir: &Path) -> Result<Lock> {
        let file = fs::OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(dir.join("lock"))?;
        use std::os::fd::AsRawFd;
        // (blocks until the other one is done)
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            bail!("couldn't lock {}", dir.join("lock").display());
        }
        Ok(Lock { _file: file })
    }
}

/// The signing key the TPM holds, as kept in the store.
pub struct Key {
    dir: PathBuf,
    /// The public key: an uncompressed P-256 point (04, x, y).
    pub point: Vec<u8>,
}

/// The uncompressed point at the end of a P-256 SubjectPublicKeyInfo.
pub fn point_of_spki(der: &[u8]) -> Option<Vec<u8>> {
    (der.len() >= 65 && der[der.len() - 65] == 4).then(|| der[der.len() - 65..].to_vec())
}

impl Key {
    /// The key in `store_root/identity/tpm/`, made the first time.
    pub fn load_or_create(store_root: &Path) -> Result<Key> {
        let dir = store_root.join("identity").join("tpm");
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let _lock = Lock::take(&dir)?;
        let (public, private, point) = (dir.join("key.pub"), dir.join("key.priv"), dir.join("public.hex"));
        if !(public.exists() && private.exists()) {
            let work = Work::new(&dir)?;
            primary(&work.0)?;
            run(
                &work.0,
                "tpm2_create",
                &["-C", "primary.ctx", "-G", "ecc256:ecdsa-sha256", "-a", "sign|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda", "-u", "key.pub", "-r", "key.priv"],
            )
            .context("make a signing key in the TPM")?;
            flush(&work.0);
            for (name, to) in [("key.pub", &public), ("key.priv", &private)] {
                fs::set_permissions(work.0.join(name), fs::Permissions::from_mode(0o600))?;
                fs::rename(work.0.join(name), to)?;
            }
            let _ = fs::remove_file(&point);
        }
        let bytes = match fs::read_to_string(&point).ok().and_then(|h| crate::util::unhex(h.trim())).filter(|b| b.len() == 65) {
            Some(b) => b,
            None => {
                let work = Work::new(&dir)?;
                fs::copy(&public, work.0.join("key.pub"))?;
                fs::copy(&private, work.0.join("key.priv"))?;
                load(&work.0)?;
                run(&work.0, "tpm2_readpublic", &["-c", "key.ctx", "-f", "der", "-o", "pub.der"])?;
                flush(&work.0);
                let der = fs::read(work.0.join("pub.der")).context("read the public key")?;
                let b = point_of_spki(&der).context("the TPM's public key isn't a P-256 key")?;
                fs::write(&point, crate::util::hex(&b))?;
                b
            }
        };
        Ok(Key { dir, point: bytes })
    }

    /// Signs `message` (the TPM hashes it with SHA-256): an ECDSA signature, DER.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let _lock = Lock::take(&self.dir)?;
        let work = Work::new(&self.dir)?;
        fs::copy(self.dir.join("key.pub"), work.0.join("key.pub"))?;
        fs::copy(self.dir.join("key.priv"), work.0.join("key.priv"))?;
        fs::write(work.0.join("message"), message)?;
        load(&work.0)?;
        let signed = run(&work.0, "tpm2_sign", &["-c", "key.ctx", "-g", "sha256", "-s", "ecdsa", "-f", "plain", "-o", "signature", "message"]);
        flush(&work.0);
        signed.context("sign with the TPM")?;
        fs::read(work.0.join("signature")).context("read the TPM's signature")
    }
}

/// Loads `key.pub`/`key.priv` under the primary into `key.ctx`.
fn load(dir: &Path) -> Result<()> {
    primary(dir)?;
    run(dir, "tpm2_load", &["-C", "primary.ctx", "-u", "key.pub", "-r", "key.priv", "-c", "key.ctx"]).context("load the signing key into the TPM")?;
    flush(dir);
    Ok(())
}

/// Seals `secret` in the TPM under the owner's primary key, wrapped as
/// `dir/NAME.pub` and `dir/NAME.priv`. With `pcrs`, the TPM gives it back only
/// while those PCRs (sha256) hold what they hold now.
pub fn seal(dir: &Path, name: &str, secret: &[u8], pcrs: &[u32]) -> Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let _lock = Lock::take(dir)?;
    let work = Work::new(dir)?;
    primary(&work.0)?;
    fs::write(work.0.join("secret"), secret)?;
    let list = pcrs.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    let selection = format!("sha256:{list}");
    let mut args = vec!["-C", "primary.ctx", "-i", "secret", "-u", "sealed.pub", "-r", "sealed.priv"];
    if pcrs.is_empty() {
        args.extend(["-a", "fixedtpm|fixedparent|noda|userwithauth"]);
    } else {
        run(&work.0, "tpm2_createpolicy", &["--policy-pcr", "-l", &selection, "-L", "policy.dat"]).context("make a policy for those PCRs")?;
        flush(&work.0);
        // (no password to fall back on: only the policy opens it)
        args.extend(["-L", "policy.dat", "-a", "fixedtpm|fixedparent|noda"]);
    }
    let created = run(&work.0, "tpm2_create", &args).context("seal a secret in the TPM");
    flush(&work.0);
    created?;
    for (from, to) in [("sealed.pub", format!("{name}.pub")), ("sealed.priv", format!("{name}.priv"))] {
        fs::set_permissions(work.0.join(from), fs::Permissions::from_mode(0o600))?;
        fs::rename(work.0.join(from), dir.join(to))?;
    }
    Ok(())
}

/// What `seal` sealed, if the TPM is the same and (when it was bound to PCRs) they hold what they did.
pub fn unseal(dir: &Path, name: &str, pcrs: &[u32]) -> Result<Vec<u8>> {
    let _lock = Lock::take(dir)?;
    let work = Work::new(dir)?;
    fs::copy(dir.join(format!("{name}.pub")), work.0.join("sealed.pub")).with_context(|| format!("read {name}.pub"))?;
    fs::copy(dir.join(format!("{name}.priv")), work.0.join("sealed.priv"))?;
    primary(&work.0)?;
    let loaded = run(&work.0, "tpm2_load", &["-C", "primary.ctx", "-u", "sealed.pub", "-r", "sealed.priv", "-c", "sealed.ctx"]).context("load the sealed secret into the TPM (is this the TPM that sealed it?)");
    flush(&work.0);
    loaded?;
    let result = if pcrs.is_empty() {
        run(&work.0, "tpm2_unseal", &["-c", "sealed.ctx", "-o", "secret"])
    } else {
        let selection = format!("sha256:{}", pcrs.iter().map(u32::to_string).collect::<Vec<_>>().join(","));
        run(&work.0, "tpm2_startauthsession", &["--policy-session", "-S", "session.ctx"])
            .and_then(|_| run(&work.0, "tpm2_policypcr", &["-S", "session.ctx", "-l", &selection]))
            .and_then(|_| run(&work.0, "tpm2_unseal", &["-c", "sealed.ctx", "-p", "session:session.ctx", "-o", "secret"]))
            .map_err(|e| anyhow::anyhow!("{e:#} (the PCRs are not what they were when it was sealed)"))
    };
    let _ = run(&work.0, "tpm2_flushcontext", &["session.ctx"]);
    flush(&work.0);
    result.context("unseal with the TPM")?;
    fs::read(work.0.join("secret")).context("read the unsealed secret")
}

/// What `tpm2_pcrread sha256:0,7` prints, as {index: hex}.
pub fn parse_pcrread(text: &str) -> BTreeMap<u32, String> {
    text.lines()
        .filter_map(|line| {
            let (index, value) = line.split_once(':')?;
            let value = value.trim().strip_prefix("0x")?;
            (value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())).then(|| Some((index.trim().parse::<u32>().ok()?, value.to_ascii_lowercase())))?
        })
        .collect()
}

/// The PCRs (sha256 bank) the TPM holds now.
pub fn pcrs(which: &[u32]) -> Result<BTreeMap<u32, String>> {
    if which.is_empty() {
        return Ok(BTreeMap::new());
    }
    let list = which.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    let out = run(&std::env::temp_dir(), "tpm2_pcrread", &[&format!("sha256:{list}")])?;
    let got = parse_pcrread(&out);
    if let Some(missing) = which.iter().find(|i| !got.contains_key(i)) {
        bail!("the TPM didn't report PCR {missing}");
    }
    Ok(got)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcrread_output_is_read() {
        let out = "  sha256:\n    0 : 0x0000000000000000000000000000000000000000000000000000000000000000\n    7 : 0x589F9FFED4C477966BFB8D41F37895B08C69047DF8F911D6F3B57FBE08FAEE8D\n";
        let got = parse_pcrread(out);
        assert_eq!(got.len(), 2);
        assert_eq!(got[&7], "589f9ffed4c477966bfb8d41f37895b08c69047df8f911d6f3b57fbe08faee8d", "lowercased, without 0x");
        assert_eq!(got[&0], "0".repeat(64));
        assert!(parse_pcrread("sha256:\n 7 : 0x12\n x : 0x00\n").is_empty(), "short or odd lines are skipped");
        assert!(parse_pcrread("").is_empty());
    }

    #[test]
    fn a_public_key_is_the_point_at_the_end_of_its_spki() {
        // The fixed header of a P-256 SubjectPublicKeyInfo, then 04 x y.
        let mut spki = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];
        let point: Vec<u8> = std::iter::once(4u8).chain(1..=64).collect();
        spki.extend(&point);
        assert_eq!(point_of_spki(&spki), Some(point));
        assert_eq!(point_of_spki(&[1, 2, 3]), None);
        assert_eq!(point_of_spki(&[0u8; 100]), None, "not an uncompressed point");
    }
}
