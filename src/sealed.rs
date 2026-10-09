//! The vault, encrypted under a key only this machine's TPM gives back.
//!
//! The vault holds real tokens: an agent's login, the sign-ins to your MCP
//! servers. They sit in the task store as files only you can read, which
//! protects them from every sandbox and every other user, but not from a copy
//! of the store (a backup, a stolen disk). `agent vault lock` seals a random
//! key in the TPM and encrypts the vault's files with it (AES-256-GCM, a fresh
//! nonce each write, the file's name authenticated), so a copy is noise
//! anywhere but on this machine's TPM. With `--pcrs 7` the TPM gives the key
//! back only while those PCRs hold what they held when you locked it: a
//! machine that booted something else can't read the vault.
//!
//! Locking is gradual and safe to do while tasks run: a file that doesn't
//! start with the marker is read as it always was, and every write while the
//! vault is locked is encrypted.

use anyhow::{Context, Result, bail};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAGIC: &[u8] = b"AGENTOS-SEALED/1\n";
/// The wrapped key's name in `identity/tpm/`.
const KEY: &str = "vault-key";

fn dir(store_root: &Path) -> PathBuf {
    store_root.join("identity").join("tpm")
}

/// Whether the vault is locked to the TPM.
pub fn locked(store_root: &Path) -> bool {
    dir(store_root).join(format!("{KEY}.pub")).exists()
}

/// The PCRs the key was bound to, if any.
fn bound(store_root: &Path) -> Vec<u32> {
    fs::read_to_string(dir(store_root).join(format!("{KEY}.pcrs")))
        .map(|t| t.trim().split(',').filter_map(|i| i.parse().ok()).collect())
        .unwrap_or_default()
}

/// The key, asked of the TPM once per process.
static CACHE: Mutex<Option<(PathBuf, [u8; 32])>> = Mutex::new(None);

fn key(store_root: &Path) -> Result<[u8; 32]> {
    let mut cache = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((root, key)) = cache.as_ref() {
        if root == store_root {
            return Ok(*key);
        }
    }
    let bytes = crate::tpm::unseal(&dir(store_root), KEY, &bound(store_root)).context("the vault is locked to this machine's TPM, which didn't give its key back")?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("the vault's key isn't the size it should be"))?;
    *cache = Some((store_root.to_path_buf(), key));
    Ok(key)
}

pub fn is_sealed(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// `plain` under `key`, for the file called `name`.
pub fn encrypt(key: &[u8; 32], name: &str, plain: &[u8]) -> Result<Vec<u8>> {
    let sealing = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow::anyhow!("bad key"))?);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&random_bytes(NONCE_LEN)?);
    let mut data = plain.to_vec();
    sealing.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(name.as_bytes()), &mut data).map_err(|_| anyhow::anyhow!("couldn't encrypt"))?;
    Ok([MAGIC, &nonce, &data].concat())
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut buf)?;
    Ok(buf)
}

/// What `encrypt` made, back; it fails for another key, another name or a changed byte.
pub fn decrypt(key: &[u8; 32], name: &str, data: &[u8]) -> Result<Vec<u8>> {
    let body = data.strip_prefix(MAGIC).context("not a sealed file")?;
    if body.len() < NONCE_LEN + AES_256_GCM.tag_len() {
        bail!("{name}: a sealed file that's too short");
    }
    let (nonce, rest) = body.split_at(NONCE_LEN);
    let opening = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow::anyhow!("bad key"))?);
    let mut data = rest.to_vec();
    let plain = opening
        .open_in_place(Nonce::try_assume_unique_for_key(nonce).map_err(|_| anyhow::anyhow!("bad nonce"))?, Aad::from(name.as_bytes()), &mut data)
        .map_err(|_| anyhow::anyhow!("{name} doesn't decrypt: it was changed, moved, or locked with another key"))?;
    Ok(plain.to_vec())
}

fn name_of(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// A vault file's contents, decrypted if it's sealed.
pub fn read(store_root: &Path, path: &Path) -> Result<Vec<u8>> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if is_sealed(&data) { decrypt(&key(store_root)?, &name_of(path), &data) } else { Ok(data) }
}

/// Writes a vault file (private to you, and whole or not at all): encrypted while the vault is locked.
pub fn write(store_root: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let data = if locked(store_root) { encrypt(&key(store_root)?, &name_of(path), bytes)? } else { bytes.to_vec() };
    put(path, &data)
}

fn put(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("save {}", path.display()))
}

/// The files of the vault: logins and sign-ins (not locks or half-written ones).
fn files(store_root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(store_root.join("vault")).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "json")).collect();
    found.sort();
    found
}

/// How many of the vault's files are encrypted, and how many aren't.
pub fn count(store_root: &Path) -> (usize, usize) {
    files(store_root).iter().fold((0, 0), |(sealed, plain), f| if fs::read(f).is_ok_and(|d| is_sealed(&d)) { (sealed + 1, plain) } else { (sealed, plain + 1) })
}

/// Seals a new key in the TPM (bound to `pcrs`, if any) and encrypts the vault's files with it.
pub fn lock(store_root: &Path, pcrs: &[u32]) -> Result<usize> {
    if locked(store_root) {
        bail!("the vault is locked already (`agent vault unlock` first to change how)");
    }
    let new: [u8; 32] = random_bytes(32)?.try_into().map_err(|_| anyhow::anyhow!("no randomness"))?;
    let tpm_dir = dir(store_root);
    crate::tpm::seal(&tpm_dir, KEY, &new, pcrs)?;
    if !pcrs.is_empty() {
        fs::write(tpm_dir.join(format!("{KEY}.pcrs")), pcrs.iter().map(u32::to_string).collect::<Vec<_>>().join(","))?;
    }
    // Whoever reads the key back from the TPM must get what we encrypt with.
    let check = crate::tpm::unseal(&tpm_dir, KEY, pcrs).context("the TPM sealed the key but won't give it back")?;
    if check != new {
        bail!("the TPM gave back another key than it was given");
    }
    *CACHE.lock().unwrap_or_else(|p| p.into_inner()) = Some((store_root.to_path_buf(), new));
    let mut done = 0;
    for file in files(store_root) {
        let data = fs::read(&file)?;
        if !is_sealed(&data) {
            put(&file, &encrypt(&new, &name_of(&file), &data)?)?;
            done += 1;
        }
    }
    Ok(done)
}

/// Decrypts the vault's files and lets the key go.
pub fn unlock(store_root: &Path) -> Result<usize> {
    if !locked(store_root) {
        bail!("the vault isn't locked");
    }
    let key = key(store_root)?;
    let mut done = 0;
    for file in files(store_root) {
        let data = fs::read(&file)?;
        if is_sealed(&data) {
            put(&file, &decrypt(&key, &name_of(&file), &data)?)?;
            done += 1;
        }
    }
    let tpm_dir = dir(store_root);
    for ext in ["pub", "priv", "pcrs"] {
        let _ = fs::remove_file(tpm_dir.join(format!("{KEY}.{ext}")));
    }
    *CACHE.lock().unwrap_or_else(|p| p.into_inner()) = None;
    Ok(done)
}

/// The mode a vault file has.
pub fn private(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_file_comes_back_only_to_its_key_and_name() {
        let key = [7u8; 32];
        let secret = br#"{"tokens":[["sk-ant-oat01-agentosplaceholder-x","sk-ant-oat01-real"]]}"#;
        let sealed = encrypt(&key, "claude.json", secret).unwrap();
        assert!(is_sealed(&sealed) && !is_sealed(secret));
        assert!(!sealed.windows(8).any(|w| w == b"oat01-re"), "no plaintext in it");
        assert_eq!(decrypt(&key, "claude.json", &sealed).unwrap(), secret);
        // Each write has its own nonce.
        assert_ne!(sealed, encrypt(&key, "claude.json", secret).unwrap());
        // Another key, another file name, a changed byte, a cut file: no.
        assert!(decrypt(&[8u8; 32], "claude.json", &sealed).is_err());
        assert!(decrypt(&key, "mcp-linear.json", &sealed).is_err(), "a file can't be passed off as another");
        let mut changed = sealed.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(decrypt(&key, "claude.json", &changed).is_err());
        let mut nonce_changed = sealed.clone();
        nonce_changed[MAGIC.len()] ^= 1;
        assert!(decrypt(&key, "claude.json", &nonce_changed).is_err());
        assert!(decrypt(&key, "claude.json", &sealed[..sealed.len() - 3]).is_err());
        assert!(decrypt(&key, "claude.json", MAGIC).is_err() && decrypt(&key, "claude.json", b"plain").is_err());
    }

    #[test]
    fn a_vault_that_isnt_locked_reads_and_writes_as_it_always_did() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("vault")).unwrap();
        let file = dir.path().join("vault/claude.json");
        assert!(!locked(dir.path()));
        write(dir.path(), &file, b"{\"tokens\":[]}").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"{\"tokens\":[]}", "plain on disk");
        assert_eq!(read(dir.path(), &file).unwrap(), b"{\"tokens\":[]}");
        assert!(private(&file));
        assert_eq!(count(dir.path()), (0, 1));
        assert!(unlock(dir.path()).is_err(), "nothing to unlock");
        assert!(read(dir.path(), &dir.path().join("vault/none.json")).is_err());
    }
}
