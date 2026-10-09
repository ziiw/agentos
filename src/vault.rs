//! Login vault: an agent's OAuth tokens live here, outside every sandbox.
//!
//! The agent's own credentials file only holds look-alike placeholders. The
//! credential broker swaps them for the real tokens on the wire: in the
//! `Authorization` header of API calls, and in the body of token-endpoint
//! requests (refresh). Token-endpoint *responses* go the other way: new real
//! tokens are stored here and replaced with fresh placeholders before the
//! agent sees them, so even a `/login` inside the sandbox never hands the
//! agent a real token.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Marks a value as ours: `sk-ant-oat01-agentosplaceholder-…`.
const MARK: &str = "agentosplaceholder";
/// JSON keys whose string values are tokens (Claude's file, OAuth responses).
const TOKEN_KEYS: &[&str] = &["accessToken", "refreshToken", "access_token", "refresh_token", "id_token"];
/// Placeholders remembered per agent; older ones stop working.
const KEEP: usize = 16;

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// (placeholder, real token), oldest first.
    tokens: Vec<(String, String)>,
    /// `agent vault unseal`: leave this agent's login alone.
    #[serde(default)]
    disabled: bool,
}

pub struct Vault {
    root: PathBuf,
    path: PathBuf,
    state: Mutex<State>,
}

pub fn is_placeholder(token: &str) -> bool {
    token.contains(MARK)
}

impl Vault {
    pub fn open(store_root: &Path, agent: &str) -> Result<Vault> {
        let dir = store_root.join("vault");
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        let path = dir.join(format!("{agent}.json"));
        // (read through the TPM-locked form, if the vault is locked: a TPM that doesn't answer is an error, not an empty vault)
        let state = if path.exists() {
            serde_json::from_slice(&crate::sealed::read(store_root, &path)?).with_context(|| format!("{} is corrupt", path.display()))?
        } else {
            State::default()
        };
        Ok(Vault { root: store_root.to_path_buf(), path, state: Mutex::new(state) })
    }

    fn save(&self, state: &State) -> Result<()> {
        crate::sealed::write(&self.root, &self.path, &serde_json::to_vec_pretty(state)?)
    }

    pub fn disabled(&self) -> bool {
        self.state.lock().map(|s| s.disabled).unwrap_or(false)
    }

    pub fn set_disabled(&self, disabled: bool) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| anyhow::anyhow!("vault lock"))?;
        s.disabled = disabled;
        self.save(&s)
    }

    pub fn real(&self, placeholder: &str) -> Option<String> {
        let s = self.state.lock().ok()?;
        s.tokens.iter().rev().find(|(p, _)| p == placeholder).map(|(_, r)| r.clone())
    }

    /// A placeholder for `real` (the same one if it's already stored), keeping
    /// the token's prefix (`sk-ant-oat01-`) so clients that check it are happy.
    fn seal_one(state: &mut State, real: &str) -> String {
        if let Some((p, _)) = state.tokens.iter().find(|(_, r)| r == real) {
            return p.clone();
        }
        let prefix: String = real.splitn(4, '-').take(3).map(|part| format!("{part}-")).collect();
        let suffix = crate::util::random_hex(16).unwrap_or_default();
        let placeholder = format!("{prefix}{MARK}-{suffix}");
        state.tokens.push((placeholder.clone(), real.to_string()));
        if state.tokens.len() > KEEP {
            state.tokens.remove(0);
        }
        placeholder
    }

    /// Replaces real tokens in a JSON document with placeholders. Returns the
    /// sealed document and how many tokens were sealed.
    pub fn seal_json(&self, doc: &[u8]) -> Result<(Vec<u8>, usize)> {
        let mut value: Value = serde_json::from_slice(doc)?;
        let mut state = self.state.lock().map_err(|_| anyhow::anyhow!("vault lock"))?;
        let mut sealed = 0;
        walk(&mut value, &mut |key, s| {
            if TOKEN_KEYS.contains(&key) && !is_placeholder(s) && !s.is_empty() {
                *s = Self::seal_one(&mut state, s);
                sealed += 1;
            }
        });
        if sealed > 0 {
            self.save(&state)?;
        }
        Ok((serde_json::to_vec(&value)?, sealed))
    }

    /// Replaces placeholders in a JSON document with the real tokens.
    /// Returns the document and how many were replaced.
    pub fn unseal_json(&self, doc: &[u8]) -> Result<(Vec<u8>, usize)> {
        let mut value: Value = serde_json::from_slice(doc)?;
        let mut unsealed = 0;
        walk(&mut value, &mut |_, s| {
            if is_placeholder(s) {
                if let Some(real) = self.real(s) {
                    *s = real;
                    unsealed += 1;
                }
            }
        });
        Ok((serde_json::to_vec(&value)?, unsealed))
    }

    /// Seals the tokens in an agent's credentials file, in place.
    pub fn seal_file(&self, path: &Path) -> Result<usize> {
        self.rewrite_file(path, |doc| self.seal_json(doc))
    }

    /// Puts the real tokens back into an agent's credentials file.
    pub fn unseal_file(&self, path: &Path) -> Result<usize> {
        self.rewrite_file(path, |doc| self.unseal_json(doc))
    }

    fn rewrite_file(&self, path: &Path, f: impl FnOnce(&[u8]) -> Result<(Vec<u8>, usize)>) -> Result<usize> {
        let Ok(doc) = fs::read(path) else { return Ok(0) };
        let (new, n) = f(&doc).with_context(|| format!("{} isn't the JSON expected", path.display()))?;
        if n > 0 {
            let tmp = path.with_extension("agentos-tmp");
            let mut out = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            // Pretty like the original, so the agent sees a normal file.
            let pretty: Value = serde_json::from_slice(&new)?;
            out.write_all(&serde_json::to_vec_pretty(&pretty)?)?;
            fs::rename(&tmp, path)?;
        }
        Ok(n)
    }

    /// API call headers: a placeholder in `Authorization: Bearer …` or
    /// `x-api-key` becomes the real token.
    pub fn inject_header(&self, name: &str, value: &mut String) -> bool {
        let token = if name.eq_ignore_ascii_case("authorization") {
            value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))
        } else if name.eq_ignore_ascii_case("x-api-key") {
            Some(value.as_str())
        } else {
            None
        };
        let Some(real) = token.filter(|t| is_placeholder(t)).and_then(|t| self.real(t)) else { return false };
        *value = if name.eq_ignore_ascii_case("authorization") { format!("Bearer {real}") } else { real };
        true
    }

    /// Whether a sealed file's placeholders are all known here (a lost vault
    /// means logging in again).
    pub fn knows_all(&self, path: &Path) -> bool {
        let Ok(doc) = fs::read(path) else { return true };
        let Ok(mut value) = serde_json::from_slice::<Value>(&doc) else { return true };
        let mut ok = true;
        walk(&mut value, &mut |_, s| {
            if is_placeholder(s) && self.real(s).is_none() {
                ok = false;
            }
        });
        ok
    }
}

/// Calls `f(key, string)` for every string value under an object key.
fn walk(v: &mut Value, f: &mut impl FnMut(&str, &mut String)) {
    match v {
        Value::Object(map) => {
            for (k, child) in map.iter_mut() {
                if let Value::String(s) = child {
                    f(k, s);
                } else {
                    walk(child, f);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|c| walk(c, f)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDS: &str = r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-REALACCESS","refreshToken":"sk-ant-ort01-REALREFRESH","expiresAt":1,"scopes":["user:inference"],"subscriptionType":"pro"}}"#;

    #[test]
    fn sealing_a_credentials_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), "claude").unwrap();
        let file = dir.path().join("creds.json");
        fs::write(&file, CREDS).unwrap();

        assert_eq!(vault.seal_file(&file).unwrap(), 2);
        let sealed = fs::read_to_string(&file).unwrap();
        assert!(!sealed.contains("REALACCESS") && !sealed.contains("REALREFRESH"));
        assert!(sealed.contains("sk-ant-oat01-agentosplaceholder-") && sealed.contains("\"subscriptionType\": \"pro\""));
        assert_eq!(vault.seal_file(&file).unwrap(), 0, "sealing twice changes nothing");

        // A fresh handle reads the persisted vault.
        let again = Vault::open(dir.path(), "claude").unwrap();
        assert!(again.knows_all(&file));
        assert_eq!(again.unseal_file(&file).unwrap(), 2);
        assert!(fs::read_to_string(&file).unwrap().contains("REALACCESS"));
    }

    #[test]
    fn headers_and_token_endpoint_bodies() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), "claude").unwrap();
        let (sealed, _) = vault.seal_json(CREDS.as_bytes()).unwrap();
        let sealed: Value = serde_json::from_slice(&sealed).unwrap();
        let access = sealed["claudeAiOauth"]["accessToken"].as_str().unwrap().to_string();
        let refresh = sealed["claudeAiOauth"]["refreshToken"].as_str().unwrap().to_string();

        let mut auth = format!("Bearer {access}");
        assert!(vault.inject_header("Authorization", &mut auth));
        assert_eq!(auth, "Bearer sk-ant-oat01-REALACCESS");
        let mut other = format!("Bearer {access}");
        assert!(!vault.inject_header("x-forwarded", &mut other), "only auth headers");
        let mut unknown = "Bearer sk-ant-oat01-agentosplaceholder-nope".to_string();
        assert!(!vault.inject_header("authorization", &mut unknown));

        // Refresh: the request carries the placeholder out…
        let req = format!(r#"{{"grant_type":"refresh_token","refresh_token":"{refresh}","client_id":"x"}}"#);
        let (out, n) = vault.unseal_json(req.as_bytes()).unwrap();
        assert_eq!(n, 1);
        assert!(String::from_utf8(out).unwrap().contains("sk-ant-ort01-REALREFRESH"));
        // …and the response's new tokens come back sealed.
        let resp = r#"{"access_token":"sk-ant-oat01-NEWACCESS","refresh_token":"sk-ant-ort01-NEWREFRESH","expires_in":28800}"#;
        let (back, n) = vault.seal_json(resp.as_bytes()).unwrap();
        let back = String::from_utf8(back).unwrap();
        assert_eq!(n, 2);
        assert!(!back.contains("NEWACCESS") && back.contains("\"expires_in\":28800"));
        let new_access: Value = serde_json::from_str(&back).unwrap();
        assert_eq!(vault.real(new_access["access_token"].as_str().unwrap()).as_deref(), Some("sk-ant-oat01-NEWACCESS"));
    }
}
