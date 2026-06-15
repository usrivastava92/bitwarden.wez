//! The data plane: decrypt the vault from the Bitwarden desktop app's own synced
//! `data.json`, using a user key supplied by the agent (held in memory, never on
//! disk). No `bw` CLI is involved.
//!
//! `obtain_user_key()` performs the biometric unlock (via the desktop bridge)
//! and returns the key; the agent holds it. `list_with_key`/`get_field_with_key`
//! take that key and decrypt — reads never spawn `bw`. Personal + organization
//! login items are supported.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::crypto::{PrivateKey, SymmetricKey};
use crate::protocol::Session;
use crate::totp;

/// Perform a biometric unlock via the desktop bridge and return the user key.
/// No caching — the agent holds the key in memory.
pub fn obtain_user_key() -> Result<SymmetricKey> {
    let user_id = desktop_user_id()?;
    let mut session =
        Session::establish(&user_id).context("connecting to the Bitwarden desktop app")?;
    let token = session.biometric_unlock().context("biometric unlock")?;
    SymmetricKey::from_b64(&token).context("decoding the unlocked user key")
}

/// Compact JSON array of login items (personal + organization), decrypted with `uk`.
pub fn list_with_key(uk: &SymmetricKey) -> Result<String> {
    let data = read_vault_data()?;
    let ciphers = find_suffix(&data, "_ciphers_ciphers")
        .ok_or_else(|| anyhow!("no items found in the vault — open the Bitwarden desktop app and let it sync"))?;
    let folders = folder_map(&data, uk);
    let orgs = org_keys(&data, uk);

    let mut out = Vec::new();
    if let Some(obj) = ciphers.as_object() {
        for c in obj.values() {
            if !is_login(c) {
                continue;
            }
            let Some(id) = c.get("id").and_then(|v| v.as_str()) else { continue };
            let Some(base) = base_key(c, uk, &orgs) else { continue };
            let ik = match item_key(base, c) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let login = c.get("login");
            out.push(serde_json::json!({
                "id": id,
                "name": dec_opt(&ik, c.get("name")).unwrap_or_default(),
                "username": dec_opt(&ik, login.and_then(|l| l.get("username"))).unwrap_or_default(),
                "folder": c.get("folderId").and_then(|v| v.as_str())
                    .and_then(|fid| folders.get(fid).cloned()).unwrap_or_default(),
                "uri": dec_opt(&ik, first_uri(login)).unwrap_or_default(),
            }));
        }
    }
    Ok(serde_json::to_string(&out)?)
}

/// Get one field of an item by id, decrypted with `uk`.
pub fn get_field_with_key(uk: &SymmetricKey, id: &str, field: &str) -> Result<String> {
    let data = read_vault_data()?;
    let ciphers = find_suffix(&data, "_ciphers_ciphers")
        .ok_or_else(|| anyhow!("no items found in the vault — open the Bitwarden desktop app and let it sync"))?;
    let c = ciphers
        .as_object()
        .and_then(|o| o.values().find(|c| c.get("id").and_then(|v| v.as_str()) == Some(id)))
        .ok_or_else(|| anyhow!("item {id} not found"))?;

    let orgs = org_keys(&data, uk);
    let base = base_key(c, uk, &orgs)
        .ok_or_else(|| anyhow!("missing organization key for this item"))?;
    let ik = item_key(base, c)?;
    let login = c.get("login");
    let enc = match field {
        "password" => login.and_then(|l| l.get("password")),
        "username" => login.and_then(|l| l.get("username")),
        "uri" => first_uri(login),
        "notes" => c.get("notes"),
        "totp" => login.and_then(|l| l.get("totp")),
        other => return Err(anyhow!("unknown field: {other}")),
    }
    .and_then(|v| v.as_str())
    .ok_or_else(|| anyhow!("item has no {field}"))?;

    let value = ik.decrypt_str(enc)?;
    if field == "totp" {
        totp::generate(&value)
    } else {
        Ok(value)
    }
}

// ---------------------------------------------------------------------------
// cipher decryption helpers
// ---------------------------------------------------------------------------

fn is_login(c: &Value) -> bool {
    c.get("type").and_then(|t| t.as_i64()) == Some(1)
}

/// The base key for a cipher: the org key if it belongs to an organization
/// (None if we couldn't unwrap that org's key), otherwise the user key.
fn base_key<'a>(
    c: &Value,
    uk: &'a SymmetricKey,
    orgs: &'a HashMap<String, SymmetricKey>,
) -> Option<&'a SymmetricKey> {
    match c.get("organizationId").and_then(|v| v.as_str()) {
        Some(org_id) => orgs.get(org_id),
        None => Some(uk),
    }
}

/// Item key: the cipher's own key (decrypted with the base key) if present,
/// else the base key itself.
fn item_key(base: &SymmetricKey, c: &Value) -> Result<SymmetricKey> {
    match c.get("key").and_then(|v| v.as_str()) {
        Some(k) => {
            let raw = base.decrypt(k).context("decrypting item key")?;
            SymmetricKey::from_bytes(&raw)
        }
        None => Ok(base.clone()),
    }
}

fn dec_opt(key: &SymmetricKey, v: Option<&Value>) -> Option<String> {
    v.and_then(|x| x.as_str()).and_then(|s| key.decrypt_str(s).ok())
}

fn first_uri(login: Option<&Value>) -> Option<&Value> {
    login
        .and_then(|l| l.get("uris"))
        .and_then(|u| u.as_array())
        .and_then(|a| a.first())
        .and_then(|f| f.get("uri"))
}

fn folder_map(data: &Value, uk: &SymmetricKey) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some(folders) = find_suffix(data, "_folder_folders").and_then(|f| f.as_object()) {
        for (id, f) in folders {
            if let Some(name) = dec_opt(uk, f.get("name")) {
                m.insert(id.clone(), name);
            }
        }
    }
    m
}

/// orgId -> organization symmetric key (account RSA private key unwraps each type-4 org key).
fn org_keys(data: &Value, uk: &SymmetricKey) -> HashMap<String, SymmetricKey> {
    let mut map = HashMap::new();
    let Some(pk) = account_private_key(data, uk) else {
        return map;
    };
    if let Some(orgk) = find_suffix(data, "_crypto_organizationKeys").and_then(|v| v.as_object()) {
        for (org_id, entry) in orgk {
            if let Some(enc) = entry.get("key").and_then(|v| v.as_str()) {
                if let Ok(raw) = pk.decrypt_type4(enc) {
                    if let Ok(k) = SymmetricKey::from_bytes(&raw) {
                        map.insert(org_id.clone(), k);
                    }
                }
            }
        }
    }
    map
}

fn account_private_key(data: &Value, uk: &SymmetricKey) -> Option<PrivateKey> {
    // The account's RSA private key (type-2 EncString under the user key). The
    // `bw` CLI nests it under `_crypto_accountCryptographicState.V1.private_key`;
    // the desktop app stores it flat as `_crypto_privateKey`. Try both so we can
    // read either vault store.
    let enc = find_suffix(data, "_crypto_accountCryptographicState")
        .and_then(|v| v.get("V1"))
        .and_then(|v| v.get("private_key"))
        .and_then(|v| v.as_str())
        .or_else(|| find_suffix(data, "_crypto_privateKey").and_then(|v| v.as_str()))?;
    let der = uk.decrypt(enc).ok()?;
    PrivateKey::from_pkcs8_der(&der).ok()
}

// ---------------------------------------------------------------------------
// bw data.json
// ---------------------------------------------------------------------------

/// Candidate locations for the desktop app's own vault store.
fn desktop_data_candidates() -> Vec<PathBuf> {
    match dirs::home_dir() {
        Some(home) => vec![
            // Mac App Store (sandboxed container) build.
            home.join("Library/Containers/com.bitwarden.desktop/Data/Library/Application Support/Bitwarden/data.json"),
            // Direct-download build.
            home.join("Library/Application Support/Bitwarden/data.json"),
        ],
        None => Vec::new(),
    }
}

/// The Bitwarden desktop app's own synced vault, if present. The app keeps it
/// fresh while running, and it must be running for biometric unlock anyway — so
/// no `bw` CLI is required.
fn desktop_data_path() -> Option<PathBuf> {
    desktop_data_candidates().into_iter().find(|p| p.exists())
}

/// Resolve the vault data file: an explicit override, else the desktop app's store.
fn vault_data_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BW_WEZ_VAULT_DATA") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    desktop_data_path()
}

fn read_vault_data() -> Result<Value> {
    let path = vault_data_path().ok_or_else(|| {
        anyhow!("could not find the Bitwarden desktop app's vault on disk — is the desktop app installed and signed in? (or set BW_WEZ_VAULT_DATA)")
    })?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading vault store {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

/// bw namespaces its keys as `user_<uid>_<area>`; find a value by key suffix.
fn find_suffix<'a>(data: &'a Value, suffix: &str) -> Option<&'a Value> {
    data.as_object()?
        .iter()
        .find(|(k, _)| k.ends_with(suffix))
        .map(|(_, v)| v)
}

// ---------------------------------------------------------------------------
// userId resolution (for the setupEncryption handshake)
// ---------------------------------------------------------------------------

fn desktop_user_id() -> Result<String> {
    if let Ok(u) = std::env::var("BW_WEZ_USER_ID") {
        if !u.is_empty() {
            return Ok(u);
        }
    }
    for path in desktop_data_candidates() {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        for key in ["global_account_activeAccountId", "activeUserId"] {
            if let Some(id) = v.get(key).and_then(|x| x.as_str()) {
                if is_guid(id) {
                    return Ok(id.to_string());
                }
            }
        }
        if let Some(obj) = v.as_object() {
            if let Some(k) = obj.keys().find(|k| is_guid(k)) {
                return Ok(k.clone());
            }
        }
    }
    Err(anyhow!(
        "could not determine the desktop app's userId — set BW_WEZ_USER_ID to your account GUID"
    ))
}

fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}
