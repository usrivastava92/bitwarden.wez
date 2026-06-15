//! The data plane: decrypt the vault directly with the biometric user key.
//!
//! Why not shell out to `bw`? The `bw` CLI's `BW_SESSION` is a *session key*
//! that encrypts bw's at-rest copy of the user key — not the user key itself —
//! so the biometric user key can't be injected as a session (bw 2026.5's key
//! model). Instead we read bw's already-synced, encrypted `data.json` and
//! decrypt the items ourselves with the user key. `bw` is only a setup/sync
//! dependency (`bw login` / `bw sync` populate `data.json`); reads never spawn it.
//!
//! Scope (v1): personal login items (type 1). Organization items need org keys
//! (decrypt the user's org key from `accountKeys`/`organizationKeys`) — deferred.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::crypto::SymmetricKey;
use crate::protocol::Session;
use crate::totp;

const DEFAULT_TTL_SECS: u64 = 300;

/// Public status string for `bw-wez status`.
pub fn status() -> Result<&'static str> {
    if !desktop_proxy_present() {
        return Ok("no-desktop");
    }
    if read_bw_data().is_err() {
        return Ok("no-vault"); // bw not logged in / no data.json yet
    }
    match cached_session() {
        Some(_) => Ok("unlocked"),
        None => Ok("locked"),
    }
}

/// `bw-wez list` -> compact JSON array of personal login items.
pub fn list() -> Result<String> {
    let uk = user_key()?;
    let data = read_bw_data()?;
    let ciphers = find_suffix(&data, "_ciphers_ciphers")
        .ok_or_else(|| anyhow!("no ciphers found in bw data — run `bw sync`"))?;
    let folders = folder_map(&data, &uk);

    let mut out = Vec::new();
    if let Some(obj) = ciphers.as_object() {
        for c in obj.values() {
            if !is_personal_login(c) {
                continue;
            }
            let Some(id) = c.get("id").and_then(|v| v.as_str()) else { continue };
            let ik = match item_key(&uk, c) {
                Ok(k) => k,
                Err(_) => continue, // skip items we can't key (e.g. unexpected org item)
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

/// `bw-wez get <id> --field <name>` -> the raw value.
pub fn get_field(id: &str, field: &str) -> Result<String> {
    let uk = user_key()?;
    let data = read_bw_data()?;
    let ciphers = find_suffix(&data, "_ciphers_ciphers")
        .ok_or_else(|| anyhow!("no ciphers found in bw data — run `bw sync`"))?;
    let c = ciphers
        .as_object()
        .and_then(|o| o.values().find(|c| c.get("id").and_then(|v| v.as_str()) == Some(id)))
        .ok_or_else(|| anyhow!("item {id} not found"))?;

    let ik = item_key(&uk, c)?;
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
// unlock (biometric, via the desktop bridge)
// ---------------------------------------------------------------------------

/// Force a biometric unlock now and cache the session.
pub fn ensure_unlocked() -> Result<String> {
    if let Some(s) = cached_session() {
        return Ok(s);
    }
    let user_id = desktop_user_id()?;
    let mut session =
        Session::establish(&user_id).context("connecting to the Bitwarden desktop app")?;
    let token = session.biometric_unlock().context("biometric unlock")?;
    store_session(&token)?;
    Ok(token)
}

fn user_key() -> Result<SymmetricKey> {
    SymmetricKey::from_b64(&ensure_unlocked()?).context("decoding the unlocked user key")
}

// ---------------------------------------------------------------------------
// cipher decryption helpers
// ---------------------------------------------------------------------------

fn is_personal_login(c: &Value) -> bool {
    let personal = c.get("organizationId").map(|v| v.is_null()).unwrap_or(true);
    let is_login = c.get("type").and_then(|t| t.as_i64()) == Some(1);
    personal && is_login
}

/// The key to decrypt a cipher's fields: its own item key (decrypted with the
/// user key) if present, else the user key itself.
fn item_key(uk: &SymmetricKey, c: &Value) -> Result<SymmetricKey> {
    match c.get("key").and_then(|v| v.as_str()) {
        Some(k) => {
            let raw = uk.decrypt(k).context("decrypting item key")?;
            SymmetricKey::from_bytes(&raw)
        }
        None => Ok(uk.clone()),
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

// ---------------------------------------------------------------------------
// bw data.json
// ---------------------------------------------------------------------------

fn bw_data_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BW_WEZ_BW_DATA") {
        return Some(PathBuf::from(p));
    }
    let dir = if let Ok(d) = std::env::var("BITWARDENCLI_APPDATA_DIR") {
        PathBuf::from(d)
    } else {
        dirs::data_dir()?.join("Bitwarden CLI")
    };
    Some(dir.join("data.json"))
}

fn read_bw_data() -> Result<Value> {
    let path = bw_data_path().ok_or_else(|| anyhow!("cannot resolve the bw data dir"))?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} — is the bw CLI logged in? (`bw login`)", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

/// bw namespaces its keys as `user_<uid>_<area>`; find a value by key suffix.
fn find_suffix<'a>(data: &'a Value, suffix: &str) -> Option<&'a Value> {
    data.as_object()?
        .iter()
        .find(|(k, _)| k.ends_with(suffix))
        .map(|(_, v)| v)
}

fn desktop_proxy_present() -> bool {
    std::path::Path::new("/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy").exists()
        || std::env::var("BW_WEZ_DESKTOP_PROXY").is_ok()
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
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve home dir"))?;
    let candidates = [
        home.join("Library/Containers/com.bitwarden.desktop/Data/Library/Application Support/Bitwarden/data.json"),
        home.join("Library/Application Support/Bitwarden/data.json"),
    ];
    for path in candidates {
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

// ---------------------------------------------------------------------------
// session cache (v1: 0600 file with TTL; swap for an agent socket later)
// ---------------------------------------------------------------------------

fn ttl_secs() -> u64 {
    std::env::var("BW_WEZ_SESSION_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TTL_SECS)
}

fn session_path() -> Option<PathBuf> {
    let mut dir = dirs::cache_dir()?;
    dir.push("bw-wez");
    Some(dir.join("session"))
}

fn cached_session() -> Option<String> {
    let path = session_path()?;
    let meta = std::fs::metadata(&path).ok()?;
    let age = meta.modified().ok()?.elapsed().ok()?;
    if age.as_secs() > ttl_secs() {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    let token = std::fs::read_to_string(&path).ok()?.trim().to_string();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn store_session(token: &str) -> Result<()> {
    let path = session_path().ok_or_else(|| anyhow!("could not resolve cache dir"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_private(&path, token)
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)?;
    Ok(())
}
