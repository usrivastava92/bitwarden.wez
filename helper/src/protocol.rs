//! The Bitwarden native-messaging command protocol (biometric-unlock subset).
//!
//! Verified against the installed desktop app (2026.5.0) by reading its bundled
//! handler (`app.asar`). The shapes below are what that version actually expects:
//!
//! Handshake:
//!   1. Read frames until `{"command":"connected"}`.
//!   2. Send `{"appId", "message":{"command":"setupEncryption","publicKey","userId"}}`.
//!      - `userId` is REQUIRED and must be an account logged into the desktop app,
//!        else the desktop logs "invalid setupEncryption message. Ignoring." and
//!        never replies (the silent-hang failure mode).
//!   3. Desktop replies (top-level) `{"command":"setupEncryption","sharedSecret":<b64>}`
//!      where sharedSecret is a random 64-byte session key, RSA-OAEP(sha1)-wrapped
//!      to our public key.
//!
//! Encrypted command (`send`/dispatch in the desktop):
//!   - On the wire: `{"appId","messageId","message":"<EncString string>"}`.
//!   - The decrypted inner command MUST carry `messageId` and a `timestamp`
//!     within 10s of the desktop clock (else "Received a too old message").
//!   - Unlock command is `"unlockWithBiometricsForUser"` with `userId`.
//!   - Reply (decrypted): `{"command":"unlockWithBiometricsForUser","response":true,
//!     "userKeyB64":"..."}`. That user key doubles as the `bw` BW_SESSION.
//!
//! LIVE-ITERATION note: if the encrypted step gets no reply, the desktop may want
//! `message` as an object rather than the EncString string — flip `send_encrypted`.

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{KeyPair, SymmetricKey};
use crate::transport::Transport;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Extract an EncString ("2.iv|data|mac") from a reply's `message` field, which
/// the desktop may send as the canonical string (its EncString.toJSON) or as an
/// object with `{iv,data,mac}` / `encryptedString`.
fn encstring_from_message(m: Option<&serde_json::Value>) -> Option<String> {
    match m {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Object(o)) => {
            if let Some(s) = o.get("encryptedString").and_then(|v| v.as_str()) {
                return Some(s.to_string());
            }
            let iv = o.get("iv")?.as_str()?;
            let data = o.get("data")?.as_str()?;
            let mac = o.get("mac")?.as_str()?;
            Some(format!("2.{iv}|{data}|{mac}"))
        }
        _ => None,
    }
}

pub struct Session {
    transport: Transport,
    app_id: String,
    user_id: String,
    key: SymmetricKey,
    next_message_id: i64,
}

impl Session {
    /// Connect to the desktop app and complete the encryption handshake for
    /// `user_id` (a GUID logged into the desktop app).
    pub fn establish(user_id: &str) -> Result<Self> {
        let mut transport = Transport::connect()?;
        let app_id = uuid::Uuid::new_v4().to_string();
        let keypair = KeyPair::generate()?;

        let setup = json!({
            "appId": app_id,
            "message": {
                "command": "setupEncryption",
                "publicKey": keypair.public_key_b64()?,
                "userId": user_id,
            }
        });

        let mut sent = false;
        let key = loop {
            let msg = transport.read_json().context("reading handshake frame")?;
            match msg.get("command").and_then(|c| c.as_str()).unwrap_or("") {
                "connected" => {
                    if !sent {
                        transport.write_json(&setup)?;
                        sent = true;
                    }
                }
                "setupEncryption" => {
                    let wrapped = msg
                        .get("sharedSecret")
                        .or_else(|| msg.get("sharedKey"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("setupEncryption reply missing sharedSecret"))?;
                    break keypair.unwrap_transport_key(wrapped)?;
                }
                "wrongUserId" => {
                    return Err(anyhow!(
                        "the desktop app is not logged into userId {user_id} (try setting BW_WEZ_USER_ID)"
                    ))
                }
                "invalidateEncryption" => {
                    return Err(anyhow!("desktop invalidated the secure channel — retry"))
                }
                "disconnected" => {
                    return Err(anyhow!(
                        "desktop disconnected during handshake — make sure the desktop vault is unlocked"
                    ))
                }
                _ => { /* ignore other control frames and keep reading */ }
            }
        };

        Ok(Session {
            transport,
            app_id,
            user_id: user_id.to_string(),
            key,
            next_message_id: 1,
        })
    }

    /// Encrypt and send a command. Stamps the inner command with a fresh
    /// `messageId` and `timestamp` (the desktop rejects anything older than 10s).
    fn send_encrypted(&mut self, mut inner: serde_json::Value) -> Result<i64> {
        let mid = self.next_message_id;
        self.next_message_id += 1;
        inner["messageId"] = json!(mid);
        inner["timestamp"] = json!(now_ms());
        // `message` must be an OBJECT: the desktop runs `"command" in message`
        // on every frame, which throws on a primitive string. decryptToUtf8 then
        // reads encryptionType/data/iv/mac off it.
        let p = self.key.encrypt_parts(inner.to_string().as_bytes());
        self.transport.write_json(&json!({
            "appId": self.app_id,
            "messageId": mid,
            "message": {
                "encryptionType": 2,
                "data": p.data,
                "iv": p.iv,
                "mac": p.mac,
            },
        }))?;
        Ok(mid)
    }

    /// Read until an encrypted reply arrives (a frame carrying `message`),
    /// tolerating the unencrypted fingerprint-approval control frames.
    fn read_encrypted(&mut self) -> Result<serde_json::Value> {
        loop {
            let frame = self.transport.read_json()?;
            if let Some(enc) = encstring_from_message(frame.get("message")) {
                let plain = self.key.decrypt(&enc)?;
                return Ok(serde_json::from_slice(&plain)?);
            }
            match frame.get("command").and_then(|c| c.as_str()).unwrap_or("") {
                // Desktop is prompting the user to approve this client. Keep waiting.
                "verifyDesktopIPCFingerprint" => {}
                "rejectedDesktopIPCFingerprint" => {
                    return Err(anyhow!("fingerprint approval was rejected in the desktop app"))
                }
                "invalidateEncryption" => {
                    return Err(anyhow!("desktop invalidated the secure channel"))
                }
                "disconnected" => return Err(anyhow!("desktop disconnected")),
                _ => {}
            }
        }
    }

    /// Trigger a biometric unlock; returns the user key (base64) = BW_SESSION value.
    pub fn biometric_unlock(&mut self) -> Result<String> {
        self.send_encrypted(json!({
            "command": "unlockWithBiometricsForUser",
            "userId": self.user_id,
        }))?;

        let reply = self.read_encrypted()?;
        let granted = reply.get("response").and_then(|r| r.as_bool()).unwrap_or(false);
        if !granted {
            return Err(anyhow!(
                "biometric unlock not granted — enable 'Unlock with Touch ID' in the desktop app and ensure its vault is unlocked"
            ));
        }
        let key_b64 = reply
            .get("userKeyB64")
            .or_else(|| reply.get("keyB64"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("unlock reply missing userKeyB64"))?;
        Ok(key_b64.to_string())
    }
}
