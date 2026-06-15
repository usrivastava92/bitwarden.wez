use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use std::time::Duration;

use crate::crypto::{KeyPair, SymmetricKey};
use crate::transport::{self, TransportIO};
use crate::transport::TransportKind;

const HANDSHAKE_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const ENCRYPTED_REPLY_TIMEOUT: Duration = Duration::from_secs(30);

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

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
    transport: Box<dyn TransportIO>,
    app_id: String,
    user_id: String,
    key: SymmetricKey,
    next_message_id: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageEncoding {
    String,
    Object,
}

impl MessageEncoding {
    fn label(self) -> &'static str {
        match self {
            MessageEncoding::String => "encrypted string",
            MessageEncoding::Object => "encrypted object",
        }
    }
}

impl Session {
    pub fn establish(user_id: &str) -> Result<Self> {
        match transport::connect_socket() {
            Ok(transport) => match Session::with_transport(transport, user_id) {
                Ok(session) => Ok(session),
                Err(socket_err) => {
                    if transport::debug_enabled() {
                        eprintln!(
                            "[bw-wez] direct IPC socket protocol failed ({socket_err:#}); fallback to desktop_proxy"
                        );
                    }
                    let transport = transport::connect_native_messaging()
                        .context("falling back to desktop_proxy after direct socket protocol failure")?;
                    Session::with_transport(transport, user_id).with_context(|| {
                        format!(
                            "failed over both direct IPC socket and desktop_proxy transports after socket protocol failure: {socket_err}"
                        )
                    })
                }
            },
            Err(socket_connect_err) => {
                let transport = transport::connect_native_messaging().with_context(|| {
                    format!(
                        "connecting via desktop_proxy after direct IPC socket failure: {socket_connect_err}"
                    )
                })?;
                Session::with_transport(transport, user_id).with_context(|| {
                    format!(
                        "failed over both direct IPC socket and desktop_proxy transports after socket connect failure: {socket_connect_err}"
                    )
                })
            }
        }
    }

    pub fn with_transport(
        transport: Box<dyn TransportIO>,
        user_id: &str,
    ) -> Result<Self> {
        let transport_kind = transport.kind();
        let app_id = uuid::Uuid::new_v4().to_string();
        let keypair = KeyPair::generate()?;
        let setup_message_id = 1_i64;

        let setup = json!({
            "appId": app_id,
            "message": {
                "command": "setupEncryption",
                "publicKey": keypair.public_key_b64()?,
                "userId": user_id,
                "messageId": setup_message_id,
                "timestamp": now_ms(),
            }
        });

        let mut transport = transport;
        let mut sent = false;
        if transport_kind == TransportKind::DirectSocket {
            transport
                .write_json(&setup)
                .context("sending direct socket setupEncryption")?;
            sent = true;
        }
        let key = loop {
            let msg = transport
                .read_json_timeout(HANDSHAKE_FRAME_TIMEOUT)
                .context("reading handshake frame")?;
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
                _ => {
                    if transport_kind == TransportKind::DirectSocket && !sent {
                        sent = true;
                    }
                }
            }
        };

        Ok(Session {
            transport,
            app_id,
            user_id: user_id.to_string(),
            key,
            next_message_id: setup_message_id + 1,
        })
    }

    fn send_encrypted(&mut self, mut inner: serde_json::Value, encoding: MessageEncoding) -> Result<i64> {
        let mid = self.next_message_id;
        self.next_message_id += 1;
        inner["messageId"] = json!(mid);
        inner["timestamp"] = json!(now_ms());
        match encoding {
            MessageEncoding::String => {
                let enc = self.key.encrypt_to_string(inner.to_string().as_bytes());
                self.transport.write_json(&json!({
                    "appId": self.app_id,
                    "messageId": mid,
                    "message": enc,
                }))?;
            }
            MessageEncoding::Object => {
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
            }
        }
        Ok(mid)
    }

    fn read_encrypted(&mut self) -> Result<serde_json::Value> {
        loop {
            let frame = self.transport.read_json_timeout(ENCRYPTED_REPLY_TIMEOUT)?;
            if let Some(enc) = encstring_from_message(frame.get("message")) {
                let plain = self.key.decrypt(&enc)?;
                return Ok(serde_json::from_slice(&plain)?);
            }
            match frame.get("command").and_then(|c| c.as_str()).unwrap_or("") {
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

    fn biometric_unlock_with_encoding(&mut self, encoding: MessageEncoding) -> Result<String> {
        self.send_encrypted(json!({
            "command": "unlockWithBiometricsForUser",
            "userId": self.user_id,
        }), encoding)?;

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

    pub fn biometric_unlock(&mut self) -> Result<String> {
        match self.biometric_unlock_with_encoding(MessageEncoding::String) {
            Ok(key) => Ok(key),
            Err(first_err) => {
                let retryable = is_encoding_retryable(&first_err);
                if !retryable {
                    return Err(first_err).context("biometric unlock via encrypted string");
                }

                let user_id = self.user_id.clone();
                let mut retry = Session::establish(&user_id)
                    .context("re-establishing secure channel for legacy desktop compatibility")?;
                retry
                    .biometric_unlock_with_encoding(MessageEncoding::Object)
                    .with_context(|| {
                        format!(
                            "biometric unlock failed with both {} and {} payloads",
                            MessageEncoding::String.label(),
                            MessageEncoding::Object.label()
                        )
                    })
                    .map_err(|retry_err| retry_err.context(first_err.to_string()))
            }
        }
    }
}

fn is_encoding_retryable(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    msg.contains("timed out waiting for a reply")
        || msg.contains("invalidated the secure channel")
        || msg.contains("desktop disconnected")
        || msg.contains("connection closed")
}
