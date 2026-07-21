use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha1::Sha1;
use sha2::Sha256;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static NEXT_ID: AtomicU32 = AtomicU32::new(0);

fn temp_socket_path() -> PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("bw-wez-test-{}-{id}.sock", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

struct ConnState {
    shared_secret: Option<Vec<u8>>,
}

/// Serve one connection, sending an initial "connected" frame, then handling
/// the IPC protocol. Returns when the client disconnects.
fn serve_one(listener: &UnixListener) {
    if let Ok((stream, _)) = listener.accept() {
        let mut stream = stream;
        let _ = handle_client(&mut stream);
    }
}

fn handle_client(stream: &mut UnixStream) -> Result<(), Box<dyn std::error::Error>> {
    // Send "connected" immediately — the real desktop does this.
    send_frame(stream, &serde_json::json!({"command": "connected"}))?;

    let mut buffer = VecDeque::new();
    let mut read_buf = [0u8; 4096];
    let mut state = ConnState {
        shared_secret: None,
    };

    loop {
        let n = stream.read(&mut read_buf)?;
        if n == 0 {
            return Ok(());
        }
        buffer.extend(&read_buf[..n]);

        loop {
            if buffer.len() < 4 {
                break;
            }
            buffer.make_contiguous();
            let len_bytes: [u8; 4] = {
                let mut b = [0u8; 4];
                let slice = buffer.as_slices().0;
                b.copy_from_slice(&slice[..4]);
                b
            };
            let frame_len = u32::from_le_bytes(len_bytes) as usize;
            if buffer.len() < 4 + frame_len {
                break;
            }
            buffer.drain(..4);
            let frame: Vec<u8> = buffer.drain(..frame_len).collect();

            let json: serde_json::Value = serde_json::from_slice(&frame)?;
            if let Some(resp) = handle_message(&json, &mut state) {
                send_frame(stream, &resp)?;
            }
        }
    }
}

fn send_frame(stream: &mut UnixStream, value: &serde_json::Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).unwrap();
    let len = u32::try_from(body.len()).unwrap();
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&body);
    stream.write_all(&buf)?;
    stream.flush()
}

fn handle_message(msg: &serde_json::Value, state: &mut ConnState) -> Option<serde_json::Value> {
    let msg_field = msg.get("message");

    // Detect encrypted messages: either a string (EncString) or an object
    // with encryptionType == 2.
    let is_encrypted_string = msg_field
        .and_then(|m| m.as_str())
        .is_some_and(|s| s.starts_with("2."));
    let is_encrypted_object = msg_field
        .and_then(|m| m.get("encryptionType"))
        .and_then(|v| v.as_i64())
        == Some(2);

    if is_encrypted_string || is_encrypted_object {
        return handle_encrypted(msg, state);
    }

    // Unencrypted command frames.
    let command = msg_field
        .and_then(|m| m.get("command"))
        .and_then(|c| c.as_str());

    match command {
        Some("setupEncryption") => {
            let public_key_b64 = msg
                .get("message")
                .and_then(|m| m.get("publicKey"))
                .and_then(|v| v.as_str())?;

            let pubkey_der = B64.decode(public_key_b64).ok()?;
            let pubkey = RsaPublicKey::from_public_key_der(&pubkey_der).ok()?;

            let mut secret = vec![0u8; 64];
            rand::thread_rng().fill_bytes(&mut secret);

            let padding = Oaep::new::<Sha1>();
            let encrypted_secret = pubkey
                .encrypt(&mut rand::thread_rng(), padding, &secret)
                .ok()?;

            state.shared_secret = Some(secret);

            Some(serde_json::json!({
                "command": "setupEncryption",
                "sharedSecret": B64.encode(&encrypted_secret),
            }))
        }
        Some(_) => Some(serde_json::json!({"command": "connected"})),
        None => Some(serde_json::json!({"command": "connected"})),
    }
}

fn handle_encrypted(msg: &serde_json::Value, state: &ConnState) -> Option<serde_json::Value> {
    let secret = state.shared_secret.as_ref()?;
    let (iv_b64, data_b64, mac_b64): (String, String, String);
    let msg_body = msg.get("message");

    match msg_body {
        Some(serde_json::Value::String(s)) => {
            let body = s.strip_prefix("2.")?;
            let mut parts = body.split('|');
            iv_b64 = parts.next()?.to_string();
            data_b64 = parts.next()?.to_string();
            mac_b64 = parts.next()?.to_string();
        }
        Some(serde_json::Value::Object(o)) => {
            iv_b64 = o.get("iv")?.as_str()?.to_string();
            data_b64 = o.get("data")?.as_str()?.to_string();
            mac_b64 = o.get("mac")?.as_str()?.to_string();
        }
        _ => return None,
    }

    let iv = B64.decode(&iv_b64).ok()?;
    let ct = B64.decode(&data_b64).ok()?;
    let tag = B64.decode(&mac_b64).ok()?;

    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&secret[..32]);
    let mut mac_key = [0u8; 32];
    mac_key.copy_from_slice(&secret[32..64]);

    let mut hmac_check = <HmacSha256 as Mac>::new_from_slice(&mac_key).ok()?;
    hmac_check.update(&iv);
    hmac_check.update(&ct);
    hmac_check.verify_slice(&tag).ok()?;

    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(&iv);
    let pt = Aes256CbcDec::new_from_slices(&enc_key, &iv_arr)
        .expect("valid key/iv length")
        .decrypt_padded_vec::<Pkcs7>(&ct)
        .ok()?;

    let inner: serde_json::Value = serde_json::from_slice(&pt).ok()?;
    let inner_cmd = inner
        .get("command")
        .and_then(|c| c.as_str())
        .unwrap_or("unknown")
        .to_string();
    let message_id = inner.get("messageId").and_then(|v| v.as_i64()).unwrap_or(1);

    let response_payload = match inner_cmd.as_str() {
        "unlockWithBiometricsForUser" => {
            serde_json::json!({
                "command": "unlockWithBiometricsForUser",
                "messageId": message_id,
                "response": true,
                "userKeyB64": B64.encode([0x42u8; 64]),
            })
        }
        _ => serde_json::json!({
            "command": inner_cmd,
            "messageId": message_id,
            "response": null,
        }),
    };

    let resp_json = serde_json::to_string(&response_payload).ok()?;
    let mut resp_iv_arr = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut resp_iv_arr);

    let resp_ct = Aes256CbcEnc::new_from_slices(&enc_key, &resp_iv_arr)
        .expect("valid key/iv length")
        .encrypt_padded_vec::<Pkcs7>(resp_json.as_bytes());

    let mut resp_mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).ok()?;
    resp_mac.update(&resp_iv_arr);
    resp_mac.update(&resp_ct);
    let resp_tag = resp_mac.finalize().into_bytes();

    let app_id = msg.get("appId").and_then(|v| v.as_str()).unwrap_or("test");

    Some(serde_json::json!({
        "appId": app_id,
        "message": {
            "encryptionType": 2,
            "encryptedString": format!(
                "2.{}|{}|{}",
                B64.encode(resp_iv_arr),
                B64.encode(&resp_ct),
                B64.encode(resp_tag),
            ),
            "iv": B64.encode(resp_iv_arr),
            "data": B64.encode(&resp_ct),
            "mac": B64.encode(resp_tag),
        }
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

use bw_wez::transport::socket::SocketTransport;
use bw_wez::transport::TransportIO;

#[test]
fn test_socket_transport_connect_refused() {
    let path = temp_socket_path();
    let result = SocketTransport::connect_with_path(&path);
    assert!(
        result.is_err(),
        "connect to non-existent socket should fail"
    );
}

#[test]
fn test_socket_transport_write_read_frame() {
    let sock_path = temp_socket_path();
    let listener = UnixListener::bind(&sock_path).expect("bind mock server");

    let handle = std::thread::spawn(move || {
        serve_one(&listener);
    });

    std::thread::sleep(Duration::from_millis(200));

    let mut transport =
        SocketTransport::connect_with_path(&sock_path).expect("should connect to mock server");

    // Read "connected" frame the server sends on connect
    let connected = transport
        .read_json_timeout(Duration::from_secs(2))
        .expect("should read connected");
    assert_eq!(
        connected.get("command").and_then(|c| c.as_str()),
        Some("connected")
    );

    transport
        .write_json(&serde_json::json!({"command": "ping"}))
        .expect("write should succeed");

    let response = transport
        .read_json_timeout(Duration::from_secs(2))
        .expect("should read response");
    assert_eq!(
        response.get("command").and_then(|c| c.as_str()),
        Some("connected")
    );

    // Drop transport before joining (signals EOF to server thread)
    std::mem::drop(transport);
    handle.join().ok();
    let _ = std::fs::remove_file(&sock_path);
}

#[test]
fn test_socket_transport_setup_encryption() {
    let sock_path = temp_socket_path();
    let listener = UnixListener::bind(&sock_path).expect("bind mock server");

    let handle = std::thread::spawn(move || {
        serve_one(&listener);
    });

    std::thread::sleep(Duration::from_millis(200));

    let mut transport =
        SocketTransport::connect_with_path(&sock_path).expect("should connect to mock server");

    let connected = transport
        .read_json_timeout(Duration::from_secs(2))
        .expect("should read connected");
    assert_eq!(
        connected.get("command").and_then(|c| c.as_str()),
        Some("connected")
    );

    let keypair = bw_wez::crypto::KeyPair::generate().expect("generate keypair");
    let setup = serde_json::json!({
        "appId": "test-app",
        "message": {
            "command": "setupEncryption",
            "publicKey": keypair.public_key_b64().expect("public key b64"),
            "userId": "00000000-0000-0000-0000-000000000000",
        }
    });
    transport.write_json(&setup).expect("write setupEncryption");

    let response = transport
        .read_json_timeout(Duration::from_secs(2))
        .expect("should read setupEncryption response");
    assert_eq!(
        response.get("command").and_then(|c| c.as_str()),
        Some("setupEncryption")
    );
    assert!(
        response
            .get("sharedSecret")
            .and_then(|v| v.as_str())
            .is_some(),
        "response should contain sharedSecret"
    );

    std::mem::drop(transport);
    handle.join().ok();
    let _ = std::fs::remove_file(&sock_path);
}

#[test]
fn test_session_full_handshake_over_socket() {
    let sock_path = temp_socket_path();
    let listener = UnixListener::bind(&sock_path).expect("bind mock server");

    let handle = std::thread::spawn(move || {
        serve_one(&listener);
    });

    std::thread::sleep(Duration::from_millis(200));

    let transport = SocketTransport::connect_with_path(&sock_path).expect("connect to mock");

    let mut session = bw_wez::protocol::Session::with_transport(
        Box::new(transport),
        "00000000-0000-0000-0000-000000000000",
    )
    .expect("session should establish");

    let user_key = session
        .biometric_unlock()
        .expect("biometric unlock should succeed");

    assert_eq!(
        user_key,
        B64.encode([0x42u8; 64]),
        "user key should survive the encrypted socket round trip"
    );
    let decoded_user_key = B64
        .decode(&user_key)
        .expect("user key should be valid base64");
    assert_eq!(
        decoded_user_key.len(),
        64,
        "user key should contain 64 bytes"
    );
    println!(
        "encrypted socket handshake and biometric unlock returned the expected 64-byte user key"
    );

    std::mem::drop(session);
    handle.join().ok();
    let _ = std::fs::remove_file(&sock_path);
}
