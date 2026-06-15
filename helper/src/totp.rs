//! Minimal TOTP generation for vault items (RFC 6238).
//!
//! Accepts either a bare base32 secret or an `otpauth://` URI (honoring its
//! `secret`, `digits`, `period`, and `algorithm` params). v1 supports SHA-1
//! (the overwhelmingly common case); SHA-256/512 are flagged as unsupported.

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

pub fn generate(secret_or_uri: &str) -> Result<String> {
    let (secret, digits, period, algo) = parse(secret_or_uri)?;
    if !algo.eq_ignore_ascii_case("SHA1") {
        return Err(anyhow!("unsupported TOTP algorithm: {algo} (v1 supports SHA1)"));
    }
    let key = base32_decode(&secret).ok_or_else(|| anyhow!("invalid base32 TOTP secret"))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(hotp(&key, now / period, digits))
}

fn parse(s: &str) -> Result<(String, u32, u64, String)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("otpauth://") {
        // e.g. totp/Label?secret=XXXX&digits=6&period=30&algorithm=SHA1
        let query = rest.split('?').nth(1).unwrap_or("");
        let mut secret = String::new();
        let mut digits = 6u32;
        let mut period = 30u64;
        let mut algo = "SHA1".to_string();
        for pair in query.split('&') {
            let mut kv = pair.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("secret"), Some(v)) => secret = v.to_string(),
                (Some("digits"), Some(v)) => digits = v.parse().unwrap_or(6),
                (Some("period"), Some(v)) => period = v.parse().unwrap_or(30),
                (Some("algorithm"), Some(v)) => algo = v.to_string(),
                _ => {}
            }
        }
        if secret.is_empty() {
            return Err(anyhow!("otpauth URI missing secret"));
        }
        Ok((secret, digits, period, algo))
    } else {
        Ok((s.replace(' ', ""), 6, 30, "SHA1".to_string()))
    }
}

fn hotp(key: &[u8], counter: u64, digits: u32) -> String {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(&counter.to_be_bytes());
    let hs = mac.finalize().into_bytes();
    let offset = (hs[hs.len() - 1] & 0x0f) as usize;
    let bin = ((hs[offset] as u32 & 0x7f) << 24)
        | ((hs[offset + 1] as u32) << 16)
        | ((hs[offset + 2] as u32) << 8)
        | (hs[offset + 3] as u32);
    let modulo = 10u32.pow(digits);
    format!("{:0width$}", bin % modulo, width = digits as usize)
}

/// RFC 4648 base32 decode (uppercase, padding/whitespace tolerant).
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buffer = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in s.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let up = c.to_ascii_uppercase() as u8;
        let val = ALPHABET.iter().position(|&a| a == up)? as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}
