//! Crypto for the native-messaging channel.
//!
//! Two pieces:
//!   1. An ephemeral RSA keypair. We send the public key in `setupEncryption`;
//!      the desktop app returns a random AES transport key encrypted to it with
//!      RSA-OAEP (SHA-1). We decrypt it with the private key.
//!   2. The Bitwarden "EncString" symmetric format (type 2:
//!      AesCbc256_HmacSha256_B64), used to encrypt every command after the
//!      handshake. Wire form: `2.<iv_b64>|<ciphertext_b64>|<mac_b64>`.
//!
//! LIVE-ITERATION: the OAEP hash (SHA-1 vs SHA-256) and the exact public-key
//! encoding (DER SPKI base64, as used here) are the most likely things to need
//! a tweak if the handshake is rejected.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::Sha256;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Ephemeral RSA keypair for the handshake.
pub struct KeyPair {
    private: RsaPrivateKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048)?;
        Ok(KeyPair { private })
    }

    /// Base64 of the DER-encoded SubjectPublicKeyInfo, as the extension sends.
    pub fn public_key_b64(&self) -> Result<String> {
        let pubkey = RsaPublicKey::from(&self.private);
        let der = pubkey.to_public_key_der()?;
        Ok(B64.encode(der.as_bytes()))
    }

    /// Decrypt the RSA-OAEP(SHA-1) wrapped transport key from the desktop app.
    pub fn unwrap_transport_key(&self, encrypted_b64: &str) -> Result<SymmetricKey> {
        let ct = B64.decode(encrypted_b64)?;
        let padding = Oaep::new::<Sha1>();
        let raw = self.private.decrypt(padding, &ct)?;
        SymmetricKey::from_bytes(&raw)
    }
}

/// Base64 components of a type-2 EncString.
pub struct EncParts {
    pub iv: String,
    pub data: String,
    pub mac: String,
}

/// A Bitwarden symmetric key: 32 bytes AES + 32 bytes HMAC (stretched form).
#[derive(Clone)]
pub struct SymmetricKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl SymmetricKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != 64 {
            // LIVE-ITERATION: some flows return a 32-byte key that must be
            // HKDF-stretched to 64. If you see this error, stretch here.
            return Err(anyhow!(
                "expected a 64-byte symmetric key, got {} bytes",
                raw.len()
            ));
        }
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        enc.copy_from_slice(&raw[..32]);
        mac.copy_from_slice(&raw[32..]);
        Ok(SymmetricKey { enc, mac })
    }

    /// Build a key from a base64-encoded 64-byte key (e.g. the BW user key).
    pub fn from_b64(s: &str) -> Result<Self> {
        let raw = B64.decode(s.trim())?;
        Self::from_bytes(&raw)
    }

    /// The raw 64-byte key (enc || mac). Used by the agent to hold/mlock it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(&self.enc);
        v.extend_from_slice(&self.mac);
        v
    }

    /// Decrypt a type-2 EncString and interpret the plaintext as UTF-8.
    pub fn decrypt_str(&self, enc_string: &str) -> Result<String> {
        let pt = self.decrypt(enc_string)?;
        String::from_utf8(pt).context("decrypted value was not valid UTF-8")
    }

    /// Encrypt plaintext into the base64 parts of a type-2 EncString.
    /// The desktop expects these as an object `{encryptionType,data,iv,mac}`.
    pub fn encrypt_parts(&self, plaintext: &[u8]) -> EncParts {
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let ct = Aes256CbcEnc::new(&self.enc.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        // MAC is computed over iv || ciphertext.
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.mac).expect("hmac key");
        mac.update(&iv);
        mac.update(&ct);
        let tag = mac.finalize().into_bytes();

        EncParts {
            iv: B64.encode(iv),
            data: B64.encode(ct),
            mac: B64.encode(tag),
        }
    }

    /// Decrypt a type-2 EncString into plaintext bytes (verifies the MAC).
    pub fn decrypt(&self, enc_string: &str) -> Result<Vec<u8>> {
        let body = enc_string
            .strip_prefix("2.")
            .ok_or_else(|| anyhow!("unsupported EncString type (expected '2.'): {enc_string:.8}…"))?;
        let mut parts = body.split('|');
        let iv = B64.decode(parts.next().ok_or_else(|| anyhow!("missing iv"))?)?;
        let ct = B64.decode(parts.next().ok_or_else(|| anyhow!("missing ciphertext"))?)?;
        let tag = B64.decode(parts.next().ok_or_else(|| anyhow!("missing mac"))?)?;

        // Verify MAC over iv || ciphertext before decrypting.
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.mac).expect("hmac key");
        mac.update(&iv);
        mac.update(&ct);
        mac.verify_slice(&tag)
            .map_err(|_| anyhow!("EncString MAC verification failed"))?;

        if iv.len() != 16 {
            return Err(anyhow!("bad iv length {}", iv.len()));
        }
        let iv_arr: [u8; 16] = iv.try_into().unwrap();
        let pt = Aes256CbcDec::new(&self.enc.into(), &iv_arr.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&ct)
            .map_err(|e| anyhow!("AES-CBC decrypt failed: {e}"))?;
        Ok(pt)
    }
}

/// The account's RSA private key (decrypted from `accountCryptographicState`),
/// used to unwrap organization keys (type-4 EncStrings).
pub struct PrivateKey(RsaPrivateKey);

impl PrivateKey {
    /// Parse from PKCS#8 DER (the plaintext of the account's private_key field).
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        RsaPrivateKey::from_pkcs8_der(der)
            .map(PrivateKey)
            .map_err(|e| anyhow!("parsing account RSA private key: {e}"))
    }

    /// Decrypt a type-4 EncString (`4.<base64>`, RSA-OAEP-SHA1).
    pub fn decrypt_type4(&self, enc_string: &str) -> Result<Vec<u8>> {
        let b64 = enc_string
            .strip_prefix("4.")
            .ok_or_else(|| anyhow!("expected a type-4 (RSA) EncString"))?;
        let ct = B64.decode(b64)?;
        self.0
            .decrypt(Oaep::new::<Sha1>(), &ct)
            .map_err(|e| anyhow!("RSA-OAEP decrypt failed: {e}"))
    }
}
