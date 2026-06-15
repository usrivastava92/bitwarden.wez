//! Native-messaging transport to the Bitwarden desktop app.
//!
//! We mirror exactly what the browser extension does: launch the desktop app's
//! bundled `desktop_proxy` and speak Chrome native-messaging framing to it over
//! stdio. The proxy relays to the desktop app's local socket, so we reuse
//! Bitwarden's own relay rather than reimplementing the socket leg.
//!
//! Framing (Chrome native messaging): a 32-bit little-endian length prefix
//! followed by that many bytes of UTF-8 JSON.
//!
//! LIVE-ITERATION: two things here need verification against your machine:
//!   1. The proxy path differs per platform/build (Mac App Store vs direct).
//!   2. The proxy may require the caller to present an allowed extension origin
//!      (see `allowed_origins` in com.8bit.bitwarden.json) as argv[1], and the
//!      desktop app may show a one-time fingerprint-approval prompt on first
//!      connect. We pass an allowed origin below; if the desktop rejects it,
//!      this is the place to adjust.

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// One of the extension origins listed in the installed native-messaging
/// manifest. Presenting a known-good origin maximizes the chance the proxy and
/// desktop app accept our connection. LIVE-ITERATION: confirm against your
/// manifest at:
///   ~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.8bit.bitwarden.json
const EXTENSION_ORIGIN: &str = "chrome-extension://nngceckbapebfimnlniiiahkandclblb/";

/// Dump every native-messaging frame to stderr when `BW_WEZ_DEBUG` is set.
/// Essential for the `LIVE-ITERATION` handshake work: run e.g.
///   BW_WEZ_DEBUG=1 bw-wez unlock
/// to see exactly what your desktop version sends, then align the structs.
fn debug_enabled() -> bool {
    std::env::var_os("BW_WEZ_DEBUG").is_some()
}

pub struct Transport {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Transport {
    /// Launch `desktop_proxy` and prepare the stdio channel.
    pub fn connect() -> Result<Self> {
        let proxy = locate_desktop_proxy()
            .ok_or_else(|| anyhow!("could not find the Bitwarden desktop_proxy binary — is the desktop app installed?"))?;

        let mut child = Command::new(&proxy)
            // Native messaging hosts are launched by the browser with the
            // calling extension origin as the first argument.
            .arg(EXTENSION_ORIGIN)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to launch {}", proxy))?;

        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(Transport { child, stdin, stdout })
    }

    /// Write one native-messaging frame (length-prefixed JSON).
    pub fn write_json(&mut self, value: &serde_json::Value) -> Result<()> {
        let body = serde_json::to_vec(value)?;
        if debug_enabled() {
            eprintln!("[bw-wez] -> {}", String::from_utf8_lossy(&body));
        }
        let len = u32::try_from(body.len()).context("message too large")?;
        self.stdin.write_all(&len.to_le_bytes())?;
        self.stdin.write_all(&body)?;
        self.stdin.flush()?;
        Ok(())
    }

    /// Read one native-messaging frame and parse it as JSON.
    pub fn read_json(&mut self) -> Result<serde_json::Value> {
        let mut len_buf = [0u8; 4];
        self.stdout
            .read_exact(&mut len_buf)
            .context("desktop proxy closed the connection during read")?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > 64 * 1024 * 1024 {
            return Err(anyhow!("implausible native-messaging frame length: {len}"));
        }
        let mut body = vec![0u8; len];
        self.stdout.read_exact(&mut body)?;
        if debug_enabled() {
            eprintln!("[bw-wez] <- {}", String::from_utf8_lossy(&body));
        }
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        Ok(value)
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Resolve the path to `desktop_proxy`. Covers the common macOS install; extend
/// for Linux/Windows in their respective milestones.
fn locate_desktop_proxy() -> Option<String> {
    // Allow an explicit override for unusual installs / testing.
    if let Ok(p) = std::env::var("BW_WEZ_DESKTOP_PROXY") {
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }

    let candidates = [
        // macOS (direct download + Mac App Store share this layout).
        "/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy",
        // Linux (Flatpak/Snap paths vary — LIVE-ITERATION for the Linux milestone).
        "/opt/Bitwarden/desktop_proxy",
        // Windows handled in the Windows milestone.
    ];
    candidates
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| p.to_string())
}
