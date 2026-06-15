use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use crate::transport::{debug_enabled, poll_readable, TransportIO, TransportKind};

const EXTENSION_ORIGIN: &str = "chrome-extension://nngceckbapebfimnlniiiahkandclblb/";

pub struct NativeMessagingTransport {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl NativeMessagingTransport {
    pub fn connect() -> Result<Self> {
        let proxy = locate_desktop_proxy()
            .ok_or_else(|| anyhow!("could not find the Bitwarden desktop_proxy binary — is the desktop app installed?"))?;

        let mut child = Command::new(&proxy)
            .arg(EXTENSION_ORIGIN)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to launch {}", proxy))?;

        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(NativeMessagingTransport { child, stdin, stdout })
    }
}

impl TransportIO for NativeMessagingTransport {
    fn write_json(&mut self, value: &serde_json::Value) -> Result<()> {
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

    fn read_json_timeout(&mut self, timeout: Duration) -> Result<serde_json::Value> {
        poll_readable(self.stdout.as_raw_fd(), timeout)
            .context("waiting for desktop proxy reply")?;
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
        Ok(serde_json::from_slice(&body)?)
    }

    fn kind(&self) -> TransportKind {
        TransportKind::NativeMessaging
    }
}

impl Drop for NativeMessagingTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn locate_desktop_proxy() -> Option<String> {
    if let Ok(p) = std::env::var("BW_WEZ_DESKTOP_PROXY") {
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    let candidates = [
        "/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy",
        "/opt/Bitwarden/desktop_proxy",
    ];
    candidates
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| p.to_string())
}
