use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::Duration;

pub mod native_messaging;
pub mod socket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    DirectSocket,
    NativeMessaging,
}

pub trait TransportIO: Send {
    fn write_json(&mut self, value: &serde_json::Value) -> Result<()>;
    fn read_json_timeout(&mut self, timeout: Duration) -> Result<serde_json::Value>;
    fn kind(&self) -> TransportKind;
}

pub fn debug_enabled() -> bool {
    std::env::var_os("BW_WEZ_DEBUG").is_some()
}

pub fn poll_readable(fd: std::os::unix::io::RawFd, timeout: Duration) -> Result<()> {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc < 0 {
        return Err(anyhow::anyhow!(std::io::Error::last_os_error())).context("poll");
    }
    if rc == 0 {
        return Err(anyhow::anyhow!("timed out waiting for a reply"));
    }
    if (pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
        return Err(anyhow::anyhow!("connection closed"));
    }
    Ok(())
}

pub fn socket_candidates() -> Vec<PathBuf> {
    if let Ok(p) = std::env::var("BW_WEZ_IPC_SOCKET") {
        return vec![PathBuf::from(p)];
    }
    let mut candidates = Vec::new();
    if let Some(home) = dirs::home_dir() {
        candidates
            .push(home.join("Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/s.bw"));
        candidates.push(home.join("Library/Caches/com.bitwarden.desktop/s.bw"));
    }
    candidates
}

pub fn connect_socket() -> Result<Box<dyn TransportIO>> {
    let candidates = socket_candidates();
    if !candidates.is_empty() && debug_enabled() {
        for c in &candidates {
            eprintln!("[bw-wez] socket candidate: {}", c.display());
        }
    }
    let t = socket::SocketTransport::connect()?;
    if debug_enabled() {
        eprintln!("[bw-wez] transport: direct IPC socket");
    }
    Ok(Box::new(t))
}

pub fn connect_native_messaging() -> Result<Box<dyn TransportIO>> {
    let t = native_messaging::NativeMessagingTransport::connect()?;
    if debug_enabled() {
        eprintln!("[bw-wez] transport: native-messaging (desktop_proxy)");
    }
    Ok(Box::new(t))
}
