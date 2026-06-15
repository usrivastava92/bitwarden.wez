use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::transport::{
    debug_enabled, poll_readable, socket_candidates, TransportIO, TransportKind,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct SocketTransport {
    stream: UnixStream,
}

impl SocketTransport {
    pub fn connect() -> Result<Self> {
        let candidates = socket_candidates();
        let mut last_err = None;
        for path in &candidates {
            if debug_enabled() {
                eprintln!("[bw-wez] trying socket: {}", path.display());
            }
            match connect_with_timeout(path, CONNECT_TIMEOUT) {
                Ok(stream) => return Ok(SocketTransport { stream }),
                Err(e) => {
                    if debug_enabled() {
                        eprintln!("[bw-wez] socket {}: {e:#}", path.display());
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no IPC socket candidates available")))
    }

    pub fn connect_with_path(path: &Path) -> Result<Self> {
        let stream = connect_with_timeout(path, CONNECT_TIMEOUT)?;
        Ok(SocketTransport { stream })
    }
}

impl TransportIO for SocketTransport {
    fn write_json(&mut self, value: &serde_json::Value) -> Result<()> {
        let body = serde_json::to_vec(value)?;
        if debug_enabled() {
            eprintln!("[bw-wez] -> {}", String::from_utf8_lossy(&body));
        }
        let len = u32::try_from(body.len()).context("message too large")?;
        self.stream.write_all(&len.to_le_bytes())?;
        self.stream.write_all(&body)?;
        self.stream.flush()?;
        Ok(())
    }

    fn read_json_timeout(&mut self, timeout: Duration) -> Result<serde_json::Value> {
        poll_readable(self.stream.as_raw_fd(), timeout)
            .context("waiting for desktop socket reply")?;
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .context("desktop socket closed the connection during read")?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > 64 * 1024 * 1024 {
            return Err(anyhow!("implausible frame length: {len}"));
        }
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body)?;
        if debug_enabled() {
            eprintln!("[bw-wez] <- {}", String::from_utf8_lossy(&body));
        }
        Ok(serde_json::from_slice(&body)?)
    }

    fn kind(&self) -> TransportKind {
        TransportKind::DirectSocket
    }
}

fn connect_with_timeout(path: &Path, timeout: Duration) -> Result<UnixStream> {
    let stream = UnixStream::connect(path)
        .with_context(|| format!("connecting to IPC socket {}", path.display()))?;
    stream.set_nonblocking(true)?;
    let fd = stream.as_raw_fd();
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc < 0 {
        return Err(anyhow::anyhow!(std::io::Error::last_os_error()))
            .context("poll during socket connect");
    }
    if rc == 0 {
        return Err(anyhow!(
            "connection to IPC socket timed out after {timeout:?}"
        ));
    }
    if (pfd.revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
        let err = stream.take_error().ok().flatten().unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused")
        });
        return Err(err).context("IPC socket connect failed");
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}
