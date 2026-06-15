//! In-memory agent (ssh-agent style).
//!
//! The user key never touches disk: a detached `bw-wez agent` process holds it
//! in memory (mlock'd, out of swap), serves `list`/`get` over a 0600 unix
//! socket, and drops the key after an idle timeout (default 15 min). The CLI
//! commands are thin clients that auto-spawn the agent and forward requests.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::crypto::SymmetricKey;
use crate::vault;

const DEFAULT_IDLE_SECS: u64 = 900; // 15 minutes
const DEFAULT_SYNC_SECS: u64 = 1800; // 30 minutes

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    pub cmd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl Request {
    pub fn new(cmd: &str) -> Self {
        Request { cmd: cmd.to_string(), id: None, field: None }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    fn ok(data: Option<String>) -> Self {
        Response { ok: true, data, error: None }
    }
    fn err(e: impl ToString) -> Self {
        Response { ok: false, data: None, error: Some(e.to_string()) }
    }
}

// ---------------------------------------------------------------------------
// paths / config
// ---------------------------------------------------------------------------

fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("BW_WEZ_AGENT_SOCK") {
        return PathBuf::from(p);
    }
    let mut d = dirs::cache_dir().unwrap_or_else(std::env::temp_dir);
    d.push("bw-wez");
    let _ = std::fs::create_dir_all(&d);
    d.join("agent.sock")
}

fn idle_timeout() -> Duration {
    let secs = std::env::var("BW_WEZ_IDLE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_IDLE_SECS);
    Duration::from_secs(secs)
}

/// Auto-sync interval, or `None` if disabled (`BW_WEZ_SYNC_SECS=0`).
fn sync_interval() -> Option<Duration> {
    let secs = std::env::var("BW_WEZ_SYNC_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SYNC_SECS);
    (secs > 0).then(|| Duration::from_secs(secs))
}

// ---------------------------------------------------------------------------
// in-memory key holder
// ---------------------------------------------------------------------------

/// Holds the raw 64-byte user key in an mlock'd buffer.
struct KeyHolder {
    key: Vec<u8>,
    last_used: Instant,
}

impl KeyHolder {
    fn new(key: Vec<u8>) -> Self {
        // Best-effort: pin the pages so the key can't be swapped to disk.
        unsafe {
            libc::mlock(key.as_ptr() as *const libc::c_void, key.len());
        }
        KeyHolder { key, last_used: Instant::now() }
    }
}

impl Drop for KeyHolder {
    fn drop(&mut self) {
        // Zero the secret, then unpin.
        for b in self.key.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0u8) };
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        unsafe {
            libc::munlock(self.key.as_ptr() as *const libc::c_void, self.key.len());
        }
    }
}

struct State {
    holder: Option<KeyHolder>,
}

type Shared = Arc<Mutex<State>>;

/// Return the in-memory user key, performing a biometric unlock if needed.
fn ensure_key(state: &Shared) -> Result<SymmetricKey> {
    // Fast path: already unlocked.
    {
        let mut s = state.lock().unwrap();
        if let Some(h) = s.holder.as_mut() {
            h.last_used = Instant::now();
            return SymmetricKey::from_bytes(&h.key);
        }
    }
    // Slow path: unlock WITHOUT holding the mutex (Touch ID can take seconds).
    let key = vault::obtain_user_key()?;
    let raw = key.to_bytes();
    let mut s = state.lock().unwrap();
    s.holder = Some(KeyHolder::new(raw));
    SymmetricKey::from_bytes(&s.holder.as_ref().unwrap().key)
}

fn lock_now(state: &Shared) {
    state.lock().unwrap().holder = None; // Drop zeroes + munlocks
}

fn is_unlocked(state: &Shared) -> bool {
    state.lock().unwrap().holder.is_some()
}

// ---------------------------------------------------------------------------
// agent (server)
// ---------------------------------------------------------------------------

pub fn run_agent() -> Result<()> {
    let sock = socket_path();

    // If a live agent already owns the socket, do nothing.
    if UnixStream::connect(&sock).is_ok() {
        return Ok(());
    }
    let _ = std::fs::remove_file(&sock); // clear a stale socket
    let listener = UnixListener::bind(&sock).context("binding agent socket")?;
    set_socket_perms(&sock);

    let state: Shared = Arc::new(Mutex::new(State { holder: None }));
    // Serializes `bw sync` invocations so the background thread and a manual
    // `bw-wez sync` never run two syncs against the same data.json at once.
    let sync_guard: Arc<Mutex<()>> = Arc::new(Mutex::new(()));

    // Idle reaper: drop the key after inactivity.
    {
        let state = state.clone();
        let timeout = idle_timeout();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(15));
            let mut s = state.lock().unwrap();
            let stale = s.holder.as_ref().map(|h| h.last_used.elapsed() > timeout).unwrap_or(false);
            if stale {
                s.holder = None;
            }
        });
    }

    // Auto-sync: keep bw's encrypted data.json fresh in the background. This
    // needs no key (bw can sync while locked), so it runs regardless of lock
    // state. Reads always re-read data.json, so a fresh sync shows up at once.
    if let Some(interval) = sync_interval() {
        let sync = sync_guard.clone();
        std::thread::spawn(move || {
            // A brief delay so the first sync doesn't race the spawn-time read.
            std::thread::sleep(Duration::from_secs(3));
            loop {
                if let Err(e) = do_sync(&sync) {
                    if std::env::var("BW_WEZ_DEBUG").is_ok() {
                        eprintln!("bw-wez auto-sync: {e}");
                    }
                }
                std::thread::sleep(interval);
            }
        });
    }

    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        // Sequential handling is fine for a single-user picker.
        if handle_conn(stream, &state, &sync_guard) == ConnOutcome::Stop {
            let _ = std::fs::remove_file(&sock);
            return Ok(());
        }
    }
    Ok(())
}

#[derive(PartialEq)]
enum ConnOutcome {
    Continue,
    Stop,
}

fn handle_conn(stream: UnixStream, state: &Shared, sync: &Arc<Mutex<()>>) -> ConnOutcome {
    let mut reader = match stream.try_clone() {
        Ok(s) => BufReader::new(s),
        Err(_) => return ConnOutcome::Continue,
    };
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return ConnOutcome::Continue;
    }
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let _ = reply(stream, &Response::err(format!("bad request: {e}")));
            return ConnOutcome::Continue;
        }
    };

    let (resp, outcome) = process(&req, state, sync);
    let _ = reply(stream, &resp);
    outcome
}

fn process(req: &Request, state: &Shared, sync: &Arc<Mutex<()>>) -> (Response, ConnOutcome) {
    match req.cmd.as_str() {
        "status" => {
            let s = if is_unlocked(state) { "unlocked" } else { "locked" };
            (Response::ok(Some(s.to_string())), ConnOutcome::Continue)
        }
        "lock" => {
            lock_now(state);
            (Response::ok(Some("locked".into())), ConnOutcome::Continue)
        }
        "stop" => (Response::ok(Some("stopped".into())), ConnOutcome::Stop),
        "sync" => match do_sync(sync) {
            Ok(_) => (Response::ok(Some("synced".into())), ConnOutcome::Continue),
            Err(e) => (Response::err(e), ConnOutcome::Continue),
        },
        "unlock" => match ensure_key(state) {
            Ok(_) => (Response::ok(Some("unlocked".into())), ConnOutcome::Continue),
            Err(e) => (Response::err(e), ConnOutcome::Continue),
        },
        "list" => match ensure_key(state).and_then(|k| vault::list_with_key(&k)) {
            Ok(data) => (Response::ok(Some(data)), ConnOutcome::Continue),
            Err(e) => (Response::err(e), ConnOutcome::Continue),
        },
        "get" => {
            let id = req.id.clone().unwrap_or_default();
            let field = req.field.clone().unwrap_or_else(|| "password".into());
            let r = ensure_key(state).and_then(|k| vault::get_field_with_key(&k, &id, &field));
            match r {
                Ok(data) => (Response::ok(Some(data)), ConnOutcome::Continue),
                Err(e) => (Response::err(e), ConnOutcome::Continue),
            }
        }
        other => (Response::err(format!("unknown command: {other}")), ConnOutcome::Continue),
    }
}

fn reply(mut stream: UnixStream, resp: &Response) -> Result<()> {
    let line = serde_json::to_string(resp)?;
    writeln!(stream, "{line}")?;
    stream.flush()?;
    Ok(())
}

fn set_socket_perms(sock: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600));
}

// ---------------------------------------------------------------------------
// sync (refresh bw's encrypted data.json)
// ---------------------------------------------------------------------------

/// Run `bw sync` to refresh the encrypted vault on disk. Serialized via `sync`
/// so the background thread and a manual `bw-wez sync` never overlap. Needs no
/// session — `bw` can sync while the vault is locked.
fn do_sync(sync: &Arc<Mutex<()>>) -> Result<String> {
    let _guard = sync.lock().unwrap();
    let bw = find_bw();
    let out = Command::new(&bw)
        .arg("sync")
        .stdin(Stdio::null())
        .output()
        .with_context(|| {
            format!("running `{bw} sync` (set BW_WEZ_BW_BIN if the bw CLI isn't on PATH)")
        })?;
    if out.status.success() {
        Ok("synced".into())
    } else {
        let msg = String::from_utf8_lossy(&out.stderr);
        let msg = msg.trim();
        Err(anyhow!(
            "bw sync failed: {}",
            if msg.is_empty() { "is the bw CLI logged in? (`bw login`)" } else { msg }
        ))
    }
}

/// Locate the `bw` CLI. GUI-launched WezTerm often has a minimal PATH that
/// misses Homebrew, so probe the usual install dirs before falling back to PATH.
fn find_bw() -> String {
    if let Ok(p) = std::env::var("BW_WEZ_BW_BIN") {
        if !p.is_empty() {
            return p;
        }
    }
    for p in ["/opt/homebrew/bin/bw", "/usr/local/bin/bw"] {
        if Path::new(p).exists() {
            return p.to_string();
        }
    }
    "bw".to_string()
}

// ---------------------------------------------------------------------------
// client
// ---------------------------------------------------------------------------

/// Send a request to the agent. With `auto_spawn`, start the agent if needed.
pub fn client(req: Request, auto_spawn: bool) -> Result<Response> {
    let sock = socket_path();
    let stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(_) if auto_spawn => spawn_and_connect(&sock)?,
        Err(_) => return Err(anyhow!("agent is not running")),
    };

    let mut writer = stream.try_clone()?;
    writeln!(writer, "{}", serde_json::to_string(&req)?)?;
    writer.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    serde_json::from_str(line.trim()).context("parsing agent response")
}

fn spawn_and_connect(sock: &Path) -> Result<UnixStream> {
    let exe = std::env::current_exe().context("locating bw-wez binary")?;
    Command::new(exe)
        .arg("agent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning bw-wez agent")?;

    // Wait (up to ~5s) for the socket to come up.
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(50));
        if let Ok(s) = UnixStream::connect(sock) {
            return Ok(s);
        }
    }
    Err(anyhow!("agent did not start within 5s"))
}
