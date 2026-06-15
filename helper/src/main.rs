//! bw-wez — the bitwarden.wez helper binary (provider A: desktop bridge).
//!
//! WezTerm's sandboxed Lua can't open sockets or do crypto, so it shells out to
//! this binary. Architecture:
//!   - `bw-wez agent` runs a background daemon (auto-spawned) that performs the
//!     biometric unlock and holds the user key in memory (mlock'd, never on
//!     disk), serving requests over a 0600 unix socket. It locks after idle.
//!   - `bw-wez list|get|status|unlock|lock|stop` are thin clients that forward
//!     to the agent. `list`/`get`/`unlock` auto-spawn the agent if needed.
//!
//! JSON contract (interchangeable with `mock/bw-wez`):
//!   bw-wez status                      -> {"status": "unlocked"|"locked"}
//!   bw-wez list                        -> JSON array of {id,name,username,folder,uri}
//!   bw-wez get <id> --field <name>     -> raw value on stdout
//!   bw-wez unlock | lock | stop        -> status JSON

mod agent;
mod crypto;
mod protocol;
mod totp;
mod transport;
mod vault;

use agent::Request;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bw-wez", version, about = "Bitwarden <-> WezTerm bridge")]
struct Cli {
    /// Reserved for multi-account selection.
    #[arg(long, global = true)]
    profile: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report whether the vault is unlocked.
    Status,
    /// List login items as JSON: [{id,name,username,folder,uri}, ...].
    List,
    /// Get a single field for an item by id.
    Get {
        /// Item id (UUID).
        id: String,
        /// Which field to fetch.
        #[arg(long, default_value = "password")]
        field: Field,
    },
    /// Force a biometric unlock now (triggers Touch ID via the desktop app).
    Unlock,
    /// Refresh the local encrypted vault now (`bw sync`); no unlock needed.
    Sync,
    /// Drop the in-memory key (re-locks the vault).
    Lock,
    /// Stop the background agent.
    Stop,
    /// Run the background agent (auto-spawned; not meant to be run by hand).
    #[command(hide = true)]
    Agent,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Field {
    Password,
    Username,
    Totp,
    Uri,
    Notes,
}

impl Field {
    fn as_str(self) -> &'static str {
        match self {
            Field::Password => "password",
            Field::Username => "username",
            Field::Totp => "totp",
            Field::Uri => "uri",
            Field::Notes => "notes",
        }
    }
}

fn main() {
    std::process::exit(run(Cli::parse()));
}

fn run(cli: Cli) -> i32 {
    match cli.command {
        Command::Agent => match agent::run_agent() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },

        Command::Status => {
            // Don't spawn an agent just to check status.
            let status = match agent::client(Request::new("status"), false) {
                Ok(r) if r.ok => r.data.unwrap_or_else(|| "locked".into()),
                _ => "locked".into(),
            };
            println!("{{\"status\":\"{status}\"}}");
            0
        }

        Command::List => forward(Request::new("list"), true, /*raw*/ true),
        Command::Unlock => status_cmd(Request::new("unlock"), true),
        Command::Sync => status_cmd(Request::new("sync"), true),
        Command::Lock => status_cmd(Request::new("lock"), false),
        Command::Stop => status_cmd(Request::new("stop"), false),

        Command::Get { id, field } => {
            let mut req = Request::new("get");
            req.id = Some(id);
            req.field = Some(field.as_str().to_string());
            forward(req, true, /*raw*/ true)
        }
    }
}

/// Forward a request and print its `data` (raw) on success, error on failure.
fn forward(req: Request, auto_spawn: bool, _raw: bool) -> i32 {
    match agent::client(req, auto_spawn) {
        Ok(r) if r.ok => {
            if let Some(data) = r.data {
                println!("{data}");
            }
            0
        }
        Ok(r) => {
            eprintln!("{}", r.error.unwrap_or_else(|| "request failed".into()));
            1
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// Like `forward`, but prints a `{"status":...}` line (for unlock/lock/stop).
fn status_cmd(req: Request, auto_spawn: bool) -> i32 {
    match agent::client(req, auto_spawn) {
        Ok(r) if r.ok => {
            let s = r.data.unwrap_or_else(|| "ok".into());
            println!("{{\"status\":\"{s}\"}}");
            0
        }
        Ok(r) => {
            eprintln!("{}", r.error.unwrap_or_else(|| "request failed".into()));
            1
        }
        // For lock/stop with no agent, that's effectively success.
        Err(_) if !auto_spawn => {
            println!("{{\"status\":\"locked\"}}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}
