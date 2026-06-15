//! bw-wez — the bitwarden.wez helper binary (provider A: desktop bridge).
//!
//! This is the part of the plugin that WezTerm's sandboxed Lua cannot do:
//! speak Bitwarden's native-messaging IPC to the *running desktop app* to
//! perform a biometric unlock, then read vault items. The plugin shells out to
//! this binary and parses its stdout.
//!
//! It implements the same JSON contract as `mock/bw-wez`, so the two are
//! interchangeable:
//!   bw-wez status                      -> {"status": "..."}
//!   bw-wez list                        -> JSON array of {id,name,username,folder,uri}
//!   bw-wez get <id> --field <name>     -> raw value on stdout
//!   bw-wez unlock                      -> force a biometric unlock now
//!
//! ## Design
//! Unlock is delegated entirely to the desktop app (so the master password is
//! never stored or seen here). We obtain the user key over the encrypted IPC
//! channel and hand it to the `bw` CLI as `BW_SESSION` for the data plane.
//! See `protocol.rs` for the handshake and `vault.rs` for the data plane.
//!
//! Honest status: the transport + handshake (`transport.rs`, `crypto.rs`,
//! `protocol.rs`) implement the documented/reverse-engineered protocol but
//! require live iteration against your desktop app — search for `LIVE-ITERATION`.

mod crypto;
mod protocol;
mod totp;
mod transport;
mod vault;

use clap::{Parser, Subcommand};
use serde::Serialize;

#[derive(Parser)]
#[command(name = "bw-wez", version, about = "Bitwarden <-> WezTerm bridge")]
struct Cli {
    /// Optional rbw/bw-style profile selector (reserved; multi-account).
    #[arg(long, global = true)]
    profile: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report whether the desktop app is reachable and the vault unlocked.
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
    /// Force a biometric unlock now (triggers Touch ID / Hello via the desktop app).
    Unlock,
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

#[derive(Serialize)]
struct StatusOut {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    let exit = run(cli);
    std::process::exit(exit);
}

fn run(cli: Cli) -> i32 {
    match cli.command {
        Command::Status => {
            let out = match vault::status() {
                Ok(s) => StatusOut { status: s, message: None },
                Err(e) => StatusOut { status: "error", message: Some(e.to_string()) },
            };
            println!("{}", serde_json::to_string(&out).unwrap());
            0
        }

        Command::Unlock => match vault::ensure_unlocked() {
            Ok(_) => {
                println!("{}", serde_json::to_string(&StatusOut { status: "unlocked", message: None }).unwrap());
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },

        Command::List => match vault::list() {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },

        Command::Get { id, field } => match vault::get_field(&id, field.as_str()) {
            Ok(value) => {
                // Raw value, single trailing newline. The plugin strips one \n.
                println!("{value}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
    }
}
