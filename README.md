# bitwarden.wez

A Bitwarden vault picker for [WezTerm](https://wezterm.org) — the browser-extension
experience in your terminal. Hit a keybind, fuzzy-search your vault, and copy or
type a password, username, or TOTP. Unlock is **biometric** (Touch ID today;
Windows Hello / polkit later) and your **master password is never stored** — it
gates a *key*, exactly like the official Bitwarden clients.

> **Status:** working end-to-end on **macOS** — biometric unlock via the
> Bitwarden desktop app, plus personal *and* organization login items, with **no
> `bw` CLI required**. Linux and Windows are next. A bundled **mock backend**
> lets you try the whole UX with zero setup (no Rust, no desktop app).

---

## What it does

- **Fuzzy picker** over your whole vault, bound to a keybind.
- **Enter copies the password**; a modifier (or the action menu) lets you copy or
  type the username, copy a live **TOTP**, the URI, or notes.
- **Biometric unlock** — one Touch ID per session, then instant for ~15 min.
- **Clipboard auto-clears** after a configurable delay.
- **Always fresh** — reads the Bitwarden desktop app's own continuously-synced
  vault, so items you add or change elsewhere just appear.

---

## Why you can trust this

This tool touches your passwords, so it's fair to ask *"why should I trust it?"*
The honest answer is **you shouldn't have to take our word for it** — the design
minimizes what you have to trust, and everything below is verifiable from the
source (and with the commands in *"Don't trust — verify"*). Here is exactly what
happens to every secret involved.

### The short version

- We **never ask for, see, or store your master password.** Ever.
- We **never store any key on disk** — not the vault key, not a session token,
  nothing. The one key we hold lives in RAM only, is pinned out of swap, and is
  wiped when you lock or after idle.
- The **biometric unlock is done by the official Bitwarden desktop app**, over
  the same channel its browser extension uses. We don't reimplement Bitwarden's
  login or crypto-of-record; we ask their app to unlock and decrypt the vault
  *they* already synced.
- The helper makes **no network connections** and has **no telemetry**. Nothing
  this tool runs touches the network — the Bitwarden desktop app (which you
  already run) does all the syncing.

### Where every secret lives

| Secret | Where it lives | On disk? | Who holds it |
| --- | --- | --- | --- |
| **Master password** | Nowhere — it is never entered into this tool | **Never** | Only you and Bitwarden's own apps |
| **Biometric secret** (the key Touch ID releases) | macOS Keychain / Secure Enclave | Yes — by the **OS**, encrypted, exactly as the official app stores it | The Bitwarden **desktop app**; we never see it |
| **Session / transport key** (handshake) | Helper RAM, for **one connection** | **Never** | The helper, then discarded when the connection closes |
| **Vault user key** (decrypts your items) | `bw-wez agent` RAM, **`mlock`'d** (can't swap to disk) | **Never** | The agent; zeroed on lock / idle / stop |
| **A decrypted item** (the password you picked) | RAM transiently → your clipboard or typed into the pane | **Never by us** | You; clipboard auto-clears |
| **Encrypted vault** (`data.json`) | Disk | Yes — but written **by the Bitwarden desktop app**, already encrypted | The OS filesystem; we only *read* it, never write it, and it's useless without the user key |

### "But what about the session key?" (the usual worry)

If you've used the `bw` CLI you've seen it print a `BW_SESSION` and tell you to
**export it into your shell** — a long-lived secret sitting in your environment,
your shell history, maybe a dotfile. **This tool never does that** (in fact it
doesn't use the `bw` CLI at all).

- We never ask you to export or store any session token.
- The transport key from the unlock handshake is **freshly generated every time**
  (a new ephemeral RSA keypair per unlock) and exists **only in memory for the
  duration of that one connection**. It is never written down, never reused.
- The vault user key the desktop app returns is **never written to disk**, never
  placed in an environment variable, never put on a command line (so it can't
  show up in `ps`), and never logged. It is held as raw bytes in the agent's
  `mlock`'d buffer and used for in-process decryption only.

### What we write to disk

Exactly one thing: a Unix-domain **socket** at
`~/Library/Caches/bw-wez/agent.sock`, created `0600` (only your user can touch
it). It carries local IPC between the tiny CLI and the agent — it is **not** a
network socket and holds no secret at rest. There is **no key file, no cache of
decrypted data, no session file**. (An earlier version briefly wrote a `0600`
session file; that was removed — see the git history.)

### Network

The **helper binary opens no network sockets at all.** To reach the desktop app
it launches Bitwarden's own `desktop_proxy` and speaks to it over stdio pipes;
the proxy relays to the desktop app's *local* socket. **Nothing this tool runs
ever contacts the network** — all server communication is done by the Bitwarden
desktop app itself, exactly as it already does. No analytics, no crash
reporting, no "phone home."

### What you are trusting (and what we can't protect against)

Being precise about the trust boundary is itself part of earning trust. When you
use this, you are trusting:

1. **Bitwarden's official desktop app** — it owns your master password, the
   biometric secret, the encrypted vault, and all syncing. (You already trust it
   by using Bitwarden.)
2. **This helper** — ~1,300 lines of Rust (much of it comments documenting the
   protocol), dependency-light, open and auditable.
3. **WezTerm** and the OS.

What this **cannot** defend against — and no password manager can:

- **A compromised machine.** Malware running as *your user* while the agent is
  unlocked can read process memory or scrape your clipboard. We shrink the window
  (in-memory only, `mlock`, idle-lock, `0600` socket, no disk persistence, no
  network) but a fully compromised host is game over. Lock (`bw-wez lock`) or
  close the session when you step away.
- **A malicious clipboard reader** during the auto-clear window — prefer
  `type_password` for the most sensitive secrets to skip the clipboard entirely.

We don't claim more than that, on purpose.

### Don't trust — verify

Run these yourself; they check the claims above directly (macOS):

```sh
# 1. No key on disk — the cache dir holds ONLY a 0600 socket, no key/session files:
ls -la ~/Library/Caches/bw-wez/

# 2. No secret in the agent's args or environment:
pgrep -fl 'bw-wez agent'                      # just "bw-wez agent" — no key in argv
ps eww -p "$(pgrep -f 'bw-wez agent')"        # scan the env: no key, no session token

# 3. The agent opens NO network sockets (note the -a: it ANDs the filters;
#    without -a, lsof ORs them and dumps every process's sockets):
lsof -a -p "$(pgrep -f 'bw-wez agent')" -i -nP   # expect: NO output

# 3b. ...and its entire open-file set is just /dev/null + the unix socket:
lsof -a -p "$(pgrep -f 'bw-wez agent')" -nP      # only /dev/null ×3 + agent.sock

# 4. See EXACTLY what is exchanged with the desktop app, frame by frame:
BW_WEZ_DEBUG=1 bw-wez unlock

# 5. Reads decrypt in-process and touch no network:
#    (watch your process list / a network monitor while picking — nothing dials out)
```

### Read the code

It's small and laid out so you can find the sensitive parts fast:

| File | Responsibility |
| --- | --- |
| `helper/src/transport.rs` | Launches `desktop_proxy`, native-messaging framing (stdio only — no network) |
| `helper/src/protocol.rs` | The handshake + biometric-unlock request to the desktop app |
| `helper/src/crypto.rs` | EncString (AES-256-CBC + HMAC) decryption; key types; ephemeral RSA |
| `helper/src/vault.rs` | Reads the desktop app's encrypted `data.json` and decrypts it **in-process** |
| `helper/src/agent.rs` | Holds the key in RAM (`mlock`, zero-on-drop, idle-lock, `0600` socket) |
| `plugin/init.lua` | The WezTerm UI — picker, copy/type, clipboard clear (no crypto) |

**The codebase is open — please dig in.** If anything is unclear, or you want to
understand *why* a decision was made, open an issue / discussion on the repo and
ask. We'd rather answer a hard question than have you guess. Independent review
and PRs are very welcome.

---

## How it works

WezTerm's Lua is sandboxed (no sockets, no FFI), so the plugin is pure UI + glue.
It shells out to a small Rust helper that does the privileged work:

```
WezTerm plugin (Lua)            helper: bw-wez (Rust)              trust anchor
─────────────────────           ──────────────────────            ───────────────
keybind → InputSelector  ──run──▶ list / get / totp        ──IPC─▶ Bitwarden Desktop
copy_to_clipboard / send_text  ◀──JSON── biometric unlock          (Touch ID; owns
                                                                    the gated key)
```

- **Provider A (today):** the helper asks the *running desktop app* to do the
  biometric unlock over its native-messaging channel — the same channel the
  browser extension uses — and gets back the **user key**, which it uses to
  decrypt the desktop app's own synced vault (`data.json`) directly in-process.
  No `bw` CLI, no network. Personal + organization login items both work.
- **Provider B (later):** a self-contained agent that provisions its own
  biometric-gated key (no desktop-app dependency). Deferred; see the plan.

Full design + rationale: `.lavish/plan.html` (open in a browser).

---

## Quick start — try the picker now (mock backend, no setup)

The mock backend returns fake vault data so you can feel the UX without Rust or
the desktop app.

In your `wezterm.lua`:

```lua
local wezterm = require 'wezterm'
local config = wezterm.config_builder()

-- For local development, point at a checkout via file://
-- (once published you'd use the GitHub URL: 'https://github.com/usrivastava92/bitwarden.wez')
local bw = wezterm.plugin.require 'file:///path/to/bitwarden.wez'

bw.apply_to_config(config, {
  helper = '/path/to/bitwarden.wez/mock/bw-wez',  -- the mock backend
  key = 'b', mods = 'CTRL|SHIFT',                 -- picker keybind (see note below)
})

return config
```

Reload WezTerm, press **Ctrl+Shift+B**, and fuzzy-search the fake vault. Enter
copies the (fake) password.

> **Keybind note:** avoid `Ctrl+Shift+P` — that's WezTerm's built-in command
> palette. Pick a free combo (the examples use `Ctrl+Shift+B`).

---

## Real setup (macOS)

Just two things — no `bw` CLI, no accounts to wire up:

1. **Bitwarden desktop app** — install it (the **Mac App Store** build exposes
   Touch ID), sign in, and in *Settings* enable:
   - ✅ **Allow browser integration**
   - ✅ **Unlock with Touch ID**

   Keep the app running (it must be running for biometric unlock anyway). It
   keeps its own vault synced, so the picker is always current — there's nothing
   else to sync.

2. **The helper** — build it once:
   ```sh
   cd helper
   cargo build --release
   # → helper/target/release/bw-wez   (put it on PATH, or point `helper` at it)
   ```
   (Prebuilt binaries, so you can skip this step too, are on the roadmap.)

Then point the plugin at the real helper (drop the `mock/` path):

```lua
bw.apply_to_config(config, {
  helper = '/abs/path/to/bw-wez',
  key = 'b', mods = 'CTRL|SHIFT',
})
```

Press your keybind → Touch ID → pick an item → password on your clipboard.

The helper finds the desktop app's vault automatically; set `BW_WEZ_VAULT_DATA`
only if yours lives in a non-standard place. See `docs/setup-macos.md` for
handshake troubleshooting and the full list of `BW_WEZ_*` environment variables.

---

## Configuration

All options, shown with example values:

```lua
bw.apply_to_config(config, {
  helper = 'bw-wez',                 -- path to the helper binary (or the mock)
  helper_args = {},                  -- extra args before the subcommand

  key = 'b', mods = 'CTRL|SHIFT',    -- main picker; runs default_action on Enter
                                     -- (avoid Ctrl+Shift+P — WezTerm's command palette)
  default_action = 'copy_password',  -- copy_password | type_password
                                     -- | copy_username | copy_totp | menu

  menu_key = 'g', menu_mods = 'CTRL|SHIFT',  -- optional: picker → action submenu

  clear_clipboard_seconds = 20,      -- wipe clipboard after copy (0 = never)
  fuzzy = true,
  notify = true,
})
```

Power users can build their own keybinds from the exposed picker factory:

```lua
local bw = wezterm.plugin.require 'file:///path/to/bitwarden.wez'
bw.apply_to_config(config, { helper = 'bw-wez' })
table.insert(config.keys, {
  key = 'u', mods = 'CTRL|SHIFT',
  action = bw.picker(bw.opts, 'type_username'),
})
```

---

## Backend contract

The plugin only knows this contract, so the mock and the real helper are
interchangeable (and you can write your own backend):

| Command | Output |
| --- | --- |
| `bw-wez status` | `{"status":"unlocked"\|"locked"\|"no-desktop"\|"error","message"?}` |
| `bw-wez list` | JSON array of `{id,name,username,folder,uri}` |
| `bw-wez get <id> --field <password\|username\|totp\|uri\|notes>` | raw value on stdout |

Other agent commands: `bw-wez unlock` (force a Touch ID unlock now),
`bw-wez lock` (drop the in-memory key immediately), `bw-wez stop` (kill the
agent). Non-zero exit = failure; the human-readable reason goes to stderr.

---

## Roadmap

- [x] WezTerm plugin: fuzzy picker, copy/type/TOTP, clipboard auto-clear, action menu
- [x] Mock backend (UX testable with zero setup)
- [x] Rust helper: native-messaging transport + handshake (verified vs desktop 2026.5.0)
- [x] **Biometric unlock + in-process vault decryption working on macOS** (personal logins)
- [x] Organization items (decrypt org keys via the account RSA private key)
- [x] In-memory agent (mlock'd key, idle-lock, 0600 socket — no on-disk key)
- [x] Read the desktop app's own synced vault directly — **no `bw` CLI dependency** (freshness handled by the app)
- [ ] Prebuilt helper binaries (skip the Rust build) via GitHub Releases
- [ ] Linux (polkit) and Windows (Hello) transports
- [ ] Provider B: self-contained biometric-gated key + official SDK (deferred)

---

## Questions, audits, and contributions

The code is open and meant to be read. If you want to verify a claim, understand
why something works the way it does, or you've found a problem:

- **Security questions or concerns:** open an issue (or, for anything sensitive,
  reach out privately) — we're happy to walk through any part of the design.
- **Audits and PRs:** very welcome. Start from the file map in
  *"Why you can trust this → Read the code."*
- **Feature requests:** open an issue describing your workflow.

We'd genuinely rather answer a hard question than have you trust us blindly.
