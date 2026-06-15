# bitwarden.wez

A Bitwarden vault picker for [WezTerm](https://wezterm.org) — the browser-extension
experience in your terminal. Hit a keybind, fuzzy-search your vault, and copy or
type a password, username, or TOTP. Unlock is **biometric** (Touch ID / Windows
Hello / polkit) and your **master password is never stored** — it gates a *key*,
exactly like the official clients.

> **Status: v1, in progress.** The WezTerm plugin and its UX are complete and
> usable today against the bundled **mock backend**. The real unlock path
> (`provider A` — bridge to the Bitwarden desktop app) is implemented to the
> documented protocol but needs live iteration against a running desktop app
> (grep the helper for `LIVE-ITERATION`). macOS is the lead platform; Linux and
> Windows follow.

---

## How it works

WezTerm's Lua is sandboxed (no sockets, no FFI), so the plugin is pure UI + glue.
It shells out to a small helper binary that does the privileged work:

```
WezTerm plugin (Lua)            helper: bw-wez (Rust)              trust anchor
─────────────────────           ──────────────────────            ───────────────
keybind → InputSelector  ──run──▶ list / get / totp        ──IPC─▶ Bitwarden Desktop
copy_to_clipboard / send_text  ◀──JSON── biometric unlock          (Touch ID; owns
                                                                    the gated key)
```

- **No master password** is ever entered in the terminal or stored by this tool.
- **Provider A (v1):** the helper asks the *running desktop app* to do the
  biometric unlock over its native-messaging channel — the same channel the
  browser extension uses — and gets back the **user key**, which it uses to
  decrypt your already-synced vault (`bw`'s `data.json`) directly in-process.
  Reads never spawn `bw`. (Personal + organization login items both work.)
- **Provider B (later):** a self-contained agent that provisions its own
  biometric-gated key (no desktop-app dependency). Deferred; see the plan.

Full design + rationale: `.lavish/plan.html` (open in a browser).

---

## Quick start — try the picker now (mock backend, no setup)

The mock backend returns fake vault data so you can feel the UX without Rust,
`bw`, or the desktop app.

In your `wezterm.lua`:

```lua
local wezterm = require 'wezterm'
local config = wezterm.config_builder()

-- During local development, point at this repo via file://
local bw = wezterm.plugin.require 'file:///Users/usrivastava/workspace/github/bitwarden.wez'

bw.apply_to_config(config, {
  -- use the mock while developing:
  helper = '/Users/usrivastava/workspace/github/bitwarden.wez/mock/bw-wez',
  key = 'p',
  mods = 'CTRL|SHIFT',
})

return config
```

Reload WezTerm, press **Ctrl+Shift+P**, and fuzzy-search the fake vault. Enter
copies the (fake) password.

---

## Real setup (macOS)

1. **Install the Bitwarden desktop app** (Mac App Store build for Touch ID),
   sign in, and enable in *Settings*:
   - **Allow browser integration**
   - **Unlock with Touch ID**
2. **Install the `bw` CLI** (used once to sync your encrypted vault to disk;
   not invoked on reads): `brew install bitwarden-cli`, then `bw login`. Re-run
   `bw sync` to refresh. You do **not** need to export the `BW_SESSION` it prints.
3. **Build the helper:**
   ```sh
   cd helper
   cargo build --release
   # binary at helper/target/release/bw-wez — put it on PATH or point `helper` at it
   ```
4. **Point the plugin at the real helper** (drop the `helper = .../mock/...`
   line, or set it to the built binary):
   ```lua
   bw.apply_to_config(config, { helper = '/abs/path/to/bw-wez' })
   ```
5. Press your keybind → Touch ID prompt → pick an item → password on your clipboard.

See `docs/setup-macos.md` for troubleshooting the native-messaging handshake.

---

## Configuration

```lua
bw.apply_to_config(config, {
  helper = 'bw-wez',                 -- path to the helper binary (or the mock)
  helper_args = {},                  -- extra args before the subcommand

  key = 'p', mods = 'CTRL|SHIFT',    -- main picker; runs default_action on Enter
  default_action = 'copy_password',  -- copy_password | type_password
                                     -- | copy_username | copy_totp | menu

  menu_key = 'b', menu_mods = 'CTRL|SHIFT',  -- optional: picker → action submenu

  clear_clipboard_seconds = 20,      -- wipe clipboard after copy (0 = never)
  fuzzy = true,
  notify = true,
})
```

Power users can build their own keybinds from the exposed picker factory:

```lua
local bw = wezterm.plugin.require 'file:///.../bitwarden.wez'
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

Non-zero exit = failure; the human-readable reason goes to stderr.

---

## Security notes

- The master password is never entered in the terminal (WezTerm's prompt can't
  mask input) nor stored by this tool. Unlock is biometric, via the desktop app.
- v1 caches the biometric user key in a `0600` file with a TTL (default 300s) so
  one Touch ID covers a picker interaction. It's used in-process to decrypt the
  vault and is never written to your shell env or passed to another process. The
  planned in-memory agent removes the on-disk key entirely.
- Copied passwords auto-clear from the clipboard after `clear_clipboard_seconds`.
- Prefer `type_password` near a trusted prompt to avoid the clipboard entirely.

---

## Roadmap

- [x] WezTerm plugin: fuzzy picker, copy/type/TOTP, clipboard auto-clear, action menu
- [x] Mock backend (UX testable with zero setup)
- [x] Rust helper: native-messaging transport + handshake (verified vs desktop 2026.5.0)
- [x] **Biometric unlock + in-process vault decryption working on macOS** (personal logins)
- [x] Organization items (decrypt org keys via the account RSA private key)
- [ ] In-memory agent (drop the on-disk key cache)
- [ ] `bw sync` freshness / auto-sync
- [ ] Linux (polkit) and Windows (Hello) transports
- [ ] Provider B: self-contained biometric-gated key + official SDK (deferred)
