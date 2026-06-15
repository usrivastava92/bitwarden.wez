# macOS setup & bridge troubleshooting

This covers getting `provider A` (the desktop-app bridge) working on macOS, and
debugging the native-messaging handshake — the part that needs live iteration.

## Prerequisites

- **Bitwarden desktop app**, signed in. Touch ID requires the **Mac App Store**
  build (the direct-download build doesn't expose Touch ID for the keychain item).
- In the desktop app → *Settings*:
  - ✅ **Allow browser integration**
  - ✅ **Unlock with Touch ID**
- The desktop app should be **running** (and, in current Bitwarden versions,
  **unlocked at least once** in the session) for biometric unlock over IPC.
- **`bw` CLI** installed and `bw login` done once (the v1 data plane).

## Verifying the pieces

```sh
# 1. The native-messaging manifest the desktop app installed:
cat ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.8bit.bitwarden.json
#    -> note "path" (the desktop_proxy binary) and "allowed_origins".

# 2. The proxy binary exists:
ls -l /Applications/Bitwarden.app/Contents/MacOS/desktop_proxy

# 3. The desktop app's local socket appears when it's running:
ls -l ~/Library/Caches/com.bitwarden.desktop/

# 4. bw works with a manual session:
bw unlock   # then `bw list items --session <token>` should return JSON
```

## How the helper connects

`bw-wez` launches `desktop_proxy` and speaks Chrome native-messaging framing
(32-bit LE length prefix + JSON) to it, exactly like the browser:

1. `setupEncryption` — send our RSA public key; receive the AES transport key
   encrypted to it.
2. `biometricUnlock` (encrypted) — the desktop app shows Touch ID and returns
   the user key, which becomes `BW_SESSION` for `bw`.

## `LIVE-ITERATION` checklist

The protocol is reverse-engineered and shifts between desktop releases. If the
handshake fails, these are the likely culprits (all marked in the source):

| Symptom | File | What to try |
| --- | --- | --- |
| Connection refused / proxy not found | `transport.rs` | Confirm the `desktop_proxy` path; set `BW_WEZ_DESKTOP_PROXY=/abs/path`. |
| Rejected on connect / fingerprint prompt | `transport.rs`, `protocol.rs` | Approve the client in the desktop app; confirm `EXTENSION_ORIGIN` matches an entry in your manifest's `allowed_origins`. |
| `setupEncryption reply missing sharedSecret` | `protocol.rs` | The field may be `sharedKey` or nested — log the raw reply and adjust. |
| `MAC verification failed` / OAEP decrypt error | `crypto.rs` | Try OAEP with SHA-256 instead of SHA-1; confirm the public-key encoding the desktop expects. |
| `expected a 64-byte symmetric key` | `crypto.rs` | The key may be 32 bytes needing HKDF-Expand to 64. |
| `unlock reply missing user key` | `protocol.rs` | Key field is `userKeyB64` (newer) or `keyB64` (older); log the reply. |

Tip: temporarily log every frame in `transport.rs::read_json` to see exactly
what your desktop version sends, then align the structs.

## Useful env vars

- `BW_WEZ_DESKTOP_PROXY` — override the proxy binary path.
- `BW_WEZ_BW_DATA` / `BITWARDENCLI_APPDATA_DIR` — override where bw's `data.json` lives.
- `BW_WEZ_IDLE_SECS` — agent idle-lock timeout in seconds (default 900).
- `BW_WEZ_AGENT_SOCK` — override the agent's unix socket path.
- `BW_WEZ_USER_ID` — override the desktop account GUID used in the handshake.

Agent commands: `bw-wez status` (unlocked/locked), `bw-wez lock` (drop the key
now), `bw-wez stop` (kill the agent). The agent auto-spawns on first use.
