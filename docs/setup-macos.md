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

No `bw` CLI is needed. The helper reads the desktop app's *own* synced vault
(`data.json`) and decrypts it in-process with the biometric user key; the
desktop app keeps that file fresh while it runs.

## Verifying the pieces

```sh
# 1. The native-messaging manifest the desktop app installed:
cat ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.8bit.bitwarden.json
#    -> note "path" (the desktop_proxy binary) and "allowed_origins".

# 2. The proxy binary exists:
ls -l /Applications/Bitwarden.app/Contents/MacOS/desktop_proxy

# 3. The desktop app's local IPC sockets appear when it's running:
ls -l ~/Library/Group\ Containers/LTZ2PFU5D6.com.bitwarden.desktop/

# 4. The desktop app's own vault store exists (this is what the helper reads):
ls -l ~/Library/Containers/com.bitwarden.desktop/Data/Library/Application\ Support/Bitwarden/data.json
```

## How the helper connects

`bw-wez` uses two transport paths to reach the Bitwarden desktop app:

### Primary: direct IPC socket

Connects directly to the desktop app's Unix domain socket (`s.bw`). This is
the same path used by `bitwarden-cli-bio` and the newer Bitwarden browser
integration behind `FeatureFlag.BiometricsSDKIPC`.

Socket candidates (in order):
1. `~/Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/s.bw`
2. `~/Library/Caches/com.bitwarden.desktop/s.bw`

If `BW_WEZ_IPC_SOCKET` is set, that path is tried exclusively (bypasses the
candidate list).

### Fallback: `desktop_proxy` native-messaging

If the direct socket is unavailable (not found, connection refused, or
timeout), `bw-wez` falls back to launching `desktop_proxy` and speaking
Chrome native-messaging framing (32-bit LE length prefix + JSON) over stdio,
exactly like the browser extension.

### Protocol (shared by both transports)

1. `setupEncryption` — send our RSA public key; receive the AES transport key
   encrypted to it.
2. `biometricUnlock` (encrypted) — the desktop app shows Touch ID and returns
   the user key, which the agent holds in memory and uses to decrypt the vault.

The encrypted `message` payload is sent as a full EncString object carrying both
the canonical `encryptedString` field and the expanded parts (`data`/`iv`/`mac`),
matching what the desktop itself emits. This works on current and older builds.

## `LIVE-ITERATION` checklist

The protocol is reverse-engineered and shifts between desktop releases. If the
handshake fails, these are the likely culprits (all marked in the source):

| Symptom | File | What to try |
| --- | --- | --- |
| Connection refused / proxy not found | `transport/native_messaging.rs` | Confirm the `desktop_proxy` path; set `BW_WEZ_DESKTOP_PROXY=/abs/path`. |
| Rejected on connect / fingerprint prompt | `transport/native_messaging.rs`, `protocol.rs` | Approve the client in the desktop app; confirm `EXTENSION_ORIGIN` matches an entry in your manifest's `allowed_origins`. |
| `setupEncryption` reply missing `sharedSecret` | `protocol.rs` | The field may be `sharedKey` or nested — log the raw reply and adjust. |
| Touch ID never appears and the helper hangs | `transport/socket.rs`, `protocol.rs` | Confirm the socket path; check the desktop app is running, unlocked, and has browser integration enabled. If the encrypted payload is missing `encryptedString`, the desktop's `decryptString` silently drops it. |
| `MAC verification failed` / OAEP decrypt error | `crypto.rs` | Try OAEP with SHA-256 instead of SHA-1; confirm the public-key encoding the desktop expects. |
| `expected a 64-byte symmetric key` | `crypto.rs` | The key may be 32 bytes needing HKDF-Expand to 64. |
| `unlock reply missing user key` | `protocol.rs` | Key field is `userKeyB64` (newer) or `keyB64` (older); log the reply. |

Tip: build with `BW_WEZ_DEBUG=1` to see every frame read from the transport.

## Useful env vars

- `BW_WEZ_IPC_SOCKET` — override the direct IPC socket path (bypasses candidate list).
- `BW_WEZ_DESKTOP_PROXY` — override the `desktop_proxy` binary path.
- `BW_WEZ_VAULT_DATA` — override the path to the vault `data.json` (defaults to
  the desktop app's store; set this only for a non-standard install).
- `BW_WEZ_IDLE_SECS` — agent idle-lock timeout in seconds (default 900).
- `BW_WEZ_AGENT_SOCK` — override the agent's unix socket path.
- `BW_WEZ_USER_ID` — override the desktop account GUID used in the handshake.

> The agent reads these env vars **when it spawns** (first use). To change one,
> set it, then `bw-wez stop` so the next request respawns the agent with it.

Agent commands: `bw-wez status` (unlocked/locked), `bw-wez lock` (drop the key
now), `bw-wez stop` (kill the agent). The agent auto-spawns on first use.
Freshness is the desktop app's job — it keeps its own vault synced while running.
