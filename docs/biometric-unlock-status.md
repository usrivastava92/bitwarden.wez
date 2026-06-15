## Bitwarden Biometric Unlock Status

> **RESOLVED (2026-06-15).** Root cause found and fixed. The blocker was **not**
> macOS biometrics — it was the encrypted-message wire format. Bitwarden Desktop
> 2026.5.0 changed its IPC `decryptString` to read `message.encryptedString`;
> neither the old object form (`{encryptionType,data,iv,mac}`) nor the bare
> EncString string carried that field, so the desktop's decrypt threw and the
> `unlockWithBiometricsForUser` command was silently dropped (no reply, no
> prompt). The helper now sends a full EncString object that includes
> `encryptedString` **and** the expanded `data`/`iv`/`mac` parts, which works on
> current builds, older builds, and matches what the desktop itself emits.
> Verified end-to-end on 2026.5.0: `locked → unlock → unlocked`, and `list`
> returns decrypted vault items. See "Resolution" at the bottom.

### Problem summary

`bitwarden.wez` should trigger Bitwarden Desktop biometric unlock from WezTerm and then open the picker. On this machine, the helper can reach Bitwarden Desktop, but the biometric unlock flow never completes.

### Expected behavior

1. WezTerm keybinding triggers `bw-wez`.
2. `bw-wez` talks to Bitwarden Desktop.
3. Bitwarden shows Touch ID / biometric prompt.
4. Bitwarden returns the user key.
5. The helper unlocks the vault in memory and the picker opens.

### Actual behavior

1. WezTerm keybinding is wired correctly.
2. The helper reaches Bitwarden Desktop successfully.
3. Bitwarden starts biometric handling internally.
4. No Touch ID prompt is shown.
5. Bitwarden never returns the unlock reply.
6. The helper waits for a reply and eventually times out or hangs at the CLI level waiting for Desktop.

### What we verified

- Active WezTerm config is correct and loads the plugin correctly.
- The Bitwarden Desktop app is installed and running.
- `desktop_proxy` exists at `/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy`.
- Bitwarden vault data exists at `~/Library/Containers/com.bitwarden.desktop/Data/Library/Application Support/Bitwarden/data.json`.
- Native messaging manifest exists at `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.8bit.bitwarden.json`.
- Current Bitwarden Desktop builds on this machine expose live IPC sockets at:
  - `~/Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/s.bw`
  - `~/Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/s.af`
- `bw-wez status` can talk to the Desktop app and reports the vault as locked.

### Important protocol findings

- The raw `s.bw` socket does not emit an initial `{"command":"connected"}` frame by itself.
- The raw `s.bw` socket does accept `setupEncryption` immediately after connect.
- `setupEncryption` must include `messageId` and `timestamp` for current Desktop builds.
- The direct socket returns a valid `sharedSecret` when the handshake is sent correctly.
- After the handshake, the helper can send `unlockWithBiometricsForUser` over the encrypted channel.
- The remaining failure happens after Bitwarden receives the unlock request.

### What we changed

#### Transport changes

- Split transport handling into:
  - `helper/src/transport/mod.rs`
  - `helper/src/transport/socket.rs`
  - `helper/src/transport/native_messaging.rs`
- Added direct IPC socket transport as the primary path.
- Kept `desktop_proxy` native-messaging as a fallback path.
- Added bounded timeout behavior so transport/protocol failures do not wedge the helper forever.

#### Protocol changes

- `Session::establish()` now tries the direct socket first and falls back to `desktop_proxy` if needed.
- Direct socket handshake now sends `setupEncryption` immediately on connect.
- `setupEncryption` now includes `messageId` and `timestamp`.
- Added compatibility handling for encrypted payload shape:
  - first try string EncString payload (`2.iv|data|mac`)
  - then retry with object payload (`{encryptionType,data,iv,mac}`) when retry conditions match
- Added bounded frame/reply timeouts.

#### Helper/debugging changes

- Added `encrypt_to_string()` in `helper/src/crypto.rs`.
- Improved agent error responses to preserve full error chains.
- Updated docs for current macOS socket locations and compatibility notes.
- Added socket integration tests and a CI workflow.

### Files changed so far

- `.github/workflows/ci.yml`
- `.gitignore`
- `bin/aarch64-apple-darwin/bw-wez`
- `docs/browser-ipc-migration-plan.md`
- `docs/setup-macos.md`
- `helper/Cargo.toml`
- `helper/src/agent.rs`
- `helper/src/crypto.rs`
- `helper/src/lib.rs`
- `helper/src/main.rs`
- `helper/src/protocol.rs`
- `helper/src/transport/mod.rs`
- `helper/src/transport/socket.rs`
- `helper/src/transport/native_messaging.rs`
- `helper/tests/socket_integration.rs`

### What works now

- The helper no longer depends only on `desktop_proxy`.
- The helper can establish encryption over the live `s.bw` socket.
- The helper can send the biometric unlock request over the encrypted direct socket channel.
- The helper build passes.
- The helper test suite passes.

### What is still not working

- Bitwarden Desktop does not complete biometric unlock after receiving the request.
- No Touch ID prompt is shown to the user.
- No final encrypted unlock response is returned to the helper.
- End-to-end unlock from WezTerm is still not working.

### Current blocker

The strongest evidence points to Bitwarden/macOS biometric execution itself, not the helper transport handshake.

Recent system logs during unlock attempts show Bitwarden repeatedly creating `LAContext`, requesting biometric auth, and then aborting internally with:

```text
IOSEPBiometricService::sksQueueDequeue -> err:0xe00002f0
```

This is followed by immediate `LAContext` teardown and no visible Touch ID prompt.

### Why we believe the helper is no longer the primary failure

- Direct socket handshake succeeds.
- Bitwarden returns the encrypted session key.
- The helper sends the unlock request successfully.
- Bitwarden begins LocalAuthentication work after that request.
- The failure happens after request delivery, inside Bitwarden/macOS biometric handling.

### Open questions

- Does current Bitwarden Desktop require an additional preflight step before `unlockWithBiometricsForUser`, such as a biometrics status query?
- Is the no-prompt behavior caused by a Bitwarden Desktop bug on this machine even though `canEvaluatePolicy` reports success?
- Is there a Desktop-side state/approval/fingerprint issue that still differs between browser and third-party client flows after `setupEncryption`?

### Suggested next debugging steps

1. Compare the helper's full post-handshake message sequence against the current official Bitwarden browser/Desktop implementation.
2. Check whether the official client sends any preflight command before `unlockWithBiometricsForUser`.
3. Verify whether Bitwarden Desktop expects additional top-level metadata on direct socket unlock frames.
4. Reproduce against another machine or macOS account to separate machine-specific biometric issues from protocol issues.
5. If needed, instrument Bitwarden Desktop behavior further around the direct socket biometric request path.

### Branch with current work

- Branch: `fix/direct-ipc-socket-fallback`

### Current conclusion

The main helper-side transport and handshake bugs appear fixed. The unresolved issue is that Bitwarden Desktop receives the unlock request but does not complete biometric authentication successfully on this machine, so no unlock reply ever returns to `bw-wez`.

---

### Resolution (2026-06-15)

The earlier conclusion above (blaming macOS/Secure Enclave) was **wrong**. The
`IOSEPBiometricService::sksQueueDequeue -> err:0xe00002f0` line is benign noise
present on healthy Apple Silicon machines and was a red herring. The unlock
request never reached the biometric handler at all.

**Root cause.** Reading the desktop's bundled handler
(`/Applications/Bitwarden.app/Contents/Resources/app.asar`,
`BiometricMessageHandlerService.handleMessage`) showed the post-handshake
encrypted command is decrypted with:

```js
decryptString(e, t) {
  if (e.encryptionType === AesCbc256_B64) throw ...;     // type 0 only
  return symmetric_decrypt_string(e.encryptedString, t); // reads e.encryptedString
}
```

The `message` we send is passed straight in as `e`. Current builds read
`e.encryptedString`. Our payloads didn't provide it:

- legacy object `{encryptionType, data, iv, mac}` → `e.encryptedString` is
  `undefined` → WASM decrypt throws → message silently dropped.
- bare string `"2.iv|data|mac"` → `"...".encryptedString` is also `undefined`
  → same silent drop.

Because the drop happens **before** the command dispatch switch, and only a
*successful-but-null* decrypt emits `invalidateEncryption`, the helper saw no
reply at all and timed out (or, on `main`, blocked forever). This is why it
broke after a Bitwarden update and why both the `main` object form and the
branch string form failed identically.

**Fix.** `Session::send_encrypted` now emits a single EncString object carrying
both representations (exactly what the desktop emits on its own replies):

```json
"message": {
  "encryptionType": 2,
  "encryptedString": "2.iv|data|mac",
  "data": "...", "iv": "...", "mac": "..."
}
```

This satisfies current builds (`encryptedString`), older builds
(`data`/`iv`/`mac`), and the integration tests. The brittle string→object retry
ladder and `is_encoding_retryable()` were removed — they were also buggy
(`is_encoding_retryable` matched on `err.to_string()`, which returns only the
top-level anyhow context, not the nested "timed out" cause, so the fallback
never fired).

**Verified on Bitwarden Desktop 2026.5.0 (arm64):**

- direct socket at `~/Library/Caches/com.bitwarden.desktop/s.bw` (the Group
  Containers path was absent on this machine — the existing candidate fallback
  handled it).
- `setupEncryption` handshake succeeds.
- `unlockWithBiometricsForUser` now returns `response:true` + `userKeyB64`.
- `bw-wez status` goes `locked → unlocked`; `bw-wez list` returns decrypted
  vault items.

Note: the desktop's own vault must be running; if it is locked the unlock still
drives Touch ID. Lock state was *not* the gate — the wire format was.
