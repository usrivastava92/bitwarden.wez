# Browser IPC Migration Plan

## Goal

Make `bitwarden.wez` use the same Bitwarden Desktop biometric unlock path that the official Bitwarden browser implementation uses, while keeping compatibility with older desktop builds.

The desired end state is:

1. Primary transport: direct Desktop IPC socket (`s.bw`)
2. Legacy fallback: `desktop_proxy` / native-messaging path
3. Shared secure message protocol compatible with both paths where possible
4. No indefinite hangs; failures must be bounded and diagnosable

---

## Problem Summary

Current user symptom:

- In WezTerm, pressing `Ctrl+Shift+B` should open the Bitwarden picker.
- Sometimes macOS asks whether WezTerm can access another app's data.
- After permission is granted, no Bitwarden biometric prompt appears.
- From the user's perspective, the plugin appears broken.

We already verified the WezTerm keybinding is correct. The failure is inside the helper/Desktop integration path.

---

## Current Repository State

Primary source repo:

- `/Users/utkarsh/workspace/github/bitwarden.wez`

Important files:

- `helper/src/main.rs`
- `helper/src/agent.rs`
- `helper/src/transport.rs`
- `helper/src/protocol.rs`
- `helper/src/crypto.rs`
- `helper/src/vault.rs`
- `plugin/init.lua`
- `docs/setup-macos.md`

Live cached WezTerm plugin install:

- `/Users/utkarsh/Library/Application Support/wezterm/plugins/httpssCssZssZsgithubsDscomsZsusrivastava92sZsbitwardensDswez`

Bitwarden Desktop app:

- `/Applications/Bitwarden.app`

Bitwarden vault data file:

- `~/Library/Containers/com.bitwarden.desktop/Data/Library/Application Support/Bitwarden/data.json`

Observed live IPC socket on this machine:

- `~/Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/s.bw`

Legacy/non-sandbox IPC socket path still relevant for compatibility:

- `~/Library/Caches/com.bitwarden.desktop/s.bw`

Native-messaging manifest:

- `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.8bit.bitwarden.json`

---

## What Has Already Been Verified

### WezTerm side

- Active config is `~/.config/wezterm/wezterm.lua`
- Plugin is loaded correctly
- Keybinding is configured correctly:

```lua
bw.apply_to_config(config, {
  key = 'b',
  mods = 'CTRL|SHIFT',
})
```

So the problem is not the keybinding.

### Bitwarden Desktop side

- Bitwarden Desktop is installed and running.
- `desktop_proxy` exists:

```text
/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy
```

- Bitwarden Desktop vault data exists and is readable.
- Native messaging manifest exists and includes allowed origins.
- Bitwarden Desktop is actively using the group-container socket path on this machine.

### Helper behavior

- Original helper could wedge its background agent and hang indefinitely.
- That no-hang issue was improved in the source repo.
- But end-to-end biometric unlock still fails.

---

## Changes Already Made In This Repo

These changes have already been made in the working tree.

### `helper/src/transport.rs`

- Added bounded read behavior using `poll`
- Added timeout-based frame reads instead of unbounded blocking

Intent:

- prevent the helper from hanging forever if the Desktop app does not reply

### `helper/src/protocol.rs`

- Added retry logic for two encrypted message formats:
  - modern string `message`
  - legacy object `message`
- Added handshake timeout and encrypted reply timeout

Intent:

- support both older and newer Bitwarden Desktop message payload shapes

### `helper/src/crypto.rs`

- Added `encrypt_to_string()` to generate canonical EncString payloads:

```text
2.iv|data|mac
```

Intent:

- support newer Desktop builds that expect encrypted payloads as a string

### `docs/setup-macos.md`

- Updated notes about current macOS IPC layout
- Documented string-vs-object encrypted payload compatibility

### Live plugin cache

The rebuilt arm64 helper binary was copied into:

- `bin/aarch64-apple-darwin/bw-wez` in the source repo
- the cached WezTerm plugin install

This was only for local testing; the real product fix should come from source, not just copied binaries.

---

## What Was Tested

### Test 1: helper isolation / no-hang regression check

Using an isolated agent socket, the rebuilt helper:

- did not wedge permanently
- remained responsive to `status` and `stop` after failed unlock attempts

This means the helper's failure mode improved, but biometric unlock still did not succeed.

### Test 2: direct helper debug against live Bitwarden Desktop

Observed behavior:

1. `setupEncryption` succeeds
2. helper sends unlock request
3. Bitwarden does not return unlock response
4. connection appears to reset / restart instead

This happened for both encrypted payload styles:

- string `message`
- object `message`

Conclusion:

- The remaining issue is not only the `message` payload shape.

### Test 3: macOS system logs during unlock attempts

System logs showed Bitwarden requesting biometrics via LocalAuthentication, but the prompt never reached the user.

Observed log pattern:

- Bitwarden creates `LAContext`
- requests `DeviceOwnerAuthenticationWithBiometricsOrWatch`
- macOS biometric stack returns:

```text
IOSEPBiometricService::sksQueueDequeue -> err:0xe00002f0
```

- Bitwarden immediately deallocates the `LAContext`
- no Touch ID prompt is shown

Interpretation:

- the request is reaching Bitwarden
- but the native-messaging / `desktop_proxy` path still does not complete a working biometric unlock on this machine

---

## Important Discovery From Source Research

We checked official Bitwarden browser code and `bitwarden-cli-bio`.

### Official Bitwarden browser implementation

Relevant upstream repo:

- `bitwarden/clients`

Relevant files:

- `apps/browser/src/key-management/biometrics/background-browser-biometrics.service.ts`
- `apps/desktop/src/services/biometric-message-handler.service.ts`
- `apps/desktop/src/key-management/biometrics/main-biometrics-ipc.listener.ts`

Key finding:

- The browser code now has two paths:
  1. newer direct IPC path behind `FeatureFlag.BiometricsSDKIPC`
  2. older native-messaging path

This means Bitwarden itself is already transitioning away from native messaging as the only path.

### `bitwarden-cli-bio` implementation

Relevant upstream repo:

- `jeanregisser/bitwarden-cli-bio`

Relevant file:

- `src/ipc/ipc-socket.service.ts`

Key finding:

- `bwbio` does not use `desktop_proxy`
- it connects directly to Desktop IPC socket `s.bw`
- on macOS it checks:
  - `~/Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/s.bw`
  - then `~/Library/Caches/com.bitwarden.desktop/s.bw`

This is the strongest signal about where `bitwarden.wez` should head next.

---

## Current Diagnosis

Current helper design is based on the legacy browser-native-messaging style:

```text
helper -> desktop_proxy -> Bitwarden Desktop
```

But the modern supported Bitwarden clients appear to be moving toward:

```text
client -> Desktop IPC socket (s.bw) -> Bitwarden Desktop
```

So the likely architectural problem is not another small tweak to `desktop_proxy`.

The likely real fix is:

- implement direct Desktop IPC socket transport as the primary path
- keep `desktop_proxy` as compatibility fallback for older builds

---

## Builder Agent Objective

Rework the helper so it behaviorally matches official Bitwarden browser/CLI desktop biometric integration as closely as practical, with compatibility for both newer and older Desktop builds.

---

## Target Architecture

### Primary transport: direct Desktop IPC socket

Implement a new transport layer that connects directly to Bitwarden Desktop's socket.

macOS socket candidate order:

1. `~/Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/s.bw`
2. `~/Library/Caches/com.bitwarden.desktop/s.bw`

Requirements:

- Unix socket connection
- length-prefixed JSON frames
- reconnect / disconnect handling
- bounded timeouts
- clear diagnostics

### Legacy fallback: `desktop_proxy`

Retain the current `desktop_proxy` transport as a fallback only.

Use it when:

- direct socket cannot be found
- direct socket connect fails in a compatibility-shaped way
- older Desktop builds require native messaging

### Shared secure protocol

Keep using the secure channel protocol:

1. `setupEncryption`
2. RSA-OAEP SHA-1 to unwrap 64-byte shared secret
3. AES-256-CBC + HMAC-SHA256 encrypted messages

But make the protocol implementation transport-agnostic so both socket and native-messaging can reuse it.

---

## Concrete Refactor Plan

### Phase 1: Introduce transport abstraction

Goal:

- separate protocol logic from transport details

Recommended shape:

- create a transport abstraction for:
  - connect
  - write JSON frame
  - read JSON frame with timeout
- current `desktop_proxy` implementation becomes one transport
- new direct socket implementation becomes another transport

Suggested files:

- keep `helper/src/transport.rs` if refactoring in place is simplest
- or split into:
  - `helper/src/transport/mod.rs`
  - `helper/src/transport/socket.rs`
  - `helper/src/transport/native_messaging.rs`

Important design rule:

- do not duplicate handshake and encrypted command logic in each transport
- keep handshake/protocol logic centralized in `protocol.rs`

### Phase 2: Add direct socket transport

Implement direct Desktop IPC socket transport.

Behavior should mimic `bitwarden-cli-bio`:

- resolve socket candidate paths in correct order
- attempt connection with short bounded timeout
- read/write length-prefixed JSON
- treat disconnects and partial frames robustly

Needed behaviors:

- socket path override env var is a good idea for debugging, e.g. `BW_WEZ_IPC_SOCKET`
- clear error if no socket candidates exist
- clear error if Desktop app is not running or browser integration is disabled

### Phase 3: Make protocol transport-agnostic

Update `protocol.rs` so `Session::establish(...)` can work with either:

- direct socket transport
- native-messaging transport

The transport should only handle frame IO.
The session logic should handle:

- `connected`
- `setupEncryption`
- `invalidateEncryption`
- encrypted request/reply flow

### Phase 4: Transport selection strategy

Implement selection policy:

1. try direct socket transport first
2. if that is unavailable, try `desktop_proxy`

Be explicit about which failures should trigger fallback.

Recommended fallback cases:

- socket path missing
- connection refused
- initial connect timeout

Probably do not fallback on all protocol failures, because that can hide real bugs.

### Phase 5: Preserve compatibility payload handling

Keep the string-vs-object encrypted payload support already added.

Recommended approach:

- keep the current logic that tries encrypted string first and retries with object when the error shape suggests compatibility mismatch

Even if direct socket becomes primary, older Desktop builds may still need object-form encrypted payloads.

### Phase 6: Improve diagnosability

The helper should produce actionable debug output when `BW_WEZ_DEBUG=1` is set.

Debug output should include:

- chosen transport
- socket candidate paths tried
- whether fallback occurred
- raw frame direction for handshake/debug mode
- concise error chain with context

Avoid noisy logging in normal mode.

### Phase 7: Keep failure bounded

No path should block indefinitely.

Required timeouts:

- transport connect timeout
- handshake frame timeout
- encrypted reply timeout
- agent request timeout if appropriate

If unlock fails, the agent must remain usable:

- `status` should still work
- `stop` should still work
- next unlock attempt should not require manual process cleanup

---

## Validation Plan

### Local unit / structural validation

1. Build helper:

```sh
cd /Users/utkarsh/workspace/github/bitwarden.wez/helper
cargo build --release
```

2. Ensure no compile regressions.

### Runtime validation with direct helper

Use isolated socket path for helper agent so tests do not interfere with live WezTerm session.

Test commands:

```sh
BW_WEZ_AGENT_SOCK="/tmp/bw-wez-test.sock" \
BW_WEZ_DEBUG=1 \
./target/release/bw-wez status
```

```sh
BW_WEZ_AGENT_SOCK="/tmp/bw-wez-test.sock" \
BW_WEZ_DEBUG=1 \
./target/release/bw-wez unlock
```

Success criteria:

- direct socket transport is used first
- if direct socket works, biometric prompt appears or a valid unlock response is returned
- if unlock fails, helper exits or returns cleanly without wedging agent

### Live WezTerm validation

After source validation, update bundled helper and cached plugin helper.

Then:

1. reload WezTerm
2. ensure old `bw-wez` processes are not lingering
3. try `Ctrl+Shift+B`

Success criteria:

- biometric prompt appears
- picker opens after unlock
- no stuck helper agent after failed attempts

### Compatibility validation

At minimum verify:

1. current local Bitwarden build works
2. legacy transport path still compiles and can be selected

If possible, add a small mock test for:

- socket transport secure handshake
- encrypted string reply path
- encrypted object reply path

---

## Recommended Testing References

Official browser/Desktop code to compare against:

- `bitwarden/clients/apps/browser/src/key-management/biometrics/background-browser-biometrics.service.ts`
- `bitwarden/clients/apps/desktop/src/services/biometric-message-handler.service.ts`
- `bitwarden/clients/apps/desktop/src/key-management/biometrics/main-biometrics-ipc.listener.ts`

Direct socket client reference:

- `jeanregisser/bitwarden-cli-bio/src/ipc/ipc-socket.service.ts`

Mock protocol inspiration:

- `jeanregisser/bitwarden-cli-bio/tests/e2e/mock-desktop-server.ts`

This mock server is especially useful because it shows a simple direct-socket implementation of:

- length-prefixed JSON
- `setupEncryption`
- encrypted request/response framing

---

## Non-Goals

Do not spend time on these unless needed by the transport rewrite:

- changing WezTerm Lua UI behavior
- changing picker UX
- changing vault decryption logic in `vault.rs`
- reworking clipboard behavior
- general refactors unrelated to Desktop IPC migration

The central problem is transport/integration, not picker UI.

---

## Suggested Deliverables For Builder Agent

1. Implement direct socket transport
2. Preserve `desktop_proxy` fallback
3. Refactor protocol layer to support both transports cleanly
4. Keep compatibility support for encrypted string/object payloads
5. Keep bounded failure behavior
6. Update docs to reflect actual architecture
7. Build and verify locally

Optional but strongly recommended:

8. Add a small test harness or mock-based validation for direct socket handshake/protocol

---

## Final Recommendation

Do not continue treating `desktop_proxy` as the primary long-term path.

Use the official Bitwarden browser/Desktop behavior as source of truth:

- direct Desktop IPC socket first
- legacy native-messaging path second

That is the most likely way to get this plugin working on current Bitwarden releases while still supporting older builds.
