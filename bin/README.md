# Prebuilt helper binaries

These are the `bw-wez` helper binaries, one per platform, laid out as
`bin/<target-triple>/bw-wez`. They ship **inside the repo on purpose**: when you
install the plugin with `wezterm.plugin.require`, WezTerm clones the whole repo
locally, so the right binary for your platform arrives with it — **no download
step**, and the binary lives next to the exact source that produced it.

The plugin auto-selects `bin/<wezterm.target_triple>/bw-wez` unless you set
`helper` to your own path.

| Triple | Platform |
| --- | --- |
| `aarch64-apple-darwin` | macOS, Apple Silicon |
| `x86_64-apple-darwin` | macOS, Intel *(added with that build)* |

## Don't trust a binary you can't see built — verify it

The whole point of this project is that you shouldn't have to take an opaque
binary on faith. For released versions, each binary here is:

- **built in GitHub Actions from the tagged commit** (not on a maintainer's
  machine) — the workflow is public at `.github/workflows/release.yml`;
- **published with a SHA-256 checksum** on the corresponding GitHub Release;
- **attested with build provenance** (SLSA, via GitHub artifact attestations),
  so you can cryptographically tie the binary to the source commit + workflow:

  ```sh
  gh attestation verify bin/aarch64-apple-darwin/bw-wez --repo usrivastava92/bitwarden.wez
  ```

- **reproducible** as a goal: build the same tag yourself and compare —

  ```sh
  cd helper && cargo build --release --locked
  shasum -a 256 target/release/bw-wez            # compare to the file here
  ```

If you'd rather not run a prebuilt binary at all, build from source and point the
plugin at your own binary (`helper = '/abs/path/to/bw-wez'`). That always wins
over the bundled one.

## ⚠️ Bootstrap notice

Until this repo is pushed to GitHub and the release workflow runs, the binary
checked in here is a **local developer build**, committed only so the bundled
path works end to end. It will be **replaced by the CI-built, checksummed, and
attested binary** before any tagged release. Treat the current file as a
placeholder, and prefer building from source until then.
