# bitwarden.wez

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/usrivastava92/bitwarden.wez/badge)](https://securityscorecards.dev/viewer/?uri=github.com/usrivastava92/bitwarden.wez)
[![CI](https://github.com/usrivastava92/bitwarden.wez/actions/workflows/ci.yml/badge.svg)](https://github.com/usrivastava92/bitwarden.wez/actions/workflows/ci.yml)
[![CodeQL](https://github.com/usrivastava92/bitwarden.wez/actions/workflows/codeql.yml/badge.svg)](https://github.com/usrivastava92/bitwarden.wez/actions/workflows/codeql.yml)
[![Release](https://github.com/usrivastava92/bitwarden.wez/actions/workflows/release.yml/badge.svg)](https://github.com/usrivastava92/bitwarden.wez/actions/workflows/release.yml)

A [wezterm](https://github.com/wez/wezterm) plugin that auto-fills Bitwarden TOTP codes on your login page.

## Usage

1. Install the [bw-wez](https://github.com/usrivastava92/bitwarden.wez/releases/) helper CLI
2. Add the plugin to your `wezterm.lua`
3. Navigate to a Bitwarden login page in wezterm and the TOTP will auto-fill

See the [documentation](./docs) for full setup instructions.

## License

MIT
