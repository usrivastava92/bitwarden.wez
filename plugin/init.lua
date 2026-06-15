-- bitwarden.wez — a Bitwarden vault picker for WezTerm
--
-- v1: provider A (desktop bridge). The plugin is pure UI + glue; it shells out
-- to a helper binary (`bw-wez`) that speaks Bitwarden's native-messaging IPC to
-- the running desktop app for biometric unlock, and returns vault data as JSON.
--
-- The plugin never sees your master password and never opens a socket itself
-- (WezTerm's Lua is sandboxed: no sockets/FFI). All it does is:
--   1. run `bw-wez list`            -> JSON array of items
--   2. show a fuzzy InputSelector   -> user picks an item by id
--   3. run `bw-wez get <id> ...`    -> the secret, which we copy or type
--
-- Backend contract (so the mock and the real helper are interchangeable):
--   bw-wez status            -> {"status":"unlocked"|"locked"|"no-desktop"|"error","message":?}
--   bw-wez list              -> [{"id","name","username","folder","uri"}...]
--   bw-wez get <id> --field <password|username|totp|uri|notes>  -> raw value on stdout
-- A non-zero exit code means failure; stderr carries the human message.

local wezterm = require('wezterm')
local act = wezterm.action

local M = {}

----------------------------------------------------------------------
-- platform helpers
----------------------------------------------------------------------

local function is_mac()
  return (wezterm.target_triple or ''):find('apple') ~= nil
end

local function is_windows()
  return (wezterm.target_triple or ''):find('windows') ~= nil
end

----------------------------------------------------------------------
-- locating the helper binary
----------------------------------------------------------------------

-- This plugin ships prebuilt helper binaries under bin/<target_triple>/. When
-- installed via `wezterm.plugin.require`, the whole repo (binary included) is
-- cloned locally — so there's nothing to download, and the binary sits next to
-- the source that produced it. Users who'd rather build from source just point
-- `helper` at their own binary; that always wins.

local function path_exists(path)
  local ok, f = pcall(io.open, path, 'r')
  if ok and f then
    f:close()
    return true
  end
  return false
end

-- Absolute path to this plugin's local clone via wezterm.plugin.list(), or nil
-- if it isn't a registered plugin (e.g. loaded with dofile during development).
local function plugin_dir()
  local ok, list = pcall(function()
    return wezterm.plugin.list()
  end)
  if not ok or type(list) ~= 'table' then
    return nil
  end
  for _, p in ipairs(list) do
    local hay = ((p.url or '') .. ' ' .. (p.component or '')):lower()
    if hay:find('bitwarden', 1, true) then
      return p.plugin_dir
    end
  end
  return nil
end

-- The bundled binary for this platform (bin/<target_triple>/bw-wez), if present.
local function bundled_helper()
  local dir = plugin_dir()
  if not dir then
    return nil
  end
  local triple = wezterm.target_triple or ''
  local sep = is_windows() and '\\' or '/'
  local exe = is_windows() and 'bw-wez.exe' or 'bw-wez'
  local path = table.concat({ dir, 'bin', triple, exe }, sep)
  return path_exists(path) and path or nil
end

-- Resolve which helper to run: an explicit `helper` (build-from-source or the
-- mock) wins; else the bundled binary for this platform; else `bw-wez` on PATH.
local function resolve_helper(opts)
  if type(opts.helper) == 'string' and opts.helper ~= '' then
    return opts.helper
  end
  return bundled_helper() or 'bw-wez'
end

----------------------------------------------------------------------
-- config
----------------------------------------------------------------------

local defaults = {
  -- Path to the helper binary. Leave unset to auto-detect: the plugin uses the
  -- prebuilt binary bundled in this repo for your platform (bin/<target_triple>/),
  -- falling back to `bw-wez` on PATH. Set it to build from source or use the
  -- mock, e.g. helper = '/path/to/bitwarden.wez/helper/target/release/bw-wez'
  helper = nil,
  -- Extra args always passed before the subcommand (e.g. {'--profile','work'}).
  helper_args = {},

  -- Main keybinding: open the picker and run `default_action` on the chosen item.
  key = 'b',
  mods = 'CTRL|SHIFT',

  -- Optional second keybinding that opens the picker then shows an action
  -- submenu (copy/type password, username, TOTP). Set to nil to disable.
  menu_key = nil,
  menu_mods = nil,

  -- What Enter does on the main picker. One of:
  -- 'copy_password' | 'type_password' | 'copy_username' | 'copy_totp' | 'menu'
  default_action = 'copy_password',

  -- Clear the clipboard this many seconds after a copy (0 disables).
  clear_clipboard_seconds = 20,

  -- Fuzzy search the item list by default.
  fuzzy = true,

  -- Notify via toast on success/failure.
  notify = true,
}

local function merge(into, from)
  if type(from) ~= 'table' then
    return into
  end
  for k, v in pairs(from) do
    if type(v) == 'table' and type(into[k]) == 'table' then
      merge(into[k], v)
    else
      into[k] = v
    end
  end
  return into
end

----------------------------------------------------------------------
-- backend invocation
----------------------------------------------------------------------

-- Build the argv for a helper subcommand.
local function helper_argv(opts, subcmd_args)
  local argv = { opts.helper }
  for _, a in ipairs(opts.helper_args or {}) do
    argv[#argv + 1] = a
  end
  for _, a in ipairs(subcmd_args) do
    argv[#argv + 1] = a
  end
  return argv
end

-- Run the helper. Returns ok(bool), stdout(string), stderr(string).
local function run_helper(opts, subcmd_args)
  local argv = helper_argv(opts, subcmd_args)
  local ok, stdout, stderr = wezterm.run_child_process(argv)
  if not ok then
    wezterm.log_error('bitwarden.wez: ' .. table.concat(argv, ' ') .. ' failed: ' .. (stderr or ''))
  end
  return ok, stdout or '', stderr or ''
end

local function notify(window, opts, message)
  if opts.notify and window then
    window:toast_notification('bitwarden.wez', message, nil, 4000)
  end
  wezterm.log_info('bitwarden.wez: ' .. message)
end

----------------------------------------------------------------------
-- clipboard
----------------------------------------------------------------------

-- Schedule a clipboard wipe `secs` from now, without blocking the GUI thread.
-- We use background_child_process (fire-and-forget) because reliable in-process
-- timers don't exist in WezTerm's Lua (see upstream issue #3026).
local function schedule_clipboard_clear(secs)
  if not secs or secs <= 0 then
    return
  end
  local clear
  if is_mac() then
    clear = 'printf "" | pbcopy'
  elseif is_windows() then
    -- handled below with a different shell
    clear = nil
  else
    clear = 'command -v wl-copy >/dev/null 2>&1 && (printf "" | wl-copy) '
      .. '|| (printf "" | xclip -selection clipboard) '
      .. '|| (printf "" | xsel -b)'
  end

  if is_windows() then
    -- ping is a portable sleep on Windows; then clear via clip.
    wezterm.background_child_process({
      'cmd', '/c',
      string.format('ping -n %d 127.0.0.1 >NUL & echo off | clip', secs + 1),
    })
  else
    wezterm.background_child_process({
      'sh', '-c', string.format('sleep %d; %s', secs, clear),
    })
  end
end

----------------------------------------------------------------------
-- actions performed on a chosen item
----------------------------------------------------------------------

-- field name -> human label
local FIELD_LABELS = {
  password = 'password',
  username = 'username',
  totp = 'TOTP code',
  uri = 'URI',
  notes = 'notes',
}

-- Fetch one field for an item and deliver it (copy or type).
local function deliver(window, pane, opts, item_id, item_name, field, mode)
  local ok, stdout, stderr = run_helper(opts, { 'get', item_id, '--field', field })
  if not ok then
    notify(window, opts, 'failed to get ' .. (FIELD_LABELS[field] or field) .. ': ' .. stderr)
    return
  end
  -- Trim a single trailing newline the helper may add; keep the value otherwise intact.
  local value = stdout:gsub('\r?\n$', '')
  if value == '' then
    notify(window, opts, 'no ' .. (FIELD_LABELS[field] or field) .. ' for "' .. item_name .. '"')
    return
  end

  if mode == 'type' then
    pane:send_text(value)
    notify(window, opts, 'typed ' .. (FIELD_LABELS[field] or field) .. ' for "' .. item_name .. '"')
  else
    window:copy_to_clipboard(value, 'Clipboard')
    if field == 'password' or field == 'totp' then
      schedule_clipboard_clear(opts.clear_clipboard_seconds)
      local suffix = (opts.clear_clipboard_seconds and opts.clear_clipboard_seconds > 0)
        and (' (clears in ' .. opts.clear_clipboard_seconds .. 's)') or ''
      notify(window, opts, 'copied ' .. (FIELD_LABELS[field] or field) .. ' for "' .. item_name .. '"' .. suffix)
    else
      notify(window, opts, 'copied ' .. (FIELD_LABELS[field] or field) .. ' for "' .. item_name .. '"')
    end
  end
end

-- action name -> {field, mode}
local ACTIONS = {
  copy_password = { field = 'password', mode = 'copy', label = 'Copy password' },
  type_password = { field = 'password', mode = 'type', label = 'Type password into pane' },
  copy_username = { field = 'username', mode = 'copy', label = 'Copy username' },
  type_username = { field = 'username', mode = 'type', label = 'Type username into pane' },
  copy_totp = { field = 'totp', mode = 'copy', label = 'Copy TOTP code' },
  copy_uri = { field = 'uri', mode = 'copy', label = 'Copy URI' },
  copy_notes = { field = 'notes', mode = 'copy', label = 'Copy notes' },
}

-- Show a submenu of actions for the already-chosen item.
local function show_action_menu(window, pane, opts, item_id, item_name)
  local order = {
    'copy_password', 'type_password',
    'copy_username', 'type_username',
    'copy_totp', 'copy_uri', 'copy_notes',
  }
  local choices = {}
  for _, name in ipairs(order) do
    choices[#choices + 1] = { id = name, label = ACTIONS[name].label }
  end
  window:perform_action(
    act.InputSelector({
      title = 'bitwarden.wez — ' .. item_name,
      choices = choices,
      fuzzy = false,
      action = wezterm.action_callback(function(win, p, id)
        if not id then
          return
        end
        local a = ACTIONS[id]
        deliver(win, p, opts, item_id, item_name, a.field, a.mode)
      end),
    }),
    pane
  )
end

----------------------------------------------------------------------
-- the picker
----------------------------------------------------------------------

-- Format a single choice label: "name  — username   [folder]"
local function format_label(item)
  local label = item.name or '(no name)'
  if item.username and item.username ~= '' then
    label = label .. '  — ' .. item.username
  end
  if item.folder and item.folder ~= '' then
    label = label .. '   [' .. item.folder .. ']'
  end
  return label
end

-- Build an action_callback that opens the picker and runs `action_name`
-- (or the action submenu) on the selection. Exposed via M.picker(opts, action).
function M.picker(opts, action_name)
  action_name = action_name or opts.default_action or 'copy_password'
  return wezterm.action_callback(function(window, pane)
    -- 1. Make sure the vault is reachable/unlocked. `list` triggers unlock
    --    (and thus the OS biometric prompt) in the helper when needed.
    local ok, stdout, stderr = run_helper(opts, { 'list' })
    if not ok then
      notify(window, opts, 'could not read vault: ' .. (stderr ~= '' and stderr or 'is the Bitwarden desktop app running?'))
      return
    end

    local items = wezterm.json_parse(stdout)
    if type(items) ~= 'table' or #items == 0 then
      notify(window, opts, 'vault is empty or returned no login items')
      return
    end

    -- 2. Build choices. We carry the item id; label is what the user searches.
    local choices = {}
    local by_id = {}
    for _, item in ipairs(items) do
      if item.id then
        choices[#choices + 1] = { id = item.id, label = format_label(item) }
        by_id[item.id] = item
      end
    end

    -- 3. Fuzzy picker.
    window:perform_action(
      act.InputSelector({
        title = 'bitwarden.wez',
        choices = choices,
        fuzzy = opts.fuzzy ~= false,
        fuzzy_description = 'Search vault: ',
        action = wezterm.action_callback(function(win, p, id)
          if not id then
            return -- cancelled
          end
          local item = by_id[id] or { name = id }
          if action_name == 'menu' then
            show_action_menu(win, p, opts, id, item.name or '(item)')
          else
            local a = ACTIONS[action_name] or ACTIONS.copy_password
            deliver(win, p, opts, id, item.name or '(item)', a.field, a.mode)
          end
        end),
      }),
      pane
    )
  end)
end

----------------------------------------------------------------------
-- wiring
----------------------------------------------------------------------

function M.apply_to_config(config, user_opts)
  local opts = merge(merge({}, defaults), user_opts or {})
  -- Resolve the helper now (bundled binary, explicit override, or PATH) so the
  -- keybind callbacks and the M.opts stash all share the same absolute path.
  opts.helper = resolve_helper(opts)

  config.keys = config.keys or {}

  -- main picker
  table.insert(config.keys, {
    key = opts.key,
    mods = opts.mods,
    action = M.picker(opts, opts.default_action),
  })

  -- optional action-menu picker
  if opts.menu_key then
    table.insert(config.keys, {
      key = opts.menu_key,
      mods = opts.menu_mods,
      action = M.picker(opts, 'menu'),
    })
  end

  -- Stash resolved opts so power users can build their own keybinds:
  --   local bw = wezterm.plugin.require '.../bitwarden.wez'
  --   { key='u', mods='CTRL|SHIFT', action = bw.picker(bw.opts, 'type_username') }
  M.opts = opts
  return config
end

return M
