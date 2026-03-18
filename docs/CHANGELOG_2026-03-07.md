# Changelog (Recent Work)
Date range: 2026-03-06 to 2026-03-18
Scope: in-progress workspace changes since tag `1.0` relevant to current stabilization pass.

## Added
- Configurable daemon server selection at startup with precedence:
  - `--server <name>` CLI
  - `SIGLATCH_SERVER` environment variable
  - `default_server` in config
- New global/server/action config policy: `payload_overflow` (`reject|clamp|inherit` by scope).
- New server metadata key: `label` (human-readable server label).
- Daemon help includes `--server` option usage.
- README release-status banner:
  - `v1.1` marked as development release.
  - `1.0` tag marked as stable baseline.

## Changed
- Startup now fails closed if the resolved server is:
  - missing
  - disabled
- Config parser now enforces unique effective server identifiers at load time.
- `[server:*] name=` no longer renames server identity:
  - section label remains machine identifier
  - `name=` is treated as deprecated alias for `label`
- Output-mode initialization timing is aligned with final server selection.
- Runtime defaults (`port`/`log_file`) were decoupled from `load_server_keys()` into a dedicated config-default pass.
- Insecure daemon startup path no longer requires server private key assignment.
- Knocker startup flow was restructured with an `app` layer (`app.opts`, `app.output_mode`, `app.help`) to centralize main-path wiring and reduce direct branching in `main`.
- Knocker parse/result flow now tracks `Opts.response_type` and routes help/error handling through app-level handlers instead of ad-hoc branches.

## Fixed
- `--server` bad usage now returns concise error + help:
  - missing arg
  - empty value
  - unknown/disabled server
- Unstructured packet path now guards NULL current-server context before dereference.
- `parse_argv` now checks fixed-array bounds for:
  - options
  - option args
  - positionals
- Knocker alias/config path building now guards unset `HOME` and path-length failures.
- Payload deserialization now exposes overflow as dedicated error (`SL_PAYLOAD_ERR_OVERFLOW`) for policy handling.

## Documentation
- Updated daemon config manual for:
  - `payload_overflow` behavior and precedence
  - `label` semantics
  - server identity rules (`[server:<name>]` is canonical)
- Updated security docs to document malformed `payload_len` handling policy.
- Added default config examples for:
  - `default_server`
  - `payload_overflow`
  - `label`

## Operational Notes
- Local binaries were rebuilt in this workspace:
  - `siglatchd`
  - `knocker`
- Validation matrix items for server-selection behavior are still pending execution.
- App-layer factory dispatch uses function pointers by design; expected overhead is minimal in this code path and not a meaningful cost relative to parsing, crypto, file I/O, and network operations.

## Update (2026-03-11): Knocker App/Opts Refactor

### Added
- New nested client app module layout under `src/knock/app/`:
  - `alias/`
  - `env/`
  - `help/`
  - `opts/`
  - `output_mode/`
  - `transmit/`
- New command-contract oriented parse flow (`AppCommand`) so parse result and execution routing are separated cleanly.
- New dedicated opts sub-libraries:
  - `app.opts.transmit`
  - `app.opts.alias`

### Changed
- Knocker `main` now routes by parsed command type (`help`, `output_mode_default`, `alias`, `transmit`, `error`) instead of direct `parseOpts(...)` branching.
- Alias parsing blob was moved out of `opts` orchestration into `src/knock/app/opts/alias.c`, preserving command behavior while reducing parser coupling.
- Build source wiring (`makefile`) was updated to compile the new app subtree and opts submodules.
- Error/help path now consistently emits concise parse errors followed by usage guidance through app handlers.

### Removed / Pruned
- Legacy flat app files removed:
  - `src/knock/app/alias.c|h`
  - `src/knock/app/env.c|h`
  - `src/knock/app/help.c|h`
  - `src/knock/app/output_mode.c|h`
  - `src/knock/app/transmit.c|h`
  - `src/knock/app/app_opts.c|h`
- Legacy parser/help wrappers removed:
  - `src/knock/parse_opts.c|h`
  - `src/knock/parse_opts_alias.c|h`
  - `src/knock/print_help.c|h`
  - `src/knock/main_helpers.c|h`
- Scratch/obsolete client files removed:
  - `src/knock/main2.c`
  - `src/knock/encrypt_knock.c`
  - `src/knock/unencrypted.c`

### Verification
- `make build-knocker` succeeds after refactor (existing local OpenSSL/macOS linker-version warnings unchanged).

## Update (2026-03-12): Parser Purity + App Surface Cleanup

### Added
- Command-level dump intent routing via `AppCommand.dump_requested`.
- Centralized dump execution path in `main` through `app.opts.dump_command(...)`.
- Alias command dump output support (`--opts-dump` with alias commands).
- New alias command `--alias-show-hosts` for listing configured alias hosts.

### Changed
- `--opts-dump` no longer exits in parse stage:
  - parser sets dump intent
  - execution layer handles dump + exit code
- Help mode detection now requires exact `--help` match:
  - non-exact variants (for example `--helpful`) are now treated as parse errors.
- Alias show-all behavior now skips non-host directories that do not contain the relevant map file (`user.map`/`action.map`) and emits one summary warning count.
- `--alias-show-hosts` now lists only host directories that have alias maps (`user.map` or `action.map`), excluding support directories like `keys`.
- Alias mode now accepts and applies `--output-mode unicode|ascii` (including alias dump paths).
- Client command-mode parsing now runs through a shared parser orchestrator:
  - mode-local `ArgvOptionSpec` tables
  - normalized `ArgvParsed` -> `AppCommand` builders
  - unchanged mode classifier (`help|output_mode_default|alias|transmit`)
- `--output-mode-default` now parses through argv spec (`--output-mode-default <mode>`) instead of raw positional indexing.
- Parse/typed errors are now shaped into command error payloads and routed consistently through `main` (`error + Use --help`) across parser modes.

### Removed / Pruned
- Dead env handler path removed from app env interface/implementation:
  - `handle_output_mode_default_command`
- Stale app interface callbacks removed:
  - `AppHelpLib.isHelp`
  - `AppHelpLib.handleParseResult`
  - `AppAliasCommandLib.handle`
- Dead argv error callback surface removed after shared shaper cutover:
  - `AppErrorArgvLib.parse`
  - `AppErrorArgvLib.typed`
- Stale `--config-dir` examples removed from:
  - client help text
  - `docs/OPERATIONS_CLIENT.md`

### Documentation
- Added `--alias-show-hosts` usage to:
  - client help text
  - `docs/OPERATIONS_CLIENT.md`

### Verification
- `make build-knocker` succeeds after cleanup.
- `./knocker --helpful` now exits with parse error + usage hint (no help-mode false positive).
- `./knocker --opts-dump ...` and `./knocker --alias-... --opts-dump` route through command dump path without parser `exit()`.
- `--alias-user-show` / `--alias-action-show` no longer emit per-directory noise for non-host directories under `~/.config/siglatch`.
- `./knocker --alias-show-hosts` now excludes non-alias support directories (for example `keys`).
- `./knocker --alias-show-hosts --output-mode ascii` and invalid mode handling were verified.
- `./knocker --output-mode-default` now returns argv-shaped missing-arg error.
- `./knocker --output-mode-default nope` now returns argv-shaped enum error.

## Update (2026-03-12): Non-Transmit Positional Strictness + Runtime Stdin Resolution

### Changed
- Non-transmit modes now reject unexpected trailing positional arguments:
  - `--output-mode-default <mode>` rejects extra positionals.
  - Alias commands now enforce per-command positional limits (exact or optional count by operation).
- Transmit parser is now parse-intent only for stdin:
  - `--stdin` sets intent (`stdin_requested`) without consuming stdin in parse.
  - Auto-piped stdin attach no longer runs during parse.
- Stdin payload resolution moved to transmit execution stage:
  - explicit `--stdin` reads multiline payload at runtime.
  - auto-piped stdin attaches payload at runtime when `--stdin` is not set.
- Dead-drop payload requirement is now enforced after runtime payload resolution (instead of parse-time pre-check).
- Transmit opts dump now prints `Stdin Requested` to reflect parse intent.

### Verification
- `./knocker --alias-show-hosts extra` now fails with concise error + usage hint.
- `./knocker --alias-user-show localhost extra` now fails with concise error + usage hint.
- `./knocker --output-mode-default ascii extra` now fails with concise error + usage hint.
- `./knocker --opts-dump` paths no longer consume stdin during parse.
- `printf 'payload' | ./knocker ... --dead-drop --stdin ...` reads stdin during runtime execution.
- `make build-knocker` succeeds after these changes.

## Update (2026-03-12): Knocker Release Hardening (Late Pass)

### Added
- New shared env helper: `lib.env.user.ensure_home_config_dir()`:
  - creates `~/.config` with `0755` on first creation
  - does not chmod existing directories
- Explicit wiring-contract notes in app/lib init paths documenting intentional all-or-nothing factory assumptions.

### Changed
- `app.env` now delegates `~/.config` bootstrap to `lib.env.user.ensure_home_config_dir()` and only owns app-specific root creation (`~/.config/siglatch`).
- Runtime stdin fallback behavior refined:
  - auto-piped stdin is consumed only when current payload is empty
  - explicit `--stdin` path remains strict and required when requested
- Transmit ID resolution order now prefers aliases first, then numeric fallback:
  - supports numeric-like alias names without ambiguity regressions in this model
- `--alias-show-hosts` now treats missing `~/.config/siglatch` as empty state (not an error).

### Fixed
- First-run alias/config bootstrap on fresh `HOME` no longer fails due to missing parent directories.
- Error-line concatenation in transmit failure path:
  - transmit failure callsites now use newline-terminated messages
  - logger defensively newline-terminates unterminated emitted messages
- Numeric positional ID bounds are now enforced at parse time:
  - `user`: `1-65535`
  - `action`: `1-255`
- Alias ID bounds are now enforced on set commands:
  - `--alias-user ... <id>` -> `1-65535`
  - `--alias-action ... <id>` -> `1-255`
- Alias map parsing now validates IDs via `strtoul` and skips malformed rows.
- Alias resolution now ignores out-of-range legacy map entries with warnings instead of allowing downstream packet-width truncation.
- Closed silent truncation path where oversized alias-derived IDs could be narrowed into packet fields (`uint16_t`/`uint8_t`) without explicit error.

### Verification
- `make build-knocker` succeeds after all hardening changes.
- Fresh-`HOME` validation:
  - alias set and output-mode-default flows succeed
  - `~/.config` created as `0755`; app config dirs remain `0700`
  - existing `~/.config` permissions are preserved (no chmod mutation)
- `./knocker --alias-show-hosts` on missing config root now returns success with friendly empty-state message.
- Out-of-range numeric IDs are rejected with explicit parse errors.
- Numeric-like alias names resolve through alias-first behavior.

## Update (2026-03-14 to 2026-03-15): Server Architecture Cleanup + Shared Boundary Pass

### Added
- New generic INI parse layer under `src/stdlib/parse/`:
  - `lib.parse`
  - `lib.parse.ini`
- New shared protocol layer under `src/shared/`:
  - `shared.knock.codec`
  - `shared.knock.digest`
  - `shared.knock.debug`
- New reusable nonce module:
  - `lib.nonce`
- New reusable signal module:
  - `lib.signal`
- New explicit server runtime state types:
  - `AppRuntimeProcessState`
  - `AppRuntimeListenerState`
- New lifecycle entry points:
  - `siglatch_boot()`
  - `siglatch_shutdown()`
- New server app module families:
  - `app.keys`
  - `app.server`
  - `app.startup`
  - `app.udp`
  - `app.daemon`
  - `app.inbound`
  - `app.inbound.crypto`
  - `app.packet`
  - `app.payload`
  - `app.help`
  - `app.signal`

### Changed
- Server config ownership moved from `lib.config` to `app.config`.
- `app.config` now supports both:
  - `load(path)` as the normal daemon-facing orchestration path
  - `consume(document)` as the lower-level INI consumption path
- Config file reading is now separated from config semantics:
  - `lib.parse.ini` reads INI into a document model
  - `app.config` consumes that document into `siglatch_config`
- Key material loading was split out of config parsing into `app.keys.*`.
- Selected-server runtime behavior was split out of config into `app.server`.
- Config dump/debug code was split out of main config implementation into `app/config/debug.c`.
- Daemon startup work was moved out of `main` into `app.startup`.
- UDP listener setup was moved under `app.udp`.
- Daemon loop ownership was moved under `app.daemon`.
- Inbound receive/normalize work was moved under `app.inbound`.
- Structured/unstructured payload handling was moved under `app.payload`.
- Server-side use of packet codec/digest now goes through `app.payload.*`, which in turn uses `shared.knock.*`.
- Runtime listener state is now explicit instead of hidden module-global state:
  - selected server now lives on listener state
  - packet count now lives on listener state
  - replay cache now lives on listener state
- Process exit state now lives on explicit process state instead of a module-global flag.
- `app.signal` now wraps `lib.signal` instead of owning its own handler state.
- Process signal state now lives on `SignalState` inside `AppRuntimeProcessState`.
- Deferred signal logging now happens in normal shutdown flow instead of inside the handler.
- Daemon signal policy is now:
  - first `SIGINT` / `SIGTERM` requests graceful shutdown
  - second `SIGINT` / `SIGTERM` forces hard exit
- Replay protection was moved from the old app-side nonce cache to `lib.nonce`.
- Packet debug dumping was moved out of `stdlib/utils` and into `shared.knock.debug`.
- Top-level daemon boot/shutdown flow in `main` is now:
  - boot
  - startup prepare
  - listener start
  - daemon run
  - shutdown

### Removed / Pruned
- Top-level server compatibility shim removed:
  - `src/siglatch/config.h`
- Old app-side shutdown module removed from active tree and moved to legacy staging.
- Old app-side nonce cache removed from active tree and moved to legacy staging.
- Old top-level daemon helper files, decrypt leftovers, UDP listener wrappers, config parser leftovers, and other inactive server-side files were moved into `__tmp/legacy`.
- Shared knock protocol implementation no longer lives behind the server/client `lib` surface.

### Documentation / Internal Notes
- Added and maintained architecture tracking in:
  - `__tmp/architecture-todo.md`
- Refreshed server cleanup tracking in:
  - `__tmp/server-todo.md`
- Maintained config follow-up notes in:
  - `__tmp/app-config-review-notes.md`

### Verification
- `make build-siglatchd` succeeds after the server architecture refactor wave.
- `make build-knocker` still succeeds after shared protocol and `lib.nonce` moves.
- `./siglatchd --help` succeeds on the new startup path.
- `./knocker --help` succeeds after the shared-layer move.
- Existing local OpenSSL/macOS linker-version warnings remain unchanged.

## Update (2026-03-17): Net Tree Promotion + Daemon Config Path Override

### Added
- New daemon CLI config override:
  - `--config <path>`
- New compile-time daemon config default:
  - `CONFIG_PATH_SIGLATCHD` in `makefile`
- New top-level stdlib net shim behavior:
  - `src/stdlib/net.h` now forwards to the promoted `src/stdlib/net/net.h` barrel

### Changed
- The new `src/stdlib/net/*` tree is now the active `lib.net` implementation.
- Active stdlib net build wiring now uses:
  - `src/stdlib/net/net.c`
  - `src/stdlib/net/addr/addr.c`
  - `src/stdlib/net/socket/socket.c`
  - `src/stdlib/net/udp/udp.c`
- `siglatchd` inbound IP formatting now routes through:
  - `lib.net.addr.sock_to_ipv4(...)`
- `knocker` hostname resolution now routes through:
  - `lib.net.addr.resolve_host_to_ip(...)`
- `knocker` UDP transmit now uses the promoted net subtree directly:
  - `lib.net.udp.open_auto(...)`
  - `lib.net.udp.send(...)`
  - `lib.net.udp.close(...)`
- `siglatchd` config loading no longer hardcodes `/etc/siglatch/server.conf` in startup code:
  - CLI `--config` overrides the compiled default
  - compiled default comes from `SL_CONFIG_PATH_DEFAULT`

### Removed / Pruned
- Old stdlib UDP runtime was removed from the active client/runtime path:
  - `src/stdlib/udp.c`
  - `src/stdlib/udp.h`
- Additional dead stdlib files were moved to `__tmp/legacy`:
  - `src/stdlib/net.c`
  - `src/stdlib/net_helpers.h`
  - `src/stdlib/parse_argv.c`
  - `src/stdlib/parse_argv.h`
  - `src/stdlib/string.c`
  - `src/stdlib/time.old.c`
  - `src/stdlib/time.old.h`
  - `src/stdlib/old/parse_argv.c`
  - `src/stdlib/old/parse_argv.h`
  - `src/stdlib/old_busted/payload_digest.c`
  - `src/stdlib/old_busted/payload_digest.h`

### Documentation
- Server operations docs now describe the live daemon config override:
  - `--config <path>`
- Compile docs now describe compile-time daemon config path selection via:
  - `CONFIG_PATH_SIGLATCHD`

### Verification
- `make build-siglatchd` succeeds after promoting the net subtree and adding daemon config-path support.
- `make build-knocker` succeeds after removing the old stdlib UDP path from the active client runtime.
- `./siglatchd --help` shows the new `--config` option.
- `./siglatchd --config /tmp/does-not-exist.conf --dump-config` fails against the override path, confirming the CLI path is honored.

## Update (2026-03-18): Builtin Action Path + Runtime Reload + Listener Rebind

### Added
- New server builtin action barrel under `src/siglatch/app/builtin/` with shared native builtin context.
- New builtin action handler families:
  - `reload_config`
  - `change_setting`
  - `save_config`
  - `load_config`
  - `list_users`
  - `test_blurt`
  - `probe_rebind`
  - `rebind_listener`
- New staged config APIs in `app.config`:
  - `load_detached(path, &cfg)`
  - `destroy(cfg)`
  - detached lookup helpers for users/actions/servers/deaddrops
- New runtime helper for config-backed pointer hygiene:
  - `app.runtime.invalidate_config_borrows(...)`
- New runtime config reload orchestration:
  - `app.runtime.reload_config(...)`
- New listener runtime state fields:
  - active config path on listener state
  - actual bound port on listener state
- New listener runtime state field:
  - actual bound IP on listener state
- New UDP listener helpers:
  - `app.udp.probe_bind(...)`
  - `app.udp.rebind_listener(...)`
- New config mutation helper for active runtime reconciliation:
  - `app.config.server_set_port(name, port)`
- New config mutation helper for full live bind reconciliation:
  - `app.config.server_set_binding(name, bind_ip, port)`
- New IPv4 range utility family under `lib.net.ip.range`:
  - single IPv4 validation
  - IPv4 CIDR validation
  - spec/range containment helpers for policy checks
- New server policy barrel:
  - `app.policy`
- New client source-bind default commands:
  - `--send-from-default <host> <user> <ipv4>`
  - `--send-from-default-clear <host> <user>`

### Changed
- Action config model now supports execution backends:
  - `handler = shell|builtin`
  - `builtin = <name>`
- Existing action behavior remains backward compatible:
  - omitted `handler` defaults to `shell`
  - shell-backed actions still use `constructor`
- Structured packet dispatch now routes builtin-backed actions through `app.builtin.handle(...)` instead of forcing all actions through shell execution.
- `reload_config` is now a real builtin:
  - logs the request
  - reloads from the active config path
  - rebuilds runtime config/session bindings
- Listener rebind behavior is now a first-class runtime operation instead of ad hoc socket mutation.
- Daemon loop no longer caches selected server encryption mode outside the receive loop:
  - it now re-reads live listener state each iteration, which makes listener/runtime mutation safer.
- Successful live rebind now updates the active config's selected server port so runtime state and config state remain aligned.
- Successful live rebind now updates the active config's selected server bind tuple so runtime state and config state remain aligned.
- Server config model now supports IPv4 bind and restriction controls:
  - `[server:*] bind_ip = <ipv4>`
  - `[server:*] allowed_ips = <ip-or-cidr,...>`
  - `[user:*] allowed_ips = <ip-or-cidr,...>`
  - `[action:*] allowed_ips = <ip-or-cidr,...>`
- Server startup listener bind now honors configured `bind_ip`; unset still binds wildcard/any.
- `reload_config` now auto-applies listener rebinding when the new bind tuple can be staged safely.
- Client transmit path now honors `--send-from <ipv4>` by explicitly binding the outbound UDP socket for IPv4 targets.
- Client now supports persisted per-host, per-user source bind defaults stored as:
  - `~/.config/siglatch/<host>/client.<user>.conf`
- `--alias-user-show` now includes the saved per-user `send_from_ip` when one exists.
- Server `--dump-config` output now includes newer policy/runtime-relevant fields more clearly:
  - numeric IDs
  - server label/logging
  - bind IP
  - allowed IP lists
  - explicit `(none)` / `(any)` markers for empty lists and unrestricted IP scopes

### Fixed
- Builtin-backed actions were no longer incorrectly rejected as “unknown action” just because they do not define a shell constructor.
- Rebind no-op behavior is now explicit:
  - same-port rebind requests log “already bound” instead of looking like a real port swap.
- Runtime reload is now staged instead of destructive-first:
  - new config is loaded and validated before replacing the live attached config
  - rollback path keeps the old config/runtime alive on failure
- Server-side IP restriction enforcement now cleanly gates requests in policy order:
  - server
  - user
  - action
- Hot config reload now fails early instead of half-reloading when a new bind tuple cannot be safely staged.

### Default Config / Examples
- Default server config now includes disabled builtin action examples for:
  - `reload_config`
  - `change_setting`
  - `save_config`
  - `load_config`
  - `list_users`
  - `probe_rebind`
  - `rebind_listener`
- Added live example builtin action:
  - `test_blurt`

### Verification
- `make build-siglatchd` succeeds after the builtin/runtime/rebind additions.
- `./siglatchd --help` succeeds after the builtin and runtime surface expansion.
- `make build-knocker` succeeds after client source-bind support and persisted send-from defaults.
- `./knocker --help` now shows:
  - `--send-from`
  - `--send-from-default`
  - `--send-from-default-clear`
- Manual end-to-end daemon validation confirmed:
  - builtin action parsing and authz
  - successful builtin dispatch via `test_blurt`
  - successful runtime config reload via `reload_config`
  - safe bind probing via `probe_rebind`
  - live socket cutover via `rebind_listener`
- Manual/local validation also confirmed:
  - enforced `allowed_ips` behavior for server, user, and action scopes
  - startup honoring `bind_ip`
  - client persisted source-bind defaults can be saved and cleared
  - user-alias display now surfaces saved `send_from_ip`
