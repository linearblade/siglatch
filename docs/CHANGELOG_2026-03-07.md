# Changelog (Recent Work)
Date range: 2026-03-06 to 2026-03-12
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
