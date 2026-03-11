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

### Removed / Pruned
- Dead env handler path removed from app env interface/implementation:
  - `handle_output_mode_default_command`
- Stale app interface callbacks removed:
  - `AppHelpLib.isHelp`
  - `AppHelpLib.handleParseResult`
  - `AppAliasCommandLib.handle`
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
