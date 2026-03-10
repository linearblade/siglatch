# Changelog (Recent Work)
Date range: 2026-03-06 to 2026-03-07
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
