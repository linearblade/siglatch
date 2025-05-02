// 📌 Client TODO — Cleaned Up & Bullet-Pointed

- **HMAC signing of payload**
  - Implement final logic for structured packets
  - Ensure signature is applied before encryption, if enabled

- **Polish `Opts` parsing**
  - Establish default initializer (`opts_default()`) to ensure safe pre-state
  - Differentiate between explicit flags (e.g., `--no-hmac`) and implicit defaults
  - Refactor `--alias-*` commands to use `parse_argv`-style parsing
    - Allow `--config-dir` and map flags within alias handler context
    - Remove hardcoded config directory paths; derive from `--config-dir` or default consistently

- **Generalize `parse_argv` into a reusable library module**
  - Support variable-length argument constructs
  - Implement lookahead to split based on `--` flag boundaries
  - Add support for Unix-style `-x` short flags
  - Optionally support `--key=value` construction
  - Consider wildcard matching or fuzzy aliasing later

- **Validate transmission pipeline**
  - Confirm default transmission works end-to-end with current config
  - Dump debug info at each stage if `--opts-dump` is passed

- **Feature toggling validation**
  - Verify all 4 payload modes:
    - Structured + Encrypted + HMAC mode (toggle: on / off / dummy)
    - Structured + Plaintext + HMAC mode (toggle: on / off / dummy)
    - DeadDrop + Encrypted
    - DeadDrop + Plaintext

- **(In Progress) HMAC payload signing ideas**
  - Allow future `--sign-window start:end` to HMAC a subregion of payload
  - Embed metadata inside payload to define HMAC target explicitly
  - Support detached signature mode for raw dead-drop payloads

- **preempt exitcodes**
  ```
  #define EXIT_OK       0
  #define EXIT_FAILURE  1
  #define EXIT_BADARGS  2
  ```