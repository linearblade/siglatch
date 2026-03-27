# Stdlib Singleton Review and Contract

Reviewed: 2026-03-25

## Scope

This note reviews:

- `src/stdlib/`
- library installation in `src/knock/lib.[ch]`
- library installation in `src/siglatch/lib.[ch]`
- enough of `src/knock/main.c`, `src/siglatch/main.c`, `src/siglatch/lifecycle.c`, and the app registries to explain how the stdlib layer is consumed

This is not a full syntax or behavior review of the rest of `src/`.

## Executive Summary

The active codebase uses a clear pattern:

1. `src/stdlib` provides singleton service modules.
2. `src/knock` and `src/siglatch` install those services into a process-global `Lib lib`.
3. The app layers then consume `lib.*` directly instead of calling `get_lib_*()` everywhere.

The important distinction is:

- `Lib` or `FooLib` means the installed singleton service surface.
- `FooContext` means dependencies/configuration for the singleton library itself.
- `FooState` means caller-owned per-object or per-request state.

That distinction is mostly respected today and should become the explicit contract for future work.

## The Canonical Pattern

For a singleton stdlib module, the intended shape is:

1. A public `FooLib` struct containing function pointers.
2. Internal `static` implementation functions in `foo.c`.
3. A global accessor returning the singleton library surface.
4. An optional `FooContext` for library-global dependencies or settings.
5. `init`, `shutdown`, and optionally `set_context` for library-global lifecycle only.
6. Optional `FooState` types for per-object runtime state, passed by caller.

The core rule:

- `init` and `shutdown` are for the library singleton, not for a request, connection, listener, packet, or user object.
- `FooState` is the "this" object when needed.
- `FooState` should not carry module function pointers unless those pointers are intentionally per-state behavior.

### Canonical Header Sketch

```c
typedef struct {
  const OtherLib *other;
  int setting;
} FooContext;

typedef struct {
  int some_runtime_field;
} FooState;

typedef struct {
  int (*init)(const FooContext *ctx);
  int (*set_context)(const FooContext *ctx); /* optional */
  void (*shutdown)(void);

  int (*state_init)(FooState *state);        /* optional */
  void (*state_reset)(FooState *state);      /* optional */

  int (*do_work)(FooState *state, const char *input);
} FooLib;

const FooLib *get_lib_foo(void);
```

### Canonical Implementation Sketch

```c
static FooContext g_ctx = {0};

static int foo_init(const FooContext *ctx) {
  if (ctx) {
    g_ctx = *ctx;
  }
  return 1;
}

static void foo_shutdown(void) {
  g_ctx = (FooContext){0};
}

static const FooLib g_foo = {
  .init = foo_init,
  .shutdown = foo_shutdown,
  .do_work = foo_do_work
};

const FooLib *get_lib_foo(void) {
  return &g_foo;
}
```

## What `lib = *get_lib_x()` Actually Means

`src/knock/lib.c` and `src/siglatch/lib.c` both do this:

```c
lib.time = *get_lib_time();
lib.file = *get_lib_file();
lib.m7mux = *get_lib_m7mux();
```

That is a copy of the function table, not a new library instance.

The singleton still lives inside the stdlib module's `static` storage. The copied `lib.*` structs are just installed call surfaces pointing back at that singleton implementation.

This matters because:

- copying `FileLib` does not create a second file library
- copying `M7MuxLib` does not create a second m7mux runtime
- calling `set_context` or `init` still mutates the singleton module's internal global state

## Current `src/stdlib` Structure

The active tree is roughly:

- top-level leaf or near-leaf services in `src/stdlib/`
- parser subtree in `src/stdlib/parse/`
- process subtree in `src/stdlib/process/`
- active net subtree in `src/stdlib/net/`
- active UDP mux subtree in `src/stdlib/protocol/udp/m7mux/`

There are also non-runtime or archival areas mixed into the same tree:

- `src/stdlib/old/`
- `src/stdlib/old_busted/`
- `src/stdlib/protocol/udp/research/`
- `src/stdlib/protocol/udp/m7mux_initial_sketch_now_research2/`
- `src/stdlib/protocol/udp/m7mux/backup/`
- editor/temp files such as `#inbox.c#`, `stream.c~`, and `.DS_Store`

These archival and temporary artifacts are one of the main reasons the tree is easy to misread.

## Module Categories in the Current Tree

### 1. Plain Singleton Leaf Modules

These mostly expose a fixed `static const` function table and have little or no library-global context:

- `time`
- `random`
- `str`
- `unicode`
- `hmac_key`

These are closest to the ideal "one struct, many static functions, one getter" pattern.

### 2. Singleton Modules With Library-Global Context

These take installer-supplied dependencies or settings and store them in singleton-global state:

- `argv`
- `print`
- `file`
- `stdin`
- `log`
- `openssl`
- `parse`

For these modules, `Context` means installation-time dependencies, not object state.

Examples:

- `PrintContext` installs `UnicodeLib`
- `FileLibContext` installs printing/error behavior
- `LogContext` installs time and print providers
- `SiglatchOpenSSLContext` installs log/file/hmac/print dependencies
- `ParseContext` installs `StrLib`

### 3. Stateful Singleton Modules

These are singleton libraries that operate on caller-owned runtime state objects:

- `signal` uses `SignalState`
- `nonce` uses `NonceCache`
- `openssl` uses `SiglatchOpenSSLSession`
- `m7mux` uses `M7MuxState` and child state structs

This is the correct place for "object instance" data.

### 4. Barrel or Composite Modules

These are singleton libraries that wire child libraries together into one surface:

- `parse` wraps `ini`
- `process` wraps `process/user`
- `net` wraps `addr`, `ip`, `socket`, and `udp`
- `m7mux` wraps `connect`, `inbox`, `outbox`, `ingress`, `normalize`, `stream`, and `egress`
- `env` is also a composite public surface with `core` and `user` sub-interfaces

These are still singleton libraries, but they are more like installers/barrels than leaf utilities.

### 4a. Private or Internal Barrels

Private child capabilities should follow the same pattern as public modules, but they may be grouped behind a private barrel instead of being exposed as public API.

That private barrel:

- is still a service surface
- may live in singleton-global context
- may live in a module-private internal struct
- may be referenced through `ctx->internal`
- is not the same thing as caller-owned runtime state

The active `m7mux` tree already demonstrates this idea with `M7MuxInternalLib`.

### 5. Helper or Data Modules That Are Not Installed Singleton Libraries

Not every file in `src/stdlib` follows the singleton-lib pattern.

Examples:

- `base64.c` / `base64.h` are plain utility functions
- `log_context.h`, `openssl_context.h`, and `openssl_session.h` are support/data headers
- `src/stdlib/net.h` is a compatibility shim that forwards to `src/stdlib/net/net.h`
- `src/stdlib/protocol/udp/m7mux/internal.h` is an internal structural header

Future chats should not assume every `src/stdlib/*` file is itself a `get_lib_*()` module.

## How `src/knock` and `src/siglatch` Instantiate Stdlib

Both applications follow the same installer model:

1. Define a global `Lib lib`.
2. Copy every needed stdlib function table into it.
3. Build context structs from already-installed `lib.*` members.
4. Call `init` in dependency order.
5. Expose `lib.*` to the rest of the program as the canonical service locator.

That means:

- `src/knock/lib.c` is the stdlib installer for the client side
- `src/siglatch/lib.c` is the stdlib installer for the server side
- the rest of the code should usually call `lib.*`, not `get_lib_*()` directly

The same pattern repeats one layer higher:

- `src/knock/app/app.c` builds a global `App app`
- `src/siglatch/app/app.c` builds a global `App app`

So the architecture is effectively:

1. stdlib singleton providers
2. app/runtime installers (`Lib lib`)
3. app module installers (`App app`)
4. caller-owned state objects passed into those installed services

## State vs Context: The Rule To Keep

This is the most important cleanup rule.

### Context

Context is singleton installation data.

Examples:

- `FileLibContext`
- `PrintContext`
- `LogContext`
- `SiglatchOpenSSLContext`
- `M7MuxContext`

Context belongs to the library singleton. It is about dependencies, options, and shared global behavior.

### State

State is caller-owned object/runtime data.

Examples:

- `SignalState`
- `NonceCache`
- `M7MuxState`
- `SiglatchOpenSSLSession`
- `AppRuntimeProcessState`
- `AppRuntimeListenerState`

State belongs to the object/request/connection/listener/session, not to the library singleton.

Private internal registries do not change that rule.

If a module needs hidden child services, those belong in an internal/private barrel, not in `State`.

### Practical Reading Rule

When reading or modifying code, assume:

- if a type is named `*Context`, it exists to install or reconfigure a singleton library
- if a type is named `*State`, it exists to represent a particular runtime instance
- `shutdown()` should tear down the library singleton, not a state object
- `state_reset()` or `state_init()` should touch only caller-owned runtime state
- required callbacks should be wired all-or-nothing before a module is considered usable
- proper initialization is the installer's responsibility
- after successful init, normal call paths do not need to keep re-checking required callback existence
- a post-init missing callback is a contract violation and should fail loudly rather than silently returning `0`

## Observed Drift and Cleanup Targets

### 1. Naming is inconsistent

Getter and type names vary more than they should:

- `get_lib_time()`
- `get_random_lib()`
- `get_logger()`
- `get_hmac_key_lib()`
- `get_siglatch_openssl()`
- `get_protocol_udp_m7mux_*_lib()`

Recommended direction:

- standardize on `get_lib_<name>()`
- standardize public surfaces on `<Name>Lib`
- reserve longer prefixes only for internal subtree names that truly need them

### 2. Leaf vs barrel modules are not clearly separated in the tree

Right now active libraries, shims, prototypes, research, backups, and temp files all sit near one another.

Recommended direction:

- treat `src/stdlib/old*`, `research`, `backup`, and `m7mux_initial_sketch_now_research2` as archival
- either move them under an explicit archive location or add a small README stating they are non-runtime
- remove editor temp files and `.DS_Store`

### 3. Some docs/comments are stale

Examples of stale naming still exist, especially around old string naming and promoted subtrees.

Recommended direction:

- update doc comments to match current filenames and getter names
- document that `src/stdlib/net.h` is now a shim, not the primary implementation

### 4. Some modules expose both raw functions and the singleton lib surface

This happens in places such as `signal` and `nonce`.

That can be a valid transition seam, but it is easy to confuse future readers.

Recommended direction:

- choose one canonical public surface per module
- if legacy free functions stay, label them as compatibility exports

### 5. Barrels sometimes build mutable singleton tables in the getter

This is visible in modules such as `parse`, `process`, `net`, and `m7mux`.

That pattern is fine for barrels that must lazily wire child libs, but it should be understood as a barrel-specific exception rather than the default style for every module.

Recommended direction:

- leaf modules should prefer `static const` singleton tables
- barrel modules may use mutable `g_lib` plus one `wire_*()` path
- barrel construction should be fractal: each child validates itself once, then the parent trusts that child and exports the same guarantee upward
- parent code should not keep wrapping child calls in repetitive `if (child_fn)` checks after wiring/init already established the contract
- lazy wiring inside the barrel is fine, as long as the barrel completes that wiring before any dependent operational path is used

### 6. `src/siglatch/lib.c` currently drifts from its own lifecycle comments

`init_lib()` in `src/siglatch/lib.c` initializes more modules than `shutdown_lib()` tears down.

At review time:

- `shutdown_lib()` does not call `lib.file.shutdown()`
- `shutdown_lib()` does not call `lib.process.shutdown()`
- the shutdown order is not a full reverse mirror of `init_lib()`

This is the sharpest lifecycle inconsistency I found during review.

### 7. `src/knock/lib.c` is closer, but still not a perfect mirror

`src/knock/lib.c` does include the major shutdown calls, but it is still maintained manually and can drift from init order over time.

Recommended direction:

- keep one authoritative ordered list for init/shutdown
- derive reverse-order shutdown from that list if possible

### 8. The state/function-pointer separation is mostly good today

The current code mostly avoids storing library surfaces inside per-object state.

Good examples:

- `SignalState` stores signal delivery state, not signal function pointers
- `NonceCache` stores cache contents, not nonce API pointers
- `M7MuxState` stores runtime packet/session state and a context pointer, not a copy of the full `M7MuxLib`
- `AppRuntimeListenerState` stores listener runtime data, not stdlib function tables

This is worth preserving exactly as a rule.

### 9. The codebase already leans toward an all-or-nothing wiring contract

The installers in `src/knock/lib.c`, `src/siglatch/lib.c`, `src/knock/app/app.c`, and `src/siglatch/app/app.c` already do a useful thing:

- acquire the surfaces first
- verify required callbacks in one place
- initialize in dependency order
- then use those surfaces as if they are valid

That should become the explicit standard.

Recommended direction:

- perform completeness checks at construction/install/init boundaries
- do not repeatedly null-check required callbacks in ordinary execution paths
- prefer fail-fast behavior for post-init contract violations rather than silent fallback
- apply the same rule recursively to barrel children so every layer can assume the layer below already "did its job"
- treat optional wiring as an explicit exception, not the default assumption

## Recommended Contract for Future Chats and Future Edits

When discussing or editing this codebase, use the following assumptions unless a file clearly says otherwise:

1. `lib.*` is the installed singleton service registry for the process.
2. `get_lib_*()` returns a singleton function table, not a new object instance.
3. `Context` configures a singleton module.
4. `State` represents caller-owned runtime state.
5. `init` and `shutdown` are library-global lifecycle only.
6. `state_init` and `state_reset` are per-object lifecycle only.
7. State objects should not be used to cache library function tables.
8. Barrels are allowed to wire child libs into a larger lib surface.
9. Required callbacks should be wired all-or-nothing before a module is considered live.
10. After successful init, callers may assume required callbacks exist and call through the installed surface directly.
11. A post-init missing callback is a wiring/programmer error and should fail loudly rather than silently degrade.
12. Barrel construction is fractal: once a child barrel has been validated, the parent may trust it and export that guarantee upward.
13. Lazy internal barrel wiring is acceptable if it completes before the operational surface is used.
14. Optional child wiring is an explicit exception to the default all-or-nothing contract.
15. Large module surfaces may be implemented by multiple flat `.c` shards inside one module directory without making each shard its own module.
16. Plain helpers in `src/stdlib` should remain plain helpers rather than being forced into the singleton pattern if they do not need lifecycle or installation.

## Short Version

If a future chat needs the simplest mental model, use this one:

- `src/stdlib` contains installed singleton services plus a few plain helper modules.
- `src/knock/lib.c` and `src/siglatch/lib.c` are installers for those singleton services.
- `Context` means singleton-global dependencies.
- `State` means per-object runtime data.
- `shutdown()` is for the library, not for the object instance.
- Do not put module function pointers into runtime state objects unless the behavior is intentionally per-instance.
- Private child modules should use the same contract as public modules and be grouped in an internal/private barrel rather than being hidden inside runtime state.
- Required callbacks should be wired all-or-nothing during init.
- After init succeeds, use the installed surface directly instead of re-checking every required callback.
- If a required callback is somehow missing after init, fail loudly instead of silently returning `0`.
- Each barrel may assume its validated child barrels already did their job; do not reintroduce pointer-check clutter in normal execution paths.
