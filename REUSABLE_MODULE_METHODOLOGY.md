# Reusable Module Methodology

Reviewed: 2026-03-25

## Purpose

This document generalizes the singleton-service pattern into a reusable methodology for building module surfaces such as:

- `lib.xyz`
- `lib.xyz.abc`
- `app.abc`
- `app.abc.def`

It is intended to answer:

- what a module is
- how to name it
- how to model inputs and outputs
- how to separate lifecycle, context, and runtime state
- how to compose leaf and aggregate modules into a registry

## Core Model

A reusable module has four distinct layers:

1. Interface surface
2. Singleton library context
3. Caller-owned runtime state
4. Installation path in a registry

In concise terms:

- `FooLib` is the service interface
- `FooContext` is install-time dependency injection
- `FooState` is per-instance runtime state
- `registry.foo` or `registry.foo.bar` is the installed access path

## Terminology

### Service Surface

The public function table for a module.

Example:

- `XyzAbcLib`

### Context

Install-time or library-global dependencies and settings.

Examples:

- other service providers
- allocators
- loggers
- feature flags
- global limits

Context is not object state.

### State

Caller-owned runtime data for one logical instance.

Examples:

- a connection
- a listener
- a parser instance
- a session
- a job

State is not the service interface.

### Registry

A composed object that exposes installed services through a stable namespace.

Examples:

- `lib.xyz`
- `lib.xyz.abc`
- `app.payload.codec`

### Leaf Module

A module that implements behavior directly and does not primarily exist to wire child modules.

### Aggregate Module

A module that composes child modules into a higher-level service surface.

### Private Module

A non-public module that still follows the same service pattern as a public module.

Private modules should still have:

- a `Lib` surface
- optional `Context`
- optional `State`
- explicit lifecycle semantics

The main difference is visibility, not structure.

### Private Barrel

A private aggregate surface that groups internal-only child capabilities.

Examples:

- `XyzInternalLib`
- `XyzPrivateLib`
- `AppAbcInternalLib`

## Design Rules

### 1. Keep Interface, Context, and State Separate

- `Lib` defines callable operations
- `Context` defines singleton dependencies/configuration
- `State` defines per-instance runtime data

Do not merge these roles into one struct.

### 2. Treat `init` and `shutdown` as Singleton Lifecycle

`init` and `shutdown` manage the module itself, not an individual object instance.

Use separate state functions for object lifecycle:

- `state_init`
- `state_reset`
- `state_free`

### 3. Do Not Store Module Function Tables in Runtime State

State may hold data and references to installed context if needed, but it should not redundantly embed service tables unless behavior is intentionally per-instance.

### 4. Use Explicit Ownership Semantics

For every input and output, specify whether data is:

- borrowed
- copied
- mutated in place
- heap-owned by caller
- heap-owned by callee

### 5. Keep the Registry Path Meaningful

Namespace depth should express composition or ownership.

Examples:

- `lib.net` means a top-level runtime service
- `lib.net.udp` means a child service under the net namespace
- `app.payload.codec` means an application-layer payload codec module

### 6. Private Modules Follow the Same Pattern

Private modules should use the same structural contract as public modules:

- interface surface
- context
- state
- lifecycle
- explicit ownership

If several private capabilities belong to one subsystem, group them behind a private barrel instead of scattering raw function pointers across unrelated structs.

Recommended forms:

- module-global internal registry
- subsystem-local `InternalLib`
- context-owned private barrel

Examples:

- `XyzInternalLib`
- `XyzContext.internal`
- `state->ctx->internal`

### 7. Do Not Confuse Private Barrels With Runtime State

A private barrel is still a service surface, not an object instance.

Use this distinction:

- `InternalLib` or `PrivateLib` groups internal capabilities
- `Context` carries installed references to those capabilities
- `State` carries per-instance runtime data

Do not use `State` as a hiding place for internal module tables unless the behavior is intentionally per-instance.

### 8. Wire Functions in an All-or-Nothing Manner

A module surface is valid only if its required callbacks are fully wired.

That means:

- either the module builds completely
- or module construction/init fails

Do not allow partially wired function tables to continue into normal runtime.

Optional wiring is not the default rule of thumb.

The default is:

- all-or-nothing wiring
- complete surface or failure

Optional capabilities are an explicit exception and should be documented as such.

### 9. Validate Once During Construction or Init

Required callbacks should be checked at the boundary where the module becomes usable:

- getter-time for a barrel, if appropriate
- install-time in a parent registry
- init-time before the module is considered live

After that point, the module should be treated as valid by contract.

### 10. After Successful Init, Call Directly

If a module or registry has already passed its wiring checks, subsequent call sites do not need to keep checking whether required callbacks exist.

Proper initialization is the caller's or installer's responsibility.

In other words:

- validate once
- then use directly

Repeated null-guarding of required callbacks in normal paths weakens the contract and scatters failure handling everywhere.

### 11. Prefer Fail-Fast Contract Violations

If a required callback is missing after successful initialization, that is a programmer error or wiring error.

Preferred behavior:

- assert
- abort
- crash loudly
- otherwise fail in an unmistakable way

Avoid silently returning `0` or degrading as if the missing callback were an expected runtime condition.

### 12. Barrel Construction Should Be Fractal

Aggregate modules should follow the same all-or-nothing contract as leaf modules.

In practice:

- a child module validates its own required callbacks
- a parent barrel validates that the child barrel is complete
- once the child is accepted, the parent treats it as valid by contract
- the parent then exposes the same contract upward

This repeats recursively through the registry tree.

So:

- `lib.xyz` should trust `lib.xyz.abc` after initial wiring
- `app.abc` should trust `app.abc.def` after initial wiring
- no layer should keep re-litigating whether its children exist during normal execution

This is what makes barrel construction fractal: each level builds and exports the same guarantee to the level above it.

Lazy wiring inside a module is still compatible with this rule.

What matters is:

- the module surface may be acquired first
- the module may wire child surfaces internally before operational use
- the module must finish that wiring before any dependent execution path is used
- after init/wiring succeeds, parent and child are both trusted by contract

## Standard Module Shapes

### A. Stateless Leaf Module

Use when the module exposes pure or near-pure operations and needs little or no runtime state.

```c
typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*encode)(const void *input, void *output);
} XyzLib;

const XyzLib *get_lib_xyz(void);
```

Use this for:

- formatting
- normalization
- lookup tables
- small utility services with stable global behavior

### B. Context-Aware Singleton Module

Use when the singleton needs installed dependencies or policy.

```c
typedef struct {
  const Logger *log;
  const FileLib *file;
  int strict_mode;
} XyzContext;

typedef struct {
  int (*init)(const XyzContext *ctx);
  int (*set_context)(const XyzContext *ctx);
  void (*shutdown)(void);
  int (*load)(const char *path);
} XyzLib;

const XyzLib *get_lib_xyz(void);
```

Use this for:

- modules with shared providers
- modules with install-time policy
- modules with process-global configuration

### C. Stateful Service Module

Use when the module acts on caller-owned object instances.

```c
typedef struct {
  int fd;
  int ready;
} XyzState;

typedef struct {
  const SocketLib *socket;
} XyzContext;

typedef struct {
  int (*init)(const XyzContext *ctx);
  int (*set_context)(const XyzContext *ctx);
  void (*shutdown)(void);

  int (*state_init)(XyzState *state);
  void (*state_reset)(XyzState *state);

  int (*open)(XyzState *state, const char *target);
  int (*pump)(XyzState *state, uint64_t timeout_ms);
} XyzLib;

const XyzLib *get_lib_xyz(void);
```

Use this for:

- sockets
- sessions
- parsers with mutable working state
- stream processors
- protocol state machines

### D. Aggregate or Barrel Module

Use when the module exists primarily to wire submodules into one higher-level surface.

```c
typedef struct {
  XyzParseLib parse;
  XyzEncodeLib encode;
  int (*init)(const XyzContext *ctx);
  int (*set_context)(const XyzContext *ctx);
  void (*shutdown)(void);
} XyzLib;

const XyzLib *get_lib_xyz(void);
```

Use this for:

- namespace grouping
- coordinated child initialization
- dependency-safe composition
- staging a subtree behind one stable entrypoint

Aggregate modules should validate child completeness once, not repeatedly inside every operational call.

### E. Private Internal Module Set

Use when a subsystem has internal child modules that should not be part of the public API but still need clear composition.

```c
typedef struct {
  XyzParseLib parse;
  XyzNormalizeLib normalize;
  XyzDispatchLib dispatch;
} XyzInternalLib;

typedef struct {
  const Logger *log;
  const XyzInternalLib *internal;
} XyzContext;
```

Storage options:

- static module-global internal barrel
- embedded in singleton-global context
- referenced through `ctx->internal`

Do not store this internal barrel in `XyzState` unless each state truly owns a distinct behavior set.

## Standard Naming Scheme

### Type Names

Use predictable suffixes:

- `XyzAbcLib`
- `XyzAbcContext`
- `XyzAbcState`
- `XyzAbcInput`
- `XyzAbcOutput`
- `XyzAbcConfig`

### Accessors

Prefer one accessor convention across the codebase:

- `get_lib_xyz()`
- `get_lib_xyz_abc()`

If the project uses another established convention, keep it consistent and use it everywhere.

### File Layout

Prefer filesystem layout that mirrors the namespace:

- `xyz/xyz.h`
- `xyz/xyz.c`
- `xyz/abc/abc.h`
- `xyz/abc/abc.c`
- `xyz/internal.h`
- `xyz/internal/*.h`
- `xyz/internal/*.c`

Large single-module surfaces may also be implemented by flat internal shards inside one module directory.

Example:

- `lib/really_big_function_surface/really_big_function_surface.c`
- `lib/really_big_function_surface/really_big_function_1.c`
- `lib/really_big_function_surface/really_big_function_2.c`

Those shard files are implementation units for one module surface, not automatically separate modules.

Then the installed registry can mirror that composition:

- `lib.xyz`
- `lib.xyz.abc`

And the private surface can mirror internal composition:

- `XyzInternalLib`
- `internal.parse`
- `internal.normalize`

### Function Verbs

Use verbs that describe lifecycle and operational role clearly:

- `init`
- `set_context`
- `shutdown`
- `state_init`
- `state_reset`
- `load`
- `store`
- `encode`
- `decode`
- `pump`
- `drain`
- `flush`
- `connect`
- `disconnect`

## Input and Output Methodology

### Install-Time Input

Use `Context` for singleton-global input.

Examples:

- dependency providers
- policy flags
- shared limits
- default formatting or output behavior

### Runtime Input

Use direct parameters for simple operations.

Use `Input` or `Request` structs when:

- the parameter list becomes long
- multiple fields are logically coupled
- versioning or extension is likely

### Runtime Output

Pick one output convention and keep it uniform within a module:

- scalar return value
- status code plus out-parameters
- status code plus `Output` struct

Recommended patterns:

```c
int xyz_parse(const char *text, XyzOutput *out);
int xyz_encode(const XyzInput *in, uint8_t *buf, size_t buf_size, size_t *out_len);
const char *xyz_name(int code);
```

### Return Semantics

Use one of these models explicitly:

- boolean success/failure: `1` / `0`
- integer status code: `0` success, negative error
- enum-based status

Do not mix multiple ad hoc status conventions inside the same module without a strong reason.

## Installation Methodology

### Step 1. Define the Public Contract

Before writing implementation, define:

- module responsibility
- namespace path
- context requirements
- runtime state requirements
- lifecycle requirements
- input/output contract

### Step 2. Define the Interface Types

Create:

- `Lib`
- `Context` if needed
- `State` if needed
- `Input` and `Output` types if needed
- `InternalLib` if the subsystem has private child capabilities

### Step 3. Implement Static Functions

Keep implementation-local symbols `static` unless they are intentionally exported.

### Step 4. Build the Singleton Surface

Leaf modules should usually expose a `static const` function table.

Aggregate modules may use a mutable singleton table if they need lazy child wiring.

In either case, required callbacks should obey an all-or-nothing contract before the surface is considered usable.

Lazy internal wiring is fine as long as it completes before the module's operational functions are used.

### Step 5. Provide a Getter

The getter returns the singleton service surface, not a newly allocated instance.

### Step 6. Install Into a Registry

A higher-level installer copies the function table into the parent registry:

```c
registry.xyz = *get_lib_xyz();
registry.xyz.abc = *get_lib_xyz_abc();
```

This copies the callable surface, not the singleton implementation state.

If the subsystem has private child modules, install them into a private barrel as well:

```c
static XyzInternalLib g_internal = {
  .parse = {0},
  .normalize = {0}
};

ctx.internal = &g_internal;
```

That private barrel is still service composition, not runtime state.

The surface may be installed before every child dependency has been initialized, provided the module's own init/wiring path completes that work before operational use.

### Step 7. Initialize in Dependency Order

Initialize providers before consumers.

Example:

1. `time`
2. `print`
3. `log`
4. `file`
5. `xyz`

During this step, verify the required callbacks for each installed dependency exactly once.

### Step 8. Shutdown in Reverse Dependency Order

Reverse the initialization order exactly unless a documented exception exists.

## Wiring Contract

The recommended wiring contract is:

1. Acquire the module surface.
2. Validate all required callbacks.
3. Install context and initialize.
4. Mark the module usable.
5. From that point onward, call it directly.

Example:

```c
registry.xyz = *get_lib_xyz();

if (!registry.xyz.init ||
    !registry.xyz.shutdown ||
    !registry.xyz.run) {
  return 0;
}

if (!registry.xyz.init(&xyz_ctx)) {
  return 0;
}

/* After this point, use directly. */
registry.xyz.run(...);
```

Do not turn every later call into:

```c
if (registry.xyz.run) {
  registry.xyz.run(...);
}
```

That defeats the purpose of establishing a strong initialization contract.

For barrels, apply the same rule recursively:

```c
registry.xyz = *get_lib_xyz();

if (!registry.xyz.init ||
    !registry.xyz.shutdown) {
  return 0;
}

/*
 * registry.xyz.init() may lazily wire and validate registry.xyz.abc
 * internally before the child surface is ever used.
 */
if (!registry.xyz.init(&xyz_ctx)) {
  return 0;
}

/* After this point, both parent and child are used directly. */
registry.xyz.abc.run(...);
```

Do not write normal execution paths like:

```c
if (registry.xyz.abc.run) {
  registry.xyz.abc.run(...);
}
```

That kind of pointer-goo harms readability and adds no value once the construction contract has already been established.

If a project supports optional child capabilities, that must be declared explicitly rather than inferred from missing function pointers.

## Methodology for `lib.xyz.abc` and `app.abc.def`

### `lib.xyz.abc`

Use this when:

- the service belongs to a runtime/system/service namespace
- it may be shared across multiple application modules
- it represents infrastructure or reusable behavior

Typical shape:

- `lib.xyz` is an aggregate parent
- `lib.xyz.abc` is a child service under that namespace

Good examples:

- `lib.net.udp`
- `lib.payload.codec`
- `lib.crypto.session`

### `app.abc.def`

Use this when:

- the module belongs to application policy or workflow rather than generic runtime infrastructure
- it consumes `lib.*` services rather than defining them
- it implements domain behavior, command handling, orchestration, or business logic

Typical shape:

- `app.abc` is an application subsystem
- `app.abc.def` is a narrower child capability

Good examples:

- `app.payload.codec`
- `app.daemon.runner`
- `app.user.lookup`

### Decision Rule

If the code is domain-agnostic and reusable outside the current app, prefer `lib.*`.

If the code expresses app policy, app orchestration, or domain-specific workflow, prefer `app.*`.

If the code is internal-only but still needs composition, add a private barrel under that subsystem rather than flattening the implementation into unrelated statics.

## Recommended Skeleton

```c
typedef struct {
  const Logger *log;
} XyzAbcContext;

typedef struct {
  int initialized;
  int counter;
} XyzAbcState;

typedef struct {
  int (*init)(const XyzAbcContext *ctx);
  int (*set_context)(const XyzAbcContext *ctx);
  void (*shutdown)(void);

  int (*state_init)(XyzAbcState *state);
  void (*state_reset)(XyzAbcState *state);

  int (*run)(XyzAbcState *state, const char *input, char *out, size_t out_size);
} XyzAbcLib;

const XyzAbcLib *get_lib_xyz_abc(void);
```

Implementation notes:

- singleton-global dependencies live in `static XyzAbcContext g_ctx`
- object data lives in `XyzAbcState`
- the accessor returns one singleton surface
- callers interact through the installed registry path
- private child capabilities, if any, live in `XyzInternalLib` or an equivalent internal barrel

## Anti-Patterns

Avoid the following:

- storing function tables inside runtime state without a per-instance reason
- using `shutdown()` to clean up one request or one object instance
- letting `Context` accumulate transient runtime fields
- storing private module barrels in `State` just to hide them
- using one module as both plain helpers and singleton surface without labeling the distinction
- inconsistent getter naming
- partially wired modules that are allowed to limp through runtime
- parent barrels that keep re-checking child callback existence after child validation already succeeded
- JavaScript-style optional-pointer habits in normal C execution paths
- treating optional wiring as the default instead of an explicit exception
- repeated null-guarding of required callbacks after successful init
- silently returning `0` on post-init contract violations
- manual init/shutdown order that is not mirrored or documented
- unclear ownership of returned buffers
- deep namespace trees that do not reflect real composition

## Short Checklist

Before adding a module, answer these questions:

1. Is this a `lib.*` service or an `app.*` service?
2. Is it a leaf module or an aggregate module?
3. What is its registry path?
4. What is install-time context?
5. What is per-instance state?
6. Does this subsystem need an internal barrel for private child modules?
7. What callbacks are required for the module to be considered fully wired?
8. What are the inputs and outputs of each operation?
9. What are the ownership rules?
10. What is the init order?
11. What is the exact reverse shutdown order?
12. Does the naming match the rest of the tree?

## Short Version

Use this formula:

- define a `Lib` surface
- inject singleton-global dependencies through `Context`
- keep per-instance data in `State`
- wire required callbacks all-or-nothing
- expose one getter
- install the surface into a registry path
- initialize in dependency order
- validate once during init, then call directly
- shutdown in exact reverse order
- keep ownership and return semantics explicit
