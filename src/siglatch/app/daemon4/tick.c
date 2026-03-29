/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "tick.h"

#define APP_TICK_DEFAULT_MS 6000u

static int app_tick_init(void) {
  return 1;
}

static void app_tick_shutdown(void) {
}

static uint64_t app_tick_next_at(const AppConnectionState *connection_state,
                                 const AppJobState *job_state,
                                 uint64_t now_ms) {
  uint64_t next_at = now_ms + APP_TICK_DEFAULT_MS;
  size_t i = 0;

  (void)connection_state;
  (void)job_state;

  if (connection_state) {
    for (i = 0; i < APP_CONNECTION_SESSION_CAPACITY; ++i) {
      if (!connection_state->sessions[i].active) {
        continue;
      }

      if (connection_state->sessions[i].expires_at_ms == 0) {
        continue;
      }

      if (connection_state->sessions[i].expires_at_ms < next_at) {
        next_at = connection_state->sessions[i].expires_at_ms;
      }
    }
  }

  return next_at;
}

/*
 * Placeholder only.
 *
 * Tick coordination is intentionally app-level rather than connection-specific.
 * Real work will land here later, for example:
 *
 * - session expiry / stale cleanup
 * - heartbeat / keepalive scheduling
 * - background promotion or maintenance across connection/job state
 * - proactive outbound scheduling
 *
 * For now it is intentionally a no-op.
 */
static void app_tick_run(AppConnectionState *connection_state,
                         AppJobState *job_state,
                         uint64_t now_ms) {
  (void)connection_state;
  (void)job_state;
  (void)now_ms;
}

static const AppTickLib app_tick_instance = {
  .init = app_tick_init,
  .shutdown = app_tick_shutdown,
  .next_at = app_tick_next_at,
  .run = app_tick_run
};

const AppTickLib *get_app_daemon4_tick_lib(void) {
  return &app_tick_instance;
}
