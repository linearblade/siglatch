/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON4_TICK_H
#define SIGLATCH_SERVER_APP_DAEMON4_TICK_H

#include "job.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  uint64_t (*next_at)(const AppConnectionState *connection_state,
                      const AppJobState *job_state,
                      uint64_t now_ms);
  void (*run)(AppConnectionState *connection_state,
              AppJobState *job_state,
              uint64_t now_ms);
} AppTickLib;

const AppTickLib *get_app_daemon4_tick_lib(void);

#endif
