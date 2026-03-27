/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON3_JOB_H
#define SIGLATCH_SERVER_APP_DAEMON3_JOB_H

#include "connection.h"
#include "../runtime/runtime.h"
#include "../../../stdlib/openssl_session.h"

typedef struct AppJobState {
  AppConnectionJob ready_queue[64];
  size_t ready_head;
  size_t ready_tail;
  size_t ready_count;
} AppJobState;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*state_init)(AppJobState *state);
  void (*state_reset)(AppJobState *state);
  int (*enqueue)(AppJobState *state, AppConnectionJob *job);
  int (*drain)(AppJobState *state, AppConnectionJob *out_job);
  int (*consume)(AppRuntimeListenerState *listener,
                 AppConnectionJob *job,
                 SiglatchOpenSSLSession *session);
  void (*dispose)(AppJobState *state, AppConnectionJob *job);
  int (*flush_buffer)(AppConnectionJob *job);
} AppJobLib;

const AppJobLib *get_app_daemon3_job_lib(void);

#endif
