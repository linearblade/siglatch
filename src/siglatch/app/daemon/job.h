/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON_JOB_H
#define SIGLATCH_SERVER_APP_DAEMON_JOB_H

#include "connection.h"
#include "../runtime/runtime.h"
#include "../../../stdlib/openssl_session.h"

#define APP_JOB_PAYLOAD_BLOCK_SIZE 1280u
#define APP_JOB_RESPONSE_BLOCK_SIZE 1280u

struct M7MuxRecvPacket;

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
  int (*enqueue)(AppJobState *state, const struct M7MuxRecvPacket *normal);
  int (*drain)(AppJobState *state, AppConnectionJob *out_job);
  int (*consume)(AppRuntimeListenerState *listener,
                 AppConnectionJob *job,
                 SiglatchOpenSSLSession *session);
  int (*reserve_response)(AppConnectionJob *job, size_t min_cap);
  void (*dispose)(AppJobState *state, AppConnectionJob *job);
  int (*flush_buffer)(AppConnectionJob *job);
} AppJobLib;

const AppJobLib *get_app_daemon_job_lib(void);

#endif
