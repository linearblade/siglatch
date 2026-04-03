/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON_HELPER_H
#define SIGLATCH_SERVER_APP_DAEMON_HELPER_H

#include <stdint.h>

#include "job.h"
#include "../../../shared/knock/codec/user.h"

typedef struct M7MuxSendPacket M7MuxSendPacket;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*copy_job_reply_to_send)(const AppConnectionJob *job,
                                M7MuxSendPacket *out_send,
                                M7MuxUserSendData *out_user);
  uint64_t (*time_until_ms)(uint64_t next_tick_at, uint64_t now_ms);
} AppDaemonHelperLib;

const AppDaemonHelperLib *get_app_daemon_helper_lib(void);

#endif
