/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON3_HELPER_H
#define SIGLATCH_SERVER_APP_DAEMON3_HELPER_H

#include <stdint.h>

#include "job.h"
#include "../payload/codec/codec.h"

struct M7MuxNormalizedPacket;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*copy_job_to_knock_packet)(const AppConnectionJob *job, KnockPacket *out_pkt);
  int (*copy_job_reply_to_mux)(const AppConnectionJob *job,
                               struct M7MuxNormalizedPacket *out_normal);
  uint64_t (*time_until_ms)(uint64_t next_tick_at, uint64_t now_ms);
} AppDaemon3HelperLib;

const AppDaemon3HelperLib *get_app_daemon3_helper_lib(void);

#endif
