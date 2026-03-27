/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON3_HELPER_H
#define SIGLATCH_SERVER_APP_DAEMON3_HELPER_H

#include <stdint.h>

#include "job.h"
#include "../payload/codec/codec.h"
#include "../../../stdlib/protocol/udp/m7mux/normalize/normalize.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*copy_job_to_knock_packet)(const AppConnectionJob *job, KnockPacket *out_pkt);
  void (*copy_mux_ingress_to_job)(const M7MuxNormalizedPacket *normal,
                                  AppConnectionJob *out_job);
  void (*copy_job_reply_to_mux)(const AppConnectionJob *job,
                                M7MuxNormalizedPacket *out_normal);
  uint64_t (*time_until_ms)(uint64_t next_tick_at, uint64_t now_ms);
} AppDaemon3HelperLib;

const AppDaemon3HelperLib *get_app_daemon3_helper_lib(void);

#endif
