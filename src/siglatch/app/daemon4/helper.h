/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON4_HELPER_H
#define SIGLATCH_SERVER_APP_DAEMON4_HELPER_H

#include <stdint.h>

#include "job.h"
#include "../payload/codec/codec.h"

typedef struct M7Mux2SendPacket M7Mux2SendPacket;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*copy_job_to_knock_packet)(const AppConnectionJob *job, KnockPacket *out_pkt);
  int (*copy_job_reply_to_send)(const AppConnectionJob *job,
                                M7Mux2SendPacket *out_send,
                                SharedKnockNormalizedUnit *out_user);
  uint64_t (*time_until_ms)(uint64_t next_tick_at, uint64_t now_ms);
} AppDaemon4HelperLib;

const AppDaemon4HelperLib *get_app_daemon4_helper_lib(void);

#endif
