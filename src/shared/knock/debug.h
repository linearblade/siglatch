/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_DEBUG_H
#define SIGLATCH_SHARED_KNOCK_DEBUG_H

#include "../../stdlib/print.h"
#include "packet.h"

typedef struct {
  const PrintLib *print;
} SharedKnockDebugContext;

typedef struct {
  int (*init)(const SharedKnockDebugContext *ctx);
  void (*shutdown)(void);
  void (*dump_packet_fields)(const char *label, const KnockPacket *pkt);
} SharedKnockDebugLib;

int shared_knock_debug_init(const SharedKnockDebugContext *ctx);
void shared_knock_debug_shutdown(void);
void shared_knock_dump_packet_fields(const char *label, const KnockPacket *pkt);
const SharedKnockDebugLib *get_shared_knock_debug_lib(void);

#endif
