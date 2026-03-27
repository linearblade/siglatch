/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_STREAM_H
#define LIB_PROTOCOL_UDP_M7MUX_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "../normalize/normalize.h"

#define M7MUX_STREAM_READY_QUEUE_CAPACITY 64u
/* Temporary fixed policy until mux config becomes first-class. */
#define M7MUX_STREAM_EXPIRE_AFTER_MS 30000u

typedef struct {
  M7MuxNormalizedPacket ready_queue[M7MUX_STREAM_READY_QUEUE_CAPACITY];
  size_t ready_head;
  size_t ready_tail;
  size_t ready_count;
  uint64_t next_message_id;
} M7MuxStreamState;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*state_init)(M7MuxStreamState *state);
  void (*state_reset)(M7MuxStreamState *state);
  int (*has_pending)(const M7MuxStreamState *state);
  int (*ingest)(M7MuxStreamState *state, const M7MuxNormalizedPacket *normal);
  int (*drain)(M7MuxStreamState *state, M7MuxNormalizedPacket *out_normal);
  int (*expire)(M7MuxStreamState *state, uint64_t now_ms);
  int (*pump)(M7MuxStreamState *state, uint64_t now_ms);
} M7MuxStreamLib;

const M7MuxStreamLib *get_protocol_udp_m7mux_stream_lib(void);

#endif
