/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX2_STREAM_H
#define LIB_PROTOCOL_UDP_M7MUX2_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "../normalize/normalize.h"

#define M7MUX2_STREAM_READY_QUEUE_CAPACITY 64u
/* Temporary fixed policy until mux config becomes first-class. */
#define M7MUX2_STREAM_EXPIRE_AFTER_MS 30000u

typedef struct {
  M7Mux2RecvPacket ready_queue[M7MUX2_STREAM_READY_QUEUE_CAPACITY];
  size_t ready_count;
  uint64_t next_message_id;
} M7Mux2StreamState;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*state_init)(M7Mux2StreamState *state);
  void (*state_reset)(M7Mux2StreamState *state);
  int (*has_pending)(const M7Mux2StreamState *state);
  int (*ingest)(M7Mux2StreamState *state, const M7Mux2RecvPacket *normal);
  int (*drain)(M7Mux2StreamState *state, M7Mux2RecvPacket *out_normal);
  int (*expire)(M7Mux2StreamState *state, uint64_t now_ms);
  int (*pump)(M7Mux2StreamState *state, uint64_t now_ms);
} M7Mux2StreamLib;

const M7Mux2StreamLib *get_protocol_udp_m7mux2_stream_lib(void);

#endif
