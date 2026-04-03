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
#define M7MUX_STREAM_SESSION_TRACKER_CAPACITY 64u
#define M7MUX_STREAM_TRACKER_CAPACITY 64u
/* Temporary fixed policy until mux config becomes first-class. */
#define M7MUX_STREAM_EXPIRE_AFTER_MS 30000u

typedef struct {
  uint32_t stream_id;
  uint64_t next_message_id;
  uint64_t message_id;
  uint32_t next_fragment_index;
  uint32_t fragment_count;
  int active;
} M7MuxStreamMessageTracker;

typedef struct {
  uint64_t session_id;
  uint32_t next_stream_id;
  int active;
  M7MuxStreamMessageTracker stream_trackers[M7MUX_STREAM_TRACKER_CAPACITY];
} M7MuxStreamSessionTracker;

typedef struct {
  M7MuxRecvPacket ready_queue[M7MUX_STREAM_READY_QUEUE_CAPACITY];
  size_t ready_count;
  M7MuxStreamSessionTracker session_trackers[M7MUX_STREAM_SESSION_TRACKER_CAPACITY];
  const M7MuxNormalizeAdapterLib *adapter_lib;
} M7MuxStreamState;

typedef struct M7MuxStreamReleaseContext {
  const M7MuxNormalizeAdapterLib *adapter_lib;
} M7MuxStreamReleaseContext;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*state_init)(M7MuxStreamState *state);
  void (*state_reset)(M7MuxStreamState *state);
  int (*has_pending)(const M7MuxStreamState *state);
  int (*ingest)(M7MuxStreamState *state, const M7MuxRecvPacket *normal);
  int (*drain)(M7MuxStreamState *state, M7MuxRecvPacket *out_normal);
  int (*expire)(M7MuxStreamState *state, uint64_t now_ms);
  int (*pump)(M7MuxStreamState *state, uint64_t now_ms);
} M7MuxStreamLib;

void m7mux_stream_release_user(M7MuxStreamState *state, const M7MuxRecvPacket *packet);

const M7MuxStreamLib *get_protocol_udp_m7mux_stream_lib(void);

#endif
