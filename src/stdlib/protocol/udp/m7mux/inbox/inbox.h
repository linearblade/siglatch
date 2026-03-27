/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_INBOX_H
#define LIB_PROTOCOL_UDP_M7MUX_INBOX_H

#include <stdint.h>

typedef struct M7MuxContext M7MuxContext;
typedef struct M7MuxNormalizedPacket M7MuxNormalizedPacket;
typedef struct M7MuxState M7MuxState;

typedef struct {
  int (*init)(const M7MuxContext *ctx);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);

  int (*state_init)(M7MuxState *state);
  void (*state_reset)(M7MuxState *state);
  int (*has_pending)(const M7MuxState *state);
  int (*pump)(M7MuxState *state, uint64_t timeout_ms);
  int (*drain)(M7MuxState *state, M7MuxNormalizedPacket *out_normal);
} M7MuxInboxLib;

const M7MuxInboxLib *get_protocol_udp_m7mux_inbox_lib(void);

#endif
