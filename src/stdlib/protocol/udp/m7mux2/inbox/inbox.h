/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX2_INBOX_H
#define LIB_PROTOCOL_UDP_M7MUX2_INBOX_H

#include <stdint.h>

typedef struct M7Mux2Context M7Mux2Context;
typedef struct M7Mux2RecvPacket M7Mux2RecvPacket;
typedef struct M7Mux2State M7Mux2State;

typedef struct {
  int (*init)(const M7Mux2Context *ctx);
  int (*set_context)(const M7Mux2Context *ctx);
  void (*shutdown)(void);

  int (*state_init)(M7Mux2State *state);
  void (*state_reset)(M7Mux2State *state);
  int (*has_pending)(const M7Mux2State *state);
  int (*pump)(M7Mux2State *state, uint64_t timeout_ms);
  int (*drain)(M7Mux2State *state, M7Mux2RecvPacket *out_normal);
} M7Mux2InboxLib;

const M7Mux2InboxLib *get_protocol_udp_m7mux2_inbox_lib(void);

#endif
