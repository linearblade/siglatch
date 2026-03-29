/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX2_OUTBOX_H
#define LIB_PROTOCOL_UDP_M7MUX2_OUTBOX_H

#include <stdint.h>

typedef struct M7Mux2Context M7Mux2Context;
typedef struct M7Mux2RecvPacket M7Mux2RecvPacket;
typedef struct M7Mux2SendPacket M7Mux2SendPacket;
typedef struct M7Mux2EgressData M7Mux2EgressData;
typedef struct M7Mux2State M7Mux2State;

typedef struct {
  int (*init)(const M7Mux2Context *ctx);
  int (*set_context)(const M7Mux2Context *ctx);
  void (*shutdown)(void);

  int (*state_init)(M7Mux2State *state);
  void (*state_reset)(M7Mux2State *state);
  int (*has_pending)(const M7Mux2State *state);
  int (*stage)(M7Mux2State *state, const M7Mux2SendPacket *send);
  int (*flush)(M7Mux2State *state, int sock, uint64_t now_ms);
} M7Mux2OutboxLib;

const M7Mux2OutboxLib *get_protocol_udp_m7mux2_outbox_lib(void);

#endif
