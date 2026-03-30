/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_EGRESS_H
#define LIB_PROTOCOL_UDP_M7MUX_EGRESS_H

#include <stddef.h>
#include <stdint.h>

#include "../normalize/normalize.h"

#define M7MUX_EGRESS_QUEUE_CAPACITY 64u
#define M7MUX_EGRESS_TIMEOUT_MS 30000u

typedef struct {
  M7MuxEgressData queue[M7MUX_EGRESS_QUEUE_CAPACITY];
  size_t head;
  size_t tail;
  size_t count;
} M7MuxEgressState;

typedef struct {
  int (*init)(void);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);

  int (*state_init)(M7MuxEgressState *state);
  void (*state_reset)(M7MuxEgressState *state);

  int (*has_pending)(const M7MuxEgressState *state);
  int (*stage)(M7MuxEgressState *state, const M7MuxEgressData *egress);
  int (*enqueue)(M7MuxEgressState *state, const M7MuxEgressData *egress);

  /*
   * Transitional seam:
   * egress does not own the socket, so transport is passed in.
   * Later this can become listener-owned wiring.
   */
  int (*flush)(M7MuxEgressState *state, int sock, uint64_t now_ms);
} M7MuxEgressLib;

const M7MuxEgressLib *get_protocol_udp_m7mux_egress_lib(void);

#endif
