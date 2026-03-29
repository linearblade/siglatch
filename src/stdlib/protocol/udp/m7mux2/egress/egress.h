/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX2_EGRESS_H
#define LIB_PROTOCOL_UDP_M7MUX2_EGRESS_H

#include <stddef.h>
#include <stdint.h>

#include "../normalize/normalize.h"

#define M7MUX2_EGRESS_QUEUE_CAPACITY 64u
#define M7MUX2_EGRESS_TIMEOUT_MS 30000u

typedef struct {
  M7Mux2EgressData queue[M7MUX2_EGRESS_QUEUE_CAPACITY];
  size_t head;
  size_t tail;
  size_t count;
} M7Mux2EgressState;

typedef struct {
  int (*init)(void);
  int (*set_context)(const M7Mux2Context *ctx);
  void (*shutdown)(void);

  int (*state_init)(M7Mux2EgressState *state);
  void (*state_reset)(M7Mux2EgressState *state);

  int (*has_pending)(const M7Mux2EgressState *state);
  int (*stage)(M7Mux2EgressState *state, const M7Mux2EgressData *egress);
  int (*enqueue)(M7Mux2EgressState *state, const M7Mux2EgressData *egress);

  /*
   * Transitional seam:
   * egress does not own the socket, so transport is passed in.
   * Later this can become listener-owned wiring.
   */
  int (*flush)(M7Mux2EgressState *state, int sock, uint64_t now_ms);
} M7Mux2EgressLib;

const M7Mux2EgressLib *get_protocol_udp_m7mux2_egress_lib(void);

#endif
