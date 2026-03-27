/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_EGRESS_H
#define LIB_PROTOCOL_UDP_M7MUX_EGRESS_H

#include <stddef.h>
#include <stdint.h>

#include "../normalize/normalize.h"

#define M7MUX_EGRESS_BUFFER_SIZE 1024u
#define M7MUX_EGRESS_QUEUE_CAPACITY 64u
#define M7MUX_EGRESS_TIMEOUT_MS 30000u

typedef struct {
  uint8_t buffer[M7MUX_EGRESS_BUFFER_SIZE];
  size_t len;

  char ip[64];
  uint16_t client_port;
  int encrypted;

  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;

  int available;
} M7MuxEgress;

typedef struct {
  M7MuxEgress queue[M7MUX_EGRESS_QUEUE_CAPACITY];
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
  int (*stage)(M7MuxEgressState *state,
                        const M7MuxNormalizedPacket *normal);
  int (*enqueue)(M7MuxEgressState *state,
                          const M7MuxEgress *egress);

  /*
   * Transitional seam:
   * egress does not own the socket, so transport is passed in.
   * Later this can become listener-owned wiring.
   */
  int (*flush)(M7MuxEgressState *state,
                        int sock,
                        uint64_t now_ms);
} M7MuxEgressLib;

const M7MuxEgressLib *get_protocol_udp_m7mux_egress_lib(void);

#endif
