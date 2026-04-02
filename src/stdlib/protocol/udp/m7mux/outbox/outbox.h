/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_OUTBOX_H
#define LIB_PROTOCOL_UDP_M7MUX_OUTBOX_H

#include <stddef.h>
#include <stdint.h>

typedef struct M7MuxContext M7MuxContext;
typedef struct M7MuxRecvPacket M7MuxRecvPacket;
typedef struct M7MuxSendPacket M7MuxSendPacket;
typedef struct M7MuxSendBytesPacket {
  uint64_t trace_id;
  char label[64];
  char ip[64];
  uint16_t client_port;
  uint64_t received_ms;
  const uint8_t *bytes;
  size_t bytes_len;
} M7MuxSendBytesPacket;
typedef struct M7MuxEgressData M7MuxEgressData;
typedef struct M7MuxState M7MuxState;

typedef struct {
  int (*init)(const M7MuxContext *ctx);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);

  int (*state_init)(M7MuxState *state);
  void (*state_reset)(M7MuxState *state);
  int (*has_pending)(const M7MuxState *state);
  int (*stage)(M7MuxState *state, const M7MuxSendPacket *send);
  int (*stage_bytes)(M7MuxState *state, const M7MuxSendBytesPacket *send_bytes);
  int (*flush)(M7MuxState *state, int sock, uint64_t now_ms);
} M7MuxOutboxLib;

const M7MuxOutboxLib *get_protocol_udp_m7mux_outbox_lib(void);

#endif
