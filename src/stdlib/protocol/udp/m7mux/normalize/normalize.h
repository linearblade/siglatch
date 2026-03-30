/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_NORMALIZE_H
#define LIB_PROTOCOL_UDP_M7MUX_NORMALIZE_H

#include <stddef.h>
#include <stdint.h>

#include "../m7mux.h"
#include "../../../../../shared/knock/codec/normalized.h"
#include "adapter/adapter.h"

#define M7MUX_NORMALIZED_PACKET_BUFFER_SIZE 1024u

typedef struct M7MuxRecvPacket {
  int complete;
  int should_reply;
  int synthetic_session;
  uint32_t wire_version;
  uint8_t wire_form;
  uint64_t received_ms;
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  uint32_t fragment_index;
  uint32_t fragment_count;
  uint32_t timestamp;
  char label[64];
  SharedKnockNormalizedUnit user;
} M7MuxRecvPacket;

typedef struct M7MuxSendPacket {
  int complete;
  int should_reply;
  int available;
  uint64_t trace_id;
  char label[64];
  uint32_t wire_version;
  uint8_t wire_form;
  uint64_t received_ms;
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  uint32_t fragment_index;
  uint32_t fragment_count;
  uint32_t timestamp;
  char ip[64];
  uint16_t client_port;
  int encrypted;
  int wire_auth;
  const SharedKnockNormalizedUnit *user;
} M7MuxSendPacket;

typedef struct M7MuxEgressData {
  int complete;
  int should_reply;
  int available;
  uint64_t trace_id;
  char label[64];
  uint32_t wire_version;
  uint8_t wire_form;
  uint64_t received_ms;
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  uint32_t fragment_index;
  uint32_t fragment_count;
  uint32_t timestamp;
  char ip[64];
  uint16_t client_port;
  int encrypted;
  int wire_auth;
  uint8_t egress_buffer[M7MUX_NORMALIZED_PACKET_BUFFER_SIZE];
  size_t egress_len;
} M7MuxEgressData;

typedef struct {
  M7MuxNormalizeAdapterLib adapter;
  int (*init)(const M7MuxContext *ctx);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);
  int (*normalize)(const M7MuxIngress *ingress, M7MuxRecvPacket *out);
} M7MuxNormalizeLib;

const M7MuxNormalizeLib *get_protocol_udp_m7mux_normalize_lib(void);

#endif
