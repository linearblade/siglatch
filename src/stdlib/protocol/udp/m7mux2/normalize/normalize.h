/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX2_NORMALIZE_H
#define LIB_PROTOCOL_UDP_M7MUX2_NORMALIZE_H

#include <stddef.h>
#include <stdint.h>

#include "../m7mux2.h"
#include "../../../../../shared/knock/codec/normalized.h"
#include "adapter/adapter.h"

#define M7MUX2_NORMALIZED_PACKET_BUFFER_SIZE 1024u

typedef struct M7Mux2RecvPacket {
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
} M7Mux2RecvPacket;

typedef struct M7Mux2SendPacket {
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
} M7Mux2SendPacket;

typedef struct M7Mux2EgressData {
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
  uint8_t egress_buffer[M7MUX2_NORMALIZED_PACKET_BUFFER_SIZE];
  size_t egress_len;
} M7Mux2EgressData;

typedef struct {
  M7Mux2NormalizeAdapterLib adapter;
  int (*init)(const M7Mux2Context *ctx);
  int (*set_context)(const M7Mux2Context *ctx);
  void (*shutdown)(void);
  int (*normalize)(const M7Mux2Ingress *ingress, M7Mux2RecvPacket *out);
} M7Mux2NormalizeLib;

const M7Mux2NormalizeLib *get_protocol_udp_m7mux2_normalize_lib(void);

#endif
