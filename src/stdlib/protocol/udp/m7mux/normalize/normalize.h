/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_NORMALIZE_H
#define LIB_PROTOCOL_UDP_M7MUX_NORMALIZE_H

#include <stddef.h>
#include <stdint.h>

#include "../m7mux.h"
#include "adapter/adapter.h"

#define M7MUX_NORMALIZED_PACKET_BUFFER_SIZE 1024u

typedef struct M7MuxNormalizedPacket {
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
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint8_t hmac[32];
  char ip[64];
  uint16_t client_port;
  int encrypted;
  int authorized;
  uint8_t payload_buffer[M7MUX_NORMALIZED_PACKET_BUFFER_SIZE];
  size_t payload_len;
  uint8_t response_buffer[M7MUX_NORMALIZED_PACKET_BUFFER_SIZE];
  size_t response_len;
} M7MuxNormalizedPacket;

typedef struct {
  M7MuxNormalizeAdapterLib adapter;
  int (*init)(const M7MuxContext *ctx);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);
  int (*normalize)(const M7MuxIngress *ingress, M7MuxNormalizedPacket *out);
} M7MuxNormalizeLib;

const M7MuxNormalizeLib *get_protocol_udp_m7mux_normalize_lib(void);

#endif
