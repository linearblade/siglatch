/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_NORMALIZED_H
#define SIGLATCH_SHARED_KNOCK_CODEC_NORMALIZED_H

#include <stddef.h>
#include <stdint.h>

#define SHARED_KNOCK_NORMALIZED_PAYLOAD_MAX 1024u

typedef struct {
  int complete;
  uint32_t wire_version;
  uint8_t wire_form;
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
  int wire_decode;
  int wire_auth;
  uint8_t payload[SHARED_KNOCK_NORMALIZED_PAYLOAD_MAX];
  size_t payload_len;
} SharedKnockNormalizedUnit;

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_NORMALIZED_H */
