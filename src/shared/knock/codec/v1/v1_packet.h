/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_V1_PACKET_H
#define SIGLATCH_SHARED_KNOCK_CODEC_V1_PACKET_H

#include <stdint.h>

#define SHARED_KNOCK_CODEC_V1_VERSION     1u
#define SHARED_KNOCK_CODEC_V1_PAYLOAD_MAX 199u
#define SHARED_KNOCK_CODEC_V1_PACKET_SIZE 245u

typedef struct __attribute__((packed)) {
  uint8_t version;
  uint32_t timestamp;
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint8_t hmac[32];
  uint16_t payload_len;
  uint8_t payload[SHARED_KNOCK_CODEC_V1_PAYLOAD_MAX];
} SharedKnockCodecV1Packet;

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_V1_PACKET_H */
