/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_PACKET_H
#define SIGLATCH_SHARED_KNOCK_PACKET_H

#include <stdint.h>

typedef struct __attribute__((packed)) {
  uint8_t version;
  uint32_t timestamp;
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint8_t hmac[32];
  uint16_t payload_len;
  uint8_t payload[199];
} KnockPacket;

#endif
