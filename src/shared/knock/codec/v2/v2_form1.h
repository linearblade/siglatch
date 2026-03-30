/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_V2_FORM1_H
#define SIGLATCH_SHARED_KNOCK_CODEC_V2_FORM1_H

#include <stdint.h>

#include "../../prefix.h"

#define SHARED_KNOCK_CODEC_V2_WIRE_VERSION   0x00020000u
#define SHARED_KNOCK_CODEC_FORM1_ID          0x01u

#define SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE  245u
#define SHARED_KNOCK_CODEC_V2_FORM1_OUTER_SIZE   SHARED_KNOCK_PREFIX_SIZE
#define SHARED_KNOCK_CODEC_V2_FORM1_INNER_SIZE   45u
#define SHARED_KNOCK_CODEC_V2_FORM1_PAYLOAD_MAX  191u

typedef SharedKnockPrefix SharedKnockCodecV2Form1Outer;

typedef struct {
  uint32_t timestamp;
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint8_t hmac[32];
  uint16_t payload_len;
} SharedKnockCodecV2Form1Inner;

typedef struct {
  SharedKnockCodecV2Form1Outer outer;
  SharedKnockCodecV2Form1Inner inner;
  uint8_t payload[SHARED_KNOCK_CODEC_V2_FORM1_PAYLOAD_MAX];
} SharedKnockCodecV2Form1Packet;

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_V2_FORM1_H */
