/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_V2_FORM1_H
#define SIGLATCH_SHARED_KNOCK_V2_FORM1_H

#include <stdint.h>

#define SHARED_KNOCK_FAMILY_MAGIC      0x534C504Bu /* "SLPK" */
#define SHARED_KNOCK_V2_WIRE_VERSION   0x00020000u
#define SHARED_KNOCK_FORM1_ID          0x01u

#define SHARED_KNOCK_V2_FORM1_PACKET_SIZE  245u
#define SHARED_KNOCK_V2_FORM1_OUTER_SIZE   9u
#define SHARED_KNOCK_V2_FORM1_INNER_SIZE   45u
#define SHARED_KNOCK_V2_FORM1_PAYLOAD_MAX  191u

typedef struct {
  uint32_t magic;
  uint32_t version;
  uint8_t form;
} KnockPacketV2Form1Outer;

typedef struct {
  uint32_t timestamp;
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint8_t hmac[32];
  uint16_t payload_len;
} KnockPacketV2Form1Inner;

typedef struct {
  KnockPacketV2Form1Outer outer;
  KnockPacketV2Form1Inner inner;
  uint8_t payload[SHARED_KNOCK_V2_FORM1_PAYLOAD_MAX];
} KnockPacketV2Form1;

#endif /* SIGLATCH_SHARED_KNOCK_V2_FORM1_H */
