/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_V4_FORM1_H
#define SIGLATCH_SHARED_KNOCK_CODEC_V4_FORM1_H

#include <stdint.h>

#include "../../prefix.h"
#include "v4_inner.h"

#define SHARED_KNOCK_CODEC_V4_WIRE_VERSION      0x00040000u
#define SHARED_KNOCK_CODEC_FORM1_ID             0x01u

#define SHARED_KNOCK_CODEC_V4_FORM1_TAG_SIZE    16u
#define SHARED_KNOCK_CODEC_V4_FORM1_CEK_SIZE    32u
#define SHARED_KNOCK_CODEC_V4_FORM1_CEK_MAX     256u
#define SHARED_KNOCK_CODEC_V4_FORM1_PAYLOAD_MAX 512u
#define SHARED_KNOCK_CODEC_V4_FORM1_INNER_SIZE   SIGLATCH_V4_INNER_ENVELOPE_WIRE_SIZE
#define SHARED_KNOCK_CODEC_V4_FORM1_BODY_FIXED_SIZE \
  (SHARED_KNOCK_CODEC_V4_FORM1_INNER_SIZE + 47u)
#define SHARED_KNOCK_CODEC_V4_FORM1_BODY_MAX \
  (SHARED_KNOCK_CODEC_V4_FORM1_BODY_FIXED_SIZE + SHARED_KNOCK_CODEC_V4_FORM1_PAYLOAD_MAX)
#define SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE \
  (SHARED_KNOCK_PREFIX_SIZE + 2u + 12u + 4u)
#define SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE \
  (SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE + \
   SHARED_KNOCK_CODEC_V4_FORM1_CEK_MAX + \
   SHARED_KNOCK_CODEC_V4_FORM1_BODY_MAX + \
   SHARED_KNOCK_CODEC_V4_FORM1_TAG_SIZE)

typedef SharedKnockPrefix SharedKnockCodecV4Form1Outer;

typedef struct {
  /* Implemented but inert for now; reserved for Siglatch-specific multi-packet flow. */
  SiglatchV4InnerEnvelope inner;
  uint32_t timestamp;
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint32_t payload_len;
  uint8_t hmac[32];
  uint8_t payload[SHARED_KNOCK_CODEC_V4_FORM1_PAYLOAD_MAX];
} SharedKnockCodecV4Form1Plaintext;

typedef struct {
  SharedKnockCodecV4Form1Outer outer;
  uint16_t wrapped_cek_len;
  uint8_t nonce[12];
  uint32_t ciphertext_len;
  uint8_t wrapped_cek[SHARED_KNOCK_CODEC_V4_FORM1_CEK_MAX];
  uint8_t ciphertext[SHARED_KNOCK_CODEC_V4_FORM1_BODY_MAX];
  uint8_t tag[SHARED_KNOCK_CODEC_V4_FORM1_TAG_SIZE];
} SharedKnockCodecV4Form1Packet;

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_V4_FORM1_H */
