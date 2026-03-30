/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_H
#define SIGLATCH_SHARED_KNOCK_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "../packet.h"
#include "context.h"
#include "normalized.h"
#include "v1/v1.h"
#include "v2/v2.h"
#include "v3/v3.h"

#define SHARED_KNOCK_CODEC_PACKET_MAX_SIZE \
  (SHARED_KNOCK_CODEC_V1_PACKET_SIZE > SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE ? \
   (SHARED_KNOCK_CODEC_V1_PACKET_SIZE > SHARED_KNOCK_CODEC_V3_FORM1_PACKET_MAX_SIZE ? \
    SHARED_KNOCK_CODEC_V1_PACKET_SIZE : \
    SHARED_KNOCK_CODEC_V3_FORM1_PACKET_MAX_SIZE) : \
   (SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE > SHARED_KNOCK_CODEC_V3_FORM1_PACKET_MAX_SIZE ? \
    SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE : \
    SHARED_KNOCK_CODEC_V3_FORM1_PACKET_MAX_SIZE))

typedef struct {
  SharedKnockCodecContextLib context;
  SharedKnockCodecV1Lib v1;
  SharedKnockCodecV2Lib v2;
  SharedKnockCodecV3Lib v3;
  int (*encode)(const SharedKnockNormalizedUnit *normal, uint8_t *out_buf, size_t *out_len);
} SharedKnockCodecLib;

int shared_knock_codec_encode(const SharedKnockNormalizedUnit *normal,
                               uint8_t *out_buf,
                               size_t *out_len);
const SharedKnockCodecLib *get_shared_knock_codec_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_H */
