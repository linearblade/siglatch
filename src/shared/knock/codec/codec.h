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
#include "../../../stdlib/protocol/udp/m7mux/barrel.h"

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
  SharedKnockCodecBarrel v1;
  SharedKnockCodecBarrel v2;
  SharedKnockCodecBarrel v3;
  const M7MuxNormalizeAdapter *v1_adapter;
  const M7MuxNormalizeAdapter *v2_adapter;
  const M7MuxNormalizeAdapter *v3_adapter;
  int (*encode)(const SharedKnockNormalizedUnit *normal, uint8_t *out_buf, size_t *out_len);
} SharedKnockCodecLib;

int shared_knock_codec_encode(const SharedKnockNormalizedUnit *normal,
                               uint8_t *out_buf,
                               size_t *out_len);
const SharedKnockCodecLib *get_shared_knock_codec_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_H */
