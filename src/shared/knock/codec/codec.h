/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_H
#define SIGLATCH_SHARED_KNOCK_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "context.h"
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

typedef struct SharedCodecLib {
  SharedKnockCodecContextLib context;
  const M7MuxNormalizeAdapter *(*v1)(void);
  const M7MuxNormalizeAdapter *(*v2)(void);
  const M7MuxNormalizeAdapter *(*v3)(void);
} SharedCodecLib;

typedef SharedCodecLib SharedKnockCodecLib;

const SharedCodecLib *get_shared_knock_codec_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_H */
