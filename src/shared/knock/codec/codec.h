/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_H
#define SIGLATCH_SHARED_KNOCK_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "context.h"
#include "normalized.h"
#include "v1/v1.h"
#include "v2/v2.h"
#include "v3/v3.h"
#include "v4/v4.h"
#include "../../../stdlib/protocol/udp/m7mux/barrel.h"

#define SHARED_KNOCK_CODEC_PACKET_MAX_SIZE \
  (SHARED_KNOCK_CODEC_V1_PACKET_SIZE > SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE ? \
   (SHARED_KNOCK_CODEC_V1_PACKET_SIZE > SHARED_KNOCK_CODEC_V3_FORM1_PACKET_MAX_SIZE ? \
    (SHARED_KNOCK_CODEC_V1_PACKET_SIZE > SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE ? \
     SHARED_KNOCK_CODEC_V1_PACKET_SIZE : \
     SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE) : \
    (SHARED_KNOCK_CODEC_V3_FORM1_PACKET_MAX_SIZE > SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE ? \
     SHARED_KNOCK_CODEC_V3_FORM1_PACKET_MAX_SIZE : \
     SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE)) : \
   (SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE > SHARED_KNOCK_CODEC_V3_FORM1_PACKET_MAX_SIZE ? \
    (SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE > SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE ? \
     SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE : \
     SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE) : \
    (SHARED_KNOCK_CODEC_V3_FORM1_PACKET_MAX_SIZE > SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE ? \
     SHARED_KNOCK_CODEC_V3_FORM1_PACKET_MAX_SIZE : \
     SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE)))

typedef struct SharedCodecLib {
  SharedKnockCodecContextLib context;
  const M7MuxNormalizeAdapter *(*v1)(void);
  const M7MuxNormalizeAdapter *(*v2)(void);
  const M7MuxNormalizeAdapter *(*v3)(void);
  const M7MuxNormalizeAdapter *(*v4)(void);
  size_t (*v1_count_fragments)(const void *state,
                               const SharedKnockNormalizedUnit *normal,
                               size_t force_fragment_count);
  size_t (*v2_count_fragments)(const void *state,
                               const SharedKnockNormalizedUnit *normal,
                               size_t force_fragment_count);
  size_t (*v3_count_fragments)(const void *state,
                               const SharedKnockNormalizedUnit *normal,
                               size_t force_fragment_count);
  size_t (*v4_count_fragments)(const void *state,
                               const SharedKnockNormalizedUnit *normal,
                               size_t force_fragment_count);
  int (*v1_encode_fragment)(const void *state,
                            const SharedKnockNormalizedUnit *normal,
                            size_t fragment_index,
                            size_t force_fragment_count,
                            uint8_t *out_buf,
                            size_t *out_len);
  int (*v2_encode_fragment)(const void *state,
                            const SharedKnockNormalizedUnit *normal,
                            size_t fragment_index,
                            size_t force_fragment_count,
                            uint8_t *out_buf,
                            size_t *out_len);
  int (*v3_encode_fragment)(const void *state,
                            const SharedKnockNormalizedUnit *normal,
                            size_t fragment_index,
                            size_t force_fragment_count,
                            uint8_t *out_buf,
                            size_t *out_len);
  int (*v4_encode_fragment)(const void *state,
                            const SharedKnockNormalizedUnit *normal,
                            size_t fragment_index,
                            size_t force_fragment_count,
                            uint8_t *out_buf,
                            size_t *out_len);
} SharedCodecLib;

typedef SharedCodecLib SharedKnockCodecLib;

const SharedCodecLib *get_shared_knock_codec_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_H */
