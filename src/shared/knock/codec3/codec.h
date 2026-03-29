/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC3_H
#define SIGLATCH_SHARED_KNOCK_CODEC3_H

#include <stddef.h>
#include <stdint.h>

#include "context.h"
#include "normalized.h"
#include "v1/v1.h"
#include "v2/v2.h"

#define SHARED_KNOCK_CODEC3_PACKET_MAX_SIZE \
  (SHARED_KNOCK_CODEC3_V1_PACKET_SIZE > SHARED_KNOCK_CODEC3_V2_FORM1_PACKET_SIZE ? \
   SHARED_KNOCK_CODEC3_V1_PACKET_SIZE : \
   SHARED_KNOCK_CODEC3_V2_FORM1_PACKET_SIZE)

typedef struct {
  SharedKnockCodec3ContextLib context;
  SharedKnockCodec3V1Lib v1;
  SharedKnockCodec3V2Lib v2;
  int (*encode)(const SharedKnockNormalizedUnit *normal, uint8_t *out_buf, size_t *out_len);
} SharedKnockCodec3Lib;

int shared_knock_codec3_encode(const SharedKnockNormalizedUnit *normal,
                               uint8_t *out_buf,
                               size_t *out_len);
const SharedKnockCodec3Lib *get_shared_knock_codec3_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC3_H */
