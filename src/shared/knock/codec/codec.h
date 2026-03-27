/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_H
#define SIGLATCH_SHARED_KNOCK_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "normalized.h"
#include "v1/v1.h"
#include "v2/v2.h"

typedef SharedKnockV1CodecLib SharedKnockCodecV1Lib;
typedef SharedKnockV2Form1CodecLib SharedKnockCodecV2Lib;

typedef struct {
  SharedKnockCodecV1Lib v1;
  SharedKnockCodecV2Lib v2;
} SharedKnockCodecLib;

const SharedKnockCodecLib *get_shared_knock_codec_lib(void);

#endif
