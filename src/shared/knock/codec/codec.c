/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "codec.h"

static const SharedKnockCodecLib shared_knock_codec = {
  .v1 = {
    .init = shared_knock_v1_codec_init,
    .shutdown = shared_knock_v1_codec_shutdown,
    .pack = shared_knock_v1_codec_pack,
    .unpack = shared_knock_v1_codec_unpack,
    .validate = shared_knock_v1_codec_validate,
    .deserialize = shared_knock_v1_codec_deserialize,
    .normalize = shared_knock_v1_codec_normalize,
    .deserialize_strerror = shared_knock_v1_codec_deserialize_strerror
  },
  .v2 = {
    .init = shared_knock_v2_form1_codec_init,
    .shutdown = shared_knock_v2_form1_codec_shutdown,
    .pack = shared_knock_v2_form1_codec_pack,
    .unpack = shared_knock_v2_form1_codec_unpack,
    .validate = shared_knock_v2_form1_codec_validate,
    .deserialize = shared_knock_v2_form1_codec_deserialize,
    .normalize = shared_knock_v2_form1_codec_normalize,
    .deserialize_strerror = shared_knock_v2_form1_codec_deserialize_strerror
  }
};

const SharedKnockCodecLib *get_shared_knock_codec_lib(void) {
  return &shared_knock_codec;
}
