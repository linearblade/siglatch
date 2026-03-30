/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "codec.h"

int shared_knock_codec_encode(const SharedKnockNormalizedUnit *normal,
                               uint8_t *out_buf,
                               size_t *out_len) {
  const SharedKnockCodecLib *codec = get_shared_knock_codec_lib();

  if (!normal || !out_buf || !out_len) {
    return 0;
  }

  if (!codec) {
    return 0;
  }

  if (normal->wire_version == SHARED_KNOCK_CODEC_V2_WIRE_VERSION) {
    if (!codec->v2.encode) {
      return 0;
    }
    return codec->v2.encode(NULL, normal, out_buf, out_len);
  }

  if (normal->wire_version == SHARED_KNOCK_CODEC_V3_WIRE_VERSION) {
    if (!codec->v3.encode) {
      return 0;
    }
    return codec->v3.encode(NULL, normal, out_buf, out_len);
  }

  if (!codec->v1.encode) {
    return 0;
  }

  return codec->v1.encode(NULL, normal, out_buf, out_len);
}

static const SharedKnockCodecLib shared_knock_codec = {
  .context = {
    .init = shared_knock_codec_context_init,
    .shutdown = shared_knock_codec_context_shutdown,
    .create = shared_knock_codec_context_create,
    .destroy = shared_knock_codec_context_destroy,
    .set_server_key = shared_knock_codec_context_set_server_key,
    .clear_server_key = shared_knock_codec_context_clear_server_key,
    .set_openssl_session = shared_knock_codec_context_set_openssl_session,
    .clear_openssl_session = shared_knock_codec_context_clear_openssl_session,
    .add_keychain = shared_knock_codec_context_add_keychain,
    .remove_keychain = shared_knock_codec_context_remove_keychain
  },
  .v1 = {
    .name = "v1",
    .init = shared_knock_codec_v1_init,
    .shutdown = shared_knock_codec_v1_shutdown,
    .create_state = shared_knock_codec_v1_create_state,
    .destroy_state = shared_knock_codec_v1_destroy_state,
    .detect = shared_knock_codec_v1_detect,
    .decode = shared_knock_codec_v1_decode,
    .wire_auth = shared_knock_codec_v1_wire_auth,
    .encode = shared_knock_codec_v1_encode
    ,
    .pack = shared_knock_codec_v1_pack,
    .unpack = shared_knock_codec_v1_unpack,
    .validate = shared_knock_codec_v1_validate,
    .deserialize = shared_knock_codec_v1_deserialize,
    .deserialize_strerror = shared_knock_codec_v1_deserialize_strerror
  },
  .v2 = {
    .name = "v2",
    .init = shared_knock_codec_v2_init,
    .shutdown = shared_knock_codec_v2_shutdown,
    .create_state = shared_knock_codec_v2_create_state,
    .destroy_state = shared_knock_codec_v2_destroy_state,
    .detect = shared_knock_codec_v2_detect,
    .decode = shared_knock_codec_v2_decode,
    .wire_auth = shared_knock_codec_v2_wire_auth,
    .encode = shared_knock_codec_v2_encode
    ,
    .pack = shared_knock_codec_v2_pack,
    .unpack = shared_knock_codec_v2_unpack,
    .validate = shared_knock_codec_v2_validate,
    .deserialize = shared_knock_codec_v2_deserialize,
    .deserialize_strerror = shared_knock_codec_v2_deserialize_strerror
  },
  .v3 = {
    .name = "v3",
    .init = shared_knock_codec_v3_init,
    .shutdown = shared_knock_codec_v3_shutdown,
    .create_state = shared_knock_codec_v3_create_state,
    .destroy_state = shared_knock_codec_v3_destroy_state,
    .detect = shared_knock_codec_v3_detect,
    .decode = shared_knock_codec_v3_decode,
    .wire_auth = shared_knock_codec_v3_wire_auth,
    .encode = shared_knock_codec_v3_encode,
    .pack = shared_knock_codec_v3_pack,
    .unpack = shared_knock_codec_v3_unpack,
    .validate = shared_knock_codec_v3_validate,
    .deserialize = shared_knock_codec_v3_deserialize,
    .deserialize_strerror = shared_knock_codec_v3_deserialize_strerror
  },
  .encode = shared_knock_codec_encode
};

const SharedKnockCodecLib *get_shared_knock_codec_lib(void) {
  return &shared_knock_codec;
}
