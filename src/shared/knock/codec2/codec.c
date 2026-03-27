/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "codec.h"

int shared_knock_codec2_encode(const SharedKnockNormalizedUnit *normal,
                               uint8_t *out_buf,
                               size_t *out_len) {
  const SharedKnockCodec2Lib *codec2 = get_shared_knock_codec2_lib();

  if (!normal || !out_buf || !out_len) {
    return 0;
  }

  if (normal->wire_version == SHARED_KNOCK_V2_WIRE_VERSION) {
    /*
     * Temporary compatibility path: outbound v2 packets still serialize
     * through the v1 wire codec until the real v2 encode path is ready.
     */
    return codec2->v1.encode(NULL, normal, out_buf, out_len);
  }

  if (!codec2 || !codec2->v1.encode) {
    return 0;
  }

  return codec2->v1.encode(NULL, normal, out_buf, out_len);
}

static const SharedKnockCodec2Lib shared_knock_codec2 = {
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
    .init = shared_knock_codec2_v1_init,
    .shutdown = shared_knock_codec2_v1_shutdown,
    .create_state = shared_knock_codec2_v1_create_state,
    .destroy_state = shared_knock_codec2_v1_destroy_state,
    .detect = shared_knock_codec2_v1_detect,
    .decode = shared_knock_codec2_v1_decode,
    .encode = shared_knock_codec2_v1_encode
  },
  .v2 = {
    .name = "v2",
    .init = shared_knock_codec2_v2_init,
    .shutdown = shared_knock_codec2_v2_shutdown,
    .create_state = shared_knock_codec2_v2_create_state,
    .destroy_state = shared_knock_codec2_v2_destroy_state,
    .detect = shared_knock_codec2_v2_detect,
    .decode = shared_knock_codec2_v2_decode,
    .encode = shared_knock_codec2_v2_encode
  },
  .encode = shared_knock_codec2_encode
};

const SharedKnockCodec2Lib *get_shared_knock_codec2_lib(void) {
  return &shared_knock_codec2;
}
