/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "codec.h"

static const SharedCodecLib shared_knock_codec = {
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
  .v1 = shared_knock_codec_v1_get_adapter,
  .v2 = shared_knock_codec_v2_get_adapter,
  .v3 = shared_knock_codec_v3_get_adapter
};

const SharedCodecLib *get_shared_knock_codec_lib(void) {
  return &shared_knock_codec;
}
