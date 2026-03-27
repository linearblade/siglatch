/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "codec.h"

#include "../../../../shared/shared.h"

int app_payload_codec_init(void) {
  return shared.knock.codec.v1.init &&
         shared.knock.codec.v1.shutdown &&
         shared.knock.codec.v1.pack &&
         shared.knock.codec.v1.unpack &&
         shared.knock.codec.v1.validate &&
         shared.knock.codec.v1.deserialize &&
         shared.knock.codec.v1.deserialize_strerror;
}

void app_payload_codec_shutdown(void) {
}

int app_payload_codec_pack(
    const KnockPacket *pkt,
    uint8_t *out_buf,
    size_t maxlen) {
  return shared.knock.codec.v1.pack(pkt, out_buf, maxlen);
}

int app_payload_codec_unpack(
    const uint8_t *buf,
    size_t buflen,
    KnockPacket *pkt) {
  return shared.knock.codec.v1.unpack(buf, buflen, pkt);
}

int app_payload_codec_validate(const KnockPacket *pkt) {
  return shared.knock.codec.v1.validate(pkt);
}

int app_payload_codec_deserialize(
    const uint8_t *decrypted_buffer,
    size_t decrypted_len,
    KnockPacket *pkt) {
  return shared.knock.codec.v1.deserialize(decrypted_buffer, decrypted_len, pkt);
}

const char *app_payload_codec_deserialize_strerror(int code) {
  return shared.knock.codec.v1.deserialize_strerror(code);
}

static const AppPayloadCodecLib app_payload_codec_instance = {
  .init = app_payload_codec_init,
  .shutdown = app_payload_codec_shutdown,
  .pack = app_payload_codec_pack,
  .unpack = app_payload_codec_unpack,
  .validate = app_payload_codec_validate,
  .deserialize = app_payload_codec_deserialize,
  .deserialize_strerror = app_payload_codec_deserialize_strerror
};

const AppPayloadCodecLib *get_app_payload_codec_lib(void) {
  return &app_payload_codec_instance;
}
