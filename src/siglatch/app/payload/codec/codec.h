/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_PAYLOAD_CODEC_H
#define SIGLATCH_SERVER_APP_PAYLOAD_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "../../../../shared/knock/codec.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*pack)(const KnockPacket *pkt, uint8_t *out_buf, size_t maxlen);
  int (*unpack)(const uint8_t *buf, size_t buflen, KnockPacket *pkt);
  int (*validate)(const KnockPacket *pkt);
  int (*deserialize)(const uint8_t *decrypted_buffer, size_t decrypted_len, KnockPacket *pkt);
  const char *(*deserialize_strerror)(int code);
} AppPayloadCodecLib;

int app_payload_codec_init(void);
void app_payload_codec_shutdown(void);
int app_payload_codec_pack(const KnockPacket *pkt, uint8_t *out_buf, size_t maxlen);
int app_payload_codec_unpack(const uint8_t *buf, size_t buflen, KnockPacket *pkt);
int app_payload_codec_validate(const KnockPacket *pkt);
int app_payload_codec_deserialize(
    const uint8_t *decrypted_buffer,
    size_t decrypted_len,
    KnockPacket *pkt);
const char *app_payload_codec_deserialize_strerror(int code);
const AppPayloadCodecLib *get_app_payload_codec_lib(void);

#endif
