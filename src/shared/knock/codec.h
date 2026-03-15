/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_H
#define SIGLATCH_SHARED_KNOCK_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "packet.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*pack)(const KnockPacket *pkt, uint8_t *out_buf, size_t maxlen);
  int (*unpack)(const uint8_t *buf, size_t buflen, KnockPacket *pkt);
  int (*validate)(const KnockPacket *pkt);
  int (*deserialize)(const uint8_t *decrypted_buffer, size_t decrypted_len, KnockPacket *pkt);
  const char *(*deserialize_strerror)(int code);
} SharedKnockCodecLib;

#define SL_PAYLOAD_OK 0
#define SL_PAYLOAD_ERR_NULL_PTR -1
#define SL_PAYLOAD_ERR_UNPACK -2
#define SL_PAYLOAD_ERR_VALIDATE -3
#define SL_PAYLOAD_ERR_OVERFLOW -4

int shared_knock_codec_init(void);
void shared_knock_codec_shutdown(void);
int shared_knock_codec_pack(const KnockPacket *pkt, uint8_t *out_buf, size_t maxlen);
int shared_knock_codec_unpack(const uint8_t *buf, size_t buflen, KnockPacket *pkt);
int shared_knock_codec_validate(const KnockPacket *pkt);
int shared_knock_codec_deserialize(
    const uint8_t *decrypted_buffer,
    size_t decrypted_len,
    KnockPacket *pkt);
const char *shared_knock_codec_deserialize_strerror(int code);
const SharedKnockCodecLib *get_shared_knock_codec_lib(void);

#endif
