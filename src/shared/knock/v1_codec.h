/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_V1_CODEC_H
#define SIGLATCH_SHARED_KNOCK_V1_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "v1_packet.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*pack)(const KnockPacketV1 *pkt, uint8_t *out_buf, size_t maxlen);
  int (*unpack)(const uint8_t *buf, size_t buflen, KnockPacketV1 *pkt);
  int (*validate)(const KnockPacketV1 *pkt);
  int (*deserialize)(const uint8_t *buf, size_t buflen, KnockPacketV1 *pkt);
  const char *(*deserialize_strerror)(int code);
} SharedKnockV1CodecLib;

#ifndef SL_PAYLOAD_OK
#define SL_PAYLOAD_OK 0
#define SL_PAYLOAD_ERR_NULL_PTR -1
#define SL_PAYLOAD_ERR_UNPACK -2
#define SL_PAYLOAD_ERR_VALIDATE -3
#define SL_PAYLOAD_ERR_OVERFLOW -4
#endif

int shared_knock_v1_codec_init(void);
void shared_knock_v1_codec_shutdown(void);
int shared_knock_v1_codec_pack(const KnockPacketV1 *pkt, uint8_t *out_buf, size_t maxlen);
int shared_knock_v1_codec_unpack(const uint8_t *buf, size_t buflen, KnockPacketV1 *pkt);
int shared_knock_v1_codec_validate(const KnockPacketV1 *pkt);
int shared_knock_v1_codec_deserialize(const uint8_t *buf, size_t buflen, KnockPacketV1 *pkt);
const char *shared_knock_v1_codec_deserialize_strerror(int code);
const SharedKnockV1CodecLib *get_shared_knock_v1_codec_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_V1_CODEC_H */
