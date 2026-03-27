/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_V2_H
#define SIGLATCH_SHARED_KNOCK_CODEC_V2_H

#include <stddef.h>
#include <stdint.h>

#include "../normalized.h"
#include "v2_form1.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*pack)(const KnockPacketV2Form1 *pkt, uint8_t *out_buf, size_t maxlen);
  int (*unpack)(const uint8_t *buf, size_t buflen, KnockPacketV2Form1 *pkt);
  int (*validate)(const KnockPacketV2Form1 *pkt);
  int (*deserialize)(const uint8_t *buf, size_t buflen, KnockPacketV2Form1 *pkt);
  int (*normalize)(const uint8_t *buf,
                   size_t buflen,
                   const char *ip,
                   uint16_t client_port,
                   int encrypted,
                   SharedKnockNormalizedUnit *out);
  const char *(*deserialize_strerror)(int code);
} SharedKnockV2Form1CodecLib;

#ifndef SL_PAYLOAD_OK
#define SL_PAYLOAD_OK 0
#define SL_PAYLOAD_ERR_NULL_PTR -1
#define SL_PAYLOAD_ERR_UNPACK -2
#define SL_PAYLOAD_ERR_VALIDATE -3
#define SL_PAYLOAD_ERR_OVERFLOW -4
#endif

int shared_knock_v2_form1_codec_init(void);
void shared_knock_v2_form1_codec_shutdown(void);
int shared_knock_v2_form1_codec_pack(const KnockPacketV2Form1 *pkt, uint8_t *out_buf, size_t maxlen);
int shared_knock_v2_form1_codec_unpack(const uint8_t *buf, size_t buflen, KnockPacketV2Form1 *pkt);
int shared_knock_v2_form1_codec_validate(const KnockPacketV2Form1 *pkt);
int shared_knock_v2_form1_codec_deserialize(const uint8_t *buf, size_t buflen, KnockPacketV2Form1 *pkt);
int shared_knock_v2_form1_codec_normalize(const uint8_t *buf,
                                          size_t buflen,
                                          const char *ip,
                                          uint16_t client_port,
                                          int encrypted,
                                          SharedKnockNormalizedUnit *out);
const char *shared_knock_v2_form1_codec_deserialize_strerror(int code);
const SharedKnockV2Form1CodecLib *get_shared_knock_v2_form1_codec_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_V2_H */
