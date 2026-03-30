/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_V2_H
#define SIGLATCH_SHARED_KNOCK_CODEC_V2_H

#include <stddef.h>
#include <stdint.h>

#include "../context.h"
#include "../normalized.h"
#include "v2_form1.h"

typedef struct SharedKnockCodecV2State SharedKnockCodecV2State;

typedef struct {
  const char *name;
  int (*init)(const SharedKnockCodecContext *context);
  void (*shutdown)(void);
  int (*create_state)(SharedKnockCodecV2State **out_state);
  void (*destroy_state)(SharedKnockCodecV2State *state);
  int (*detect)(const SharedKnockCodecV2State *state, const uint8_t *buf, size_t buflen);
  int (*decode)(const SharedKnockCodecV2State *state,
                const uint8_t *buf,
                size_t buflen,
                const char *ip,
                uint16_t client_port,
                int encrypted,
                SharedKnockNormalizedUnit *out);
  int (*wire_auth)(const SharedKnockCodecV2State *state,
                   const uint8_t *buf,
                   size_t buflen,
                   const char *ip,
                   uint16_t client_port,
                   int encrypted,
                   SharedKnockNormalizedUnit *normal);
  int (*encode)(const SharedKnockCodecV2State *state,
                const SharedKnockNormalizedUnit *normal,
                uint8_t *out_buf,
                size_t *out_len);
  int (*pack)(const SharedKnockCodecV2Form1Packet *pkt, uint8_t *out_buf, size_t maxlen);
  int (*unpack)(const uint8_t *buf, size_t buflen, SharedKnockCodecV2Form1Packet *pkt);
  int (*validate)(const SharedKnockCodecV2Form1Packet *pkt);
  int (*deserialize)(const uint8_t *decrypted_buffer,
                      size_t decrypted_len,
                      SharedKnockCodecV2Form1Packet *pkt);
  const char *(*deserialize_strerror)(int code);
} SharedKnockCodecV2Lib;

#ifndef SL_PAYLOAD_OK
#define SL_PAYLOAD_OK 0
#define SL_PAYLOAD_ERR_NULL_PTR -1
#define SL_PAYLOAD_ERR_UNPACK -2
#define SL_PAYLOAD_ERR_VALIDATE -3
#define SL_PAYLOAD_ERR_OVERFLOW -4
#endif

int shared_knock_codec_v2_create_state(SharedKnockCodecV2State **out_state);
void shared_knock_codec_v2_destroy_state(SharedKnockCodecV2State *state);
int shared_knock_codec_v2_init(const SharedKnockCodecContext *context);
void shared_knock_codec_v2_shutdown(void);
int shared_knock_codec_v2_detect(const SharedKnockCodecV2State *state,
                                 const uint8_t *buf,
                                 size_t buflen);
int shared_knock_codec_v2_decode(const SharedKnockCodecV2State *state,
                                  const uint8_t *buf,
                                  size_t buflen,
                                  const char *ip,
                                  uint16_t client_port,
                                  int encrypted,
                                  SharedKnockNormalizedUnit *out);
int shared_knock_codec_v2_wire_auth(const SharedKnockCodecV2State *state,
                                     const uint8_t *buf,
                                     size_t buflen,
                                     const char *ip,
                                     uint16_t client_port,
                                     int encrypted,
                                     SharedKnockNormalizedUnit *normal);
int shared_knock_codec_v2_encode(const SharedKnockCodecV2State *state,
                                  const SharedKnockNormalizedUnit *normal,
                                  uint8_t *out_buf,
                                  size_t *out_len);
int shared_knock_codec_v2_pack(const SharedKnockCodecV2Form1Packet *pkt, uint8_t *out_buf, size_t maxlen);
int shared_knock_codec_v2_unpack(const uint8_t *buf, size_t buflen, SharedKnockCodecV2Form1Packet *pkt);
int shared_knock_codec_v2_validate(const SharedKnockCodecV2Form1Packet *pkt);
int shared_knock_codec_v2_deserialize(const uint8_t *decrypted_buffer,
                                      size_t decrypted_len,
                                      SharedKnockCodecV2Form1Packet *pkt);
const char *shared_knock_codec_v2_deserialize_strerror(int code);
const SharedKnockCodecV2Lib *get_shared_knock_codec_v2_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_V2_H */
