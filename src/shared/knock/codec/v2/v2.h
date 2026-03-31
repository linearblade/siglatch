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
struct M7MuxIngress;
struct M7MuxNormalizeAdapter;
typedef struct M7MuxIngressIdentity M7MuxIngressIdentity;

typedef struct {
  const char *name;
  uint32_t wire_version;
  int (*init)(const SharedKnockCodecContext *context);
  void (*shutdown)(void);
  int (*create_state)(SharedKnockCodecV2State **out_state);
  void (*destroy_state)(SharedKnockCodecV2State *state);
  int (*detect)(const SharedKnockCodecV2State *state,
                const struct M7MuxIngress *ingress,
                M7MuxIngressIdentity *identity);
  int (*decode)(const SharedKnockCodecV2State *state,
                const struct M7MuxIngress *ingress,
                SharedKnockNormalizedUnit *out);
  int (*wire_auth)(const SharedKnockCodecV2State *state,
                   const struct M7MuxIngress *ingress,
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
                                 const struct M7MuxIngress *ingress,
                                 M7MuxIngressIdentity *identity);
int shared_knock_codec_v2_decode(const SharedKnockCodecV2State *state,
                                  const struct M7MuxIngress *ingress,
                                  SharedKnockNormalizedUnit *out);
int shared_knock_codec_v2_wire_auth(const SharedKnockCodecV2State *state,
                                     const struct M7MuxIngress *ingress,
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
const struct M7MuxNormalizeAdapter *shared_knock_codec_v2_get_adapter(void);
const SharedKnockCodecV2Lib *get_shared_knock_codec_v2_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_V2_H */
