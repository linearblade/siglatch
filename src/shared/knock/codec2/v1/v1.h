/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC2_V1_H
#define SIGLATCH_SHARED_KNOCK_CODEC2_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../context.h"
#include "../normalized.h"
#include "../../codec/v1/v1_packet.h"

typedef struct SharedKnockCodec2V1State SharedKnockCodec2V1State;

typedef struct {
  const char *name;
  int (*init)(const SharedKnockCodecContext *context);
  void (*shutdown)(void);
  int (*create_state)(SharedKnockCodec2V1State **out_state);
  void (*destroy_state)(SharedKnockCodec2V1State *state);
  int (*detect)(const SharedKnockCodec2V1State *state, const uint8_t *buf, size_t buflen);
  int (*decode)(const SharedKnockCodec2V1State *state,
                const uint8_t *buf,
                size_t buflen,
                const char *ip,
                uint16_t client_port,
                int encrypted,
                SharedKnockNormalizedUnit *out);
  int (*encode)(const SharedKnockCodec2V1State *state,
                const SharedKnockNormalizedUnit *normal,
                uint8_t *out_buf,
                size_t *out_len);
} SharedKnockCodec2V1Lib;

int shared_knock_codec2_v1_create_state(SharedKnockCodec2V1State **out_state);
void shared_knock_codec2_v1_destroy_state(SharedKnockCodec2V1State *state);
int shared_knock_codec2_v1_init(const SharedKnockCodecContext *context);
void shared_knock_codec2_v1_shutdown(void);
int shared_knock_codec2_v1_detect(const SharedKnockCodec2V1State *state,
                                 const uint8_t *buf,
                                 size_t buflen);
int shared_knock_codec2_v1_decode(const SharedKnockCodec2V1State *state,
                                  const uint8_t *buf,
                                  size_t buflen,
                                  const char *ip,
                                  uint16_t client_port,
                                  int encrypted,
                                  SharedKnockNormalizedUnit *out);
int shared_knock_codec2_v1_encode(const SharedKnockCodec2V1State *state,
                                  const SharedKnockNormalizedUnit *normal,
                                  uint8_t *out_buf,
                                  size_t *out_len);
const SharedKnockCodec2V1Lib *get_shared_knock_codec2_v1_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC2_V1_H */
