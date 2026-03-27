/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC2_V2_H
#define SIGLATCH_SHARED_KNOCK_CODEC2_V2_H

#include <stddef.h>
#include <stdint.h>

#include "../context.h"
#include "../normalized.h"
#include "../../codec/v2/v2_form1.h"

typedef struct SharedKnockCodec2V2State SharedKnockCodec2V2State;

typedef struct {
  const char *name;
  int (*init)(const SharedKnockCodecContext *context);
  void (*shutdown)(void);
  int (*create_state)(SharedKnockCodec2V2State **out_state);
  void (*destroy_state)(SharedKnockCodec2V2State *state);
  int (*detect)(const SharedKnockCodec2V2State *state, const uint8_t *buf, size_t buflen);
  int (*decode)(const SharedKnockCodec2V2State *state,
                const uint8_t *buf,
                size_t buflen,
                const char *ip,
                uint16_t client_port,
                int encrypted,
                SharedKnockNormalizedUnit *out);
  int (*encode)(const SharedKnockCodec2V2State *state,
                const SharedKnockNormalizedUnit *normal,
                uint8_t *out_buf,
                size_t *out_len);
} SharedKnockCodec2V2Lib;

int shared_knock_codec2_v2_create_state(SharedKnockCodec2V2State **out_state);
void shared_knock_codec2_v2_destroy_state(SharedKnockCodec2V2State *state);
int shared_knock_codec2_v2_init(const SharedKnockCodecContext *context);
void shared_knock_codec2_v2_shutdown(void);
int shared_knock_codec2_v2_detect(const SharedKnockCodec2V2State *state,
                                 const uint8_t *buf,
                                 size_t buflen);
int shared_knock_codec2_v2_decode(const SharedKnockCodec2V2State *state,
                                  const uint8_t *buf,
                                  size_t buflen,
                                  const char *ip,
                                  uint16_t client_port,
                                  int encrypted,
                                  SharedKnockNormalizedUnit *out);
int shared_knock_codec2_v2_encode(const SharedKnockCodec2V2State *state,
                                  const SharedKnockNormalizedUnit *normal,
                                  uint8_t *out_buf,
                                  size_t *out_len);
const SharedKnockCodec2V2Lib *get_shared_knock_codec2_v2_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC2_V2_H */
