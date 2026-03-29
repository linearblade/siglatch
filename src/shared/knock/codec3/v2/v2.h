/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC3_V2_H
#define SIGLATCH_SHARED_KNOCK_CODEC3_V2_H

#include <stddef.h>
#include <stdint.h>

#include "../context.h"
#include "../normalized.h"
#include "v2_form1.h"

typedef struct SharedKnockCodec3V2State SharedKnockCodec3V2State;

typedef struct {
  const char *name;
  int (*init)(const SharedKnockCodec3Context *context);
  void (*shutdown)(void);
  int (*create_state)(SharedKnockCodec3V2State **out_state);
  void (*destroy_state)(SharedKnockCodec3V2State *state);
  int (*detect)(const SharedKnockCodec3V2State *state, const uint8_t *buf, size_t buflen);
  int (*decode)(const SharedKnockCodec3V2State *state,
                const uint8_t *buf,
                size_t buflen,
                const char *ip,
                uint16_t client_port,
                int encrypted,
                SharedKnockNormalizedUnit *out);
  int (*wire_auth)(const SharedKnockCodec3V2State *state,
                   const uint8_t *buf,
                   size_t buflen,
                   const char *ip,
                   uint16_t client_port,
                   int encrypted,
                   SharedKnockNormalizedUnit *normal);
  int (*encode)(const SharedKnockCodec3V2State *state,
                const SharedKnockNormalizedUnit *normal,
                uint8_t *out_buf,
                size_t *out_len);
} SharedKnockCodec3V2Lib;

#ifndef SL_PAYLOAD_OK
#define SL_PAYLOAD_OK 0
#define SL_PAYLOAD_ERR_NULL_PTR -1
#define SL_PAYLOAD_ERR_UNPACK -2
#define SL_PAYLOAD_ERR_VALIDATE -3
#define SL_PAYLOAD_ERR_OVERFLOW -4
#endif

int shared_knock_codec3_v2_create_state(SharedKnockCodec3V2State **out_state);
void shared_knock_codec3_v2_destroy_state(SharedKnockCodec3V2State *state);
int shared_knock_codec3_v2_init(const SharedKnockCodec3Context *context);
void shared_knock_codec3_v2_shutdown(void);
int shared_knock_codec3_v2_detect(const SharedKnockCodec3V2State *state,
                                 const uint8_t *buf,
                                 size_t buflen);
int shared_knock_codec3_v2_decode(const SharedKnockCodec3V2State *state,
                                  const uint8_t *buf,
                                  size_t buflen,
                                  const char *ip,
                                  uint16_t client_port,
                                  int encrypted,
                                  SharedKnockNormalizedUnit *out);
int shared_knock_codec3_v2_wire_auth(const SharedKnockCodec3V2State *state,
                                     const uint8_t *buf,
                                     size_t buflen,
                                     const char *ip,
                                     uint16_t client_port,
                                     int encrypted,
                                     SharedKnockNormalizedUnit *normal);
int shared_knock_codec3_v2_encode(const SharedKnockCodec3V2State *state,
                                  const SharedKnockNormalizedUnit *normal,
                                  uint8_t *out_buf,
                                  size_t *out_len);
const SharedKnockCodec3V2Lib *get_shared_knock_codec3_v2_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC3_V2_H */
