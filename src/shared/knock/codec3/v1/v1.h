/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC3_V1_H
#define SIGLATCH_SHARED_KNOCK_CODEC3_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../context.h"
#include "../normalized.h"
#include "v1_packet.h"

typedef struct SharedKnockCodec3V1State SharedKnockCodec3V1State;

typedef struct {
  const char *name;
  int (*init)(const SharedKnockCodec3Context *context);
  void (*shutdown)(void);
  int (*create_state)(SharedKnockCodec3V1State **out_state);
  void (*destroy_state)(SharedKnockCodec3V1State *state);
  int (*detect)(const SharedKnockCodec3V1State *state, const uint8_t *buf, size_t buflen);
  int (*decode)(const SharedKnockCodec3V1State *state,
                const uint8_t *buf,
                size_t buflen,
                const char *ip,
                uint16_t client_port,
                int encrypted,
                SharedKnockNormalizedUnit *out);
  int (*wire_auth)(const SharedKnockCodec3V1State *state,
                   const uint8_t *buf,
                   size_t buflen,
                   const char *ip,
                   uint16_t client_port,
                   int encrypted,
                   SharedKnockNormalizedUnit *normal);
  int (*encode)(const SharedKnockCodec3V1State *state,
                const SharedKnockNormalizedUnit *normal,
                uint8_t *out_buf,
                size_t *out_len);
} SharedKnockCodec3V1Lib;

#ifndef SL_PAYLOAD_OK
#define SL_PAYLOAD_OK 0
#define SL_PAYLOAD_ERR_NULL_PTR -1
#define SL_PAYLOAD_ERR_UNPACK -2
#define SL_PAYLOAD_ERR_VALIDATE -3
#define SL_PAYLOAD_ERR_OVERFLOW -4
#endif

int shared_knock_codec3_v1_create_state(SharedKnockCodec3V1State **out_state);
void shared_knock_codec3_v1_destroy_state(SharedKnockCodec3V1State *state);
int shared_knock_codec3_v1_init(const SharedKnockCodec3Context *context);
void shared_knock_codec3_v1_shutdown(void);
int shared_knock_codec3_v1_detect(const SharedKnockCodec3V1State *state,
                                 const uint8_t *buf,
                                 size_t buflen);
int shared_knock_codec3_v1_decode(const SharedKnockCodec3V1State *state,
                                  const uint8_t *buf,
                                  size_t buflen,
                                  const char *ip,
                                  uint16_t client_port,
                                  int encrypted,
                                  SharedKnockNormalizedUnit *out);
int shared_knock_codec3_v1_wire_auth(const SharedKnockCodec3V1State *state,
                                     const uint8_t *buf,
                                     size_t buflen,
                                     const char *ip,
                                     uint16_t client_port,
                                     int encrypted,
                                     SharedKnockNormalizedUnit *normal);
int shared_knock_codec3_v1_encode(const SharedKnockCodec3V1State *state,
                                  const SharedKnockNormalizedUnit *normal,
                                  uint8_t *out_buf,
                                  size_t *out_len);
const SharedKnockCodec3V1Lib *get_shared_knock_codec3_v1_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC3_V1_H */
