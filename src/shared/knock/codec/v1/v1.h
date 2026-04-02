/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_V1_H
#define SIGLATCH_SHARED_KNOCK_CODEC_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../../packet.h"
#include "../context.h"
#include "../normalized.h"
#include "../../../../stdlib/protocol/udp/m7mux/barrel.h"
#include "v1_packet.h"

typedef struct SharedKnockCodecV1State SharedKnockCodecV1State;
struct M7MuxIngress;
struct M7MuxNormalizeAdapter;
typedef struct M7MuxIngressIdentity M7MuxIngressIdentity;

#ifndef SL_PAYLOAD_OK
#define SL_PAYLOAD_OK 0
#define SL_PAYLOAD_ERR_NULL_PTR -1
#define SL_PAYLOAD_ERR_UNPACK -2
#define SL_PAYLOAD_ERR_VALIDATE -3
#define SL_PAYLOAD_ERR_OVERFLOW -4
#endif

int shared_knock_codec_v1_create_state(void **out_state);
void shared_knock_codec_v1_destroy_state(void *state);
M7MuxUserRecvData *shared_knock_codec_v1_alloc_user_recv_data(void);
void shared_knock_codec_v1_free_user_recv_data(M7MuxUserRecvData *user);
int shared_knock_codec_v1_init(const SharedKnockCodecContext *context);
void shared_knock_codec_v1_shutdown(void);
int shared_knock_codec_v1_detect(const void *state,
                                 const struct M7MuxIngress *ingress,
                                 M7MuxIngressIdentity *identity);
int shared_knock_codec_v1_decode(const void *state,
                                  const struct M7MuxIngress *ingress,
                                  SharedKnockNormalizedUnit *out);
int shared_knock_codec_v1_wire_auth(const void *state,
                                     const struct M7MuxIngress *ingress,
                                     SharedKnockNormalizedUnit *normal);
int shared_knock_codec_v1_encode(const void *state,
                                  const SharedKnockNormalizedUnit *normal,
                                  uint8_t *out_buf,
                                  size_t *out_len);
int shared_knock_codec_v1_pack(const void *pkt, uint8_t *out_buf, size_t maxlen);
int shared_knock_codec_v1_unpack(const uint8_t *buf, size_t buflen, void *pkt);
int shared_knock_codec_v1_validate(const void *pkt);
int shared_knock_codec_v1_deserialize(const uint8_t *decrypted_buffer,
                                      size_t decrypted_len,
                                      void *pkt);
const char *shared_knock_codec_v1_deserialize_strerror(int code);
const struct M7MuxNormalizeAdapter *shared_knock_codec_v1_get_adapter(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_V1_H */
