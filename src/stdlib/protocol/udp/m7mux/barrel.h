/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_BARREL_H
#define LIB_PROTOCOL_UDP_M7MUX_BARREL_H

#include <stddef.h>
#include <stdint.h>

typedef struct SharedKnockCodecContext SharedKnockCodecContext;
typedef struct M7MuxIngress M7MuxIngress;
typedef struct M7MuxIngressIdentity M7MuxIngressIdentity;
typedef struct M7MuxControl M7MuxControl;
typedef struct M7MuxNormalizeAdapter M7MuxNormalizeAdapter;
typedef struct M7MuxUserSendData M7MuxUserSendData;
typedef struct M7MuxUserRecvData M7MuxUserRecvData;
typedef struct M7MuxSendPacket M7MuxSendPacket;
typedef struct M7MuxEgressData M7MuxEgressData;

typedef struct SharedKnockCodecBarrel {
  const char *name;
  uint32_t wire_version;
  int (*init)(const SharedKnockCodecContext *context);
  void (*shutdown)(void);
  int (*create_state)(void **out_state);
  void (*destroy_state)(void *state);
  M7MuxUserRecvData *(*alloc_user_recv_data)(void);
  void (*free_user_recv_data)(M7MuxUserRecvData *user);
  int (*detect)(const void *state,
                const M7MuxIngress *ingress,
                M7MuxIngressIdentity *identity);
  int (*decode)(const void *state,
                const M7MuxIngress *ingress,
                M7MuxControl *control,
                M7MuxUserRecvData *out);
  int (*wire_auth)(const void *state,
                   const M7MuxIngress *ingress,
                   M7MuxUserRecvData *normal);
  int (*encode)(const void *state,
                const M7MuxUserSendData *normal,
                uint8_t *out_buf,
                size_t *out_len);
  int (*pack)(const void *pkt, uint8_t *out_buf, size_t maxlen);
  int (*unpack)(const uint8_t *buf, size_t buflen, void *pkt);
  int (*validate)(const void *pkt);
  int (*deserialize)(const uint8_t *decrypted_buffer, size_t decrypted_len, void *pkt);
  const char *(*deserialize_strerror)(int code);
} SharedKnockCodecBarrel;

#endif /* LIB_PROTOCOL_UDP_M7MUX_BARREL_H */
