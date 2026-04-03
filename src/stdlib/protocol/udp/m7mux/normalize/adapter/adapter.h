/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_NORMALIZE_ADAPTER_H
#define LIB_PROTOCOL_UDP_M7MUX_NORMALIZE_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include "../../m7mux.h"

typedef struct M7MuxIngress M7MuxIngress;
typedef struct M7MuxIngressIdentity M7MuxIngressIdentity;
typedef struct M7MuxControl M7MuxControl;
typedef struct M7MuxUserSendData M7MuxUserSendData;
typedef struct M7MuxUserRecvData M7MuxUserRecvData;
typedef struct M7MuxRecvPacket M7MuxRecvPacket;
typedef struct M7MuxSendPacket M7MuxSendPacket;
typedef struct M7MuxEgressData M7MuxEgressData;

typedef struct M7MuxNormalizeAdapter {
  const char *name;
  uint32_t wire_version;
  int (*create_state)(void **out_state);
  void (*destroy_state)(void *state);
  M7MuxUserRecvData *(*alloc_user_recv_data)(void);
  void (*free_user_recv_data)(M7MuxUserRecvData *user);
  int (*copy_user_recv_data)(M7MuxUserRecvData *dst, const M7MuxUserRecvData *src);
  size_t (*count_fragments)(const M7MuxContext *ctx,
                            const void *state,
                            const M7MuxSendPacket *send);
  int (*detect)(const M7MuxContext *ctx,
                const void *state,
                const M7MuxIngress *ingress,
                M7MuxIngressIdentity *identity);
  int (*decode)(const M7MuxContext *ctx,
                const void *state,
                const M7MuxIngress *ingress,
                M7MuxControl *control,
                M7MuxRecvPacket *out);
  int (*encode)(const M7MuxContext *ctx,
                const void *state,
                const M7MuxSendPacket *send,
                M7MuxEgressData *out);
  int (*encode_fragment)(const M7MuxContext *ctx,
                         const void *state,
                         const M7MuxSendPacket *send,
                         size_t fragment_index,
                         size_t fragment_count,
                         M7MuxEgressData *out);
  void *state;
  void *reserved;
} M7MuxNormalizeAdapter;

typedef struct {
  int (*init)(void);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);
  int (*register_adapter)(const M7MuxNormalizeAdapter *adapter);
  int (*unregister_adapter)(const char *name);
  const M7MuxNormalizeAdapter *(*lookup_adapter)(const char *name);
  const M7MuxNormalizeAdapter *(*lookup_adapter_wire_version)(uint32_t wire_version);
  const M7MuxNormalizeAdapter *(*demux)(const M7MuxContext *ctx,
                                        const M7MuxIngress *ingress,
                                        M7MuxIngressIdentity *identity);
  int (*decode)(const M7MuxContext *ctx,
                const M7MuxNormalizeAdapter *adapter,
                const M7MuxIngress *ingress,
                M7MuxControl *control,
                M7MuxRecvPacket *out);
  int (*encode)(const M7MuxContext *ctx,
                const M7MuxNormalizeAdapter *adapter,
                const M7MuxSendPacket *send,
                M7MuxEgressData *out);
  size_t (*count)(void);
} M7MuxNormalizeAdapterLib;

int m7mux_normalize_adapter_fill_egress(const M7MuxSendPacket *src,
                                        const uint8_t *payload,
                                        size_t payload_len,
                                        M7MuxEgressData *dst);

const M7MuxNormalizeAdapterLib *get_protocol_udp_m7mux_normalize_adapter_lib(void);

#endif
