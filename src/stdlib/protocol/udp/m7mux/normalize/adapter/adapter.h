/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_NORMALIZE_ADAPTER_H
#define LIB_PROTOCOL_UDP_M7MUX_NORMALIZE_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include "../../m7mux.h"
#include "../../../../../../shared/knock/codec/normalized.h"

typedef struct M7MuxIngress M7MuxIngress;
typedef struct M7MuxIngressIdentity M7MuxIngressIdentity;
typedef struct M7MuxRecvPacket M7MuxRecvPacket;
typedef struct M7MuxSendPacket M7MuxSendPacket;
typedef struct M7MuxEgressData M7MuxEgressData;

typedef struct M7MuxNormalizeAdapter {
  const char *name;
  uint32_t wire_version;
  int (*create_state)(void **out_state);
  void (*destroy_state)(void *state);
  int (*detect)(const M7MuxContext *ctx,
                const void *state,
                const M7MuxIngress *ingress,
                M7MuxIngressIdentity *identity);
  int (*decode)(const M7MuxContext *ctx,
                const void *state,
                const M7MuxIngress *ingress,
                M7MuxRecvPacket *out);
  int (*encode)(const M7MuxContext *ctx,
                const void *state,
                const M7MuxSendPacket *send,
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
                M7MuxRecvPacket *out);
  int (*encode)(const M7MuxContext *ctx,
                const M7MuxNormalizeAdapter *adapter,
                const M7MuxSendPacket *send,
                M7MuxEgressData *out);
  size_t (*count)(void);
} M7MuxNormalizeAdapterLib;

void m7mux_normalize_adapter_copy_shared_to_mux(const SharedKnockNormalizedUnit *src,
                                                M7MuxRecvPacket *dst);
int m7mux_normalize_adapter_copy_mux_to_shared(const M7MuxSendPacket *src,
                                               SharedKnockNormalizedUnit *dst);
int m7mux_normalize_adapter_fill_egress(const M7MuxSendPacket *src,
                                        const uint8_t *payload,
                                        size_t payload_len,
                                        M7MuxEgressData *dst);

const M7MuxNormalizeAdapterLib *get_protocol_udp_m7mux_normalize_adapter_lib(void);

#endif
