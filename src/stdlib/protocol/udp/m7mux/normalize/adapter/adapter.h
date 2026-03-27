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
typedef struct M7MuxNormalizedPacket M7MuxNormalizedPacket;

typedef struct {
  const char *name;
  int (*create_state)(void **out_state);
  void (*destroy_state)(void *state);
  int (*detect)(const M7MuxContext *ctx, const void *state, const M7MuxIngress *ingress);
  int (*decode)(const M7MuxContext *ctx,
                const void *state,
                const M7MuxIngress *ingress,
                M7MuxNormalizedPacket *out);
  int (*encode)(const M7MuxContext *ctx,
                const void *state,
                const M7MuxNormalizedPacket *normal,
                uint8_t *out,
                size_t *out_len);
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
  const M7MuxNormalizeAdapter *(*demux)(const M7MuxContext *ctx, const M7MuxIngress *ingress);
  int (*decode)(const M7MuxContext *ctx,
                const M7MuxNormalizeAdapter *adapter,
                const M7MuxIngress *ingress,
                M7MuxNormalizedPacket *out);
  int (*encode)(const M7MuxContext *ctx,
                const M7MuxNormalizeAdapter *adapter,
                const M7MuxNormalizedPacket *normal,
                uint8_t *out,
                size_t *out_len);
  size_t (*count)(void);
} M7MuxNormalizeAdapterLib;

const M7MuxNormalizeAdapterLib *get_protocol_udp_m7mux_normalize_adapter_lib(void);

#endif
