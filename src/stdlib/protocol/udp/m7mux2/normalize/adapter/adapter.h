/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX2_NORMALIZE_ADAPTER_H
#define LIB_PROTOCOL_UDP_M7MUX2_NORMALIZE_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include "../../m7mux2.h"

typedef struct M7Mux2Ingress M7Mux2Ingress;
typedef struct M7Mux2RecvPacket M7Mux2RecvPacket;
typedef struct M7Mux2SendPacket M7Mux2SendPacket;
typedef struct M7Mux2EgressData M7Mux2EgressData;

typedef struct {
  const char *name;
  int (*create_state)(void **out_state);
  void (*destroy_state)(void *state);
  int (*detect)(const M7Mux2Context *ctx, const void *state, const M7Mux2Ingress *ingress);
  int (*decode)(const M7Mux2Context *ctx,
                const void *state,
                const M7Mux2Ingress *ingress,
                M7Mux2RecvPacket *out);
  int (*encode)(const M7Mux2Context *ctx,
                const void *state,
                const M7Mux2SendPacket *send,
                M7Mux2EgressData *out);
  void *state;
  void *reserved;
} M7Mux2NormalizeAdapter;

typedef struct {
  int (*init)(void);
  int (*set_context)(const M7Mux2Context *ctx);
  void (*shutdown)(void);
  int (*register_adapter)(const M7Mux2NormalizeAdapter *adapter);
  int (*unregister_adapter)(const char *name);
  const M7Mux2NormalizeAdapter *(*lookup_adapter)(const char *name);
  const M7Mux2NormalizeAdapter *(*demux)(const M7Mux2Context *ctx, const M7Mux2Ingress *ingress);
  int (*decode)(const M7Mux2Context *ctx,
                const M7Mux2NormalizeAdapter *adapter,
                const M7Mux2Ingress *ingress,
                M7Mux2RecvPacket *out);
  int (*encode)(const M7Mux2Context *ctx,
                const M7Mux2NormalizeAdapter *adapter,
                const M7Mux2SendPacket *send,
                M7Mux2EgressData *out);
  size_t (*count)(void);
} M7Mux2NormalizeAdapterLib;

const M7Mux2NormalizeAdapterLib *get_protocol_udp_m7mux2_normalize_adapter_lib(void);

#endif
