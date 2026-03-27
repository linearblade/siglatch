/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_NORMALIZE_BACKUP_DECODE_H
#define SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_NORMALIZE_BACKUP_DECODE_H

#include "../../../m7mux.h"

typedef struct {
  int (*init)(const M7MuxContext *ctx);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);
  int (*register_adapter)(const M7MuxAdapter *adapter);
  int (*unregister_adapter)(const char *name);
  const M7MuxAdapter *(*lookup_adapter)(const char *name);
} M7MuxDecodeLib;

const M7MuxDecodeLib *get_lib_m7mux_decode(void);

#endif /* SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_NORMALIZE_BACKUP_DECODE_H */
