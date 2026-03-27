/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_NORMALIZE_BACKUP_DEMUX_H
#define SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_NORMALIZE_BACKUP_DEMUX_H

#include <stddef.h>

#include "../../../m7mux.h"

typedef struct {
  int (*init)(const M7MuxContext *ctx);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);
  int (*register_demux)(const M7MuxDemux *demux);
  int (*unregister_demux)(const char *name);
  size_t (*count)(void);
  const M7MuxDemux *(*at)(size_t index);
} M7MuxDemuxLib;

const M7MuxDemuxLib *get_lib_m7mux_demux(void);

#endif /* SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_NORMALIZE_BACKUP_DEMUX_H */
