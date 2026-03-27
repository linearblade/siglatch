/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "demux.h"

#include <string.h>

#define M7MUX_MAX_DEMUXES 16u

#include "../../../../../../../shared/knock/detect.h"

static M7MuxContext g_ctx = {0};
static M7MuxDemux g_demuxes[M7MUX_MAX_DEMUXES] = {0};
static size_t g_demux_count = 0;

static int m7mux_demux_register(const M7MuxDemux *demux);
static int m7mux_demux_unregister(const char *name);

static int m7mux_demux_detect_v1(const uint8_t *input,
                                 size_t input_len,
                                 void *route,
                                 size_t route_len) {
  SharedKnockRoutingInfo shared = {0};

  if (route_len == 0) {
    return 0;
  }

  if (!shared_knock_detect(input, input_len, &shared)) {
    return 0;
  }

  if (shared.kind != SHARED_KNOCK_ROUTE_V1_LEGACY) {
    return 0;
  }

  memset(route, 0, route_len);
  strncpy((char *)route, "v1", route_len - 1);
  return 1;
}

static int m7mux_demux_detect_v2(const uint8_t *input,
                                 size_t input_len,
                                 void *route,
                                 size_t route_len) {
  SharedKnockRoutingInfo shared = {0};

  if (route_len == 0) {
    return 0;
  }

  if (!shared_knock_detect(input, input_len, &shared)) {
    return 0;
  }

  if (shared.kind != SHARED_KNOCK_ROUTE_V2_FORM1) {
    return 0;
  }

  memset(route, 0, route_len);
  strncpy((char *)route, "v2", route_len - 1);
  return 1;
}

static const M7MuxDemux g_builtin_demuxes[] = {
  {
    .name = "v1",
    .adapter_name = "v1",
    .detect = m7mux_demux_detect_v1,
    .route_len = 16u,
    .reserved = NULL
  },
  {
    .name = "v2",
    .adapter_name = "v2",
    .detect = m7mux_demux_detect_v2,
    .route_len = 16u,
    .reserved = NULL
  }
};

static void m7mux_demux_reset_context(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static void m7mux_demux_reset_registry(void) {
  memset(g_demuxes, 0, sizeof(g_demuxes));
  g_demux_count = 0;
}

static int m7mux_demux_apply_context(const M7MuxContext *ctx) {
  g_ctx = *ctx;
  return 1;
}

static int m7mux_name_matches(const char *lhs, const char *rhs) {
  return strcmp(lhs, rhs) == 0;
}

static int m7mux_demux_init(const M7MuxContext *ctx) {
  m7mux_demux_apply_context(ctx);
  m7mux_demux_reset_registry();
  for (size_t i = 0; i < sizeof(g_builtin_demuxes) / sizeof(g_builtin_demuxes[0]); ++i) {
    (void)m7mux_demux_register(&g_builtin_demuxes[i]);
  }
  return 1;
}

static int m7mux_demux_set_context(const M7MuxContext *ctx) {
  return m7mux_demux_apply_context(ctx);
}

static void m7mux_demux_shutdown(void) {
  m7mux_demux_reset_registry();
  m7mux_demux_reset_context();
}

static int m7mux_demux_register(const M7MuxDemux *demux) {
  size_t i = 0;

  for (i = 0; i < g_demux_count; ++i) {
    if (m7mux_name_matches(g_demuxes[i].name, demux->name)) {
      return 0;
    }
  }

  if (g_demux_count >= M7MUX_MAX_DEMUXES) {
    return 0;
  }

  g_demuxes[g_demux_count++] = *demux;
  return 1;
}

static int m7mux_demux_unregister(const char *name) {
  size_t i = 0;
  size_t j = 0;

  for (i = 0; i < g_demux_count; ++i) {
    if (m7mux_name_matches(g_demuxes[i].name, name)) {
      for (j = i; j + 1 < g_demux_count; ++j) {
        g_demuxes[j] = g_demuxes[j + 1];
      }

      memset(&g_demuxes[g_demux_count - 1], 0, sizeof(g_demuxes[0]));
      --g_demux_count;
      return 1;
    }
  }

  return 0;
}

static size_t m7mux_demux_count_fn(void) {
  return g_demux_count;
}

static const M7MuxDemux *m7mux_demux_at_fn(size_t index) {
  if (index >= g_demux_count) {
    return NULL;
  }

  return &g_demuxes[index];
}

static const M7MuxDemuxLib g_demux_lib = {
  .init = m7mux_demux_init,
  .set_context = m7mux_demux_set_context,
  .shutdown = m7mux_demux_shutdown,
  .register_demux = m7mux_demux_register,
  .unregister_demux = m7mux_demux_unregister,
  .count = m7mux_demux_count_fn,
  .at = m7mux_demux_at_fn
};

const M7MuxDemuxLib *get_lib_m7mux_demux(void) {
  return &g_demux_lib;
}
