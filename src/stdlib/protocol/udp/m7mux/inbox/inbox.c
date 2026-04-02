/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "inbox.h"

#include "../internal.h"

#include <string.h>

static M7MuxContext g_ctx = {0};

static void m7mux_inbox_reset_context(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static void m7mux_inbox_configure_stream_adapter(M7MuxState *state) {
  if (!state || !g_ctx.internal || !g_ctx.internal->normalize) {
    return;
  }

  state->stream.adapter_lib = &g_ctx.internal->normalize->adapter;
}

static int m7mux_inbox_init(const M7MuxContext *ctx) {
  if (!ctx) {
    m7mux_inbox_reset_context();
    return 0;
  }

  g_ctx = *ctx;
  return 1;
}

static int m7mux_inbox_set_context(const M7MuxContext *ctx) {
  return m7mux_inbox_init(ctx);
}

static void m7mux_inbox_shutdown(void) {
  m7mux_inbox_reset_context();
}

static void m7mux_inbox_state_reset(M7MuxState *state) {
  if (!state) {
    return;
  }

  g_ctx.internal->ingress->state_reset(&state->ingress);
  g_ctx.internal->session->state_reset(&state->session);
  g_ctx.internal->stream->state_reset(&state->stream);
  m7mux_inbox_configure_stream_adapter(state);
}

static int m7mux_inbox_state_init(M7MuxState *state) {
  if (!state) {
    return 0;
  }

  if (!g_ctx.internal->session->state_init(&state->session)) {
    m7mux_inbox_state_reset(state);
    return 0;
  }

  if (!g_ctx.internal->ingress->state_init(&state->ingress)) {
    m7mux_inbox_state_reset(state);
    return 0;
  }

  if (!g_ctx.internal->stream->state_init(&state->stream)) {
    m7mux_inbox_state_reset(state);
    return 0;
  }

  m7mux_inbox_configure_stream_adapter(state);

  return 1;
}

static int m7mux_inbox_has_pending(const M7MuxState *state) {
  if (!state) {
    return 0;
  }

  return g_ctx.internal->stream->has_pending(&state->stream);
}

static int m7mux_inbox_pump(M7MuxState *state, uint64_t timeout_ms) {
  M7MuxIngress raw = {0};
  M7MuxRecvPacket normal = {0};
  uint64_t now_ms = 0u;
  int rc = 0;
  int did_work = 0;

  if (!state) {
    return 0;
  }

  /* Keep ingress pointed at the connected socket before staging raw packets. */
  state->ingress.socket_fd = state->connect.socket_fd;
  now_ms = g_ctx.time->monotonic_ms();
  did_work = g_ctx.internal->session->expire(&state->session, now_ms) > 0;
  did_work = g_ctx.internal->stream->expire(&state->stream, now_ms) > 0 || did_work;

  rc = g_ctx.internal->ingress->pump(&state->ingress, timeout_ms);
  if (rc < 0) {
    return rc;
  }

  if (rc > 0) {
    did_work = 1;
  }

  while (g_ctx.internal->ingress->drain(&state->ingress, &raw)) {
    memset(&normal, 0, sizeof(normal));

    if (!g_ctx.internal->normalize->normalize(state, &raw, &normal)) {
      continue;
    }

    if (!g_ctx.internal->session->ingest(&state->session, &normal)) {
      m7mux_stream_release_user(&state->stream, &normal);
      return did_work;
    }

    if (!g_ctx.internal->stream->ingest(&state->stream, &normal)) {
      m7mux_stream_release_user(&state->stream, &normal);
      return did_work;
    }

    did_work = 1;
  }

  now_ms = g_ctx.time->monotonic_ms();
  did_work = g_ctx.internal->stream->expire(&state->stream, now_ms) > 0 || did_work;

  return did_work;
}

static int m7mux_inbox_drain(M7MuxState *state, M7MuxRecvPacket *out_normal) {
  if (!state || !out_normal) {
    return 0;
  }

  return g_ctx.internal->stream->drain(&state->stream, out_normal);
}

static const M7MuxInboxLib _instance = {
  .init = m7mux_inbox_init,
  .set_context = m7mux_inbox_set_context,
  .shutdown = m7mux_inbox_shutdown,
  .state_init = m7mux_inbox_state_init,
  .state_reset = m7mux_inbox_state_reset,
  .has_pending = m7mux_inbox_has_pending,
  .pump = m7mux_inbox_pump,
  .drain = m7mux_inbox_drain
};

const M7MuxInboxLib *get_protocol_udp_m7mux_inbox_lib(void) {
  return &_instance;
}
