/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "m7mux.h"
#include "internal.h"

#include <string.h>

static M7MuxContext g_ctx = {0};
static M7MuxInternalLib g_internal = {0};
static const M7MuxConnectLib *g_connect = NULL;
static const M7MuxInboxLib *g_inbox = NULL;
static const M7MuxOutboxLib *g_outbox = NULL;
static const M7MuxIngressLib *g_ingress = NULL;
static const M7MuxNormalizeLib *g_normalize = NULL;
static const M7MuxSessionLib *g_session = NULL;
static const M7MuxStreamLib *g_stream = NULL;
static const M7MuxEgressLib *g_egress = NULL;
static M7MuxLib g_lib = {0};

#define M7MUX_FLUSH_OUTBOX_OR_RETURN(_state, _now_ms, _did_work, _inbox_timeout) \
  do { \
    int _m7mux_flush_rc = 0; \
    if (g_ctx.internal->outbox->has_pending((_state))) { \
      _m7mux_flush_rc = g_ctx.internal->outbox->flush( \
          (_state), (_state)->connect.socket_fd, (_now_ms)); \
      if (_m7mux_flush_rc < 0) { \
        return _m7mux_flush_rc; \
      } \
      if (_m7mux_flush_rc > 0) { \
        (_did_work) = 1; \
        (_inbox_timeout) = 0u; \
      } \
    } \
  } while (0)

static void m7mux_reset_context(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
  g_ctx.internal = &g_internal;
}

static int m7mux_apply_context(const M7MuxContext *ctx) {
  if (!ctx) {
    return 0;
  }

  g_ctx = *ctx;
  g_ctx.internal = &g_internal;
  return 1;
}

static void m7mux_shutdown_bundle(void) {
  if (g_connect && g_connect->shutdown) {
    g_connect->shutdown();
  }
  if (g_inbox && g_inbox->shutdown) {
    g_inbox->shutdown();
  }
  if (g_outbox && g_outbox->shutdown) {
    g_outbox->shutdown();
  }
  if (g_egress && g_egress->shutdown) {
    g_egress->shutdown();
  }
  if (g_session && g_session->shutdown) {
    g_session->shutdown();
  }
  if (g_stream && g_stream->shutdown) {
    g_stream->shutdown();
  }
  if (g_normalize && g_normalize->shutdown) {
    g_normalize->shutdown();
  }
  if (g_ingress && g_ingress->shutdown) {
    g_ingress->shutdown();
  }

  g_connect = NULL;
  g_inbox = NULL;
  g_outbox = NULL;
  g_ingress = NULL;
  g_normalize = NULL;
  g_session = NULL;
  g_stream = NULL;
  g_egress = NULL;
  memset(&g_internal, 0, sizeof(g_internal));
  m7mux_reset_context();
}

static int m7mux_init(const M7MuxContext *ctx) {
  g_connect = get_protocol_udp_m7mux_connect_lib();
  g_inbox = get_protocol_udp_m7mux_inbox_lib();
  g_outbox = get_protocol_udp_m7mux_outbox_lib();
  g_ingress = get_protocol_udp_m7mux_ingress_lib();
  g_normalize = get_protocol_udp_m7mux_normalize_lib();
  g_session = get_protocol_udp_m7mux_session_lib();
  g_stream = get_protocol_udp_m7mux_stream_lib();
  g_egress = get_protocol_udp_m7mux_egress_lib();

  g_internal.connect = g_connect;
  g_internal.inbox = g_inbox;
  g_internal.outbox = g_outbox;
  g_internal.ingress = g_ingress;
  g_internal.normalize = g_normalize;
  g_internal.session = g_session;
  g_internal.stream = g_stream;
  g_internal.egress = g_egress;

  if (!m7mux_apply_context(ctx)) {
    return 0;
  }

  if (!g_connect->init(&g_ctx) ||
      !g_inbox->init(&g_ctx) ||
      !g_outbox->init(&g_ctx) ||
      !g_ingress->init(&g_ctx) ||
      !g_normalize->init(&g_ctx) ||
      !g_session->init() ||
      !g_stream->init() ||
      !g_egress->init() ||
      !g_connect->set_context(&g_ctx) ||
      !g_inbox->set_context(&g_ctx) ||
      !g_outbox->set_context(&g_ctx) ||
      !g_ingress->set_context(&g_ctx) ||
      !g_normalize->set_context(&g_ctx) ||
      !g_egress->set_context(&g_ctx)) {
    m7mux_shutdown_bundle();
    return 0;
  }

  g_lib.connect = *g_connect;
  g_lib.inbox = *g_inbox;
  g_lib.outbox = *g_outbox;
  return 1;
}

static int m7mux_set_context(const M7MuxContext *ctx) {
  if (!m7mux_apply_context(ctx)) {
    return 0;
  }

  if (!g_connect->set_context(&g_ctx) ||
      !g_inbox->set_context(&g_ctx) ||
      !g_outbox->set_context(&g_ctx) ||
      !g_ingress->set_context(&g_ctx) ||
      !g_normalize->set_context(&g_ctx) ||
      !g_egress->set_context(&g_ctx)) {
    return 0;
  }

  return 1;
}

static int m7mux_pump(M7MuxState *state, uint64_t timeout_ms) {
  uint64_t now_ms = 0u;
  uint64_t inbox_timeout = timeout_ms;
  int rc = 0;
  int did_work = 0;

  if (!state) {
    return 0;
  }

  if (!state->connect.connected || state->connect.socket_fd < 0) {
    return 0;
  }

  now_ms = g_ctx.time->monotonic_ms();

  M7MUX_FLUSH_OUTBOX_OR_RETURN(state, now_ms, did_work, inbox_timeout);

  rc = g_ctx.internal->inbox->pump(state, inbox_timeout);
  if (rc < 0) {
    return rc;
  }

  if (rc > 0) {
    did_work = 1;
  }

  now_ms = g_ctx.time->monotonic_ms();

  M7MUX_FLUSH_OUTBOX_OR_RETURN(state, now_ms, did_work, inbox_timeout);

  return did_work;
}

static void m7mux_shutdown(void) {
  m7mux_shutdown_bundle();
}

const M7MuxLib *get_lib_m7mux(void) {
  if (!g_lib.init) {
    g_lib.init = m7mux_init;
    g_lib.set_context = m7mux_set_context;
    g_lib.pump = m7mux_pump;
    g_lib.shutdown = m7mux_shutdown;
    g_lib.connect = *get_protocol_udp_m7mux_connect_lib();
    g_lib.inbox = *get_protocol_udp_m7mux_inbox_lib();
    g_lib.outbox = *get_protocol_udp_m7mux_outbox_lib();
  }

  return &g_lib;
}
