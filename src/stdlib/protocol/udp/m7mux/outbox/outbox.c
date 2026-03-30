/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "outbox.h"

#include "../internal.h"
#include "../../../../../shared/knock/codec/v2/v2_form1.h"
#include "../../../../../shared/knock/codec/v3/v3_form1.h"

#include <string.h>

static M7MuxContext g_ctx = {0};

static void m7mux_outbox_reset_context(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static int m7mux_outbox_init(const M7MuxContext *ctx) {
  if (!ctx || !ctx->internal || !ctx->internal->egress) {
    m7mux_outbox_reset_context();
    return 0;
  }

  g_ctx = *ctx;
  return 1;
}

static int m7mux_outbox_set_context(const M7MuxContext *ctx) {
  return m7mux_outbox_init(ctx);
}

static void m7mux_outbox_shutdown(void) {
  m7mux_outbox_reset_context();
}

static int m7mux_outbox_state_init(M7MuxState *state) {
  if (!state) {
    return 0;
  }

  if (!g_ctx.internal->egress->state_init(&state->egress)) {
    return 0;
  }

  return 1;
}

static void m7mux_outbox_state_reset(M7MuxState *state) {
  if (!state) {
    return;
  }

  g_ctx.internal->egress->state_reset(&state->egress);
}

static int m7mux_outbox_has_pending(const M7MuxState *state) {
  if (!state) {
    return 0;
  }

  return g_ctx.internal->egress->has_pending(&state->egress);
}

static const M7MuxNormalizeAdapter *m7mux_outbox_select_adapter(const M7MuxSendPacket *send) {
  if (!send || !g_ctx.internal || !g_ctx.internal->normalize ||
      !g_ctx.internal->normalize->adapter.lookup_adapter) {
    return NULL;
  }

  if (send->wire_version == SHARED_KNOCK_CODEC_V3_WIRE_VERSION) {
    return g_ctx.internal->normalize->adapter.lookup_adapter("codec.v3");
  }

  if (send->wire_version == SHARED_KNOCK_CODEC_V2_WIRE_VERSION) {
    return g_ctx.internal->normalize->adapter.lookup_adapter("codec.v2");
  }

  return g_ctx.internal->normalize->adapter.lookup_adapter("codec.v1");
}

static int m7mux_outbox_stage(M7MuxState *state, const M7MuxSendPacket *send) {
  const M7MuxNormalizeAdapter *adapter = NULL;
  M7MuxEgressData serialized = {0};

  if (!state || !send || !send->available) {
    return 0;
  }

  if (!send->complete) {
    return 0;
  }

  if (!send->should_reply) {
    return 1;
  }

  if (!g_ctx.internal || !g_ctx.internal->normalize || !g_ctx.internal->normalize->adapter.encode) {
    return 0;
  }

  adapter = m7mux_outbox_select_adapter(send);
  if (!adapter) {
    return 0;
  }

  if (!g_ctx.internal->normalize->adapter.encode(&g_ctx, adapter, send, &serialized)) {
    return 0;
  }

  return g_ctx.internal->egress->stage(&state->egress, &serialized);
}

static int m7mux_outbox_flush(M7MuxState *state, int sock, uint64_t now_ms) {
  if (!state) {
    return 0;
  }

  return g_ctx.internal->egress->flush(&state->egress, sock, now_ms);
}

static const M7MuxOutboxLib _instance = {
  .init = m7mux_outbox_init,
  .set_context = m7mux_outbox_set_context,
  .shutdown = m7mux_outbox_shutdown,
  .state_init = m7mux_outbox_state_init,
  .state_reset = m7mux_outbox_state_reset,
  .has_pending = m7mux_outbox_has_pending,
  .stage = m7mux_outbox_stage,
  .flush = m7mux_outbox_flush
};

const M7MuxOutboxLib *get_protocol_udp_m7mux_outbox_lib(void) {
  return &_instance;
}
