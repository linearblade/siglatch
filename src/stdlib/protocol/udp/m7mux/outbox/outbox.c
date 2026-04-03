/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "outbox.h"

#include "../internal.h"

#include <stdlib.h>
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
  if (!send) {
    return NULL;
  }

  return g_ctx.internal->normalize->adapter.lookup_adapter_wire_version(send->wire_version);
}

static int m7mux_outbox_stage_common(M7MuxState *state,
                                     const M7MuxSendPacket *send,
                                     size_t force_fragment_count) {
  const M7MuxNormalizeAdapter *adapter = NULL;
  M7MuxEgressData serialized = {0};
  M7MuxEgressData *fragments = NULL;
  size_t fragment_count = 0u;
  size_t available_slots = 0u;
  size_t i = 0u;
  int use_forced_fragments = 0;

  if (!state || !send) {
    return 0;
  }

  if (!g_ctx.internal || !g_ctx.internal->normalize || !g_ctx.internal->normalize->adapter.encode) {
    return 0;
  }

  adapter = m7mux_outbox_select_adapter(send);
  if (!adapter) {
    return 0;
  }

  use_forced_fragments = (force_fragment_count > 1u) ? 1 : 0;
  if (use_forced_fragments) {
    fragment_count = force_fragment_count;
  } else {
    fragment_count = adapter->count_fragments(&g_ctx, adapter->state, send);
  }
  if (fragment_count == 0u) {
    return 0;
  }

  if (state->egress.count >= M7MUX_EGRESS_QUEUE_CAPACITY) {
    return 0;
  }

  available_slots = M7MUX_EGRESS_QUEUE_CAPACITY - state->egress.count;
  if (fragment_count > available_slots) {
    return 0;
  }

  if (fragment_count == 1u) {
    if (!g_ctx.internal->normalize->adapter.encode(&g_ctx, adapter, send, &serialized)) {
      return 0;
    }

    if (!g_ctx.internal->egress->stage(&state->egress, &serialized)) {
      return 0;
    }

    return 1;
  }

  if (!adapter->encode_fragment) {
    return 0;
  }

  fragments = (M7MuxEgressData *)calloc(fragment_count, sizeof(*fragments));
  if (!fragments) {
    return 0;
  }

  for (i = 0u; i < fragment_count; ++i) {
    M7MuxSendPacket fragment_send = *send;

    fragment_send.fragment_index = (uint32_t)i;
    fragment_send.fragment_count = (uint32_t)fragment_count;

    if (!adapter->encode_fragment(&g_ctx,
                                  adapter->state,
                                  &fragment_send,
                                  i,
                                  use_forced_fragments ? force_fragment_count : 0u,
                                  &fragments[i])) {
      free(fragments);
      return 0;
    }
  }

  for (i = 0u; i < fragment_count; ++i) {
    if (!g_ctx.internal->egress->stage(&state->egress, &fragments[i])) {
      free(fragments);
      return 0;
    }
  }

  free(fragments);
  return 1;
}

static int m7mux_outbox_stage(M7MuxState *state, const M7MuxSendPacket *send) {
  return m7mux_outbox_stage_common(state, send, 0u);
}

static int m7mux_outbox_stage_fragments(M7MuxState *state,
                                        const M7MuxSendPacket *send,
                                        size_t fragment_count) {
  if (fragment_count <= 1u) {
    return m7mux_outbox_stage(state, send);
  }

  return m7mux_outbox_stage_common(state, send, fragment_count);
}

static int m7mux_outbox_stage_bytes(M7MuxState *state, const M7MuxSendBytesPacket *send_bytes) {
  M7MuxEgressData serialized = {0};

  if (!state || !send_bytes) {
    return 0;
  }

  if (send_bytes->bytes_len > sizeof(serialized.egress_buffer)) {
    return 0;
  }

  serialized.trace_id = send_bytes->trace_id;
  memcpy(serialized.label, send_bytes->label, sizeof(serialized.label));
  serialized.wire_version = 0u;
  serialized.wire_form = 0u;
  serialized.received_ms = send_bytes->received_ms;
  memcpy(serialized.ip, send_bytes->ip, sizeof(serialized.ip));
  serialized.client_port = send_bytes->client_port;
  serialized.encrypted = 0;
  serialized.wire_auth = 0;
  serialized.egress_len = send_bytes->bytes_len;

  if (send_bytes->bytes_len > 0u) {
    if (!send_bytes->bytes) {
      return 0;
    }
    memcpy(serialized.egress_buffer, send_bytes->bytes, send_bytes->bytes_len);
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
  .stage_fragments = m7mux_outbox_stage_fragments,
  .stage_bytes = m7mux_outbox_stage_bytes,
  .flush = m7mux_outbox_flush
};

const M7MuxOutboxLib *get_protocol_udp_m7mux_outbox_lib(void) {
  return &_instance;
}
