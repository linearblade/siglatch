#include "egress.h"
#include "../m7mux.h"

#include <string.h>

static M7MuxContext g_ctx = {0};

static int _init(void) {
  return 1;
}

static int _set_context(const M7MuxContext *ctx) {
  if (!ctx) {
    return 0;
  }

  g_ctx = *ctx;
  return 1;
}

static void _shutdown(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static int _state_init(M7MuxEgressState *state) {
  if (!state) {
    return 0;
  }

  memset(state, 0, sizeof(*state));
  return 1;
}

static void _state_reset(M7MuxEgressState *state) {
  if (!state) {
    return;
  }

  memset(state, 0, sizeof(*state));
}

/*
 * Egress readiness means the transport already has outbound work staged in
 * its queue and the runner should not block waiting on new ingress.
 */
static int _egress_ready(const M7MuxEgressState *state) {
  if (!state) {
    return 0;
  }

  return state->count > 0;
}

/*
 * The egress queue is transport-owned state, not transient job state.
 *
 * By the time outbound work reaches this queue it should already be divorced
 * from the temporary job view and ready for transport delivery later in
 * flush().
 */
static int _enqueue_egress(M7MuxEgressState *state,
                           const M7MuxEgress *egress) {
  M7MuxEgress *slot = NULL;

  if (!state || !egress || !egress->available) {
    return 0;
  }

  if (egress->len > sizeof(egress->buffer)) {
    return 0;
  }

  if (state->count >= M7MUX_EGRESS_QUEUE_CAPACITY) {
    return 0;
  }

  slot = &state->queue[state->tail];
  memset(slot, 0, sizeof(*slot));
  memcpy(slot, egress, sizeof(*slot));
  slot->ip[sizeof(slot->ip) - 1] = '\0';
  slot->available = 1;

  state->tail = (state->tail + 1u) % M7MUX_EGRESS_QUEUE_CAPACITY;
  state->count++;

  return 1;
}

static int _stage_egress(M7MuxEgressState *state,
                         const M7MuxNormalizedPacket *normal) {
  M7MuxEgress egress = {0};

  if (!state || !normal) {
    return 0;
  }

  if (!normal->complete) {
    return 0;
  }

  if (!normal->should_reply && normal->response_len == 0) {
    return 1;
  }

  if (normal->response_len > sizeof(egress.buffer)) {
    return 0;
  }

  egress.len = normal->response_len;
  egress.session_id = normal->session_id;
  egress.message_id = normal->message_id;
  egress.stream_id = normal->stream_id;
  egress.client_port = normal->client_port;
  egress.encrypted = normal->encrypted;
  memcpy(egress.ip, normal->ip, sizeof(egress.ip));
  memcpy(egress.buffer, normal->response_buffer, normal->response_len);
  egress.available = 1;

  return _enqueue_egress(state, &egress);
}

static int _flush_egress(M7MuxEgressState *state,
                         int sock,
                         uint64_t now_ms) {
  M7MuxEgress *egress = NULL;
  int flushed = 0;

  if (!state) {
    return 0;
  }

  (void)now_ms;

  /*
   * Placeholder transport-delivery stage.
   *
   * This sends queued outbound datagrams using the caller-provided listener
   * socket. If send fails, the first queued outbound entry is preserved so the
   * runner can retry on a later loop iteration.
   */
  while (state->count > 0) {
    egress = &state->queue[state->head];

    if (sock < 0 || !g_ctx.udp || !g_ctx.udp->send) {
      return flushed;
    }

    if (!egress->available || egress->len == 0) {
      memset(egress, 0, sizeof(*egress));
      state->head = (state->head + 1u) % M7MUX_EGRESS_QUEUE_CAPACITY;
      state->count--;
      continue;
    }

    if (!g_ctx.udp->send(sock,
                         egress->ip,
                         egress->client_port,
                         egress->buffer,
                         egress->len)) {
      return flushed;
    }

    memset(egress, 0, sizeof(*egress));
    state->head = (state->head + 1u) % M7MUX_EGRESS_QUEUE_CAPACITY;
    state->count--;
    flushed++;
  }

  return flushed;
}

static const M7MuxEgressLib _instance = {
  .init = _init,
  .set_context = _set_context,
  .shutdown = _shutdown,
  .state_init = _state_init,
  .state_reset = _state_reset,
  .has_pending = _egress_ready,
  .stage = _stage_egress,
  .enqueue = _enqueue_egress,
  .flush = _flush_egress
};

const M7MuxEgressLib *get_protocol_udp_m7mux_egress_lib(void) {
  return &_instance;
}
