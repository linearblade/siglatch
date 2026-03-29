#include "egress.h"
#include "../m7mux2.h"

#include <string.h>

static M7Mux2Context g_ctx = {0};

static int _init(void) {
  return 1;
}

static int _set_context(const M7Mux2Context *ctx) {
  if (!ctx) {
    return 0;
  }

  g_ctx = *ctx;
  return 1;
}

static void _shutdown(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static int _state_init(M7Mux2EgressState *state) {
  if (!state) {
    return 0;
  }

  memset(state, 0, sizeof(*state));
  return 1;
}

static void _state_reset(M7Mux2EgressState *state) {
  if (!state) {
    return;
  }

  memset(state, 0, sizeof(*state));
}

/*
 * Egress readiness means the transport already has outbound work staged in
 * its queue and the runner should not block waiting on new ingress.
 */
static int _egress_ready(const M7Mux2EgressState *state) {
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
static int _enqueue_egress(M7Mux2EgressState *state,
                           const M7Mux2EgressData *egress) {
  M7Mux2EgressData *slot = NULL;

  if (!state || !egress || !egress->available) {
    return 0;
  }

  if (egress->egress_len > sizeof(egress->egress_buffer)) {
    return 0;
  }

  if (state->count >= M7MUX2_EGRESS_QUEUE_CAPACITY) {
    return 0;
  }

  slot = &state->queue[state->tail];
  memset(slot, 0, sizeof(*slot));
  memcpy(slot, egress, sizeof(*slot));
  slot->ip[sizeof(slot->ip) - 1] = '\0';
  slot->available = 1;

  state->tail = (state->tail + 1u) % M7MUX2_EGRESS_QUEUE_CAPACITY;
  state->count++;

  return 1;
}

static int _stage_egress(M7Mux2EgressState *state,
                         const M7Mux2EgressData *packet) {
  M7Mux2EgressData egress = {0};

  if (!state || !packet) {
    return 0;
  }

  if (!packet->complete) {
    return 0;
  }

  if (!packet->should_reply && packet->egress_len == 0u) {
    return 1;
  }

  if (packet->egress_len > sizeof(egress.egress_buffer)) {
    return 0;
  }

  egress = *packet;
  egress.available = 1;

  return _enqueue_egress(state, &egress);
}

static int _flush_egress(M7Mux2EgressState *state,
                         int sock,
                         uint64_t now_ms) {
  M7Mux2EgressData *egress = NULL;
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

    if (!egress->available || egress->egress_len == 0u) {
      memset(egress, 0, sizeof(*egress));
      state->head = (state->head + 1u) % M7MUX2_EGRESS_QUEUE_CAPACITY;
      state->count--;
      continue;
    }

    if (!g_ctx.udp->send(sock,
                         egress->ip,
                         egress->client_port,
                         egress->egress_buffer,
                         egress->egress_len)) {
      return flushed;
    }

    memset(egress, 0, sizeof(*egress));
    state->head = (state->head + 1u) % M7MUX2_EGRESS_QUEUE_CAPACITY;
    state->count--;
    flushed++;
  }

  return flushed;
}

static const M7Mux2EgressLib _instance = {
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

const M7Mux2EgressLib *get_protocol_udp_m7mux2_egress_lib(void) {
  return &_instance;
}
