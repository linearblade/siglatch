/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "ingress.h"

#include <arpa/inet.h>
#include <limits.h>
#include <string.h>

static M7MuxContext g_ctx = {0};

static int m7mux_ingress_apply_context(const M7MuxContext *ctx) {
  if (!ctx) {
    return 0;
  }

  g_ctx = *ctx;
  return 1;
}

static int m7mux_ingress_peer_to_ip(const struct sockaddr_storage *peer,
                                    char *ip_out,
                                    size_t ip_len,
                                    uint16_t *port_out) {
  if (!peer || !ip_out || ip_len == 0 || !port_out) {
    return 0;
  }

  memset(ip_out, 0, ip_len);
  *port_out = 0;

  switch (peer->ss_family) {
  case AF_INET: {
    const struct sockaddr_in *addr = (const struct sockaddr_in *)peer;
    if (!inet_ntop(AF_INET, &addr->sin_addr, ip_out, (socklen_t)ip_len)) {
      return 0;
    }
    *port_out = ntohs(addr->sin_port);
    return 1;
  }
  case AF_INET6: {
    const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)peer;
    if (!inet_ntop(AF_INET6, &addr->sin6_addr, ip_out, (socklen_t)ip_len)) {
      return 0;
    }
    *port_out = ntohs(addr->sin6_port);
    return 1;
  }
  default:
    break;
  }

  return 0;
}

static int m7mux_ingress_state_init(M7MuxIngressState *state) {
  if (!state) {
    return 0;
  }

  memset(state, 0, sizeof(*state));
  state->socket_fd = -1;
  return 1;
}

static void m7mux_ingress_state_reset(M7MuxIngressState *state) {
  if (!state) {
    return;
  }

  memset(state, 0, sizeof(*state));
  state->socket_fd = -1;
}

static int m7mux_ingress_has_pending(const M7MuxIngressState *state) {
  if (!state) {
    return 0;
  }

  return state->queue_count > 0u;
}

static int m7mux_ingress_queue_push(M7MuxIngressState *state,
                                    const M7MuxIngress *ingress) {
  if (!state || !ingress || state->queue_count >= M7MUX_INGRESS_QUEUE_CAPACITY) {
    return 0;
  }

  state->queue[state->queue_tail] = *ingress;
  state->queue_tail = (state->queue_tail + 1u) % M7MUX_INGRESS_QUEUE_CAPACITY;
  state->queue_count++;
  return 1;
}

static int m7mux_ingress_queue_pop(M7MuxIngressState *state,
                                   M7MuxIngress *out_ingress) {
  M7MuxIngress *slot = NULL;

  if (!state || !out_ingress || state->queue_count == 0u) {
    if (out_ingress) {
      memset(out_ingress, 0, sizeof(*out_ingress));
    }
    return 0;
  }

  slot = &state->queue[state->queue_head];
  *out_ingress = *slot;
  memset(slot, 0, sizeof(*slot));
  state->queue_head = (state->queue_head + 1u) % M7MUX_INGRESS_QUEUE_CAPACITY;
  state->queue_count--;
  return 1;
}

/*
 * Ingress is the thin socket adapter.
 *
 * It waits for readability, then drains every immediately available UDP
 * datagram into a fixed queue while recording peer metadata. It does not
 * demux, decode, or otherwise interpret the packet.
 */
static int m7mux_ingress_pump(M7MuxIngressState *state, uint64_t timeout_ms) {
  struct sockaddr_storage peer = {0};
  M7MuxIngress ingress = {0};
  size_t received_len = 0;
  int wait_rc = 0;
  int timeout = 0;
  int queued = 0;

  if (!state || state->socket_fd < 0 || !g_ctx.socket || !g_ctx.udp) {
    return 0;
  }

  if (state->queue_count > 0u) {
    return 1;
  }

  if (timeout_ms > (uint64_t)INT_MAX) {
    timeout_ms = (uint64_t)INT_MAX;
  }
  timeout = (int)timeout_ms;

  wait_rc = g_ctx.socket->wait_readable(state->socket_fd, timeout);
  if (wait_rc <= 0) {
    return wait_rc;
  }

  while (state->queue_count < M7MUX_INGRESS_QUEUE_CAPACITY) {
    if (g_ctx.socket->wait_readable(state->socket_fd, 0) <= 0) {
      break;
    }

    memset(&ingress, 0, sizeof(ingress));
    if (!g_ctx.udp->recv(state->socket_fd,
                         ingress.buffer,
                         sizeof(ingress.buffer),
                         &peer,
                         &received_len)) {
      break;
    }

    ingress.len = received_len;
    ingress.received_ms = g_ctx.time->monotonic_ms();
    if (!m7mux_ingress_peer_to_ip(&peer,
                                  ingress.ip,
                                  sizeof(ingress.ip),
                                  &ingress.client_port)) {
      break;
    }

    /*
     * Packet-level encryption is determined during codec detection/decoding.
     * The raw ingress adapter does not assume every packet on a secure server
     * is encrypted.
     */
    ingress.encrypted = 0;
    if (!m7mux_ingress_queue_push(state, &ingress)) {
      break;
    }

    queued = 1;
  }

  return queued;
}

static int m7mux_ingress_drain(M7MuxIngressState *state, M7MuxIngress *out_ingress) {
  return m7mux_ingress_queue_pop(state, out_ingress);
}

static int m7mux_ingress_init(const M7MuxContext *ctx) {
  return m7mux_ingress_apply_context(ctx);
}

static int m7mux_ingress_set_context(const M7MuxContext *ctx) {
  return m7mux_ingress_apply_context(ctx);
}

static void m7mux_ingress_shutdown(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static const M7MuxIngressLib _instance = {
  .init = m7mux_ingress_init,
  .set_context = m7mux_ingress_set_context,
  .shutdown = m7mux_ingress_shutdown,
  .state_init = m7mux_ingress_state_init,
  .state_reset = m7mux_ingress_state_reset,
  .has_pending = m7mux_ingress_has_pending,
  .pump = m7mux_ingress_pump,
  .drain = m7mux_ingress_drain
};

const M7MuxIngressLib *get_protocol_udp_m7mux_ingress_lib(void) {
  return &_instance;
}
