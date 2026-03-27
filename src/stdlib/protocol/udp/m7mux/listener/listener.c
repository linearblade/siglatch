/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "listener.h"

#include <arpa/inet.h>
#include <limits.h>
#include <string.h>

#ifndef M7MUX_NORMALIZE_OK
#define M7MUX_NORMALIZE_OK 0
#define M7MUX_NORMALIZE_ERR_OVERFLOW -4
#endif

static void m7mux_listener_copy_ip(char *dst, size_t dst_len, const char *src) {
  if (dst_len == 0) {
    return;
  }

  memset(dst, 0, dst_len);
  strncpy(dst, src, dst_len - 1);
}

static int m7mux_listener_peer_to_ip(const struct sockaddr_storage *peer,
                                     char *ip_out,
                                     size_t ip_len,
                                     uint16_t *port_out) {
  if (ip_len == 0) {
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

static int m7mux_listener_receive_ingress(M7MuxState *state,
                                          uint64_t timeout_ms,
                                          M7MuxListenerIngress *out_ingress) {
  struct sockaddr_storage peer = {0};
  size_t received_len = 0;
  int wait_rc = 0;
  int timeout = 0;

  if (state->socket_fd < 0) {
    return 0;
  }

  if (timeout_ms > (uint64_t)INT_MAX) {
    timeout_ms = (uint64_t)INT_MAX;
  }
  timeout = (int)timeout_ms;

  if (timeout >= 0) {
    wait_rc = state->ctx->socket->wait_readable(state->socket_fd, timeout);
    if (wait_rc <= 0) {
      return 0;
    }
  }

  memset(out_ingress, 0, sizeof(*out_ingress));
  if (!state->ctx->udp->recv(state->socket_fd,
                             out_ingress->buffer,
                             sizeof(out_ingress->buffer),
                             &peer,
                             &received_len)) {
    return 0;
  }

  out_ingress->len = received_len;
  out_ingress->encrypted = 0;
  if (!m7mux_listener_peer_to_ip(&peer, out_ingress->ip, sizeof(out_ingress->ip), &out_ingress->port)) {
    return 0;
  }

  out_ingress->available = 1;
  return 1;
}

static int m7mux_listener_demux(const M7MuxListenerIngress *ingress,
                                M7MuxListenerRouting *out_routing) {
  size_t i = 0;
  size_t route_len = 0;

  if (!ingress->available) {
    return 0;
  }

  memset(out_routing, 0, sizeof(*out_routing));

  for (i = 0; i < m7mux_demux_count(); ++i) {
    const M7MuxDemux *demux = m7mux_demux_at(i);

    route_len = demux->route_len;
    if (route_len == 0 || route_len > sizeof(out_routing->route)) {
      route_len = sizeof(out_routing->route);
    }

    if (!demux->detect(ingress->buffer, ingress->len, out_routing->route, route_len)) {
      continue;
    }

    out_routing->route_len = route_len;
    out_routing->available = 1;
    m7mux_listener_copy_ip(out_routing->adapter_name,
                            sizeof(out_routing->adapter_name),
                            demux->adapter_name);
    return 1;
  }

  return 0;
}

static void m7mux_listener_copy_normalized(const M7MuxListenerIngress *ingress,
                                           const M7MuxRecvContext *normalized,
                                           M7MuxRecvContext *out) {
  memset(out, 0, sizeof(*out));
  out->complete = normalized->complete;
  out->final = normalized->final;
  out->wire_version = normalized->wire_version;
  out->wire_form = normalized->wire_form;
  out->session_id = normalized->session_id;
  out->message_id = normalized->message_id;
  out->stream_id = normalized->stream_id;
  out->fragment_index = normalized->fragment_index;
  out->fragment_count = normalized->fragment_count;
  out->timestamp = normalized->timestamp;
  out->user_id = normalized->user_id;
  out->action_id = normalized->action_id;
  out->challenge = normalized->challenge;
  memcpy(out->hmac, normalized->hmac, sizeof(out->hmac));
  out->flags = normalized->flags;
  out->encrypted = normalized->encrypted;
  m7mux_listener_copy_ip(out->ip, sizeof(out->ip), normalized->ip);
  if (out->ip[0] == '\0') {
    m7mux_listener_copy_ip(out->ip, sizeof(out->ip), ingress->ip);
  }
  out->port = normalized->port != 0 ? normalized->port : ingress->port;
  out->payload = ingress->buffer;
  out->payload_len = normalized->payload_len != 0 ? normalized->payload_len : ingress->len;
}

static void m7mux_listener_build_unstructured(const M7MuxListenerIngress *ingress,
                                              M7MuxRecvContext *out) {
  memset(out, 0, sizeof(*out));
  m7mux_listener_copy_ip(out->ip, sizeof(out->ip), ingress->ip);
  out->port = ingress->port;
  out->encrypted = ingress->encrypted;
  out->payload = ingress->buffer;
  out->payload_len = ingress->len;
  out->complete = 1;
  out->final = 1;
  out->fragment_count = 1;
}

static int m7mux_listener_normalize(M7MuxState *state,
                                    const M7MuxListenerIngress *ingress,
                                    const M7MuxListenerRouting *routing,
                                    M7MuxRecvContext *out) {
  const M7MuxAdapter *adapter = NULL;
  M7MuxRecvContext normalized = {0};
  int rc = 0;

  (void)state;

  if (!ingress->available || !routing->available) {
    return 0;
  }

  adapter = m7mux_lookup_adapter(routing->adapter_name);
  rc = adapter->normalize(routing->route,
                          routing->route_len,
                          ingress->buffer,
                          ingress->len,
                          ingress->ip,
                          ingress->port,
                          ingress->encrypted,
                          &normalized);
  if (rc != M7MUX_NORMALIZE_OK && rc != M7MUX_NORMALIZE_ERR_OVERFLOW) {
    return 0;
  }

  m7mux_listener_copy_normalized(ingress, &normalized, out);
  return 1;
}

int m7mux_listener_drain(M7MuxState *state, uint64_t timeout_ms, M7MuxRecvContext *out) {
  if (!m7mux_listener_receive_ingress(state, timeout_ms, &state->listener.ingress)) {
    return 0;
  }

  if (!m7mux_listener_demux(&state->listener.ingress, &state->listener.routing)) {
    m7mux_listener_build_unstructured(&state->listener.ingress, out);
    state->listener.ingress.available = 0;
    return 1;
  }

  if (!m7mux_listener_normalize(state, &state->listener.ingress, &state->listener.routing, out)) {
    m7mux_listener_build_unstructured(&state->listener.ingress, out);
    state->listener.ingress.available = 0;
    return 1;
  }

  state->listener.ingress.available = 0;
  state->listener.routing.available = 0;
  return 1;
}
