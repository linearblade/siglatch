/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_LISTENER_H
#define SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_LISTENER_H

#include <stddef.h>
#include <stdint.h>

#include "../m7mux.h"

#define M7MUX_LISTENER_MAX_PACKET_SIZE 65535u
#define M7MUX_LISTENER_MAX_ROUTE_SIZE 256u

typedef struct {
  uint8_t buffer[M7MUX_LISTENER_MAX_PACKET_SIZE];
  size_t len;
  char ip[64];
  uint16_t port;
  int encrypted;
  int available;
} M7MuxListenerIngress;

typedef struct {
  char adapter_name[64];
  uint8_t route[M7MUX_LISTENER_MAX_ROUTE_SIZE];
  size_t route_len;
  int available;
} M7MuxListenerRouting;

typedef struct M7MuxListenerState {
  M7MuxListenerIngress ingress;
  M7MuxListenerRouting routing;
} M7MuxListenerState;

typedef struct M7MuxState {
  const M7MuxContext *ctx;
  int socket_fd;
  int owns_socket;
  int connected;
  uint64_t session_id;
  uint64_t next_session_id;
  uint64_t next_message_id;
  uint32_t next_stream_id;
  char remote_ip[64];
  uint16_t remote_port;
  M7MuxListenerState listener;
} M7MuxState;

size_t m7mux_demux_count(void);
const M7MuxDemux *m7mux_demux_at(size_t index);
const M7MuxAdapter *m7mux_lookup_adapter(const char *name);

int m7mux_listener_drain(M7MuxState *state, uint64_t timeout_ms, M7MuxRecvContext *out);

#endif /* SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_LISTENER_H */
