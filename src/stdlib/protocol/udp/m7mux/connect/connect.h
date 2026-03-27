/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_CONNECT_H
#define LIB_PROTOCOL_UDP_M7MUX_CONNECT_H

#include <stdint.h>

typedef struct M7MuxContext M7MuxContext;
typedef struct M7MuxState M7MuxState;

typedef struct {
  int (*init)(const M7MuxContext *ctx);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);

  int (*state_init)(M7MuxState *state);
  void (*state_reset)(M7MuxState *state);

  M7MuxState *(*connect_ip)(const char *ip, uint16_t port);
  M7MuxState *(*connect_socket)(int socket_fd);
  void (*disconnect)(M7MuxState *state);
} M7MuxConnectLib;

const M7MuxConnectLib *get_protocol_udp_m7mux_connect_lib(void);

#endif
