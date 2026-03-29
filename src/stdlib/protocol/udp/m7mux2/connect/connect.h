/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX2_CONNECT_H
#define LIB_PROTOCOL_UDP_M7MUX2_CONNECT_H

#include <stdint.h>

typedef struct M7Mux2Context M7Mux2Context;
typedef struct M7Mux2State M7Mux2State;

typedef struct {
  int (*init)(const M7Mux2Context *ctx);
  int (*set_context)(const M7Mux2Context *ctx);
  void (*shutdown)(void);

  int (*state_init)(M7Mux2State *state);
  void (*state_reset)(M7Mux2State *state);

  M7Mux2State *(*connect_ip)(const char *ip, uint16_t port);
  M7Mux2State *(*connect_socket)(int socket_fd);
  void (*disconnect)(M7Mux2State *state);
} M7Mux2ConnectLib;

const M7Mux2ConnectLib *get_protocol_udp_m7mux2_connect_lib(void);

#endif
