/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX2_SESSION_H
#define LIB_PROTOCOL_UDP_M7MUX2_SESSION_H

#include <stddef.h>
#include <stdint.h>
//this is for mux state, but I dont think we need this any longer. leave commented out until your sure. then remove.
//#include "../m7mux2.h"
#include "../normalize/normalize.h"

#define M7MUX2_SESSION_SESSION_CAPACITY 64u
#define M7MUX2_SESSION_SESSION_TIMEOUT_MS 30000u

typedef struct {
  uint64_t session_id;
  uint64_t last_active_ms;
  uint64_t expires_at_ms;
  char ip[64];
  uint16_t client_port;
  int encrypted;
  int active;
} M7Mux2Session;


typedef struct {
  M7Mux2Session sessions[M7MUX2_SESSION_SESSION_CAPACITY];
  size_t session_count;
  uint64_t next_session_id;
} M7Mux2SessionState;


typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*state_init)(M7Mux2SessionState *state);
  void (*state_reset)(M7Mux2SessionState *state);
  int (*ingest)(M7Mux2SessionState *state, M7Mux2RecvPacket *normal);
  int (*release)(M7Mux2SessionState *state, uint64_t session_id);
  int (*expire)(M7Mux2SessionState *state, uint64_t now_ms);
} M7Mux2SessionLib;

const M7Mux2SessionLib *get_protocol_udp_m7mux2_session_lib(void);

#endif
