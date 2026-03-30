/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_SESSION_H
#define LIB_PROTOCOL_UDP_M7MUX_SESSION_H

#include <stddef.h>
#include <stdint.h>
//this is for mux state, but I dont think we need this any longer. leave commented out until your sure. then remove.
//#include "../m7mux.h"
#include "../normalize/normalize.h"

#define M7MUX_SESSION_SESSION_CAPACITY 64u
#define M7MUX_SESSION_SESSION_TIMEOUT_MS 30000u

typedef struct {
  uint64_t session_id;
  uint64_t last_active_ms;
  uint64_t expires_at_ms;
  uint32_t wire_version;
  uint8_t wire_form;
  char ip[64];
  uint16_t client_port;
  int encrypted;
  int active;
} M7MuxSession;


typedef struct {
  M7MuxSession sessions[M7MUX_SESSION_SESSION_CAPACITY];
  size_t session_count;
  uint64_t next_session_id;
} M7MuxSessionState;


typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*state_init)(M7MuxSessionState *state);
  void (*state_reset)(M7MuxSessionState *state);
  int (*ingest)(M7MuxSessionState *state, M7MuxRecvPacket *normal);
  int (*release)(M7MuxSessionState *state, uint64_t session_id);
  int (*expire)(M7MuxSessionState *state, uint64_t now_ms);
} M7MuxSessionLib;

const M7MuxSessionLib *get_protocol_udp_m7mux_session_lib(void);

#endif
