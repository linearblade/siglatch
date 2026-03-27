/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

/*
 * NOTE:
 * This header still carries some transplanted daemon2/connection concepts
 * while we shape m7mux. The session-oriented pieces here are not part of the
 * minimal lib.protocol.udp.m7mux model yet and should be treated as staging
 * scaffolding, not the final transport contract.
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_OUTBOUND_H
#define LIB_PROTOCOL_UDP_M7MUX_OUTBOUND_H

#include <stddef.h>
#include <stdint.h>

#define M7MUX_SESSION_BUFFER_SIZE 1024u
#define M7MUX_SESSION_SESSION_CAPACITY 64u
#define M7MUX_SESSION_OUTBOUND_QUEUE_CAPACITY 64u
#define M7MUX_SESSION_SESSION_TIMEOUT_MS 30000u

typedef struct {
  uint64_t session_id;
  uint64_t last_active_ms;
  uint64_t expires_at_ms;
  char ip[64];
  uint16_t client_port;
  int encrypted;
  int active;
} M7MuxSession;


typedef struct {
  uint8_t buffer[M7MUX_SESSION_BUFFER_SIZE];
  size_t len;
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  int available;
} M7MuxLocalIntent;

typedef struct {
  uint8_t buffer[M7MUX_SESSION_BUFFER_SIZE];
  size_t len;
  char ip[64];
  uint16_t client_port;
  int encrypted;
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  int available;
} M7MuxOutbound;


typedef struct {
  M7MuxSession sessions[M7MUX_SESSION_SESSION_CAPACITY];
  size_t session_count;

  M7MuxOutbound outbound_queue[M7MUX_SESSION_OUTBOUND_QUEUE_CAPACITY];
  size_t outbound_head;
  size_t outbound_tail;
  size_t outbound_count;

  int sock;
  uint64_t next_session_id;
} M7MuxSessionState;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*outbound_ready)(const M7MuxSessionState *state);
  int (*drain)(M7MuxSessionState *state, M7MuxStream *out_job);
  int (*enqueue_local)(M7MuxSessionState *state, const M7MuxLocalIntent *intent);
  int (*stage_outbound)(M7MuxSessionState *state, const M7MuxStream *job);
  int (*enqueue_outbound)(M7MuxSessionState *state, const M7MuxOutbound *outbound);
  int (*flush_outbound)(M7MuxSessionState *state, uint64_t now_ms);
} M7MuxSessionLib;

const M7MuxSessionLib *get_protocol_udp_m7mux_session_lib(void);

#endif
