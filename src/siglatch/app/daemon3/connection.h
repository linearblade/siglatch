/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON3_CONNECTION_H
#define SIGLATCH_SERVER_APP_DAEMON3_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

#define APP_CONNECTION_BUFFER_SIZE 1024u
#define APP_CONNECTION_SESSION_CAPACITY 64u
#define APP_CONNECTION_OUTBOUND_QUEUE_CAPACITY 64u
#define APP_CONNECTION_SESSION_TIMEOUT_MS 30000u

typedef struct {
  uint64_t session_id;
  uint64_t last_active_ms;
  uint64_t expires_at_ms;
  char ip[64];
  uint16_t client_port;
  int encrypted;
  int active;
} AppConnectionSession;

typedef struct {
  uint8_t buffer[APP_CONNECTION_BUFFER_SIZE];
  size_t len;
  char ip[64];
  uint16_t client_port;
  int encrypted;
  int available;
} AppConnectionIngress;

typedef struct {
  uint8_t buffer[APP_CONNECTION_BUFFER_SIZE];
  size_t len;
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  int available;
} AppConnectionLocalIntent;

typedef struct {
  uint8_t buffer[APP_CONNECTION_BUFFER_SIZE];
  size_t len;
  char ip[64];
  uint16_t client_port;
  int encrypted;
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  int available;
} AppConnectionOutbound;

typedef struct {
  int complete;
  int should_reply;
  int synthetic_session;
  uint32_t wire_version;
  uint8_t wire_form;
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  uint32_t fragment_index;
  uint32_t fragment_count;
  uint32_t timestamp;
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint8_t hmac[32];
  char ip[64];
  uint16_t client_port;
  int encrypted;
  uint8_t payload_buffer[APP_CONNECTION_BUFFER_SIZE];
  size_t payload_len;
  uint8_t response_buffer[APP_CONNECTION_BUFFER_SIZE];
  size_t response_len;
} AppConnectionJob;

typedef struct {
  AppConnectionSession sessions[APP_CONNECTION_SESSION_CAPACITY];
  size_t session_count;

  AppConnectionOutbound outbound_queue[APP_CONNECTION_OUTBOUND_QUEUE_CAPACITY];
  size_t outbound_head;
  size_t outbound_tail;
  size_t outbound_count;

  int sock;
  uint64_t next_session_id;
} AppConnectionState;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*state_init)(AppConnectionState *state);
  void (*state_reset)(AppConnectionState *state);
  int (*outbound_ready)(const AppConnectionState *state);
  int (*ingest)(AppConnectionState *state, AppConnectionJob *job);
  int (*drain)(AppConnectionState *state, AppConnectionJob *out_job);
  int (*enqueue_local)(AppConnectionState *state, const AppConnectionLocalIntent *intent);
  int (*stage_outbound)(AppConnectionState *state, const AppConnectionJob *job);
  int (*enqueue_outbound)(AppConnectionState *state, const AppConnectionOutbound *outbound);
  int (*release_session)(AppConnectionState *state, uint64_t session_id);
  int (*expire_sessions)(AppConnectionState *state, uint64_t now_ms);
  int (*flush_outbound)(AppConnectionState *state, uint64_t now_ms);
} AppConnectionLib;

#endif
