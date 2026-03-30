/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON_CONNECTION_H
#define SIGLATCH_SERVER_APP_DAEMON_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

#include "packet.h"

#define APP_CONNECTION_SESSION_CAPACITY 64u

typedef struct {
  uint64_t expires_at_ms;
  int active;
} AppConnectionSession;

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
  char ip[64];
  uint16_t client_port;
  int encrypted;
  int wire_auth;
  AppDaemonRequestPacket request;
  uint8_t *response_buffer;
  size_t response_len;
  size_t response_cap;
} AppConnectionJob;

typedef struct {
  AppConnectionSession sessions[APP_CONNECTION_SESSION_CAPACITY];
} AppConnectionState;

#endif
