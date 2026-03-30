/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_OPTS_CONTRACT_H
#define SIGLATCH_KNOCK_APP_OPTS_CONTRACT_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "../../../stdlib/log.h"

/* Shared option/type contract for knocker app modules. */

typedef enum {
  HMAC_MODE_NONE = 0,
  HMAC_MODE_NORMAL = 1,
  HMAC_MODE_DUMMY = 2
} HmacMode;

typedef enum {
  KNOCK_PROTOCOL_V1 = 1,
  KNOCK_PROTOCOL_V2 = 2,
  KNOCK_PROTOCOL_V3 = 3
} KnockProtocol;

typedef enum {
  OPTS_RESPONSE_HELP = 1,
  OPTS_RESPONSE_ERROR = 2,
  OPTS_RESPONSE_ALIAS = 3,
  OPTS_RESPONSE_TRANSMIT = 4
} OptsResponseType;

/*
 * Keep room for the v3 bootstrap payloads. The actual structured packet
 * limit is lower, but the client payload buffer should not be the bottleneck.
 */
#define MAX_PAYLOAD_SIZE 513

typedef struct {
  char hmac_key_path[PATH_MAX];
  char server_pubkey_path[PATH_MAX];
  char client_privkey_path[PATH_MAX];
  char log_file[PATH_MAX];
  LogLevel log_level;

  char host[256];
  char user_selector[128];
  char send_from_ip[64];
  uint16_t port;

  HmacMode hmac_mode;
  KnockProtocol protocol;
  int encrypt;
  int dead_drop;
  int output_mode;
  int stdin_requested;

  uint32_t user_id;
  uint32_t action_id;
  uint8_t payload[MAX_PAYLOAD_SIZE];
  size_t payload_len;

  int verbose;
  OptsResponseType response_type;
} Opts;

#endif
