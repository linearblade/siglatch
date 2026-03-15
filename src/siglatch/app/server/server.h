/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_SERVER_H
#define SIGLATCH_SERVER_APP_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "../config/config.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  const siglatch_server *(*select)(const char *name);
  int (*action_available)(const siglatch_server *server, const char *action_name);
  int (*deaddrop_available)(const siglatch_server *server, const char *deaddrop_name);
  const siglatch_deaddrop *(*deaddrop_starts_with_buffer)(
      const siglatch_server *server,
      const uint8_t *payload,
      size_t payload_len,
      char *match,
      int match_buf_size,
      size_t *matched_prefix_len);
  siglatch_payload_overflow_policy (*resolve_payload_overflow_by_action)(
      const siglatch_server *server,
      uint32_t action_id);
} AppServerLib;

const AppServerLib *get_app_server_lib(void);

#endif
