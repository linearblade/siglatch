/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <string.h>

#include "server.h"
#include "../app.h"

static siglatch_payload_overflow_policy normalize_payload_overflow_effective(
    siglatch_payload_overflow_policy policy) {
  switch (policy) {
  case SL_PAYLOAD_OVERFLOW_REJECT:
  case SL_PAYLOAD_OVERFLOW_CLAMP:
    return policy;
  default:
    return SL_PAYLOAD_OVERFLOW_REJECT;
  }
}

static int server_init(void) {
  return 1;
}

static void server_shutdown(void) {
}

static const siglatch_server *server_select(const char *name) {
  const siglatch_server *current = NULL;

  if (!name) {
    return NULL;
  }

  current = app.config.server_by_name(name);
  if (!current || !current->enabled) {
    return NULL;
  }

  return current;
}

static int server_action_available(const siglatch_server *server, const char *action_name) {
  int i = 0;

  if (!server || !action_name) {
    return 0;
  }

  for (i = 0; i < server->action_count; ++i) {
    if (strcmp(server->actions[i], action_name) == 0) {
      return 1;
    }
  }

  return 0;
}

static int server_deaddrop_available(const siglatch_server *server, const char *deaddrop_name) {
  int i = 0;

  if (!server || !deaddrop_name) {
    return 0;
  }

  for (i = 0; i < server->deaddrop_count; ++i) {
    if (strcmp(server->deaddrops[i], deaddrop_name) == 0) {
      return 1;
    }
  }

  return 0;
}

static const siglatch_deaddrop *server_deaddrop_starts_with_buffer(
    const siglatch_server *server,
    const uint8_t *payload,
    size_t payload_len,
    char *match,
    int match_buf_size,
    size_t *matched_prefix_len) {
  int i = 0;

  if (!server || !payload || payload_len == 0) {
    return NULL;
  }

  for (i = 0; i < server->deaddrop_count; ++i) {
    const char *allowed = server->deaddrops[i];
    const siglatch_deaddrop *deaddrop = app.config.deaddrop_by_name(allowed);
    int j = 0;

    if (!deaddrop || !deaddrop->enabled) {
      continue;
    }

    for (j = 0; j < deaddrop->starts_with_count; ++j) {
      const char *prefix = deaddrop->starts_with[j];
      size_t prefix_len = strlen(prefix);

      if (prefix_len <= payload_len && memcmp(payload, prefix, prefix_len) == 0) {
        if (match && match_buf_size > 0) {
          snprintf(match, match_buf_size, "%s", prefix);
        }
        if (matched_prefix_len) {
          *matched_prefix_len = prefix_len;
        }
        return deaddrop;
      }
    }
  }

  return NULL;
}

static siglatch_payload_overflow_policy server_resolve_payload_overflow_by_action(
    const siglatch_server *server,
    uint32_t action_id) {
  const siglatch_config *cfg = NULL;
  const siglatch_action *action = NULL;
  siglatch_payload_overflow_policy effective = SL_PAYLOAD_OVERFLOW_REJECT;

  cfg = app.config.get();
  if (!cfg) {
    return effective;
  }

  effective = normalize_payload_overflow_effective(cfg->payload_overflow);

  if (server && server->payload_overflow != SL_PAYLOAD_OVERFLOW_INHERIT) {
    effective = normalize_payload_overflow_effective(server->payload_overflow);
  }

  action = app.config.action_by_id(action_id);
  if (action && action->payload_overflow != SL_PAYLOAD_OVERFLOW_INHERIT) {
    effective = normalize_payload_overflow_effective(action->payload_overflow);
  }

  return effective;
}

static const AppServerLib server_instance = {
  .init = server_init,
  .shutdown = server_shutdown,
  .select = server_select,
  .action_available = server_action_available,
  .deaddrop_available = server_deaddrop_available,
  .deaddrop_starts_with_buffer = server_deaddrop_starts_with_buffer,
  .resolve_payload_overflow_by_action = server_resolve_payload_overflow_by_action,
};

const AppServerLib *get_app_server_lib(void) {
  return &server_instance;
}
