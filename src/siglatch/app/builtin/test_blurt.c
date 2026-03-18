/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "test_blurt.h"

#include <string.h>

#include "../../lib.h"

static int app_builtin_test_blurt_payload_is_ascii(
    const uint8_t *payload,
    size_t payload_len);

int app_builtin_test_blurt_init(void) {
  return 1;
}

void app_builtin_test_blurt_shutdown(void) {
}

int app_builtin_test_blurt_handle(const AppBuiltinContext *ctx) {
  char payload_text[257] = {0};
  size_t copy_len = 0;

  if (!ctx || !ctx->listener || !ctx->packet || !ctx->user || !ctx->action || !ctx->ip_addr) {
    LOGE("[builtin:test_blurt] Invalid builtin context\n");
    return 0;
  }

  lib.log.emit(LOG_INFO, 1,
               "[builtin:test_blurt] action=%s user=%s ip=%s payload_len=%u server=%s",
               ctx->action->name,
               ctx->user->name,
               ctx->ip_addr,
               (unsigned int)ctx->packet->payload_len,
               (ctx->listener->server && ctx->listener->server->name[0] != '\0')
                   ? ctx->listener->server->name
                   : "(none)");

  if (ctx->packet->payload_len == 0) {
    lib.log.emit(LOG_INFO, 1, "[builtin:test_blurt] payload=(empty)");
    return 1;
  }

  if (!app_builtin_test_blurt_payload_is_ascii(
          ctx->packet->payload,
          ctx->packet->payload_len)) {
    lib.log.emit(LOG_INFO, 1,
                 "[builtin:test_blurt] payload is not printable ASCII; skipping text dump");
    return 1;
  }

  copy_len = ctx->packet->payload_len;
  if (copy_len >= sizeof(payload_text)) {
    copy_len = sizeof(payload_text) - 1;
  }

  memcpy(payload_text, ctx->packet->payload, copy_len);
  payload_text[copy_len] = '\0';

  lib.log.emit(LOG_INFO, 1, "[builtin:test_blurt] payload=%s", payload_text);
  return 1;
}

static int app_builtin_test_blurt_payload_is_ascii(
    const uint8_t *payload,
    size_t payload_len) {
  size_t i = 0;

  if (!payload) {
    return 0;
  }

  for (i = 0; i < payload_len; ++i) {
    if (payload[i] == '\t' || payload[i] == '\n' || payload[i] == '\r') {
      continue;
    }

    if (payload[i] < 32 || payload[i] > 126) {
      return 0;
    }
  }

  return 1;
}
