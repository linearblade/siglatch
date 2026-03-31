/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "reply.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void app_action_reply_reset(AppActionReply *reply) {
  if (!reply) {
    return;
  }

  memset(reply, 0, sizeof(*reply));
}

int app_action_reply_set(AppActionReply *reply, int ok, const char *fmt, ...) {
  va_list args;
  int written = 0;

  if (!reply) {
    return 0;
  }

  app_action_reply_reset(reply);
  reply->should_reply = 1;
  reply->ok = ok ? 1 : 0;

  if (!fmt || fmt[0] == '\0') {
    return 1;
  }

  va_start(args, fmt);
  written = vsnprintf(reply->message, sizeof(reply->message), fmt, args);
  va_end(args);

  if (written < 0) {
    reply->message[0] = '\0';
    return 0;
  }

  if ((size_t)written >= sizeof(reply->message)) {
    reply->truncated = 1;
  }

  return 1;
}
