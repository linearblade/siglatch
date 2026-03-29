/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "sample_blurt.h"

#include <ctype.h>
#include <string.h>

#include "../../lib.h"

static int siglatch_object_sample_blurt_payload_is_ascii(
    const uint8_t *payload,
    size_t payload_len);

int siglatch_object_sample_blurt_static_init(void) {
  return 1;
}

void siglatch_object_sample_blurt_static_shutdown(void) {
}

int siglatch_object_sample_blurt_static_handle(const AppObjectContext *ctx, AppActionReply *reply) {
  char payload_text[APP_ACTION_REPLY_MESSAGE_MAX] = {0};
  size_t payload_len = 0;

  if (!ctx || !ctx->action || !ctx->user || !ctx->job || !reply) {
    LOGE("[object:sample_blurt_static] Invalid object context\n");
    return 0;
  }

  payload_len = ctx->job->request.payload_len;
  lib.log.emit(LOG_INFO,
               1,
               "[object:sample_blurt_static] user=%s ip=%s payload_len=%u server=%s",
               ctx->user->name,
               ctx->ip_addr,
               (unsigned int)payload_len,
               ctx->listener && ctx->listener->server ? ctx->listener->server->name : "(none)");

  if (payload_len == 0) {
    app_action_reply_set(reply, 1, "SAMPLE_STATIC_BLURT (empty)");
    return 1;
  }

  if (!ctx->job->request.payload_buffer) {
    LOGE("[object:sample_blurt_static] payload buffer missing for non-empty job\n");
    app_action_reply_set(reply, 0, "INVALID_PAYLOAD");
    return 0;
  }

  if (!siglatch_object_sample_blurt_payload_is_ascii(ctx->job->request.payload_buffer, payload_len)) {
    app_action_reply_set(reply, 1, "SAMPLE_STATIC_BLURT payload skipped");
    return 1;
  }

  if (payload_len >= sizeof(payload_text)) {
    payload_len = sizeof(payload_text) - 1;
  }

  memcpy(payload_text, ctx->job->request.payload_buffer, payload_len);
  payload_text[payload_len] = '\0';
  app_action_reply_set(reply, 1, "%s", payload_text);
  return 1;
}

static int siglatch_object_sample_blurt_payload_is_ascii(
    const uint8_t *payload,
    size_t payload_len) {
  size_t i = 0;

  if (!payload) {
    return 0;
  }

  for (i = 0; i < payload_len; ++i) {
    if (payload[i] == '\n' || payload[i] == '\r' || payload[i] == '\t') {
      continue;
    }

    if (!isprint((unsigned char)payload[i])) {
      return 0;
    }
  }

  return 1;
}
