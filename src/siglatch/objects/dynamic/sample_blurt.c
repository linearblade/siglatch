/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "../../app/object/types.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int sample_blurt_dynamic_payload_is_ascii(const uint8_t *payload, size_t payload_len);
static int sample_blurt_dynamic_reply_set(AppActionReply *reply, int ok, const char *fmt, ...);

int sample_blurt_dynamic_handle(const AppObjectContext *ctx, AppActionReply *reply) {
  char payload_text[APP_ACTION_REPLY_MESSAGE_MAX] = {0};
  size_t payload_len = 0;

  if (!ctx || !ctx->action || !ctx->user || !ctx->job || !reply) {
    return 0;
  }

  payload_len = ctx->job->request.payload_len;

  if (payload_len == 0) {
    sample_blurt_dynamic_reply_set(reply, 1, "SAMPLE_DYNAMIC_BLURT (empty)");
    return 1;
  }

  if (!ctx->job->request.payload_buffer) {
    sample_blurt_dynamic_reply_set(reply, 0, "INVALID_PAYLOAD");
    return 0;
  }

  if (!sample_blurt_dynamic_payload_is_ascii(ctx->job->request.payload_buffer, payload_len)) {
    sample_blurt_dynamic_reply_set(reply, 1, "SAMPLE_DYNAMIC_BLURT payload skipped");
    return 1;
  }

  if (payload_len >= sizeof(payload_text)) {
    payload_len = sizeof(payload_text) - 1;
  }

  memcpy(payload_text, ctx->job->request.payload_buffer, payload_len);
  payload_text[payload_len] = '\0';
  sample_blurt_dynamic_reply_set(reply, 1, "%s", payload_text);
  return 1;
}

static int sample_blurt_dynamic_payload_is_ascii(const uint8_t *payload, size_t payload_len) {
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

static int sample_blurt_dynamic_reply_set(AppActionReply *reply, int ok, const char *fmt, ...) {
  va_list args;
  int written = 0;

  if (!reply) {
    return 0;
  }

  memset(reply, 0, sizeof(*reply));
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
