/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_PAYLOAD_REPLY_H
#define SIGLATCH_SERVER_APP_PAYLOAD_REPLY_H

#define APP_ACTION_REPLY_MESSAGE_MAX 512

typedef struct {
  int should_reply;
  int ok;
  int truncated;
  char message[APP_ACTION_REPLY_MESSAGE_MAX];
} AppActionReply;

typedef struct {
  void (*reset)(AppActionReply *reply);
  int (*set)(AppActionReply *reply, int ok, const char *fmt, ...);
} AppPayloadReplyLib;

void app_action_reply_reset(AppActionReply *reply);
int app_action_reply_set(AppActionReply *reply, int ok, const char *fmt, ...);

#endif
