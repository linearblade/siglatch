/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_PAYLOAD_REPLY_H
#define SIGLATCH_SERVER_APP_PAYLOAD_REPLY_H

#include <stdint.h>

#include "../runtime/runtime.h"
#include "codec/codec.h"
#include "../../../stdlib/openssl_session.h"

#define APP_ACTION_REPLY_MESSAGE_MAX 512

typedef struct {
  int should_reply;
  int ok;
  int truncated;
  char message[APP_ACTION_REPLY_MESSAGE_MAX];
} AppActionReply;

void app_action_reply_reset(AppActionReply *reply);
int app_action_reply_set(AppActionReply *reply, int ok, const char *fmt, ...);

int app_payload_reply_send_v1(AppRuntimeListenerState *listener,
                              SiglatchOpenSSLSession *session,
                              const KnockPacket *request_pkt,
                              const char *ip_addr,
                              uint16_t client_port,
                              const AppActionReply *reply);

#endif
