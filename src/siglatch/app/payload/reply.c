/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "reply.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../app.h"
#include "../../../shared/shared.h"
#include "../../../shared/knock/response.h"
#include "../../lib.h"

static int app_payload_reply_action_prefix(uint8_t action_id, char *out, size_t out_size);

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

int app_payload_reply_send_v1(AppRuntimeListenerState *listener,
                              SiglatchOpenSSLSession *session,
                              const KnockPacket *request_pkt,
                              const char *ip_addr,
                              uint16_t client_port,
                              const AppActionReply *reply) {
  KnockPacket response_pkt = {0};
  uint8_t digest[32] = {0};
  uint8_t packed[512] = {0};
  uint8_t output[512] = {0};
  size_t output_len = 0;
  size_t message_len = 0;
  size_t rendered_len = 0;
  size_t max_text_len = 0;
  int packed_len = 0;
  uint8_t flags = 0;
  char action_prefix[64] = {0};
  char rendered_message[APP_ACTION_REPLY_MESSAGE_MAX + MAX_ACTION_NAME + 8] = {0};

  if (!listener || !session || !request_pkt || !ip_addr || !reply) {
    return 0;
  }

  if (!reply->should_reply) {
    return 1;
  }

  if (client_port == 0) {
    LOGE("[reply] Client source port is unavailable; cannot send response\n");
    return 0;
  }

  response_pkt.version = request_pkt->version ? request_pkt->version : 1;
  response_pkt.timestamp = (uint32_t)lib.time.unix_ts();
  response_pkt.user_id = request_pkt->user_id;
  response_pkt.action_id = SL_KNOCK_RESPONSE_ACTION_ID;
  response_pkt.challenge = request_pkt->challenge;

  response_pkt.payload[0] = reply->ok ? SL_KNOCK_RESPONSE_STATUS_OK
                                      : SL_KNOCK_RESPONSE_STATUS_ERROR;
  response_pkt.payload[1] = request_pkt->action_id;

  if (app_payload_reply_action_prefix(request_pkt->action_id,
                                      action_prefix,
                                      sizeof(action_prefix))) {
    if (reply->message[0] != '\0') {
      snprintf(rendered_message, sizeof(rendered_message), "%s: %s",
               action_prefix, reply->message);
    } else {
      snprintf(rendered_message, sizeof(rendered_message), "%s", action_prefix);
    }
  } else if (reply->message[0] != '\0') {
    snprintf(rendered_message, sizeof(rendered_message), "%s", reply->message);
  }

  max_text_len = sizeof(response_pkt.payload) - SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE;
  rendered_len = strnlen(rendered_message, sizeof(rendered_message));
  message_len = rendered_len;
  if (message_len > max_text_len) {
    message_len = max_text_len;
    flags |= SL_KNOCK_RESPONSE_FLAG_TRUNCATED;
  }

  if (reply->truncated || rendered_len >= sizeof(rendered_message)) {
    flags |= SL_KNOCK_RESPONSE_FLAG_TRUNCATED;
  }

  response_pkt.payload[2] = flags;

  if (message_len > 0) {
    memcpy(response_pkt.payload + SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE,
           rendered_message,
           message_len);
  }

  response_pkt.payload_len = (uint16_t)(SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE + message_len);

  if (!shared.knock.digest.generate(&response_pkt, digest)) {
    LOGE("[reply] Failed to generate reply digest\n");
    return 0;
  }

  if (!lib.openssl.sign(session, digest, response_pkt.hmac)) {
    LOGE("[reply] Failed to sign reply packet\n");
    return 0;
  }

  packed_len = shared.knock.codec.pack(&response_pkt, packed, sizeof(packed));
  if (packed_len <= 0) {
    LOGE("[reply] Failed to pack reply packet\n");
    return 0;
  }

  if (listener->server && listener->server->secure) {
    if (!session->public_key) {
      LOGE("[reply] Secure reply requested but user public key is unavailable\n");
      return 0;
    }

    if (!lib.openssl.session_encrypt(session, packed, (size_t)packed_len, output, &output_len)) {
      LOGE("[reply] Failed to encrypt reply packet\n");
      return 0;
    }
  } else {
    memcpy(output, packed, (size_t)packed_len);
    output_len = (size_t)packed_len;
  }

  if (!lib.net.udp.send(listener->sock, ip_addr, client_port, output, output_len)) {
    LOGE("[reply] Failed to send reply to %s:%u\n", ip_addr, (unsigned int)client_port);
    return 0;
  }

  return 1;
}

static int app_payload_reply_action_prefix(uint8_t action_id, char *out, size_t out_size) {
  const siglatch_action *action = NULL;

  if (!out || out_size == 0 || action_id == 0) {
    return 0;
  }

  action = app.config.action_by_id(action_id);
  if (action && action->label[0] != '\0') {
    snprintf(out, out_size, "%s", action->label);
    return 1;
  }

  snprintf(out, out_size, "%u", (unsigned int)action_id);
  return 1;
}
