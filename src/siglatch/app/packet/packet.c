/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "packet.h"

#include "../app.h"
#include "../../lib.h"

static const char *app_packet_payload_overflow_policy_name(
    siglatch_payload_overflow_policy policy);
static int app_packet_enforce_payload_overflow_policy(
    AppRuntimeListenerState *listener,
    KnockPacket *pkt);

static int app_packet_init(void) {
  return 1;
}

static void app_packet_shutdown(void) {
}

static const char *app_packet_payload_overflow_policy_name(
    siglatch_payload_overflow_policy policy) {
  switch (policy) {
  case SL_PAYLOAD_OVERFLOW_REJECT:
    return "reject";
  case SL_PAYLOAD_OVERFLOW_CLAMP:
    return "clamp";
  case SL_PAYLOAD_OVERFLOW_INHERIT:
    return "inherit";
  default:
    return "unknown";
  }
}

static int app_packet_enforce_payload_overflow_policy(
    AppRuntimeListenerState *listener,
    KnockPacket *pkt) {
  siglatch_payload_overflow_policy policy = SL_PAYLOAD_OVERFLOW_REJECT;
  unsigned int raw_len = 0;
  unsigned int max_len = 0;

  if (!listener || !pkt) {
    return 0;
  }

  if (pkt->payload_len <= sizeof(pkt->payload)) {
    return 1;
  }

  raw_len = pkt->payload_len;
  max_len = (unsigned int)sizeof(pkt->payload);
  policy = app.server.resolve_payload_overflow_by_action(listener->server, pkt->action_id);

  if (policy == SL_PAYLOAD_OVERFLOW_CLAMP) {
    pkt->payload_len = (uint16_t)sizeof(pkt->payload);
    LOGW("[deserialize] payload_overflow=clamp action_id=%u payload_len=%u->%u\n",
         pkt->action_id, raw_len, (unsigned int)pkt->payload_len);
    return 1;
  }

  LOGW("[deserialize] payload_overflow=%s action_id=%u payload_len=%u max=%u; dropping packet\n",
       app_packet_payload_overflow_policy_name(policy),
       pkt->action_id,
       raw_len,
       max_len);
  return 0;
}

static int app_packet_consume_normalized(
    AppRuntimeListenerState *listener,
    const uint8_t *normalized_buffer,
    size_t normalized_len,
    SiglatchOpenSSLSession *session,
    const char *ip,
    uint16_t client_port,
    int is_encrypted) {
  KnockPacket pkt = {0};
  int payload_rc = 0;

  if (!listener || !normalized_buffer || !session || !ip) {
    return 0;
  }

  payload_rc = app.payload.codec.deserialize(normalized_buffer, normalized_len, &pkt);

  if (payload_rc == SL_PAYLOAD_OK) {
    LOGT("[deserialize] Valid %s KnockPacket - User ID: %u, Action ID: %u\n",
         is_encrypted ? "encrypted" : "unencrypted", pkt.user_id, pkt.action_id);
    app.payload.structured.handle(listener, &pkt, session, ip, client_port);
    return 1;
  }

  if (payload_rc == SL_PAYLOAD_ERR_OVERFLOW) {
    if (app_packet_enforce_payload_overflow_policy(listener, &pkt)) {
      LOGT("[deserialize] Overflow packet accepted by policy - User ID: %u, Action ID: %u, payload_len=%u\n",
           pkt.user_id, pkt.action_id, (unsigned int)pkt.payload_len);
      app.payload.structured.handle(listener, &pkt, session, ip, client_port);
    }
    return 1;
  }

  LOGW("[deserialize] Error: encrypted=%d; %s\n",
       is_encrypted,
       app.payload.codec.deserialize_strerror(payload_rc));
  app.payload.unstructured.handle(listener, normalized_buffer, normalized_len, ip);
  return 1;
}

static const AppPacketLib app_packet_instance = {
  .init = app_packet_init,
  .shutdown = app_packet_shutdown,
  .consume_normalized = app_packet_consume_normalized
};

const AppPacketLib *get_app_packet_lib(void) {
  return &app_packet_instance;
}
