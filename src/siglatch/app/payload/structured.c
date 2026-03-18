/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "structured.h"

#include <stdio.h>

#include "../app.h"
#include "../../../shared/shared.h"
#include "../../lib.h"
#include "../../../stdlib/base64.h"
#include "../../../stdlib/utils.h"

static int app_payload_structured_validate_payload(
    AppRuntimeListenerState *listener,
    const KnockPacket *pkt);
static int app_payload_structured_dispatch_action(
    AppRuntimeListenerState *listener,
    const KnockPacket *pkt,
    SiglatchOpenSSLSession *session,
    const siglatch_user *user,
    const char *ip_addr,
    int valid_signature);

int app_payload_structured_init(void) {
  return 1;
}

void app_payload_structured_shutdown(void) {
}

void app_payload_structured_handle(
    AppRuntimeListenerState *listener,
    const KnockPacket *pkt,
    SiglatchOpenSSLSession *session,
    const char *ip) {
  const siglatch_user *user = NULL;
  int signature_valid = 0;

  if (!listener || !listener->server || !pkt) {
    LOGE("Null packet passed to structured payload handler\n");
    return;
  }

  if (pkt->payload_len > sizeof(pkt->payload)) {
    LOGE("Dropping packet with invalid payload_len=%u (max=%zu)\n",
         pkt->payload_len, sizeof(pkt->payload));
    return;
  }

  if (!app_payload_structured_validate_payload(listener, pkt)) {
    LOGW("Packet failed semantic validation (e.g. replay nonce)\n");
    return;
  }

  dumpDigest("Received Packet HMAC (server)", pkt->hmac, sizeof(pkt->hmac));
  shared.knock.debug.dump_packet_fields("Server Received Packet", pkt);

  user = app.config.user_by_id(pkt->user_id);
  if (!user) {
    LOGW("No matching enabled user for user_id %u\n", pkt->user_id);
    return;
  }

  if (!app.inbound.crypto.assign_session_to_user(session, user)) {
    LOGE("Failed to assign session to user ID: %u\n", pkt->user_id);
    return;
  }

  signature_valid = app.inbound.crypto.validate_signature(session, pkt);
  if (!signature_valid) {
    LOGE("Dropping structured packet due to invalid signature (user_id=%u action_id=%u)\n",
         pkt->user_id, pkt->action_id);
    return;
  }

  LOGD("routing to handle packet...\n");
  app_payload_structured_dispatch_action(listener, pkt, session, user, ip, signature_valid);
}

static int app_payload_structured_validate_payload(
    AppRuntimeListenerState *listener,
    const KnockPacket *pkt) {
  time_t now = 0;
  char nonce_str[64];

  if (!listener || !pkt) {
    LOGE("[validate] Invalid structured payload validation arguments\n");
    return 0;
  }

  now = lib.time.now();
  snprintf(nonce_str, sizeof(nonce_str), "%u-%u", pkt->timestamp, pkt->challenge);

  if (lib.nonce.check(&listener->nonce, nonce_str, now)) {
    LOGW("[validate] Replay detected for nonce: %s\n", nonce_str);
    return 0;
  }

  LOGT("[validate] Nonce accepted: %s\n", nonce_str);
  lib.nonce.add(&listener->nonce, nonce_str, now);
  return 1;
}

static int app_payload_structured_dispatch_action(
    AppRuntimeListenerState *listener,
    const KnockPacket *pkt,
    SiglatchOpenSSLSession *session,
    const siglatch_user *user,
    const char *ip_addr,
    int valid_signature) {
  const siglatch_action *action = NULL;
  AppBuiltinContext builtin_ctx = {0};
  char payload_b64[512] = {0};
  char user_id_str[16];
  char action_id_str[16];
  char encrypted_str[8];
  char *argv[8] = {0};

  LOGD("TRYING HANDLE PACKET\n");

  if (!listener || !listener->server || !pkt || !session || !user || !ip_addr) {
    LOGE("[handle] Invalid arguments to handle_packet\n");
    return 0;
  }

  if (pkt->payload_len > sizeof(pkt->payload)) {
    LOGE("[handle] Invalid payload_len=%u (max=%zu)\n", pkt->payload_len, sizeof(pkt->payload));
    return 0;
  }

  if (!valid_signature) {
    LOGE("[handle] Invalid signature; dropping packet\n");
    return 0;
  }

  LOGT("signature validated\n");

  if (user->name[0] == '\0') {
    LOGE("[handle] User found for ID=%u, but username is NULL\n", pkt->user_id);
    return 0;
  }

  action = app.config.action_by_id(pkt->action_id);
  if (!action) {
    LOGW("[handle] Unknown action ID: %u\n", pkt->action_id);
    return 0;
  }

  if (!app.server.action_available(listener->server, action->name)) {
    LOGE("[handle] Action (%s) not permitted on this server.\n", action->name);
    return 0;
  }

  if (!app.config.action_available_by_user(pkt->user_id, action->name)) {
    LOGE("[handle] Action (%s) not permitted by this user(%s).\n", action->name, user->name);
    return 0;
  }

  if (!action->enabled) {
    LOGE("[handle] Action is disabled.\n");
    return 0;
  }

  if (!app.policy.request_ip_allowed(listener->server, user, action, ip_addr)) {
    if (!app.policy.server_ip_allowed(listener->server, ip_addr)) {
      LOGE("[handle] Source IP (%s) is not permitted on this server(%s).\n",
           ip_addr,
           listener->server->name);
      return 0;
    }

    if (!app.policy.user_ip_allowed(user, ip_addr)) {
      LOGE("[handle] Source IP (%s) is not permitted for user(%s).\n",
           ip_addr,
           user->name);
      return 0;
    }

    if (!app.policy.action_ip_allowed(action, ip_addr)) {
      LOGE("[handle] Source IP (%s) is not permitted for action(%s).\n",
           ip_addr,
           action->name);
      return 0;
    }

    LOGE("[handle] Source IP (%s) is not permitted by request policy.\n", ip_addr);
    return 0;
  }

  if (app.builtin.is_action(action)) {
    if (!app.builtin.build_context(
            &builtin_ctx, listener, pkt, session, user, action, ip_addr)) {
      LOGE("[handle] Failed to build builtin context for action (%s)\n", action->name);
      return 0;
    }

    LOGD("[handle] Routing to builtin: %s (Ip=%s, User=%s, Action=%s)\n",
         action->builtin,
         ip_addr,
         user->name,
         action->name);

    return app.builtin.handle(&builtin_ctx);
  }

  if (action->constructor[0] == '\0') {
    LOGW("[handle] Shell action ID %u has no constructor\n", pkt->action_id);
    return 0;
  }

  base64_encode(pkt->payload, pkt->payload_len, payload_b64, sizeof(payload_b64));

  snprintf(user_id_str, sizeof(user_id_str), "%u", pkt->user_id);
  snprintf(action_id_str, sizeof(action_id_str), "%u", pkt->action_id);
  snprintf(encrypted_str, sizeof(encrypted_str), "%d", listener->server->secure ? 1 : 0);

  argv[0] = (char *)ip_addr;
  argv[1] = user_id_str;
  argv[2] = (char *)user->name;
  argv[3] = action_id_str;
  argv[4] = (char *)action->name;
  argv[5] = encrypted_str;
  argv[6] = payload_b64;
  argv[7] = NULL;

  LOGD("[handle] Routing to script: %s (Ip=%s, User=%s, Action=%s,execSplit = %d)\n",
       action->constructor,
       ip_addr,
       user->name,
       action->name,
       action->exec_split);

  return app.payload.run_shell(action->constructor, 7, argv, action->exec_split);
}
