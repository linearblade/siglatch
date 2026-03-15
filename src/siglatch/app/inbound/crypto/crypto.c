/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "crypto.h"

#include <string.h>

#include "../../app.h"
#include "../../../lib.h"
#include "../../../../stdlib/utils.h"

int app_inbound_crypto_init(void) {
  return 1;
}

void app_inbound_crypto_shutdown(void) {
}

int app_inbound_crypto_init_session_for_server(
    const siglatch_server *server,
    SiglatchOpenSSLSession *session) {
  if (!server || !session) {
    lib.log.console("NULL session pointer passed to server OpenSSL initializer\n");
    return 0;
  }

  if (!lib.openssl.session_init(session)) {
    lib.log.console("Failed to initialize OpenSSL session\n");
    return 0;
  }

  if (server->secure) {
    if (!server->priv_key) {
      lib.log.console("Secure server selected but private key is missing\n");
      return 0;
    }
    session->private_key = server->priv_key;
  } else {
    session->private_key = NULL;
  }

  return 1;
}

int app_inbound_crypto_assign_session_to_user(
    SiglatchOpenSSLSession *session,
    const siglatch_user *user) {
  if (!session || !user) {
    LOGE("assign_session_to_user: NULL session or user pointer");
    return 0;
  }

  memcpy(session->hmac_key, user->hmac_key, sizeof(session->hmac_key));
  session->hmac_key_len = 32;
  session->public_key = user->pubkey;

  LOGT("Session now attached to user: %s\n", user->name);
  return 1;
}

int app_inbound_crypto_validate_signature(
    const SiglatchOpenSSLSession *session,
    const KnockPacket *pkt) {
  uint8_t digest[32] = {0};

  if (!session || !pkt) {
    LOGE("[validate_signature] Null session or packet\n");
    return 0;
  }

  if (!app.payload.digest.generate(pkt, digest)) {
    LOGE("[validate_signature] Failed to generate digest\n");
    return 0;
  }

  dumpDigest("Server-computed Digest", digest, sizeof(digest));
  dumpDigest("Packet hmac field (Client-sent Signature)", pkt->hmac, sizeof(pkt->hmac));

  if (!app.payload.digest.validate(session->hmac_key, digest, pkt->hmac)) {
    LOGW("[validate_signature] Signature mismatch for user_id %u\n", pkt->user_id);
    return 0;
  }

  LOGT("[validate_signature] Signature verified for user_id %u\n", pkt->user_id);
  return 1;
}
