/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "crypto.h"

#include <string.h>
#include <openssl/sha.h>

#include "../../app.h"
#include "../../../lib.h"
#include "../../../../shared/knock/digest.h"
#include "../../../../shared/knock/codec/normalized.h"
#include "../../../../shared/knock/codec/v1/v1.h"
#include "../../../../shared/knock/codec/v2/v2_form1.h"
#include "../../../../shared/knock/codec/v3/v3_form1.h"
#include "../../../../stdlib/utils.h"

int app_inbound_crypto_init(void) {
  return 1;
}

void app_inbound_crypto_shutdown(void) {
}

int app_inbound_crypto_init_session_for_server(
    const siglatch_server *server,
    SiglatchOpenSSLSession *session) {
  char fingerprint[(SHA256_DIGEST_LENGTH * 2u) + 1u] = {0};

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
    if (siglatch_openssl_key_fingerprint(session->private_key, fingerprint, sizeof(fingerprint))) {
      lib.log.emit(LOG_DEBUG, 1,
                   "Server private key fingerprint for %s: %s\n",
                   server->name[0] ? server->name : "(unnamed)",
                   fingerprint);
    }
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

static int app_inbound_crypto_validate_signature_v1(
    const SiglatchOpenSSLSession *session,
    const AppConnectionJob *job) {
  KnockPacket pkt = {0};
  uint8_t digest[32] = {0};

  if (!session || !job) {
    return 0;
  }

  if (job->request.payload_len > sizeof(pkt.payload)) {
    return 0;
  }

  pkt.version = (uint8_t)job->wire_version;
  pkt.timestamp = job->timestamp;
  pkt.user_id = job->request.user_id;
  pkt.action_id = job->request.action_id;
  pkt.challenge = job->request.challenge;
  pkt.payload_len = (uint16_t)job->request.payload_len;
  if (job->request.payload_len > 0u) {
    memcpy(pkt.payload, job->request.payload_buffer, job->request.payload_len);
  }

  if (!app.payload.digest.generate(&pkt, digest)) {
    LOGE("[validate_signature] Failed to generate v1 digest\n");
    return 0;
  }

  dumpDigest("Server-computed Digest", digest, sizeof(digest));
  dumpDigest("Packet hmac field (Client-sent Signature)", job->request.hmac, sizeof(pkt.hmac));

  if (!app.payload.digest.validate(session->hmac_key, digest, job->request.hmac)) {
    LOGW("[validate_signature] Signature mismatch for user_id %u\n", job->request.user_id);
    return 0;
  }

  LOGT("[validate_signature] Signature verified for user_id %u\n", job->request.user_id);
  return 1;
}

static int app_inbound_crypto_validate_signature_v2(
    const SiglatchOpenSSLSession *session,
    const AppConnectionJob *job) {
  SharedKnockCodecV2Form1Packet pkt = {0};
  uint8_t digest[32] = {0};

  if (!session || !job) {
    return 0;
  }

  if (job->request.payload_len > sizeof(pkt.payload)) {
    return 0;
  }

  pkt.outer.magic = SHARED_KNOCK_PREFIX_MAGIC;
  pkt.outer.version = job->wire_version;
  pkt.outer.form = job->wire_form;
  pkt.inner.timestamp = job->timestamp;
  pkt.inner.user_id = job->request.user_id;
  pkt.inner.action_id = job->request.action_id;
  pkt.inner.challenge = job->request.challenge;
  pkt.inner.payload_len = (uint16_t)job->request.payload_len;
  if (job->request.payload_len > 0u) {
    memcpy(pkt.payload, job->request.payload_buffer, job->request.payload_len);
  }
  memcpy(pkt.inner.hmac, job->request.hmac, sizeof(pkt.inner.hmac));

  if (!shared_knock_digest_generate_v2_form1(&pkt, digest)) {
    LOGE("[validate_signature] Failed to generate v2 digest\n");
    return 0;
  }

  dumpDigest("Server-computed Digest", digest, sizeof(digest));
  dumpDigest("Packet hmac field (Client-sent Signature)", job->request.hmac, sizeof(pkt.inner.hmac));

  if (!app.payload.digest.validate(session->hmac_key, digest, job->request.hmac)) {
    LOGW("[validate_signature] Signature mismatch for user_id %u\n", job->request.user_id);
    return 0;
  }

  LOGT("[validate_signature] Signature verified for user_id %u\n", job->request.user_id);
  return 1;
}

static int app_inbound_crypto_validate_signature_v3(
    const SiglatchOpenSSLSession *session,
    const AppConnectionJob *job) {
  SharedKnockNormalizedUnit normal = {0};
  uint8_t digest[32] = {0};

  if (!session || !job) {
    return 0;
  }

  if (job->request.payload_len > sizeof(normal.payload)) {
    return 0;
  }

  normal.wire_version = job->wire_version;
  normal.wire_form = job->wire_form;
  normal.timestamp = job->timestamp;
  normal.user_id = job->request.user_id;
  normal.action_id = job->request.action_id;
  normal.challenge = job->request.challenge;
  normal.payload_len = job->request.payload_len;
  if (job->request.payload_len > 0u) {
    memcpy(normal.payload, job->request.payload_buffer, job->request.payload_len);
  }
  memcpy(normal.hmac, job->request.hmac, sizeof(normal.hmac));

  if (!shared_knock_digest_generate_v3_form1(&normal, digest)) {
    LOGE("[validate_signature] Failed to generate v3 digest\n");
    return 0;
  }

  dumpDigest("Server-computed Digest", digest, sizeof(digest));
  dumpDigest("Packet hmac field (Client-sent Signature)", job->request.hmac, sizeof(normal.hmac));

  if (!app.payload.digest.validate(session->hmac_key, digest, job->request.hmac)) {
    LOGW("[validate_signature] Signature mismatch for user_id %u\n", job->request.user_id);
    return 0;
  }

  LOGT("[validate_signature] Signature verified for user_id %u\n", job->request.user_id);
  return 1;
}

int app_inbound_crypto_validate_signature(
    const SiglatchOpenSSLSession *session,
    const AppConnectionJob *job) {
  if (!session || !job) {
    LOGE("[validate_signature] Null session or job\n");
    return 0;
  }

  switch (job->wire_version) {
    case SHARED_KNOCK_CODEC_V1_VERSION:
    case 0u:
      return app_inbound_crypto_validate_signature_v1(session, job);
    case SHARED_KNOCK_CODEC_V2_WIRE_VERSION:
      return app_inbound_crypto_validate_signature_v2(session, job);
    case SHARED_KNOCK_CODEC_V3_WIRE_VERSION:
      return app_inbound_crypto_validate_signature_v3(session, job);
    default:
      LOGE("[validate_signature] Unsupported wire version %u\n", job->wire_version);
      return 0;
  }
}
