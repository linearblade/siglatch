/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "v1.h"

#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../../knock/response.h"
#include "../../digest.h"
#include "../../../../stdlib/nonce.h"
#include "../../../../stdlib/openssl_session.h"
#include "v1_packet.h"

#define SHARED_KNOCK_CODEC3_V1_TIMESTAMP_FUZZ 300

struct SharedKnockCodec3V1State {
  NonceCache nonce;
  int nonce_ready;
  int last_packet_encrypted;
};

static const SharedKnockCodec3Context *g_context = NULL;
static const SharedKnockCodec3Context *shared_knock_codec3_v1_context(void);
static const SharedKnockCodec3KeyEntry *shared_knock_codec3_v1_keychain_entry_for_user_id(
    const SharedKnockCodec3Context *context,
    uint32_t user_id);
static int shared_knock_codec3_v1_authorize_normalized(const SharedKnockNormalizedUnit *normal);
static int shared_knock_codec3_v1_sync_nonce_cache(SharedKnockCodec3V1State *state);
static int shared_knock_codec3_v1_private_decrypt(const uint8_t *input,
                                                  size_t input_len,
                                                  uint8_t *output,
                                                  size_t *output_len);
static int shared_knock_codec3_v1_pack(const SharedKnockCodec3V1Packet *pkt,
                                       uint8_t *out_buf,
                                       size_t maxlen);
static int shared_knock_codec3_v1_unpack(const uint8_t *buf,
                                         size_t buflen,
                                         SharedKnockCodec3V1Packet *pkt);
static int shared_knock_codec3_v1_validate(const SharedKnockCodec3V1Packet *pkt);
static int shared_knock_codec3_v1_deserialize(const uint8_t *buf,
                                               size_t buflen,
                                               SharedKnockCodec3V1Packet *pkt);
static int shared_knock_codec3_v1_normalize(const uint8_t *buf,
                                            size_t buflen,
                                            const char *ip,
                                            uint16_t client_port,
                                            int encrypted,
                                            SharedKnockNormalizedUnit *out);
static int shared_knock_codec3_v1_packet_nonce_accept(SharedKnockCodec3V1State *state,
                                                      uint32_t timestamp,
                                                      uint32_t challenge);
void shared_knock_codec3_v1_destroy_state(SharedKnockCodec3V1State *state);

static const SharedKnockCodec3Context *shared_knock_codec3_v1_context(void) {
  return g_context;
}

static const SharedKnockCodec3KeyEntry *shared_knock_codec3_v1_keychain_entry_for_user_id(
    const SharedKnockCodec3Context *context,
    uint32_t user_id) {
  size_t i = 0;

  if (!context || !context->keychain || context->keychain_len == 0u) {
    return NULL;
  }

  for (i = 0; i < context->keychain_len; ++i) {
    const SharedKnockCodec3KeyEntry *entry = &context->keychain[i];

    if (entry->name && entry->user_id == user_id) {
      return entry;
    }
  }

  return NULL;
}

static time_t shared_knock_codec3_v1_nonce_ttl(void) {
  const SharedKnockCodec3Context *context = shared_knock_codec3_v1_context();
  time_t ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;

  if (context && context->nonce_window_ms > 0u) {
    ttl_seconds = (time_t)(context->nonce_window_ms / 1000u);
    if (ttl_seconds <= 0) {
      ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;
    }
  }

  return ttl_seconds;
}

static int shared_knock_codec3_v1_sync_nonce_cache(SharedKnockCodec3V1State *state) {
  NonceConfig cfg = {0};

  if (!state) {
    return 0;
  }

  cfg.capacity = NONCE_DEFAULT_CAPACITY;
  cfg.nonce_strlen = NONCE_DEFAULT_STRLEN;
  cfg.ttl_seconds = shared_knock_codec3_v1_nonce_ttl();

  if (state->nonce_ready &&
      state->nonce.capacity == cfg.capacity &&
      state->nonce.nonce_strlen == cfg.nonce_strlen &&
      state->nonce.ttl_seconds == cfg.ttl_seconds) {
    return 1;
  }

  if (state->nonce_ready) {
    lib_nonce_cache_shutdown(&state->nonce);
    state->nonce_ready = 0;
  }

  if (!lib_nonce_cache_init(&state->nonce, &cfg)) {
    return 0;
  }

  state->nonce_ready = 1;
  return 1;
}

static int shared_knock_codec3_v1_private_decrypt(const uint8_t *input,
                                                  size_t input_len,
                                                  uint8_t *output,
                                                  size_t *output_len) {
  EVP_PKEY_CTX *pctx = NULL;
  size_t plain_len = 0u;
  int ok = 0;
  const SharedKnockCodec3Context *context = shared_knock_codec3_v1_context();

  if (!context || !context->has_server_key || !context->server_key.private_key ||
      !input || !output || !output_len || *output_len == 0u) {
    return 0;
  }

  pctx = EVP_PKEY_CTX_new(context->server_key.private_key, NULL);
  if (!pctx) {
    return 0;
  }

  do {
    if (EVP_PKEY_decrypt_init(pctx) <= 0) {
      break;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
      break;
    }

    if (EVP_PKEY_decrypt(pctx, NULL, &plain_len, input, input_len) <= 0) {
      break;
    }

    if (plain_len > *output_len) {
      break;
    }

    if (EVP_PKEY_decrypt(pctx, output, &plain_len, input, input_len) <= 0) {
      break;
    }

    *output_len = plain_len;
    ok = 1;
  } while (0);

  EVP_PKEY_CTX_free(pctx);
  return ok;
}

static int shared_knock_codec3_v1_pack(const SharedKnockCodec3V1Packet *pkt,
                                       uint8_t *out_buf,
                                       size_t maxlen) {
  if (!pkt || !out_buf) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (maxlen < sizeof(SharedKnockCodec3V1Packet)) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memcpy(out_buf, pkt, sizeof(SharedKnockCodec3V1Packet));
  return (int)sizeof(SharedKnockCodec3V1Packet);
}

static int shared_knock_codec3_v1_unpack(const uint8_t *buf,
                                         size_t buflen,
                                         SharedKnockCodec3V1Packet *pkt) {
  if (!pkt || !buf) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (buflen < sizeof(SharedKnockCodec3V1Packet)) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memcpy(pkt, buf, sizeof(SharedKnockCodec3V1Packet));
  return SL_PAYLOAD_OK;
}

static int shared_knock_codec3_v1_validate(const SharedKnockCodec3V1Packet *pkt) {
  time_t now = 0;

  if (!pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (pkt->version != SHARED_KNOCK_CODEC3_V1_VERSION) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->payload_len > sizeof(pkt->payload)) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  now = time(NULL);
  if (pkt->timestamp > now + SHARED_KNOCK_CODEC3_V1_TIMESTAMP_FUZZ ||
      pkt->timestamp < now - SHARED_KNOCK_CODEC3_V1_TIMESTAMP_FUZZ) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec3_v1_deserialize(const uint8_t *buf,
                                              size_t buflen,
                                              SharedKnockCodec3V1Packet *pkt) {
  int validate_rc = 0;

  validate_rc = shared_knock_codec3_v1_unpack(buf, buflen, pkt);
  if (validate_rc != SL_PAYLOAD_OK) {
    return validate_rc;
  }

  validate_rc = shared_knock_codec3_v1_validate(pkt);
  if (validate_rc == SL_PAYLOAD_ERR_OVERFLOW) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }
  if (validate_rc != SL_PAYLOAD_OK) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec3_v1_normalize(const uint8_t *buf,
                                            size_t buflen,
                                            const char *ip,
                                            uint16_t client_port,
                                            int encrypted,
                                            SharedKnockNormalizedUnit *out) {
  SharedKnockCodec3V1Packet pkt = {0};
  int deserialize_rc = 0;
  size_t payload_len = 0;
  size_t ip_len = 0;
  size_t copy_len = 0;
  int overflow = 0;

  if (!out) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  deserialize_rc = shared_knock_codec3_v1_deserialize(buf, buflen, &pkt);
  if (deserialize_rc != SL_PAYLOAD_OK) {
    return deserialize_rc;
  }

  overflow = (pkt.payload_len > sizeof(out->payload));

  memset(out, 0, sizeof(*out));

  out->complete = 1;
  out->wire_version = pkt.version;
  out->wire_form = 0u;
  out->session_id = 0;
  out->message_id = 0;
  out->stream_id = 0;
  out->fragment_index = 0;
  out->fragment_count = 1;
  out->timestamp = pkt.timestamp;
  out->user_id = pkt.user_id;
  out->action_id = pkt.action_id;
  out->challenge = pkt.challenge;
  memcpy(out->hmac, pkt.hmac, sizeof(out->hmac));

  if (ip) {
    ip_len = strlen(ip);
    if (ip_len >= sizeof(out->ip)) {
      ip_len = sizeof(out->ip) - 1u;
    }
    memcpy(out->ip, ip, ip_len);
    out->ip[ip_len] = '\0';
  }

  out->client_port = client_port;
  out->encrypted = encrypted ? 1 : 0;
  copy_len = pkt.payload_len;
  if (copy_len > sizeof(out->payload)) {
    copy_len = sizeof(out->payload);
  }

  out->payload_len = copy_len;
  payload_len = copy_len;
  if (payload_len > 0) {
    memcpy(out->payload, pkt.payload, payload_len);
  }

  return overflow ? SL_PAYLOAD_ERR_OVERFLOW : SL_PAYLOAD_OK;
}

static int shared_knock_codec3_v1_packet_nonce_accept(SharedKnockCodec3V1State *state,
                                                      uint32_t timestamp,
                                                      uint32_t challenge) {
  char nonce_str[64] = {0};
  time_t now = time(NULL);

  if (!state) {
    return 0;
  }

  if (!shared_knock_codec3_v1_sync_nonce_cache(state)) {
    return 0;
  }

  snprintf(nonce_str, sizeof(nonce_str), "%u-%u", timestamp, challenge);
  if (lib_nonce_check(&state->nonce, nonce_str, now)) {
    return 0;
  }

  lib_nonce_add(&state->nonce, nonce_str, now);
  return 1;
}

int shared_knock_codec3_v1_create_state(SharedKnockCodec3V1State **out_state) {
  SharedKnockCodec3V1State *state = NULL;

  if (!out_state) {
    return 0;
  }

  state = (SharedKnockCodec3V1State *)calloc(1u, sizeof(*state));
  if (!state) {
    return 0;
  }

  if (!shared_knock_codec3_v1_sync_nonce_cache(state)) {
    shared_knock_codec3_v1_destroy_state(state);
    *out_state = NULL;
    return 0;
  }

  *out_state = state;
  return 1;
}

void shared_knock_codec3_v1_destroy_state(SharedKnockCodec3V1State *state) {
  if (!state) {
    return;
  }

  if (state->nonce_ready) {
    lib_nonce_cache_shutdown(&state->nonce);
    state->nonce_ready = 0;
  }

  free(state);
}

int shared_knock_codec3_v1_init(const SharedKnockCodec3Context *context) {
  g_context = context;
  return 1;
}

void shared_knock_codec3_v1_shutdown(void) {
  g_context = NULL;
}

int shared_knock_codec3_v1_detect(const SharedKnockCodec3V1State *state,
                                  const uint8_t *buf,
                                  size_t buflen) {
  SharedKnockCodec3V1Packet pkt = {0};
  size_t decrypted_cap = 0u;
  const SharedKnockCodec3Context *context = shared_knock_codec3_v1_context();

  if (!buf) {
    return 0;
  }

  if (state) {
    ((SharedKnockCodec3V1State *)state)->last_packet_encrypted = 0;
  }

  if (buflen == SHARED_KNOCK_CODEC3_V1_PACKET_SIZE &&
      shared_knock_codec3_v1_deserialize(buf, buflen, &pkt) == SL_PAYLOAD_OK) {
    if (state) {
      ((SharedKnockCodec3V1State *)state)->last_packet_encrypted = 0;
    }
    return 1;
  }

  if (!state || !context || !context->has_server_key ||
      !context->server_key.private_key) {
    return 0;
  }

  decrypted_cap = (size_t)EVP_PKEY_get_size(context->server_key.private_key);
  if (decrypted_cap == 0u) {
    return 0;
  }
  {
    uint8_t *decrypted_buf = (uint8_t *)calloc(1u, decrypted_cap);
    size_t decrypted_len = decrypted_cap;
    int ok = 0;

    if (!decrypted_buf) {
      return 0;
    }

    ok = shared_knock_codec3_v1_private_decrypt(buf,
                                                buflen,
                                                decrypted_buf,
                                                &decrypted_len);
    if (!ok) {
      free(decrypted_buf);
      return 0;
    }

    if (decrypted_len != SHARED_KNOCK_CODEC3_V1_PACKET_SIZE) {
      free(decrypted_buf);
      return 0;
    }

    if (shared_knock_codec3_v1_deserialize(decrypted_buf, decrypted_len, &pkt) != SL_PAYLOAD_OK) {
      free(decrypted_buf);
      return 0;
    }

    free(decrypted_buf);
  }

  ((SharedKnockCodec3V1State *)state)->last_packet_encrypted = 1;
  return 1;
}

int shared_knock_codec3_v1_decode(const SharedKnockCodec3V1State *state,
                                  const uint8_t *buf,
                                  size_t buflen,
                                  const char *ip,
                                  uint16_t client_port,
                                  int encrypted,
                                  SharedKnockNormalizedUnit *out) {
  size_t decrypted_cap = 0u;
  const uint8_t *payload = buf;
  size_t payload_len = buflen;
  int should_decrypt = 0;
  int rc = 0;
  const SharedKnockCodec3Context *context = shared_knock_codec3_v1_context();

  if (!state || !out || !buf) {
    return 0;
  }

  (void)encrypted;
  should_decrypt = state->last_packet_encrypted ? 1 : 0;
  if (should_decrypt) {
    if (!context || !context->has_server_key || !context->server_key.private_key) {
      return 0;
    }
    decrypted_cap = (size_t)EVP_PKEY_get_size(context->server_key.private_key);
    if (decrypted_cap == 0u) {
      return 0;
    }
    {
      uint8_t *decrypted_buf = (uint8_t *)calloc(1u, decrypted_cap);
      size_t decrypted_len = decrypted_cap;

      if (!decrypted_buf) {
        return 0;
      }
      if (!shared_knock_codec3_v1_private_decrypt(buf,
                                                  buflen,
                                                  decrypted_buf,
                                                  &decrypted_len)) {
        free(decrypted_buf);
        return 0;
      }
      payload = decrypted_buf;
      payload_len = decrypted_len;
      rc = shared_knock_codec3_v1_normalize(payload, payload_len, ip, client_port, should_decrypt, out);
      if (rc != SL_PAYLOAD_OK) {
        free(decrypted_buf);
        return 0;
      }
      free(decrypted_buf);
      return 1;
    }
  }

  if (context && context->server_secure) {
    return 0;
  }

  rc = shared_knock_codec3_v1_normalize(payload, payload_len, ip, client_port, should_decrypt, out);
  if (rc != SL_PAYLOAD_OK) {
    return 0;
  }

  return 1;
}

int shared_knock_codec3_v1_wire_auth(const SharedKnockCodec3V1State *state,
                                     const uint8_t *buf,
                                     size_t buflen,
                                     const char *ip,
                                     uint16_t client_port,
                                     int encrypted,
                                     SharedKnockNormalizedUnit *normal) {
  if (!state || !normal) {
    return 0;
  }

  (void)buf;
  (void)buflen;
  (void)ip;
  (void)client_port;
  (void)encrypted;

  normal->wire_auth = 0;
  if (!shared_knock_codec3_v1_authorize_normalized(normal)) {
    return 0;
  }

  normal->wire_auth = shared_knock_codec3_v1_packet_nonce_accept((SharedKnockCodec3V1State *)state,
                                                                 normal->timestamp,
                                                                 normal->challenge) ? 1 : 0;
  return normal->wire_auth;
}

int shared_knock_codec3_v1_encode(const SharedKnockCodec3V1State *state,
                                  const SharedKnockNormalizedUnit *normal,
                                  uint8_t *out_buf,
                                  size_t *out_len) {
  SharedKnockCodec3V1Packet wire_pkt = {0};
  KnockPacket digest_pkt = {0};
  const SharedKnockCodec3Context *context = shared_knock_codec3_v1_context();
  const SharedKnockDigestLib *digest_lib = NULL;
  const SiglatchOpenSSLSession *session = NULL;
  uint8_t digest[32] = {0};
  size_t payload_len = 0;
  size_t capacity = 0;

  (void)state;

  if (!normal || !out_buf || !out_len) {
    return 0;
  }

  capacity = *out_len;
  if (capacity < SHARED_KNOCK_CODEC3_V1_PACKET_SIZE) {
    return 0;
  }

  if (normal->payload_len > SHARED_KNOCK_CODEC3_V1_PAYLOAD_MAX) {
    return 0;
  }

  wire_pkt.version = SHARED_KNOCK_CODEC3_V1_VERSION;
  wire_pkt.timestamp = normal->timestamp;
  wire_pkt.user_id = normal->user_id;
  wire_pkt.action_id = SL_KNOCK_RESPONSE_ACTION_ID;
  wire_pkt.challenge = normal->challenge;
  wire_pkt.payload_len = (uint16_t)normal->payload_len;
  digest_pkt.version = wire_pkt.version;
  digest_pkt.timestamp = wire_pkt.timestamp;
  digest_pkt.user_id = wire_pkt.user_id;
  digest_pkt.action_id = wire_pkt.action_id;
  digest_pkt.challenge = wire_pkt.challenge;
  digest_pkt.payload_len = wire_pkt.payload_len;
  payload_len = normal->payload_len;
  if (payload_len > 0) {
    memcpy(wire_pkt.payload, normal->payload, payload_len);
    memcpy(digest_pkt.payload, normal->payload, payload_len);
  }

  if (!context || !context->openssl_session) {
    return 0;
  }

  session = context->openssl_session;
  if (session->hmac_key_len < sizeof(wire_pkt.hmac)) {
    return 0;
  }

  digest_lib = get_shared_knock_digest_lib();
  if (!digest_lib || !digest_lib->generate || !digest_lib->sign) {
    return 0;
  }

  if (!digest_lib->generate(&digest_pkt, digest)) {
    return 0;
  }

  if (!digest_lib->sign(session->hmac_key, digest, wire_pkt.hmac)) {
    return 0;
  }

  if (shared_knock_codec3_v1_pack(&wire_pkt, out_buf, capacity) < 0) {
    return 0;
  }

  *out_len = SHARED_KNOCK_CODEC3_V1_PACKET_SIZE;
  return 1;
}

static int shared_knock_codec3_v1_authorize_normalized(const SharedKnockNormalizedUnit *normal) {
  const SharedKnockCodec3Context *context = shared_knock_codec3_v1_context();
  const SharedKnockCodec3KeyEntry *entry = NULL;
  const SharedKnockDigestLib *digest_lib = NULL;
  KnockPacket pkt = {0};
  uint8_t digest[32] = {0};

  if (!context || !normal) {
    return 0;
  }

  if (normal->payload_len > sizeof(pkt.payload)) {
    return 0;
  }

  entry = shared_knock_codec3_v1_keychain_entry_for_user_id(context, normal->user_id);
  if (!entry || !entry->hmac_key || entry->hmac_key_len < sizeof(pkt.hmac)) {
    return 0;
  }

  pkt.version = SHARED_KNOCK_CODEC3_V1_VERSION;
  pkt.timestamp = normal->timestamp;
  pkt.user_id = normal->user_id;
  pkt.action_id = normal->action_id;
  pkt.challenge = normal->challenge;
  pkt.payload_len = (uint16_t)normal->payload_len;
  if (normal->payload_len > 0u) {
    memcpy(pkt.payload, normal->payload, normal->payload_len);
  }

  digest_lib = get_shared_knock_digest_lib();
  if (!digest_lib || !digest_lib->generate || !digest_lib->validate) {
    return 0;
  }

  if (!digest_lib->generate(&pkt, digest)) {
    return 0;
  }

  return digest_lib->validate(entry->hmac_key, digest, normal->hmac);
}

static const SharedKnockCodec3V1Lib shared_knock_codec3_v1 = {
  .name = "v1",
  .init = shared_knock_codec3_v1_init,
  .shutdown = shared_knock_codec3_v1_shutdown,
  .create_state = shared_knock_codec3_v1_create_state,
  .destroy_state = shared_knock_codec3_v1_destroy_state,
  .detect = shared_knock_codec3_v1_detect,
  .decode = shared_knock_codec3_v1_decode,
  .encode = shared_knock_codec3_v1_encode
};

const SharedKnockCodec3V1Lib *get_shared_knock_codec3_v1_lib(void) {
  return &shared_knock_codec3_v1;
}
