/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "v1.h"

#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../../shared.h"
#include "../../../knock/response.h"
#include "../../../../stdlib/nonce.h"
#include "../../../../stdlib/openssl_session.h"
#include "../../codec/v1/v1.h"

struct SharedKnockCodec2V1State {
  NonceCache nonce;
  int nonce_ready;
  int last_packet_encrypted;
};

static const SharedKnockCodecContext *g_context = NULL;
static const SharedKnockCodecContext *shared_knock_codec2_v1_context(void);
static int shared_knock_codec2_v1_sync_nonce_cache(SharedKnockCodec2V1State *state);
static int shared_knock_codec2_v1_private_decrypt(const uint8_t *input,
                                                  size_t input_len,
                                                  uint8_t *output,
                                                  size_t *output_len);
static int shared_knock_codec2_v1_packet_nonce_accept(SharedKnockCodec2V1State *state,
                                                      uint32_t timestamp,
                                                      uint32_t challenge);
void shared_knock_codec2_v1_destroy_state(SharedKnockCodec2V1State *state);

static const SharedKnockCodecContext *shared_knock_codec2_v1_context(void) {
  return g_context;
}

static time_t shared_knock_codec2_v1_nonce_ttl(void) {
  const SharedKnockCodecContext *context = shared_knock_codec2_v1_context();
  time_t ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;

  if (context && context->nonce_window_ms > 0u) {
    ttl_seconds = (time_t)(context->nonce_window_ms / 1000u);
    if (ttl_seconds <= 0) {
      ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;
    }
  }

  return ttl_seconds;
}

static int shared_knock_codec2_v1_sync_nonce_cache(SharedKnockCodec2V1State *state) {
  NonceConfig cfg = {0};

  if (!state) {
    return 0;
  }

  cfg.capacity = NONCE_DEFAULT_CAPACITY;
  cfg.nonce_strlen = NONCE_DEFAULT_STRLEN;
  cfg.ttl_seconds = shared_knock_codec2_v1_nonce_ttl();

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

static int shared_knock_codec2_v1_private_decrypt(const uint8_t *input,
                                                  size_t input_len,
                                                  uint8_t *output,
                                                  size_t *output_len) {
  EVP_PKEY_CTX *pctx = NULL;
  size_t plain_len = 0u;
  int ok = 0;
  const SharedKnockCodecContext *context = shared_knock_codec2_v1_context();

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

static int shared_knock_codec2_v1_packet_nonce_accept(SharedKnockCodec2V1State *state,
                                                      uint32_t timestamp,
                                                      uint32_t challenge) {
  char nonce_str[64] = {0};
  time_t now = time(NULL);

  if (!state) {
    return 0;
  }

  if (!shared_knock_codec2_v1_sync_nonce_cache(state)) {
    return 0;
  }

  snprintf(nonce_str, sizeof(nonce_str), "%u-%u", timestamp, challenge);
  if (lib_nonce_check(&state->nonce, nonce_str, now)) {
    return 0;
  }

  lib_nonce_add(&state->nonce, nonce_str, now);
  return 1;
}

int shared_knock_codec2_v1_create_state(SharedKnockCodec2V1State **out_state) {
  SharedKnockCodec2V1State *state = NULL;

  if (!out_state) {
    return 0;
  }

  state = (SharedKnockCodec2V1State *)calloc(1u, sizeof(*state));
  if (!state) {
    return 0;
  }

  if (!shared_knock_codec2_v1_sync_nonce_cache(state)) {
    shared_knock_codec2_v1_destroy_state(state);
    *out_state = NULL;
    return 0;
  }

  *out_state = state;
  return 1;
}

void shared_knock_codec2_v1_destroy_state(SharedKnockCodec2V1State *state) {
  if (!state) {
    return;
  }

  if (state->nonce_ready) {
    lib_nonce_cache_shutdown(&state->nonce);
    state->nonce_ready = 0;
  }

  free(state);
}

int shared_knock_codec2_v1_init(const SharedKnockCodecContext *context) {
  g_context = context;
  return 1;
}

void shared_knock_codec2_v1_shutdown(void) {
  g_context = NULL;
}

int shared_knock_codec2_v1_detect(const SharedKnockCodec2V1State *state,
                                  const uint8_t *buf,
                                  size_t buflen) {
  KnockPacket pkt = {0};
  size_t decrypted_cap = 0u;
  const SharedKnockCodecContext *context = shared_knock_codec2_v1_context();

  if (!buf) {
    return 0;
  }

  if (state) {
    ((SharedKnockCodec2V1State *)state)->last_packet_encrypted = 0;
  }

  if (buflen == SHARED_KNOCK_V1_PACKET_SIZE &&
      shared_knock_v1_codec_deserialize(buf, buflen, &pkt) == SL_PAYLOAD_OK) {
    if (state) {
      ((SharedKnockCodec2V1State *)state)->last_packet_encrypted = 0;
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

    ok = shared_knock_codec2_v1_private_decrypt(buf,
                                                buflen,
                                                decrypted_buf,
                                                &decrypted_len);
    if (!ok) {
      free(decrypted_buf);
      return 0;
    }

    if (decrypted_len != SHARED_KNOCK_V1_PACKET_SIZE) {
      free(decrypted_buf);
      return 0;
    }

    if (shared_knock_v1_codec_deserialize(decrypted_buf, decrypted_len, &pkt) != SL_PAYLOAD_OK) {
      free(decrypted_buf);
      return 0;
    }

    free(decrypted_buf);
  }

  ((SharedKnockCodec2V1State *)state)->last_packet_encrypted = 1;
  return 1;
}

int shared_knock_codec2_v1_decode(const SharedKnockCodec2V1State *state,
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
  const SharedKnockCodecContext *context = shared_knock_codec2_v1_context();

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
      if (!shared_knock_codec2_v1_private_decrypt(buf,
                                                  buflen,
                                                  decrypted_buf,
                                                  &decrypted_len)) {
        free(decrypted_buf);
        return 0;
      }
      payload = decrypted_buf;
      payload_len = decrypted_len;
      rc = shared_knock_v1_codec_normalize(payload, payload_len, ip, client_port, should_decrypt, out);
      if (rc != SL_PAYLOAD_OK) {
        free(decrypted_buf);
        return 0;
      }
      if (!shared_knock_codec2_v1_packet_nonce_accept((SharedKnockCodec2V1State *)state,
                                                      out->timestamp,
                                                      out->challenge)) {
        free(decrypted_buf);
        return 0;
      }
      free(decrypted_buf);
      return 1;
    }
  }

  rc = shared_knock_v1_codec_normalize(payload, payload_len, ip, client_port, should_decrypt, out);
  if (rc != SL_PAYLOAD_OK) {
    return 0;
  }

  if (!shared_knock_codec2_v1_packet_nonce_accept((SharedKnockCodec2V1State *)state,
                                                  out->timestamp,
                                                  out->challenge)) {
    return 0;
  }

  return 1;
}

int shared_knock_codec2_v1_encode(const SharedKnockCodec2V1State *state,
                                  const SharedKnockNormalizedUnit *normal,
                                  uint8_t *out_buf,
                                  size_t *out_len) {
  KnockPacket pkt = {0};
  const SharedKnockCodecContext *context = shared_knock_codec2_v1_context();
  const SiglatchOpenSSLSession *session = NULL;
  uint8_t digest[32] = {0};
  size_t payload_len = 0;
  size_t capacity = 0;

  (void)state;

  if (!normal || !out_buf || !out_len) {
    return 0;
  }

  capacity = *out_len;
  if (capacity < SHARED_KNOCK_V1_PACKET_SIZE) {
    return 0;
  }

  if (normal->payload_len > SHARED_KNOCK_V1_PAYLOAD_MAX) {
    return 0;
  }

  pkt.version = SHARED_KNOCK_V1_VERSION;
  pkt.timestamp = normal->timestamp;
  pkt.user_id = normal->user_id;
  pkt.action_id = SL_KNOCK_RESPONSE_ACTION_ID;
  pkt.challenge = normal->challenge;
  pkt.payload_len = (uint16_t)normal->payload_len;
  payload_len = normal->payload_len;
  if (payload_len > 0) {
    memcpy(pkt.payload, normal->payload, payload_len);
  }

  if (!context || !context->openssl_session) {
    return 0;
  }

  session = context->openssl_session;
  if (session->hmac_key_len < sizeof(pkt.hmac)) {
    return 0;
  }

  if (!shared.knock.digest.generate(&pkt, digest)) {
    return 0;
  }

  if (!shared.knock.digest.sign(session->hmac_key, digest, pkt.hmac)) {
    return 0;
  }

  if (shared_knock_v1_codec_pack(&pkt, out_buf, capacity) < 0) {
    return 0;
  }

  *out_len = SHARED_KNOCK_V1_PACKET_SIZE;
  return 1;
}

static const SharedKnockCodec2V1Lib shared_knock_codec2_v1 = {
  .name = "v1",
  .init = shared_knock_codec2_v1_init,
  .shutdown = shared_knock_codec2_v1_shutdown,
  .create_state = shared_knock_codec2_v1_create_state,
  .destroy_state = shared_knock_codec2_v1_destroy_state,
  .detect = shared_knock_codec2_v1_detect,
  .decode = shared_knock_codec2_v1_decode,
  .encode = shared_knock_codec2_v1_encode
};

const SharedKnockCodec2V1Lib *get_shared_knock_codec2_v1_lib(void) {
  return &shared_knock_codec2_v1;
}
