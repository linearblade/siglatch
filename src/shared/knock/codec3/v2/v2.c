/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "v2.h"

#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../../../stdlib/nonce.h"
#include "../v1/v1.h"
#include "v2_form1.h"

#define SHARED_KNOCK_CODEC3_V2_FORM1_TIMESTAMP_FUZZ 300

static uint16_t shared_knock_codec3_v2_read_u16_be(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

static uint32_t shared_knock_codec3_v2_read_u32_be(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) |
         ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) |
         (uint32_t)src[3];
}

struct SharedKnockCodec3V2State {
  NonceCache nonce;
  int nonce_ready;
  int last_packet_encrypted;
};

static const SharedKnockCodec3Context *g_context = NULL;
static const SharedKnockCodec3Context *shared_knock_codec3_v2_context(void);
static int shared_knock_codec3_v2_sync_nonce_cache(SharedKnockCodec3V2State *state);
static int shared_knock_codec3_v2_private_decrypt(const uint8_t *input,
                                                  size_t input_len,
                                                  uint8_t *output,
                                                  size_t *output_len);
static int shared_knock_codec3_v2_unpack(const uint8_t *buf,
                                         size_t buflen,
                                         SharedKnockCodec3V2Form1Packet *pkt);
static int shared_knock_codec3_v2_validate(const SharedKnockCodec3V2Form1Packet *pkt);
static int shared_knock_codec3_v2_deserialize(const uint8_t *buf,
                                              size_t buflen,
                                              SharedKnockCodec3V2Form1Packet *pkt);
static int shared_knock_codec3_v2_normalize(const uint8_t *buf,
                                            size_t buflen,
                                            const char *ip,
                                            uint16_t client_port,
                                            int encrypted,
                                            SharedKnockNormalizedUnit *out);
static int shared_knock_codec3_v2_packet_nonce_accept(SharedKnockCodec3V2State *state,
                                                      uint32_t timestamp,
                                                      uint32_t challenge);
void shared_knock_codec3_v2_destroy_state(SharedKnockCodec3V2State *state);

static const SharedKnockCodec3Context *shared_knock_codec3_v2_context(void) {
  return g_context;
}

static time_t shared_knock_codec3_v2_nonce_ttl(void) {
  const SharedKnockCodec3Context *context = shared_knock_codec3_v2_context();
  time_t ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;

  if (context && context->nonce_window_ms > 0u) {
    ttl_seconds = (time_t)(context->nonce_window_ms / 1000u);
    if (ttl_seconds <= 0) {
      ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;
    }
  }

  return ttl_seconds;
}

static int shared_knock_codec3_v2_sync_nonce_cache(SharedKnockCodec3V2State *state) {
  NonceConfig cfg = {0};

  if (!state) {
    return 0;
  }

  cfg.capacity = NONCE_DEFAULT_CAPACITY;
  cfg.nonce_strlen = NONCE_DEFAULT_STRLEN;
  cfg.ttl_seconds = shared_knock_codec3_v2_nonce_ttl();

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

static int shared_knock_codec3_v2_private_decrypt(const uint8_t *input,
                                                  size_t input_len,
                                                  uint8_t *output,
                                                  size_t *output_len) {
  EVP_PKEY_CTX *pctx = NULL;
  size_t plain_len = 0u;
  int ok = 0;
  const SharedKnockCodec3Context *context = shared_knock_codec3_v2_context();

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

static int shared_knock_codec3_v2_unpack(const uint8_t *buf,
                                         size_t buflen,
                                         SharedKnockCodec3V2Form1Packet *pkt) {
  if (!buf || !pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (buflen != SHARED_KNOCK_CODEC3_V2_FORM1_PACKET_SIZE) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memset(pkt, 0, sizeof(*pkt));

  pkt->outer.magic = shared_knock_codec3_v2_read_u32_be(buf + 0);
  pkt->outer.version = shared_knock_codec3_v2_read_u32_be(buf + 4);
  pkt->outer.form = buf[8];

  pkt->inner.timestamp = shared_knock_codec3_v2_read_u32_be(buf + 9);
  pkt->inner.user_id = shared_knock_codec3_v2_read_u16_be(buf + 13);
  pkt->inner.action_id = buf[15];
  pkt->inner.challenge = shared_knock_codec3_v2_read_u32_be(buf + 16);
  memcpy(pkt->inner.hmac, buf + 20, sizeof(pkt->inner.hmac));
  pkt->inner.payload_len = shared_knock_codec3_v2_read_u16_be(buf + 52);

  memcpy(pkt->payload,
         buf + SHARED_KNOCK_CODEC3_V2_FORM1_OUTER_SIZE + SHARED_KNOCK_CODEC3_V2_FORM1_INNER_SIZE,
         sizeof(pkt->payload));

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec3_v2_validate(const SharedKnockCodec3V2Form1Packet *pkt) {
  time_t now = 0;

  if (!pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (pkt->outer.magic != SHARED_KNOCK_CODEC3_FAMILY_MAGIC) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->outer.version != SHARED_KNOCK_CODEC3_V2_WIRE_VERSION) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->outer.form != SHARED_KNOCK_CODEC3_FORM1_ID) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->inner.payload_len > sizeof(pkt->payload)) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  now = time(NULL);
  if (pkt->inner.timestamp > now + SHARED_KNOCK_CODEC3_V2_FORM1_TIMESTAMP_FUZZ ||
      pkt->inner.timestamp < now - SHARED_KNOCK_CODEC3_V2_FORM1_TIMESTAMP_FUZZ) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec3_v2_deserialize(const uint8_t *buf,
                                              size_t buflen,
                                              SharedKnockCodec3V2Form1Packet *pkt) {
  int validate_rc = 0;

  validate_rc = shared_knock_codec3_v2_unpack(buf, buflen, pkt);
  if (validate_rc != SL_PAYLOAD_OK) {
    return validate_rc;
  }

  validate_rc = shared_knock_codec3_v2_validate(pkt);
  if (validate_rc == SL_PAYLOAD_ERR_OVERFLOW) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }
  if (validate_rc != SL_PAYLOAD_OK) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec3_v2_normalize(const uint8_t *buf,
                                            size_t buflen,
                                            const char *ip,
                                            uint16_t client_port,
                                            int encrypted,
                                            SharedKnockNormalizedUnit *out) {
  SharedKnockCodec3V2Form1Packet pkt = {0};
  int deserialize_rc = 0;
  size_t ip_len = 0;
  size_t copy_len = 0;
  int overflow = 0;

  if (!out) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  deserialize_rc = shared_knock_codec3_v2_deserialize(buf, buflen, &pkt);
  if (deserialize_rc != SL_PAYLOAD_OK) {
    return deserialize_rc;
  }

  overflow = (pkt.inner.payload_len > sizeof(out->payload));

  memset(out, 0, sizeof(*out));

  out->complete = 1;
  out->wire_version = pkt.outer.version;
  out->wire_form = pkt.outer.form;
  out->session_id = 0;
  out->message_id = 0;
  out->stream_id = 0;
  out->fragment_index = 0;
  out->fragment_count = 1;
  out->timestamp = pkt.inner.timestamp;
  out->user_id = pkt.inner.user_id;
  out->action_id = pkt.inner.action_id;
  out->challenge = pkt.inner.challenge;
  memcpy(out->hmac, pkt.inner.hmac, sizeof(out->hmac));

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
  copy_len = pkt.inner.payload_len;
  if (copy_len > sizeof(out->payload)) {
    copy_len = sizeof(out->payload);
  }

  out->payload_len = copy_len;
  if (copy_len > 0) {
    memcpy(out->payload, pkt.payload, copy_len);
  }

  return overflow ? SL_PAYLOAD_ERR_OVERFLOW : SL_PAYLOAD_OK;
}

static int shared_knock_codec3_v2_packet_nonce_accept(SharedKnockCodec3V2State *state,
                                                      uint32_t timestamp,
                                                      uint32_t challenge) {
  char nonce_str[64] = {0};
  time_t now = time(NULL);

  if (!state) {
    return 0;
  }

  if (!shared_knock_codec3_v2_sync_nonce_cache(state)) {
    return 0;
  }

  snprintf(nonce_str, sizeof(nonce_str), "%u-%u", timestamp, challenge);
  if (lib_nonce_check(&state->nonce, nonce_str, now)) {
    return 0;
  }

  lib_nonce_add(&state->nonce, nonce_str, now);
  return 1;
}

int shared_knock_codec3_v2_create_state(SharedKnockCodec3V2State **out_state) {
  SharedKnockCodec3V2State *state = NULL;

  if (!out_state) {
    return 0;
  }

  state = (SharedKnockCodec3V2State *)calloc(1u, sizeof(*state));
  if (!state) {
    return 0;
  }

  if (!shared_knock_codec3_v2_sync_nonce_cache(state)) {
    shared_knock_codec3_v2_destroy_state(state);
    *out_state = NULL;
    return 0;
  }

  *out_state = state;
  return 1;
}

void shared_knock_codec3_v2_destroy_state(SharedKnockCodec3V2State *state) {
  if (!state) {
    return;
  }

  if (state->nonce_ready) {
    lib_nonce_cache_shutdown(&state->nonce);
    state->nonce_ready = 0;
  }

  free(state);
}

int shared_knock_codec3_v2_init(const SharedKnockCodec3Context *context) {
  g_context = context;
  return 1;
}

void shared_knock_codec3_v2_shutdown(void) {
  g_context = NULL;
}

int shared_knock_codec3_v2_detect(const SharedKnockCodec3V2State *state,
                                  const uint8_t *buf,
                                  size_t buflen) {
  SharedKnockCodec3V2Form1Packet pkt = {0};
  size_t decrypted_cap = 0u;
  const SharedKnockCodec3Context *context = shared_knock_codec3_v2_context();

  if (!buf) {
    return 0;
  }

  if (buflen == SHARED_KNOCK_CODEC3_V2_FORM1_PACKET_SIZE &&
      shared_knock_codec3_v2_deserialize(buf, buflen, &pkt) == SL_PAYLOAD_OK) {
    if (state) {
      ((SharedKnockCodec3V2State *)state)->last_packet_encrypted = 0;
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
    uint8_t *decrypted = (uint8_t *)calloc(1u, decrypted_cap);
    size_t decrypted_len = decrypted_cap;

    if (!decrypted) {
      return 0;
    }

    if (!shared_knock_codec3_v2_private_decrypt(buf, buflen, decrypted, &decrypted_len)) {
      free(decrypted);
      return 0;
    }

    if (decrypted_len != SHARED_KNOCK_CODEC3_V2_FORM1_PACKET_SIZE) {
      free(decrypted);
      return 0;
    }

    if (shared_knock_codec3_v2_deserialize(decrypted, decrypted_len, &pkt) != SL_PAYLOAD_OK) {
      free(decrypted);
      return 0;
    }

    free(decrypted);
  }

  ((SharedKnockCodec3V2State *)state)->last_packet_encrypted = 1;
  return 1;
}

int shared_knock_codec3_v2_decode(const SharedKnockCodec3V2State *state,
                                  const uint8_t *buf,
                                  size_t buflen,
                                  const char *ip,
                                  uint16_t client_port,
                                  int encrypted,
                                  SharedKnockNormalizedUnit *out) {
  const uint8_t *payload = buf;
  size_t payload_len = buflen;
  int should_decrypt = 0;
  int rc = 0;
  const SharedKnockCodec3Context *context = shared_knock_codec3_v2_context();

  if (!state || !out || !buf) {
    return 0;
  }

  (void)encrypted;
  should_decrypt = state->last_packet_encrypted ? 1 : 0;
  if (should_decrypt) {
    size_t decrypted_cap;
    uint8_t *decrypted_buf = NULL;

    if (!context || !context->has_server_key || !context->server_key.private_key) {
      return 0;
    }
    decrypted_cap = (size_t)EVP_PKEY_get_size(context->server_key.private_key);
    if (decrypted_cap == 0u) {
      return 0;
    }
    decrypted_buf = (uint8_t *)calloc(1u, decrypted_cap);
    if (!decrypted_buf) {
      return 0;
    }
    size_t decrypted_len = decrypted_cap;
    if (!shared_knock_codec3_v2_private_decrypt(buf,
                                                buflen,
                                                decrypted_buf,
                                                &decrypted_len)) {
      free(decrypted_buf);
      return 0;
    }
    payload = decrypted_buf;
    payload_len = decrypted_len;
  }

  if (context && context->server_secure && !should_decrypt) {
    return 0;
  }

  rc = shared_knock_codec3_v2_normalize(payload, payload_len, ip, client_port, should_decrypt, out);
  if (rc != SL_PAYLOAD_OK) {
    if (should_decrypt) {
      free((void *)payload);
    }
    return 0;
  }

  if (should_decrypt) {
    free((void *)payload);
  }

  return 1;
}

int shared_knock_codec3_v2_wire_auth(const SharedKnockCodec3V2State *state,
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

  normal->wire_auth = shared_knock_codec3_v2_packet_nonce_accept((SharedKnockCodec3V2State *)state,
                                                                 normal->timestamp,
                                                                 normal->challenge) ? 1 : 0;
  return normal->wire_auth;
}

int shared_knock_codec3_v2_encode(const SharedKnockCodec3V2State *state,
                                  const SharedKnockNormalizedUnit *normal,
                                  uint8_t *out_buf,
                                  size_t *out_len) {
  (void)state;
  return shared_knock_codec3_v1_encode(NULL, normal, out_buf, out_len);
}

static const SharedKnockCodec3V2Lib shared_knock_codec3_v2 = {
  .name = "v2",
  .init = shared_knock_codec3_v2_init,
  .shutdown = shared_knock_codec3_v2_shutdown,
  .create_state = shared_knock_codec3_v2_create_state,
  .destroy_state = shared_knock_codec3_v2_destroy_state,
  .detect = shared_knock_codec3_v2_detect,
  .decode = shared_knock_codec3_v2_decode,
  .encode = shared_knock_codec3_v2_encode
};

const SharedKnockCodec3V2Lib *get_shared_knock_codec3_v2_lib(void) {
  return &shared_knock_codec3_v2;
}
