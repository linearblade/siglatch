/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "v3.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../digest.h"
#include "../../../../stdlib/nonce.h"
#include "../../../../stdlib/openssl.h"

#define SHARED_KNOCK_CODEC_V3_TIMESTAMP_FUZZ 300

struct SharedKnockCodecV3State {
  NonceCache nonce;
  int nonce_ready;
};

static const SharedKnockCodecContext *g_context = NULL;

static const SharedKnockCodecContext *shared_knock_codec_v3_context(void);
static int shared_knock_codec_v3_sync_nonce_cache(SharedKnockCodecV3State *state);
static int shared_knock_codec_v3_packet_nonce_accept(SharedKnockCodecV3State *state,
                                                      uint32_t timestamp,
                                                      uint32_t challenge);
static int shared_knock_codec_v3_private_decrypt(const uint8_t *input,
                                                  size_t input_len,
                                                  uint8_t *output,
                                                  size_t *output_len);
static void shared_knock_codec_v3_log_openssl_error(const char *label);
static size_t shared_knock_codec_v3_plaintext_size(size_t payload_len);
static int shared_knock_codec_v3_pack_plaintext(const SharedKnockNormalizedUnit *normal,
                                                uint8_t *out_buf,
                                                size_t *out_len);
static int shared_knock_codec_v3_unpack_plaintext(const uint8_t *buf,
                                                  size_t buflen,
                                                  const char *ip,
                                                  uint16_t client_port,
                                                  int encrypted,
                                                  SharedKnockNormalizedUnit *out);
static int shared_knock_codec_v3_build_aad(const SharedKnockCodecV3Form1Packet *pkt,
                                           uint8_t *aad,
                                           size_t aad_size);
static int shared_knock_codec_v3_unpack_wire(const uint8_t *buf,
                                             size_t buflen,
                                             SharedKnockCodecV3Form1Packet *pkt);
static int shared_knock_codec_v3_validate_wire(const SharedKnockCodecV3Form1Packet *pkt);
static int shared_knock_codec_v3_deserialize_wire(const uint8_t *buf,
                                                  size_t buflen,
                                                  SharedKnockCodecV3Form1Packet *pkt);
static int shared_knock_codec_v3_normalize(const uint8_t *buf,
                                           size_t buflen,
                                           const char *ip,
                                           uint16_t client_port,
                                           int encrypted,
                                           SharedKnockNormalizedUnit *out);

static uint16_t shared_knock_codec_v3_read_u16_be(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

static uint32_t shared_knock_codec_v3_read_u32_be(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) |
         ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) |
         (uint32_t)src[3];
}

static void shared_knock_codec_v3_write_u16_be(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)((value >> 8) & 0xffu);
  dst[1] = (uint8_t)(value & 0xffu);
}

static void shared_knock_codec_v3_write_u32_be(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)((value >> 24) & 0xffu);
  dst[1] = (uint8_t)((value >> 16) & 0xffu);
  dst[2] = (uint8_t)((value >> 8) & 0xffu);
  dst[3] = (uint8_t)(value & 0xffu);
}

static void shared_knock_codec_v3_log_openssl_error(const char *label) {
  unsigned long err = 0u;
  const char *reason = NULL;
  int saw_error = 0;

  while ((err = ERR_get_error()) != 0u) {
    saw_error = 1;
    reason = ERR_reason_error_string(err);
    if (!reason) {
      reason = "(unknown)";
    }

    fprintf(stderr,
            "[codec.v3] %s openssl error=0x%lx reason=%s\n",
            label ? label : "(null)",
            err,
            reason);
  }

  if (!saw_error) {
    fprintf(stderr,
            "[codec.v3] %s openssl error unavailable\n",
            label ? label : "(null)");
  }
}

static const SharedKnockCodecContext *shared_knock_codec_v3_context(void) {
  return g_context;
}

static time_t shared_knock_codec_v3_nonce_ttl(void) {
  const SharedKnockCodecContext *context = shared_knock_codec_v3_context();
  time_t ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;

  if (context && context->nonce_window_ms > 0u) {
    ttl_seconds = (time_t)(context->nonce_window_ms / 1000u);
    if (ttl_seconds <= 0) {
      ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;
    }
  }

  return ttl_seconds;
}

static int shared_knock_codec_v3_sync_nonce_cache(SharedKnockCodecV3State *state) {
  NonceConfig cfg = {0};

  if (!state) {
    return 0;
  }

  cfg.capacity = NONCE_DEFAULT_CAPACITY;
  cfg.nonce_strlen = NONCE_DEFAULT_STRLEN;
  cfg.ttl_seconds = shared_knock_codec_v3_nonce_ttl();

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

static int shared_knock_codec_v3_packet_nonce_accept(SharedKnockCodecV3State *state,
                                                     uint32_t timestamp,
                                                     uint32_t challenge) {
  char nonce_str[64] = {0};
  time_t now = time(NULL);

  if (!state) {
    return 0;
  }

  if (!shared_knock_codec_v3_sync_nonce_cache(state)) {
    return 0;
  }

  snprintf(nonce_str, sizeof(nonce_str), "%u-%u", timestamp, challenge);
  if (lib_nonce_check(&state->nonce, nonce_str, now)) {
    return 0;
  }

  lib_nonce_add(&state->nonce, nonce_str, now);
  return 1;
}

static int shared_knock_codec_v3_private_decrypt(const uint8_t *input,
                                                 size_t input_len,
                                                 uint8_t *output,
                                                 size_t *output_len) {
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *private_key = NULL;
  uint8_t temp_output[SHARED_KNOCK_CODEC_V3_FORM1_CEK_MAX] = {0};
  size_t temp_output_cap = sizeof(temp_output);
  size_t plain_len = 0u;
  int ok = 0;
  const SharedKnockCodecContext *context = shared_knock_codec_v3_context();
  const SiglatchOpenSSLSession *session = NULL;

  if (!context || !input || !output || !output_len || *output_len == 0u) {
    return 0;
  }

  session = context->openssl_session;
  if (session && session->private_key) {
    private_key = session->private_key;
  } else if (context->has_server_key && context->server_key.private_key) {
    private_key = context->server_key.private_key;
  }

  if (!private_key) {
    return 0;
  }

  pctx = EVP_PKEY_CTX_new(private_key, NULL);
  if (!pctx) {
    fprintf(stderr, "[codec.v3] wrapped cek decrypt ctx alloc failed\n");
    shared_knock_codec_v3_log_openssl_error("wrapped cek decrypt ctx alloc failed");
    return 0;
  }

  do {
    if (EVP_PKEY_decrypt_init(pctx) <= 0) {
      shared_knock_codec_v3_log_openssl_error("wrapped cek decrypt init failed");
      break;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
      shared_knock_codec_v3_log_openssl_error("wrapped cek decrypt padding failed");
      break;
    }
    if (EVP_PKEY_decrypt(pctx, NULL, &plain_len, input, input_len) <= 0) {
      shared_knock_codec_v3_log_openssl_error("wrapped cek decrypt len query failed");
      break;
    }
    if (plain_len > temp_output_cap) {
      fprintf(stderr,
              "[codec.v3] wrapped cek decrypt output too small plain_len=%zu cap=%zu\n",
              plain_len,
              temp_output_cap);
      break;
    }
    if (EVP_PKEY_decrypt(pctx, temp_output, &plain_len, input, input_len) <= 0) {
      shared_knock_codec_v3_log_openssl_error("wrapped cek decrypt failed");
      break;
    }

    if (plain_len != SHARED_KNOCK_CODEC_V3_FORM1_CEK_SIZE) {
      fprintf(stderr,
              "[codec.v3] wrapped cek decrypt unexpected size plain_len=%zu expected=%u\n",
              plain_len,
              (unsigned)SHARED_KNOCK_CODEC_V3_FORM1_CEK_SIZE);
      break;
    }

    memcpy(output, temp_output, plain_len);
    *output_len = plain_len;
    ok = 1;
  } while (0);

  EVP_PKEY_CTX_free(pctx);
  return ok;
}

static size_t shared_knock_codec_v3_plaintext_size(size_t payload_len) {
  return SHARED_KNOCK_CODEC_V3_FORM1_BODY_FIXED_SIZE + payload_len;
}

static int shared_knock_codec_v3_pack_plaintext(const SharedKnockNormalizedUnit *normal,
                                                uint8_t *out_buf,
                                                size_t *out_len) {
  size_t need = 0u;

  if (!normal || !out_buf || !out_len) {
    return 0;
  }

  if (normal->payload_len > SHARED_KNOCK_CODEC_V3_FORM1_PAYLOAD_MAX) {
    return 0;
  }

  if (normal->wire_version != SHARED_KNOCK_CODEC_V3_WIRE_VERSION ||
      normal->wire_form != SHARED_KNOCK_CODEC_FORM1_ID) {
    return 0;
  }

  need = shared_knock_codec_v3_plaintext_size(normal->payload_len);
  if (*out_len < need) {
    return 0;
  }

  shared_knock_codec_v3_write_u32_be(out_buf + 0, normal->timestamp);
  shared_knock_codec_v3_write_u16_be(out_buf + 4, normal->user_id);
  out_buf[6] = normal->action_id;
  shared_knock_codec_v3_write_u32_be(out_buf + 7, normal->challenge);
  shared_knock_codec_v3_write_u32_be(out_buf + 11, (uint32_t)normal->payload_len);

  if (normal->payload_len > 0u) {
    memcpy(out_buf + 15, normal->payload, normal->payload_len);
  }

  memcpy(out_buf + 15 + normal->payload_len, normal->hmac, sizeof(normal->hmac));
  *out_len = need;
  return 1;
}

static int shared_knock_codec_v3_unpack_plaintext(const uint8_t *buf,
                                                  size_t buflen,
                                                  const char *ip,
                                                  uint16_t client_port,
                                                  int encrypted,
                                                  SharedKnockNormalizedUnit *out) {
  size_t payload_len = 0u;
  size_t need = 0u;
  size_t ip_len = 0u;

  if (!buf || !out) {
    return 0;
  }

  if (buflen < SHARED_KNOCK_CODEC_V3_FORM1_BODY_FIXED_SIZE) {
    return 0;
  }

  payload_len = (size_t)shared_knock_codec_v3_read_u32_be(buf + 11);
  if (payload_len > SHARED_KNOCK_CODEC_V3_FORM1_PAYLOAD_MAX) {
    return 0;
  }

  need = shared_knock_codec_v3_plaintext_size(payload_len);
  if (buflen != need) {
    return 0;
  }

  memset(out, 0, sizeof(*out));
  out->complete = 1;
  out->wire_version = SHARED_KNOCK_CODEC_V3_WIRE_VERSION;
  out->wire_form = SHARED_KNOCK_CODEC_FORM1_ID;
  out->session_id = 0;
  out->message_id = 0;
  out->stream_id = 0;
  out->fragment_index = 0;
  out->fragment_count = 1;
  out->timestamp = shared_knock_codec_v3_read_u32_be(buf + 0);
  out->user_id = shared_knock_codec_v3_read_u16_be(buf + 4);
  out->action_id = buf[6];
  out->challenge = shared_knock_codec_v3_read_u32_be(buf + 7);
  out->encrypted = encrypted ? 1 : 0;
  out->wire_decode = 1;
  out->wire_auth = 0;

  if (ip) {
    ip_len = strlen(ip);
    if (ip_len >= sizeof(out->ip)) {
      ip_len = sizeof(out->ip) - 1u;
    }
    memcpy(out->ip, ip, ip_len);
    out->ip[ip_len] = '\0';
  }

  out->client_port = client_port;
  out->payload_len = payload_len;
  if (payload_len > 0u) {
    memcpy(out->payload, buf + 15, payload_len);
  }
  memcpy(out->hmac, buf + 15 + payload_len, sizeof(out->hmac));

  return 1;
}

static int shared_knock_codec_v3_build_aad(const SharedKnockCodecV3Form1Packet *pkt,
                                           uint8_t *aad,
                                           size_t aad_size) {
  if (!pkt || !aad || aad_size < SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE) {
    return 0;
  }

  shared_knock_codec_v3_write_u32_be(aad + 0, pkt->outer.magic);
  shared_knock_codec_v3_write_u32_be(aad + 4, pkt->outer.version);
  aad[8] = pkt->outer.form;
  shared_knock_codec_v3_write_u16_be(aad + 9, pkt->wrapped_cek_len);
  memcpy(aad + 11, pkt->nonce, sizeof(pkt->nonce));
  shared_knock_codec_v3_write_u32_be(aad + 23, pkt->ciphertext_len);
  return 1;
}

static int shared_knock_codec_v3_unpack_wire(const uint8_t *buf,
                                             size_t buflen,
                                             SharedKnockCodecV3Form1Packet *pkt) {
  size_t expected_size = 0u;
  size_t wrapped_cek_len = 0u;
  size_t ciphertext_len = 0u;

  if (!buf || !pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (buflen < SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memset(pkt, 0, sizeof(*pkt));

  pkt->outer.magic = shared_knock_codec_v3_read_u32_be(buf + 0);
  pkt->outer.version = shared_knock_codec_v3_read_u32_be(buf + 4);
  pkt->outer.form = buf[8];
  pkt->wrapped_cek_len = shared_knock_codec_v3_read_u16_be(buf + 9);
  memcpy(pkt->nonce, buf + 11, sizeof(pkt->nonce));
  pkt->ciphertext_len = shared_knock_codec_v3_read_u32_be(buf + 23);

  wrapped_cek_len = pkt->wrapped_cek_len;
  ciphertext_len = pkt->ciphertext_len;
  if (wrapped_cek_len == 0u || wrapped_cek_len > SHARED_KNOCK_CODEC_V3_FORM1_CEK_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  if (ciphertext_len < SHARED_KNOCK_CODEC_V3_FORM1_BODY_FIXED_SIZE ||
      ciphertext_len > SHARED_KNOCK_CODEC_V3_FORM1_BODY_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  expected_size = SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE +
                  wrapped_cek_len +
                  ciphertext_len +
                  SHARED_KNOCK_CODEC_V3_FORM1_TAG_SIZE;
  if (buflen != expected_size) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memcpy(pkt->wrapped_cek, buf + SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE, wrapped_cek_len);
  memcpy(pkt->ciphertext,
         buf + SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE + wrapped_cek_len,
         ciphertext_len);
  memcpy(pkt->tag,
         buf + SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE + wrapped_cek_len + ciphertext_len,
         sizeof(pkt->tag));

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec_v3_validate_wire(const SharedKnockCodecV3Form1Packet *pkt) {
  if (!pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (pkt->outer.magic != SHARED_KNOCK_PREFIX_MAGIC) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->outer.version != SHARED_KNOCK_CODEC_V3_WIRE_VERSION) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->outer.form != SHARED_KNOCK_CODEC_FORM1_ID) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->wrapped_cek_len == 0u || pkt->wrapped_cek_len > SHARED_KNOCK_CODEC_V3_FORM1_CEK_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  if (pkt->ciphertext_len < SHARED_KNOCK_CODEC_V3_FORM1_BODY_FIXED_SIZE ||
      pkt->ciphertext_len > SHARED_KNOCK_CODEC_V3_FORM1_BODY_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec_v3_deserialize_wire(const uint8_t *buf,
                                                  size_t buflen,
                                                  SharedKnockCodecV3Form1Packet *pkt) {
  int validate_rc = 0;

  validate_rc = shared_knock_codec_v3_unpack_wire(buf, buflen, pkt);
  if (validate_rc != SL_PAYLOAD_OK) {
    return validate_rc;
  }

  validate_rc = shared_knock_codec_v3_validate_wire(pkt);
  if (validate_rc == SL_PAYLOAD_ERR_OVERFLOW) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }
  if (validate_rc != SL_PAYLOAD_OK) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec_v3_normalize(const uint8_t *buf,
                                           size_t buflen,
                                           const char *ip,
                                           uint16_t client_port,
                                           int encrypted,
                                           SharedKnockNormalizedUnit *out) {
  SharedKnockCodecV3Form1Packet pkt = {0};
  const SiglatchOpenSSL_Lib *openssl = NULL;
  uint8_t cek[SHARED_KNOCK_CODEC_V3_FORM1_CEK_SIZE] = {0};
  uint8_t aad[SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE] = {0};
  uint8_t plaintext[SHARED_KNOCK_CODEC_V3_FORM1_BODY_MAX] = {0};
  size_t cek_len = sizeof(cek);
  size_t plaintext_len = sizeof(plaintext);
  int rc = 0;

  if (!out) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (shared_knock_codec_v3_deserialize_wire(buf, buflen, &pkt) != SL_PAYLOAD_OK) {
    fprintf(stderr,
            "[codec.v3] deserialize wire failed ip=%s port=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            buflen);
    return SL_PAYLOAD_ERR_UNPACK;
  }

  if (!shared_knock_codec_v3_private_decrypt(pkt.wrapped_cek,
                                             pkt.wrapped_cek_len,
                                             cek,
                                             &cek_len)) {
    fprintf(stderr,
            "[codec.v3] wrapped cek decrypt failed ip=%s port=%u wrapped=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            (unsigned)pkt.wrapped_cek_len,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (cek_len != SHARED_KNOCK_CODEC_V3_FORM1_CEK_SIZE) {
    fprintf(stderr,
            "[codec.v3] cek length mismatch ip=%s port=%u got=%zu expected=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            cek_len,
            (unsigned)SHARED_KNOCK_CODEC_V3_FORM1_CEK_SIZE,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (!shared_knock_codec_v3_build_aad(&pkt, aad, sizeof(aad))) {
    fprintf(stderr,
            "[codec.v3] aad build failed ip=%s port=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  openssl = get_siglatch_openssl();
  if (!openssl || !openssl->aesgcm_decrypt) {
    fprintf(stderr,
            "[codec.v3] aesgcm decrypt helper unavailable ip=%s port=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (!openssl->aesgcm_decrypt(cek,
                               cek_len,
                               pkt.nonce,
                               sizeof(pkt.nonce),
                               aad,
                               sizeof(aad),
                               pkt.ciphertext,
                               pkt.ciphertext_len,
                               pkt.tag,
                               sizeof(pkt.tag),
                               plaintext,
                               &plaintext_len)) {
    fprintf(stderr,
            "[codec.v3] aesgcm decrypt failed ip=%s port=%u ciphertext=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            (unsigned)pkt.ciphertext_len,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  rc = shared_knock_codec_v3_unpack_plaintext(plaintext,
                                              plaintext_len,
                                              ip,
                                              client_port,
                                              encrypted,
                                              out);
  if (rc != 1) {
    fprintf(stderr,
            "[codec.v3] plaintext unpack failed ip=%s port=%u plaintext=%zu bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            plaintext_len,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  out->complete = 1;
  out->wire_version = SHARED_KNOCK_CODEC_V3_WIRE_VERSION;
  out->wire_form = SHARED_KNOCK_CODEC_FORM1_ID;
  out->encrypted = 1;
  out->wire_decode = 1;
  out->wire_auth = 0;
  out->fragment_count = 1;
  return SL_PAYLOAD_OK;
}

int shared_knock_codec_v3_pack(const SharedKnockCodecV3Form1Packet *pkt,
                               uint8_t *out_buf,
                               size_t maxlen) {
  size_t total_len = 0u;

  if (!pkt || !out_buf) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (pkt->wrapped_cek_len == 0u || pkt->wrapped_cek_len > SHARED_KNOCK_CODEC_V3_FORM1_CEK_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  if (pkt->ciphertext_len < SHARED_KNOCK_CODEC_V3_FORM1_BODY_FIXED_SIZE ||
      pkt->ciphertext_len > SHARED_KNOCK_CODEC_V3_FORM1_BODY_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  total_len = SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE +
              pkt->wrapped_cek_len +
              pkt->ciphertext_len +
              SHARED_KNOCK_CODEC_V3_FORM1_TAG_SIZE;
  if (maxlen < total_len) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memset(out_buf, 0, total_len);
  shared_knock_codec_v3_write_u32_be(out_buf + 0, pkt->outer.magic);
  shared_knock_codec_v3_write_u32_be(out_buf + 4, pkt->outer.version);
  out_buf[8] = pkt->outer.form;
  shared_knock_codec_v3_write_u16_be(out_buf + 9, pkt->wrapped_cek_len);
  memcpy(out_buf + 11, pkt->nonce, sizeof(pkt->nonce));
  shared_knock_codec_v3_write_u32_be(out_buf + 23, pkt->ciphertext_len);
  memcpy(out_buf + SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE,
         pkt->wrapped_cek,
         pkt->wrapped_cek_len);
  memcpy(out_buf + SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE + pkt->wrapped_cek_len,
         pkt->ciphertext,
         pkt->ciphertext_len);
  memcpy(out_buf + SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE +
         pkt->wrapped_cek_len +
         pkt->ciphertext_len,
         pkt->tag,
         sizeof(pkt->tag));

  return (int)total_len;
}

int shared_knock_codec_v3_unpack(const uint8_t *buf,
                                 size_t buflen,
                                 SharedKnockCodecV3Form1Packet *pkt) {
  return shared_knock_codec_v3_unpack_wire(buf, buflen, pkt);
}

int shared_knock_codec_v3_validate(const SharedKnockCodecV3Form1Packet *pkt) {
  return shared_knock_codec_v3_validate_wire(pkt);
}

int shared_knock_codec_v3_deserialize(const uint8_t *decrypted_buffer,
                                      size_t decrypted_len,
                                      SharedKnockCodecV3Form1Packet *pkt) {
  return shared_knock_codec_v3_deserialize_wire(decrypted_buffer, decrypted_len, pkt);
}

const char *shared_knock_codec_v3_deserialize_strerror(int code) {
  switch (code) {
  case SL_PAYLOAD_OK:
    return "ok";
  case SL_PAYLOAD_ERR_NULL_PTR:
    return "null_ptr";
  case SL_PAYLOAD_ERR_UNPACK:
    return "unpack";
  case SL_PAYLOAD_ERR_VALIDATE:
    return "validate";
  case SL_PAYLOAD_ERR_OVERFLOW:
    return "overflow";
  default:
    return "unknown";
  }
}

int shared_knock_codec_v3_create_state(SharedKnockCodecV3State **out_state) {
  SharedKnockCodecV3State *state = NULL;

  if (!out_state) {
    return 0;
  }

  state = (SharedKnockCodecV3State *)calloc(1u, sizeof(*state));
  if (!state) {
    return 0;
  }

  if (!shared_knock_codec_v3_sync_nonce_cache(state)) {
    shared_knock_codec_v3_destroy_state(state);
    *out_state = NULL;
    return 0;
  }

  *out_state = state;
  return 1;
}

void shared_knock_codec_v3_destroy_state(SharedKnockCodecV3State *state) {
  if (!state) {
    return;
  }

  if (state->nonce_ready) {
    lib_nonce_cache_shutdown(&state->nonce);
    state->nonce_ready = 0;
  }

  free(state);
}

int shared_knock_codec_v3_init(const SharedKnockCodecContext *context) {
  g_context = context;
  return 1;
}

void shared_knock_codec_v3_shutdown(void) {
  g_context = NULL;
}

int shared_knock_codec_v3_detect(const SharedKnockCodecV3State *state,
                                 const uint8_t *buf,
                                 size_t buflen) {
  SharedKnockCodecV3Form1Packet pkt = {0};

  (void)state;

  if (!buf) {
    return 0;
  }

  return shared_knock_codec_v3_deserialize_wire(buf, buflen, &pkt) == SL_PAYLOAD_OK;
}

int shared_knock_codec_v3_decode(const SharedKnockCodecV3State *state,
                                 const uint8_t *buf,
                                 size_t buflen,
                                 const char *ip,
                                 uint16_t client_port,
                                 int encrypted,
                                 SharedKnockNormalizedUnit *out) {
  if (!state || !out || !buf) {
    return 0;
  }

  (void)encrypted;

  return shared_knock_codec_v3_normalize(buf, buflen, ip, client_port, 1, out) == SL_PAYLOAD_OK;
}

int shared_knock_codec_v3_wire_auth(const SharedKnockCodecV3State *state,
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

  normal->wire_auth = shared_knock_codec_v3_packet_nonce_accept((SharedKnockCodecV3State *)state,
                                                                  normal->timestamp,
                                                                  normal->challenge) ? 1 : 0;
  return normal->wire_auth;
}

int shared_knock_codec_v3_encode(const SharedKnockCodecV3State *state,
                                 const SharedKnockNormalizedUnit *normal,
                                 uint8_t *out_buf,
                                 size_t *out_len) {
  const SharedKnockCodecContext *context = shared_knock_codec_v3_context();
  const SiglatchOpenSSL_Lib *openssl = NULL;
  SharedKnockNormalizedUnit body = {0};
  SharedKnockCodecV3Form1Packet pkt = {0};
  uint8_t digest[32] = {0};
  uint8_t plaintext[SHARED_KNOCK_CODEC_V3_FORM1_BODY_MAX] = {0};
  uint8_t cek[SHARED_KNOCK_CODEC_V3_FORM1_CEK_SIZE] = {0};
  uint8_t ciphertext[SHARED_KNOCK_CODEC_V3_FORM1_BODY_MAX] = {0};
  uint8_t aad[SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE] = {0};
  size_t plaintext_len = sizeof(plaintext);
  size_t ciphertext_len = sizeof(ciphertext);
  size_t wrapped_cek_len = 0u;
  size_t out_cap = 0u;
  size_t tag_len = SHARED_KNOCK_CODEC_V3_FORM1_TAG_SIZE;
  size_t total_len = 0u;

  (void)state;

  if (!normal || !out_buf || !out_len) {
    return 0;
  }

  if (!context || !context->openssl_session ||
      !context->openssl_session->public_key ||
      context->openssl_session->hmac_key_len < sizeof(body.hmac)) {
    return 0;
  }

  if (normal->wire_version != SHARED_KNOCK_CODEC_V3_WIRE_VERSION ||
      normal->wire_form != SHARED_KNOCK_CODEC_FORM1_ID) {
    return 0;
  }

  if (normal->payload_len > SHARED_KNOCK_CODEC_V3_FORM1_PAYLOAD_MAX) {
    return 0;
  }

  if (!shared_knock_digest_generate_v3_form1(normal, digest)) {
    return 0;
  }

  body = *normal;
  if (!shared_knock_digest_sign(context->openssl_session->hmac_key, digest, body.hmac)) {
    return 0;
  }

  if (!shared_knock_codec_v3_pack_plaintext(&body, plaintext, &plaintext_len)) {
    return 0;
  }

  if (RAND_bytes(cek, sizeof(cek)) != 1) {
    return 0;
  }

  wrapped_cek_len = (size_t)EVP_PKEY_get_size(context->openssl_session->public_key);
  if (wrapped_cek_len == 0u || wrapped_cek_len > SHARED_KNOCK_CODEC_V3_FORM1_CEK_MAX) {
    return 0;
  }

  {
    size_t wrapped_len = wrapped_cek_len;
    if (!context->openssl_session ||
        !context->openssl_session->public_key ||
        !get_siglatch_openssl() ||
        !get_siglatch_openssl()->session_encrypt) {
      return 0;
    }

    if (!get_siglatch_openssl()->session_encrypt(context->openssl_session,
                                                 cek,
                                                 sizeof(cek),
                                                 pkt.wrapped_cek,
                                                 &wrapped_len)) {
      return 0;
    }

    wrapped_cek_len = wrapped_len;
  }

  pkt.outer.magic = SHARED_KNOCK_PREFIX_MAGIC;
  pkt.outer.version = SHARED_KNOCK_CODEC_V3_WIRE_VERSION;
  pkt.outer.form = SHARED_KNOCK_CODEC_FORM1_ID;
  pkt.wrapped_cek_len = (uint16_t)wrapped_cek_len;
  pkt.ciphertext_len = (uint32_t)plaintext_len;

  if (RAND_bytes(pkt.nonce, sizeof(pkt.nonce)) != 1) {
    return 0;
  }

  if (!shared_knock_codec_v3_build_aad(&pkt, aad, sizeof(aad))) {
    return 0;
  }

  openssl = get_siglatch_openssl();
  if (!openssl || !openssl->aesgcm_encrypt) {
    return 0;
  }

  if (!openssl->aesgcm_encrypt(cek,
                               sizeof(cek),
                               pkt.nonce,
                               sizeof(pkt.nonce),
                               aad,
                               sizeof(aad),
                               plaintext,
                               plaintext_len,
                               ciphertext,
                               &ciphertext_len,
                               pkt.tag,
                               tag_len)) {
    return 0;
  }

  if (ciphertext_len > sizeof(pkt.ciphertext) || wrapped_cek_len > sizeof(pkt.wrapped_cek)) {
    return 0;
  }
  pkt.ciphertext_len = (uint32_t)ciphertext_len;
  memcpy(pkt.ciphertext, ciphertext, ciphertext_len);

  out_cap = *out_len;
  if (!shared_knock_codec_v3_pack(&pkt, out_buf, out_cap)) {
    return 0;
  }

  total_len = SHARED_KNOCK_CODEC_V3_FORM1_HEADER_SIZE +
              wrapped_cek_len +
              ciphertext_len +
              SHARED_KNOCK_CODEC_V3_FORM1_TAG_SIZE;
  *out_len = total_len;
  return 1;
}

static const SharedKnockCodecV3Lib shared_knock_codec_v3 = {
  .name = "v3",
  .init = shared_knock_codec_v3_init,
  .shutdown = shared_knock_codec_v3_shutdown,
  .create_state = shared_knock_codec_v3_create_state,
  .destroy_state = shared_knock_codec_v3_destroy_state,
  .detect = shared_knock_codec_v3_detect,
  .decode = shared_knock_codec_v3_decode,
  .wire_auth = shared_knock_codec_v3_wire_auth,
  .encode = shared_knock_codec_v3_encode,
  .pack = shared_knock_codec_v3_pack,
  .unpack = shared_knock_codec_v3_unpack,
  .validate = shared_knock_codec_v3_validate,
  .deserialize = shared_knock_codec_v3_deserialize,
  .deserialize_strerror = shared_knock_codec_v3_deserialize_strerror
};

const SharedKnockCodecV3Lib *get_shared_knock_codec_v3_lib(void) {
  return &shared_knock_codec_v3;
}
