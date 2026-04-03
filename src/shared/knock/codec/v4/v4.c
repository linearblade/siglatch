/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "v4.h"
#include "../../../../stdlib/protocol/udp/m7mux/normalize/normalize.h"
#include "../../../../stdlib/protocol/udp/m7mux/ingress/ingress.h"
#include "../user.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../digest.h"
#include "../../../../stdlib/nonce.h"
#include "../../../../stdlib/openssl/openssl.h"

#define SHARED_KNOCK_CODEC_V4_TIMESTAMP_FUZZ 300
#define WIRE_VERSION SHARED_KNOCK_CODEC_V4_WIRE_VERSION

struct SharedKnockCodecV4State {
  NonceCache nonce;
  int nonce_ready;
};

typedef struct {
  SharedKnockDigestLib lib;
  int (*generate_v4_form1)(const SharedKnockNormalizedUnit *normal, uint8_t *out_digest);
} SharedKnockCodecV4DigestInternal;

typedef struct {
  NonceLib                         nonce;
  SiglatchOpenSSL_Lib              openssl;
  SharedKnockCodecV4DigestInternal digest;
} SharedKnockCodecV4Internal;

static const SharedKnockCodecContext *g_context = NULL;
static SharedKnockCodecV4Internal internal = {0};

static const SharedKnockCodecContext *shared_knock_codec_v4_context(void);
static int shared_knock_codec_v4_attach_internal(void);
static int shared_knock_codec_v4_sync_nonce_cache(SharedKnockCodecV4State *state);
static int shared_knock_codec_v4_packet_nonce_accept(SharedKnockCodecV4State *state,
                                                      uint32_t timestamp,
                                                      uint32_t challenge);
static int shared_knock_codec_v4_decrypt_payload_key(const uint8_t *input,
                                                     size_t input_len,
                                                     uint8_t *output,
                                                     size_t *output_len);
static int shared_knock_codec_v4_get_payload_key(const SharedKnockCodecV4Form1Packet *pkt,
                                                 const char *ip,
                                                 uint16_t client_port,
                                                 size_t buflen,
                                                 uint8_t *cek,
                                                 size_t *cek_len);
static int shared_knock_codec_v4_encrypt_payload_key(const uint8_t *input,
                                                     size_t input_len,
                                                     uint8_t *output,
                                                     size_t *output_len);
static size_t shared_knock_codec_v4_plaintext_size(size_t payload_len);
static int shared_knock_codec_v4_pack_plaintext(const SharedKnockNormalizedUnit *normal,
                                                uint8_t *out_buf,
                                                size_t *out_len);
static int shared_knock_codec_v4_unpack_plaintext(const uint8_t *buf,
                                                  size_t buflen,
                                                  const char *ip,
                                                  uint16_t client_port,
                                                  M7MuxControl *control,
                                                  SharedKnockNormalizedUnit *out);
static int shared_knock_codec_v4_build_aad(const SharedKnockCodecV4Form1Packet *pkt,
                                           uint8_t *aad,
                                           size_t aad_size);
static int shared_knock_codec_v4_unpack_wire(const uint8_t *buf,
                                             size_t buflen,
                                             SharedKnockCodecV4Form1Packet *pkt);
static int shared_knock_codec_v4_validate_wire(const SharedKnockCodecV4Form1Packet *pkt);
static int shared_knock_codec_v4_deserialize_wire(const uint8_t *buf,
                                                  size_t buflen,
                                                  SharedKnockCodecV4Form1Packet *pkt);
static int shared_knock_codec_v4_decrypt_and_unpack_packet(const SharedKnockCodecV4Form1Packet *pkt,
                                                           size_t buflen,
                                                           const char *ip,
                                                           uint16_t client_port,
                                                           M7MuxControl *control,
                                                           SharedKnockNormalizedUnit *out);
static int shared_knock_codec_v4_copy_recv_packet(const SharedKnockNormalizedUnit *src,
                                                  M7MuxRecvPacket *dst);
static int shared_knock_codec_v4_copy_send_packet(const M7MuxSendPacket *src,
                                                  SharedKnockNormalizedUnit *dst);
M7MuxUserRecvData *shared_knock_codec_v4_alloc_user_recv_data(void);
void shared_knock_codec_v4_free_user_recv_data(M7MuxUserRecvData *user);
int shared_knock_codec_v4_copy_user_recv_data(M7MuxUserRecvData *dst,
                                              const M7MuxUserRecvData *src);

static uint16_t shared_knock_codec_v4_read_u16_be(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

static uint32_t shared_knock_codec_v4_read_u32_be(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) |
         ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) |
         (uint32_t)src[3];
}

static uint64_t shared_knock_codec_v4_read_u64_be(const uint8_t *src) {
  return ((uint64_t)src[0] << 56) |
         ((uint64_t)src[1] << 48) |
         ((uint64_t)src[2] << 40) |
         ((uint64_t)src[3] << 32) |
         ((uint64_t)src[4] << 24) |
         ((uint64_t)src[5] << 16) |
         ((uint64_t)src[6] << 8) |
         (uint64_t)src[7];
}

static void shared_knock_codec_v4_write_u16_be(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)((value >> 8) & 0xffu);
  dst[1] = (uint8_t)(value & 0xffu);
}

static void shared_knock_codec_v4_write_u32_be(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)((value >> 24) & 0xffu);
  dst[1] = (uint8_t)((value >> 16) & 0xffu);
  dst[2] = (uint8_t)((value >> 8) & 0xffu);
  dst[3] = (uint8_t)(value & 0xffu);
}

static void shared_knock_codec_v4_write_u64_be(uint8_t *dst, uint64_t value) {
  dst[0] = (uint8_t)((value >> 56) & 0xffu);
  dst[1] = (uint8_t)((value >> 48) & 0xffu);
  dst[2] = (uint8_t)((value >> 40) & 0xffu);
  dst[3] = (uint8_t)((value >> 32) & 0xffu);
  dst[4] = (uint8_t)((value >> 24) & 0xffu);
  dst[5] = (uint8_t)((value >> 16) & 0xffu);
  dst[6] = (uint8_t)((value >> 8) & 0xffu);
  dst[7] = (uint8_t)(value & 0xffu);
}

static const SharedKnockCodecContext *shared_knock_codec_v4_context(void) {
  return g_context;
}

static int shared_knock_codec_v4_attach_internal(void) {
  const NonceLib *nonce_lib = NULL;
  const SharedKnockDigestLib *digest_lib = NULL;
  const SiglatchOpenSSL_Lib *openssl_lib = NULL;

  nonce_lib = get_lib_nonce();
  digest_lib = get_shared_knock_digest_lib();
  openssl_lib = get_siglatch_openssl();
  if (!nonce_lib || !digest_lib || !openssl_lib) {
    return 0;
  }

  internal.nonce = *nonce_lib;
  internal.digest.lib = *digest_lib;
  internal.digest.generate_v4_form1 = shared_knock_digest_generate_v4_form1;
  internal.openssl = *openssl_lib;
  if (!internal.digest.generate_v4_form1 ||
      !internal.digest.lib.sign ||
      !internal.openssl.session_encrypt ||
      !internal.openssl.session_decrypt ||
      !internal.openssl.session_decrypt_strerror ||
      !internal.openssl.aesgcm_encrypt ||
      !internal.openssl.aesgcm_decrypt) {
    return 0;
  }
  return 1;
}

static time_t shared_knock_codec_v4_nonce_ttl(void) {
  const SharedKnockCodecContext *context = shared_knock_codec_v4_context();
  time_t ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;

  if (context && context->nonce_window_ms > 0u) {
    ttl_seconds = (time_t)(context->nonce_window_ms / 1000u);
    if (ttl_seconds <= 0) {
      ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;
    }
  }

  return ttl_seconds;
}

static int shared_knock_codec_v4_sync_nonce_cache(SharedKnockCodecV4State *state) {
  NonceConfig cfg = {0};

  if (!state) {
    return 0;
  }

  cfg.capacity = NONCE_DEFAULT_CAPACITY;
  cfg.nonce_strlen = NONCE_DEFAULT_STRLEN;
  cfg.ttl_seconds = shared_knock_codec_v4_nonce_ttl();

  if (state->nonce_ready &&
      state->nonce.capacity == cfg.capacity &&
      state->nonce.nonce_strlen == cfg.nonce_strlen &&
      state->nonce.ttl_seconds == cfg.ttl_seconds) {
    return 1;
  }

  if (state->nonce_ready) {
    internal.nonce.cache_shutdown(&state->nonce);
    state->nonce_ready = 0;
  }

  if (!internal.nonce.cache_init(&state->nonce, &cfg)) {
    return 0;
  }

  state->nonce_ready = 1;
  return 1;
}

static int shared_knock_codec_v4_packet_nonce_accept(SharedKnockCodecV4State *state,
                                                     uint32_t timestamp,
                                                     uint32_t challenge) {
  char nonce_str[64] = {0};
  time_t now = time(NULL);

  if (!state) {
    return 0;
  }

  if (!shared_knock_codec_v4_sync_nonce_cache(state)) {
    return 0;
  }

  snprintf(nonce_str, sizeof(nonce_str), "%u-%u", timestamp, challenge);
  if (internal.nonce.check(&state->nonce, nonce_str, now)) {
    return 0;
  }

  internal.nonce.add(&state->nonce, nonce_str, now);
  return 1;
}

static int shared_knock_codec_v4_decrypt_payload_key(const uint8_t *input,
                                                     size_t input_len,
                                                     uint8_t *output,
                                                     size_t *output_len) {
  const SharedKnockCodecContext *context = shared_knock_codec_v4_context();
  uint8_t temp_output[SHARED_KNOCK_CODEC_V4_FORM1_CEK_MAX] = {0};
  size_t temp_output_len = sizeof(temp_output);
  int decrypt_rc = SL_SSL_DECRYPT_ERR_ARGS;

  if (!context || !context->openssl_session || !internal.openssl.session_decrypt ||
      !internal.openssl.session_decrypt_strerror || !input || !output || !output_len ||
      *output_len == 0u) {
    return 0;
  }

  decrypt_rc = internal.openssl.session_decrypt(context->openssl_session,
                                                input,
                                                input_len,
                                                temp_output,
                                                &temp_output_len);
  if (decrypt_rc != SL_SSL_DECRYPT_OK) {
    fprintf(stderr,
            "[codec.v4] payload key decrypt failed rc=%d reason=%s\n",
            decrypt_rc,
            internal.openssl.session_decrypt_strerror(decrypt_rc));
    return 0;
  }

  if (temp_output_len != SHARED_KNOCK_CODEC_V4_FORM1_CEK_SIZE) {
    fprintf(stderr,
            "[codec.v4] payload key decrypt unexpected size plain_len=%zu expected=%u\n",
            temp_output_len,
            (unsigned)SHARED_KNOCK_CODEC_V4_FORM1_CEK_SIZE);
    return 0;
  }

  if (*output_len < temp_output_len) {
    fprintf(stderr,
            "[codec.v4] payload key decrypt output too small plain_len=%zu cap=%zu\n",
            temp_output_len,
            *output_len);
    return 0;
  }

  memcpy(output, temp_output, temp_output_len);
  *output_len = temp_output_len;
  return 1;
}

static int shared_knock_codec_v4_get_payload_key(const SharedKnockCodecV4Form1Packet *pkt,
                                                 const char *ip,
                                                 uint16_t client_port,
                                                 size_t buflen,
                                                 uint8_t *cek,
                                                 size_t *cek_len) {
  if (!pkt || !cek || !cek_len) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (!shared_knock_codec_v4_decrypt_payload_key(pkt->wrapped_cek,
                                                 pkt->wrapped_cek_len,
                                                 cek,
                                                 cek_len)) {
    fprintf(stderr,
            "[codec.v4] payload key decrypt failed ip=%s port=%u wrapped=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            (unsigned)pkt->wrapped_cek_len,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (*cek_len != SHARED_KNOCK_CODEC_V4_FORM1_CEK_SIZE) {
    fprintf(stderr,
            "[codec.v4] cek length mismatch ip=%s port=%u got=%zu expected=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            *cek_len,
            (unsigned)SHARED_KNOCK_CODEC_V4_FORM1_CEK_SIZE,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec_v4_encrypt_payload_key(const uint8_t *input,
                                                     size_t input_len,
                                                     uint8_t *output,
                                                     size_t *output_len) {
  const SharedKnockCodecContext *context = shared_knock_codec_v4_context();
  size_t wrapped_len = 0u;

  if (!context || !context->openssl_session || !internal.openssl.session_encrypt ||
      !input || !output || !output_len || *output_len == 0u) {
    return 0;
  }

  wrapped_len = *output_len;
  if (!internal.openssl.session_encrypt(context->openssl_session,
                                        input,
                                        input_len,
                                        output,
                                        &wrapped_len)) {
    return 0;
  }

  if (wrapped_len == 0u || wrapped_len > *output_len) {
    return 0;
  }

  *output_len = wrapped_len;
  return 1;
}

static size_t shared_knock_codec_v4_plaintext_size(size_t payload_len) {
  return SHARED_KNOCK_CODEC_V4_FORM1_BODY_FIXED_SIZE + payload_len;
}

static int shared_knock_codec_v4_pack_inner_envelope(const SharedKnockNormalizedUnit *normal,
                                                     uint8_t *out_buf,
                                                     size_t out_len) {
  SiglatchV4InnerEnvelope inner = {0};

  if (!normal || !out_buf || out_len < SIGLATCH_V4_INNER_ENVELOPE_WIRE_SIZE) {
    return 0;
  }

  inner.session_id = normal->session_id;
  inner.message_id = normal->message_id;
  inner.stream_id = normal->stream_id;
  inner.fragment_index = normal->fragment_index;
  inner.fragment_count = normal->fragment_count;
  inner.flags = 0u;
  inner.stream_type = 0u;

  shared_knock_codec_v4_write_u64_be(out_buf + 0u, inner.session_id);
  shared_knock_codec_v4_write_u64_be(out_buf + 8u, inner.message_id);
  shared_knock_codec_v4_write_u32_be(out_buf + 16u, inner.stream_id);
  shared_knock_codec_v4_write_u32_be(out_buf + 20u, inner.fragment_index);
  shared_knock_codec_v4_write_u32_be(out_buf + 24u, inner.fragment_count);
  out_buf[28u] = inner.flags;
  out_buf[29u] = inner.stream_type;
  return 1;
}

static int shared_knock_codec_v4_pack_plaintext(const SharedKnockNormalizedUnit *normal,
                                                uint8_t *out_buf,
                                                size_t *out_len) {
  size_t body_offset = SHARED_KNOCK_CODEC_V4_FORM1_INNER_SIZE;
  size_t need = 0u;

  if (!normal || !out_buf || !out_len) {
    return 0;
  }

  if (normal->payload_len > SHARED_KNOCK_CODEC_V4_FORM1_PAYLOAD_MAX) {
    return 0;
  }

  if (normal->wire_version != WIRE_VERSION ||
      normal->wire_form != SHARED_KNOCK_CODEC_FORM1_ID) {
    return 0;
  }

  need = shared_knock_codec_v4_plaintext_size(normal->payload_len);
  if (*out_len < need) {
    return 0;
  }

  memset(out_buf, 0, need);
  if (!shared_knock_codec_v4_pack_inner_envelope(normal, out_buf, body_offset)) {
    return 0;
  }

  shared_knock_codec_v4_write_u32_be(out_buf + body_offset + 0, normal->timestamp);
  shared_knock_codec_v4_write_u16_be(out_buf + body_offset + 4, normal->user_id);
  out_buf[body_offset + 6] = normal->action_id;
  shared_knock_codec_v4_write_u32_be(out_buf + body_offset + 7, normal->challenge);
  shared_knock_codec_v4_write_u32_be(out_buf + body_offset + 11, (uint32_t)normal->payload_len);

  if (normal->payload_len > 0u) {
    memcpy(out_buf + body_offset + 15, normal->payload, normal->payload_len);
  }

  memcpy(out_buf + body_offset + 15 + normal->payload_len,
         normal->hmac,
         sizeof(normal->hmac));
  *out_len = need;
  return 1;
}

static int shared_knock_codec_v4_unpack_inner_envelope(const uint8_t *buf,
                                                       size_t buflen,
                                                       M7MuxControl *control,
                                                       SharedKnockNormalizedUnit *out) {
  SiglatchV4InnerEnvelope inner = {0};

  if (!buf || !out || buflen < SIGLATCH_V4_INNER_ENVELOPE_WIRE_SIZE) {
    return 0;
  }

  inner.session_id = shared_knock_codec_v4_read_u64_be(buf + 0u);
  inner.message_id = shared_knock_codec_v4_read_u64_be(buf + 8u);
  inner.stream_id = shared_knock_codec_v4_read_u32_be(buf + 16u);
  inner.fragment_index = shared_knock_codec_v4_read_u32_be(buf + 20u);
  inner.fragment_count = shared_knock_codec_v4_read_u32_be(buf + 24u);
  inner.flags = buf[28u];
  inner.stream_type = buf[29u];

  out->session_id = inner.session_id;
  out->message_id = inner.message_id;
  out->stream_id = inner.stream_id;
  out->fragment_index = inner.fragment_index;
  out->fragment_count = inner.fragment_count;

  if (control) {
    control->stream_type = inner.stream_type;
  }

  return 1;
}

static int shared_knock_codec_v4_unpack_plaintext(const uint8_t *buf,
                                                  size_t buflen,
                                                  const char *ip,
                                                  uint16_t client_port,
                                                  M7MuxControl *control,
                                                  SharedKnockNormalizedUnit *out) {
  size_t body_offset = SHARED_KNOCK_CODEC_V4_FORM1_INNER_SIZE;
  size_t payload_len = 0u;
  size_t need = 0u;
  size_t ip_len = 0u;

  if (!buf || !out) {
    return 0;
  }

  if (buflen < SHARED_KNOCK_CODEC_V4_FORM1_BODY_FIXED_SIZE) {
    return 0;
  }

  memset(out, 0, sizeof(*out));

  if (!shared_knock_codec_v4_unpack_inner_envelope(buf, buflen, control, out)) {
    return 0;
  }

  payload_len = (size_t)shared_knock_codec_v4_read_u32_be(buf + body_offset + 11);
  if (payload_len > SHARED_KNOCK_CODEC_V4_FORM1_PAYLOAD_MAX) {
    return 0;
  }

  need = shared_knock_codec_v4_plaintext_size(payload_len);
  if (buflen != need) {
    return 0;
  }

  out->timestamp = shared_knock_codec_v4_read_u32_be(buf + body_offset + 0);
  out->user_id = shared_knock_codec_v4_read_u16_be(buf + body_offset + 4);
  out->action_id = buf[body_offset + 6];
  out->challenge = shared_knock_codec_v4_read_u32_be(buf + body_offset + 7);

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
    memcpy(out->payload, buf + body_offset + 15, payload_len);
  }
  memcpy(out->hmac, buf + body_offset + 15 + payload_len, sizeof(out->hmac));

  return 1;
}

static int shared_knock_codec_v4_build_aad(const SharedKnockCodecV4Form1Packet *pkt,
                                           uint8_t *aad,
                                           size_t aad_size) {
  if (!pkt || !aad || aad_size < SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE) {
    return 0;
  }

  shared_knock_codec_v4_write_u32_be(aad + 0, pkt->outer.magic);
  shared_knock_codec_v4_write_u32_be(aad + 4, pkt->outer.version);
  aad[8] = pkt->outer.form;
  shared_knock_codec_v4_write_u16_be(aad + 9, pkt->wrapped_cek_len);
  memcpy(aad + 11, pkt->nonce, sizeof(pkt->nonce));
  shared_knock_codec_v4_write_u32_be(aad + 23, pkt->ciphertext_len);
  return 1;
}

static int shared_knock_codec_v4_unpack_wire(const uint8_t *buf,
                                             size_t buflen,
                                             SharedKnockCodecV4Form1Packet *pkt) {
  size_t expected_size = 0u;
  size_t wrapped_cek_len = 0u;
  size_t ciphertext_len = 0u;

  if (!buf || !pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (buflen < SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memset(pkt, 0, sizeof(*pkt));

  pkt->outer.magic = shared_knock_codec_v4_read_u32_be(buf + 0);
  pkt->outer.version = shared_knock_codec_v4_read_u32_be(buf + 4);
  pkt->outer.form = buf[8];
  pkt->wrapped_cek_len = shared_knock_codec_v4_read_u16_be(buf + 9);
  memcpy(pkt->nonce, buf + 11, sizeof(pkt->nonce));
  pkt->ciphertext_len = shared_knock_codec_v4_read_u32_be(buf + 23);

  wrapped_cek_len = pkt->wrapped_cek_len;
  ciphertext_len = pkt->ciphertext_len;
  if (wrapped_cek_len == 0u || wrapped_cek_len > SHARED_KNOCK_CODEC_V4_FORM1_CEK_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  if (ciphertext_len < SHARED_KNOCK_CODEC_V4_FORM1_BODY_FIXED_SIZE ||
      ciphertext_len > SHARED_KNOCK_CODEC_V4_FORM1_BODY_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  expected_size = SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE +
                  wrapped_cek_len +
                  ciphertext_len +
                  SHARED_KNOCK_CODEC_V4_FORM1_TAG_SIZE;
  if (buflen != expected_size) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memcpy(pkt->wrapped_cek, buf + SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE, wrapped_cek_len);
  memcpy(pkt->ciphertext,
         buf + SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE + wrapped_cek_len,
         ciphertext_len);
  memcpy(pkt->tag,
         buf + SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE + wrapped_cek_len + ciphertext_len,
         sizeof(pkt->tag));

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec_v4_validate_wire(const SharedKnockCodecV4Form1Packet *pkt) {
  if (!pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (pkt->outer.magic != SHARED_KNOCK_PREFIX_MAGIC) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->outer.version != WIRE_VERSION) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->outer.form != SHARED_KNOCK_CODEC_FORM1_ID) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->wrapped_cek_len == 0u || pkt->wrapped_cek_len > SHARED_KNOCK_CODEC_V4_FORM1_CEK_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  if (pkt->ciphertext_len < SHARED_KNOCK_CODEC_V4_FORM1_BODY_FIXED_SIZE ||
      pkt->ciphertext_len > SHARED_KNOCK_CODEC_V4_FORM1_BODY_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec_v4_deserialize_wire(const uint8_t *buf,
                                                  size_t buflen,
                                                  SharedKnockCodecV4Form1Packet *pkt) {
  int validate_rc = 0;

  validate_rc = shared_knock_codec_v4_unpack_wire(buf, buflen, pkt);
  if (validate_rc != SL_PAYLOAD_OK) {
    return validate_rc;
  }

  validate_rc = shared_knock_codec_v4_validate_wire(pkt);
  if (validate_rc == SL_PAYLOAD_ERR_OVERFLOW) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }
  if (validate_rc != SL_PAYLOAD_OK) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec_v4_decrypt_and_unpack_packet(const SharedKnockCodecV4Form1Packet *pkt,
                                                           size_t buflen,
                                                           const char *ip,
                                                           uint16_t client_port,
                                                           M7MuxControl *control,
                                                           SharedKnockNormalizedUnit *out) {
  uint8_t cek[SHARED_KNOCK_CODEC_V4_FORM1_CEK_SIZE] = {0};
  uint8_t aad[SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE] = {0};
  uint8_t plaintext[SHARED_KNOCK_CODEC_V4_FORM1_BODY_MAX] = {0};
  size_t cek_len = sizeof(cek);
  size_t plaintext_len = sizeof(plaintext);
  int rc = 0;

  if (!pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (shared_knock_codec_v4_get_payload_key(pkt,
                                             ip,
                                             client_port,
                                             buflen,
                                             cek,
                                             &cek_len) != SL_PAYLOAD_OK) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (!shared_knock_codec_v4_build_aad(pkt, aad, sizeof(aad))) {
    fprintf(stderr,
            "[codec.v4] aad build failed ip=%s port=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (!internal.openssl.aesgcm_decrypt(cek,
                                       cek_len,
                                       pkt->nonce,
                                       sizeof(pkt->nonce),
                                       aad,
                                       sizeof(aad),
                                       pkt->ciphertext,
                                       pkt->ciphertext_len,
                                       pkt->tag,
                                       sizeof(pkt->tag),
                                       plaintext,
                                       &plaintext_len)) {
    fprintf(stderr,
            "[codec.v4] aesgcm decrypt failed ip=%s port=%u ciphertext=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            (unsigned)pkt->ciphertext_len,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  rc = shared_knock_codec_v4_unpack_plaintext(plaintext,
                                              plaintext_len,
                                              ip,
                                              client_port,
                                              control,
                                              out);
  if (rc != 1) {
    fprintf(stderr,
            "[codec.v4] plaintext unpack failed ip=%s port=%u plaintext=%zu bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            plaintext_len,
            buflen);
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

int shared_knock_codec_v4_pack(const void *pkt_,
                               uint8_t *out_buf,
                               size_t maxlen) {
  const SharedKnockCodecV4Form1Packet *pkt = (const SharedKnockCodecV4Form1Packet *)pkt_;
  size_t total_len = 0u;

  if (!pkt || !out_buf) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (pkt->wrapped_cek_len == 0u || pkt->wrapped_cek_len > SHARED_KNOCK_CODEC_V4_FORM1_CEK_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  if (pkt->ciphertext_len < SHARED_KNOCK_CODEC_V4_FORM1_BODY_FIXED_SIZE ||
      pkt->ciphertext_len > SHARED_KNOCK_CODEC_V4_FORM1_BODY_MAX) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  total_len = SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE +
              pkt->wrapped_cek_len +
              pkt->ciphertext_len +
              SHARED_KNOCK_CODEC_V4_FORM1_TAG_SIZE;
  if (maxlen < total_len) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memset(out_buf, 0, total_len);
  shared_knock_codec_v4_write_u32_be(out_buf + 0, pkt->outer.magic);
  shared_knock_codec_v4_write_u32_be(out_buf + 4, pkt->outer.version);
  out_buf[8] = pkt->outer.form;
  shared_knock_codec_v4_write_u16_be(out_buf + 9, pkt->wrapped_cek_len);
  memcpy(out_buf + 11, pkt->nonce, sizeof(pkt->nonce));
  shared_knock_codec_v4_write_u32_be(out_buf + 23, pkt->ciphertext_len);
  memcpy(out_buf + SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE,
         pkt->wrapped_cek,
         pkt->wrapped_cek_len);
  memcpy(out_buf + SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE + pkt->wrapped_cek_len,
         pkt->ciphertext,
         pkt->ciphertext_len);
  memcpy(out_buf + SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE +
         pkt->wrapped_cek_len +
         pkt->ciphertext_len,
         pkt->tag,
         sizeof(pkt->tag));

  return (int)total_len;
}

int shared_knock_codec_v4_unpack(const uint8_t *buf,
                                 size_t buflen,
                                 void *pkt_) {
  SharedKnockCodecV4Form1Packet *pkt = (SharedKnockCodecV4Form1Packet *)pkt_;

  return shared_knock_codec_v4_unpack_wire(buf, buflen, pkt);
}

int shared_knock_codec_v4_validate(const void *pkt_) {
  const SharedKnockCodecV4Form1Packet *pkt = (const SharedKnockCodecV4Form1Packet *)pkt_;

  return shared_knock_codec_v4_validate_wire(pkt);
}

int shared_knock_codec_v4_deserialize(const uint8_t *decrypted_buffer,
                                      size_t decrypted_len,
                                      void *pkt_) {
  SharedKnockCodecV4Form1Packet *pkt = (SharedKnockCodecV4Form1Packet *)pkt_;

  return shared_knock_codec_v4_deserialize_wire(decrypted_buffer, decrypted_len, pkt);
}

const char *shared_knock_codec_v4_deserialize_strerror(int code) {
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

static int shared_knock_codec_v4_copy_recv_packet(const SharedKnockNormalizedUnit *src,
                                                  M7MuxRecvPacket *dst) {
  M7MuxUserRecvData *user = NULL;

  if (!src || !dst || !dst->user) {
    return 0;
  }

  user = (M7MuxUserRecvData *)dst->user;

  if (src->payload_len > sizeof(user->payload)) {
    return 0;
  }

  memset(dst, 0, sizeof(*dst));
  dst->user = user;
  dst->complete = src->complete;
  dst->should_reply = 0;
  dst->synthetic_session = 0;
  dst->wire_version = src->wire_version;
  dst->wire_form = src->wire_form;
  dst->received_ms = 0u;
  dst->session_id = src->session_id;
  dst->message_id = src->message_id;
  dst->stream_id = src->stream_id;
  dst->fragment_index = src->fragment_index;
  dst->fragment_count = src->fragment_count;
  dst->timestamp = src->timestamp;
  memcpy(dst->label, "codec", sizeof("codec"));
  memcpy(dst->ip, src->ip, sizeof(dst->ip));
  dst->client_port = src->client_port;
  dst->encrypted = src->encrypted;
  dst->wire_decode = src->wire_decode;
  dst->wire_auth = src->wire_auth;

  memset(user, 0, sizeof(*user));
  user->user_id = src->user_id;
  user->action_id = src->action_id;
  user->challenge = src->challenge;
  memcpy(user->hmac, src->hmac, sizeof(user->hmac));
  user->payload_len = (uint16_t)src->payload_len;
  if (src->payload_len > 0u) {
  memcpy(user->payload, src->payload, src->payload_len);
  }

  return 1;
}

static int shared_knock_codec_v4_copy_send_packet(const M7MuxSendPacket *src,
                                                  SharedKnockNormalizedUnit *dst) {
  const M7MuxUserSendData *user = NULL;

  if (!src || !dst || !src->user) {
    return 0;
  }

  user = src->user;
  if (user->payload_len > sizeof(dst->payload)) {
    return 0;
  }

  memset(dst, 0, sizeof(*dst));
  dst->complete = (src->fragment_count == 0u) ? 1 : ((src->fragment_index + 1u) >= src->fragment_count);
  dst->wire_version = src->wire_version;
  dst->wire_form = src->wire_form;
  dst->session_id = src->session_id;
  dst->message_id = src->message_id;
  dst->stream_id = src->stream_id;
  dst->fragment_index = src->fragment_index;
  dst->fragment_count = src->fragment_count;
  dst->timestamp = src->timestamp;
  dst->user_id = user->user_id;
  dst->action_id = user->action_id;
  dst->challenge = user->challenge;
  memcpy(dst->hmac, user->hmac, sizeof(dst->hmac));
  memcpy(dst->ip, src->ip, sizeof(dst->ip));
  dst->client_port = src->client_port;
  dst->encrypted = src->encrypted;
  dst->wire_auth = src->wire_auth;
  dst->payload_len = user->payload_len;
  if (user->payload_len > 0u) {
    memcpy(dst->payload, user->payload, user->payload_len);
  }

  return 1;
}

static int shared_knock_codec_v4_adapter_create_state(void **out_state) {
  return shared_knock_codec_v4_create_state(out_state);
}

static void shared_knock_codec_v4_adapter_destroy_state(void *state) {
  shared_knock_codec_v4_destroy_state((SharedKnockCodecV4State *)state);
}

static int shared_knock_codec_v4_adapter_detect(const M7MuxContext *ctx,
                                                 const void *state,
                                                 const M7MuxIngress *ingress,
                                                 M7MuxIngressIdentity *identity) {
  (void)ctx;

  return shared_knock_codec_v4_detect((const SharedKnockCodecV4State *)state, ingress, identity);
}

static size_t shared_knock_codec_v4_adapter_count_fragments(const M7MuxContext *ctx,
                                                            const void *state,
                                                            const M7MuxSendPacket *send) {
  SharedKnockNormalizedUnit normal = {0};

  (void)ctx;

  if (!shared_knock_codec_v4_copy_send_packet(send, &normal)) {
    return 0u;
  }

  return shared_knock_codec_v4_count_fragments((const SharedKnockCodecV4State *)state,
                                               &normal,
                                               0u);
}

static int shared_knock_codec_v4_adapter_decode(const M7MuxContext *ctx,
                                                 const void *state,
                                                 const M7MuxIngress *ingress,
                                                 M7MuxControl *control,
                                                 M7MuxRecvPacket *out) {
  SharedKnockNormalizedUnit normal = {0};

  (void)ctx;

  if (!shared_knock_codec_v4_decode((const SharedKnockCodecV4State *)state,
                                     ingress,
                                     control,
                                     &normal)) {
    return 0;
  }

  if (!shared_knock_codec_v4_copy_recv_packet(&normal, out)) {
    return 0;
  }
  if (out && ingress) {
    out->received_ms = ingress->received_ms;
  }

  return 1;
}

static int shared_knock_codec_v4_adapter_encode(const M7MuxContext *ctx,
                                                 const void *state,
                                                 const M7MuxSendPacket *send,
                                                 M7MuxEgressData *out) {
  SharedKnockNormalizedUnit normal = {0};
  uint8_t encoded[SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE] = {0};
  size_t encoded_len = sizeof(encoded);

  (void)ctx;

  if (!shared_knock_codec_v4_copy_send_packet(send, &normal)) {
    return 0;
  }

  if (!shared_knock_codec_v4_encode((const SharedKnockCodecV4State *)state,
                                    &normal,
                                    encoded,
                                    &encoded_len)) {
    return 0;
  }

  return m7mux_normalize_adapter_fill_egress(send, encoded, encoded_len, out);
}

static int shared_knock_codec_v4_adapter_encode_fragment(const M7MuxContext *ctx,
                                                         const void *state,
                                                         const M7MuxSendPacket *send,
                                                         size_t fragment_index,
                                                         size_t fragment_count,
                                                         M7MuxEgressData *out) {
  SharedKnockNormalizedUnit normal = {0};
  uint8_t encoded[SHARED_KNOCK_CODEC_V4_FORM1_PACKET_MAX_SIZE] = {0};
  size_t encoded_len = sizeof(encoded);

  (void)ctx;

  if (!shared_knock_codec_v4_copy_send_packet(send, &normal)) {
    return 0;
  }

  if (!shared_knock_codec_v4_encode_fragment((const SharedKnockCodecV4State *)state,
                                             &normal,
                                             fragment_index,
                                             fragment_count,
                                             encoded,
                                             &encoded_len)) {
    return 0;
  }

  return m7mux_normalize_adapter_fill_egress(send, encoded, encoded_len, out);
}

static const M7MuxNormalizeAdapter shared_knock_codec_v4_adapter = {
  .name = "codec.v4",
  .wire_version = WIRE_VERSION,
  .create_state = shared_knock_codec_v4_adapter_create_state,
  .destroy_state = shared_knock_codec_v4_adapter_destroy_state,
  .alloc_user_recv_data = shared_knock_codec_v4_alloc_user_recv_data,
  .free_user_recv_data = shared_knock_codec_v4_free_user_recv_data,
  .copy_user_recv_data = shared_knock_codec_v4_copy_user_recv_data,
  .count_fragments = shared_knock_codec_v4_adapter_count_fragments,
  .detect = shared_knock_codec_v4_adapter_detect,
  .decode = shared_knock_codec_v4_adapter_decode,
  .encode = shared_knock_codec_v4_adapter_encode,
  .encode_fragment = shared_knock_codec_v4_adapter_encode_fragment,
  .state = NULL,
  .reserved = NULL
};

int shared_knock_codec_v4_create_state(void **out_state_) {
  SharedKnockCodecV4State **out_state = (SharedKnockCodecV4State **)out_state_;
  SharedKnockCodecV4State *state = NULL;

  if (!out_state) {
    return 0;
  }

  state = (SharedKnockCodecV4State *)calloc(1u, sizeof(*state));
  if (!state) {
    return 0;
  }

  if (!shared_knock_codec_v4_sync_nonce_cache(state)) {
    shared_knock_codec_v4_destroy_state(state);
    *out_state = NULL;
    return 0;
  }

  *out_state = state;
  return 1;
}

void shared_knock_codec_v4_destroy_state(void *state_) {
  SharedKnockCodecV4State *state = (SharedKnockCodecV4State *)state_;

  if (!state) {
    return;
  }

  if (state->nonce_ready) {
    internal.nonce.cache_shutdown(&state->nonce);
    state->nonce_ready = 0;
  }

  free(state);
}

M7MuxUserRecvData *shared_knock_codec_v4_alloc_user_recv_data(void) {
  return (M7MuxUserRecvData *)calloc(1u, sizeof(M7MuxUserRecvData));
}

void shared_knock_codec_v4_free_user_recv_data(M7MuxUserRecvData *user) {
  free(user);
}

int shared_knock_codec_v4_copy_user_recv_data(M7MuxUserRecvData *dst,
                                              const M7MuxUserRecvData *src) {
  if (!dst || !src) {
    return 0;
  }

  memcpy(dst, src, sizeof(*dst));
  return 1;
}

int shared_knock_codec_v4_init(const SharedKnockCodecContext *context) {
  g_context = context;
  memset(&internal, 0, sizeof(internal));
  if (!shared_knock_codec_v4_attach_internal()) {
    g_context = NULL;
    return 0;
  }
  return 1;
}

void shared_knock_codec_v4_shutdown(void) {
  g_context = NULL;
  /*
   * Keep the internal helper table alive until m7mux tears down its adapter
   * states. These are borrowed singleton function tables, and the adapter
   * destroy path still needs internal.nonce for cached nonce cleanup.
   */
  //  memset(&internal, 0, sizeof(internal));
}

int shared_knock_codec_v4_detect(const void *state_,
                                 const struct M7MuxIngress *ingress,
                                 M7MuxIngressIdentity *identity) {
  SharedKnockCodecV4Form1Packet pkt = {0};
  const uint8_t *buf = NULL;
  size_t buflen = 0u;

  (void)state_;

  if (!ingress) {
    return 0;
  }

  buf = ingress->buffer;
  buflen = ingress->len;

  if (shared_knock_codec_v4_deserialize_wire(buf, buflen, &pkt) != SL_PAYLOAD_OK) {
    return 0;
  }

  if (identity) {
    identity->encrypted = 1;
    identity->magic = pkt.outer.magic;
    identity->version = pkt.outer.version;
    identity->form = pkt.outer.form;
  }

  return 1;
}

size_t shared_knock_codec_v4_count_fragments(const void *state_,
                                             const SharedKnockNormalizedUnit *normal,
                                             size_t force_fragment_count) {
  const SharedKnockCodecV4State *state = (const SharedKnockCodecV4State *)state_;
  size_t payload_len = 0u;
  size_t required = 0u;
  size_t payload_max = SHARED_KNOCK_CODEC_V4_FORM1_PAYLOAD_MAX;

  (void)state;

  if (!normal || payload_max == 0u) {
    return 0u;
  }

  payload_len = normal->payload_len;
  required = payload_len / payload_max;
  if ((payload_len % payload_max) != 0u) {
    required++;
  }
  if (required == 0u) {
    required = 1u;
  }

  if (force_fragment_count > 0u) {
    if (force_fragment_count < required) {
      return 0u;
    }
    return force_fragment_count;
  }

  return required;
}

int shared_knock_codec_v4_encode_fragment(const void *state_,
                                          const SharedKnockNormalizedUnit *normal,
                                          size_t fragment_index,
                                          size_t force_fragment_count,
                                          uint8_t *out_buf,
                                          size_t *out_len) {
  SharedKnockNormalizedUnit fragment = {0};
  size_t fragment_count = 0u;
  size_t payload_base = 0u;
  size_t payload_remainder = 0u;
  size_t fragment_payload_len = 0u;
  size_t fragment_offset = 0u;

  if (!normal || !out_buf || !out_len) {
    return 0;
  }

  if (normal->wire_version != WIRE_VERSION ||
      normal->wire_form != SHARED_KNOCK_CODEC_FORM1_ID) {
    return 0;
  }

  fragment_count = shared_knock_codec_v4_count_fragments(state_, normal, force_fragment_count);
  if (fragment_count == 0u || fragment_index >= fragment_count) {
    return 0;
  }

  fragment = *normal;
  payload_base = normal->payload_len / fragment_count;
  payload_remainder = normal->payload_len % fragment_count;
  fragment_payload_len = payload_base + ((fragment_index < payload_remainder) ? 1u : 0u);
  fragment_offset = (fragment_index * payload_base) +
                    ((fragment_index < payload_remainder) ? fragment_index : payload_remainder);

  fragment.fragment_index = (uint32_t)fragment_index;
  fragment.fragment_count = (uint32_t)fragment_count;
  fragment.complete = ((fragment_index + 1u) >= fragment_count) ? 1 : 0;
  fragment.payload_len = fragment_payload_len;
  memset(fragment.payload, 0, sizeof(fragment.payload));
  if (fragment_payload_len > 0u) {
    memcpy(fragment.payload, normal->payload + fragment_offset, fragment_payload_len);
  }

  return shared_knock_codec_v4_encode(state_, &fragment, out_buf, out_len);
}

int shared_knock_codec_v4_decode(const void *state_,
                                 const struct M7MuxIngress *ingress,
                                 M7MuxControl *control,
                                 SharedKnockNormalizedUnit *out) {
  const SharedKnockCodecV4State *state = (const SharedKnockCodecV4State *)state_;
  SharedKnockCodecV4Form1Packet pkt = {0};
  const uint8_t *buf = NULL;
  size_t buflen = 0u;
  const char *ip = NULL;
  uint16_t client_port = 0u;

  if (!state || !out || !ingress) {
    return 0;
  }

  buf = ingress->buffer;
  buflen = ingress->len;
  ip = ingress->ip;
  client_port = ingress->client_port;

  if (control) {
    control->session_by_client = 1u;
  }

  if (shared_knock_codec_v4_deserialize_wire(buf, buflen, &pkt) != SL_PAYLOAD_OK) {
    fprintf(stderr,
            "[codec.v4] deserialize wire failed ip=%s port=%u bytes=%zu\n",
            ip ? ip : "(null)",
            (unsigned)client_port,
            buflen);
    return SL_PAYLOAD_ERR_UNPACK;
  }
  if (shared_knock_codec_v4_decrypt_and_unpack_packet(&pkt,
                                                       buflen,
                                                       ip,
                                                       client_port,
                                                       control,
                                                       out) != SL_PAYLOAD_OK) {
    return 0;
  }

  out->complete = (out->fragment_count == 0u) ? 1 : ((out->fragment_index + 1u) >= out->fragment_count);
  out->wire_version = WIRE_VERSION;
  out->wire_form = SHARED_KNOCK_CODEC_FORM1_ID;
  out->encrypted = 1;
  out->wire_decode = 1;
  out->wire_auth = 0;

  return 1;
}

int shared_knock_codec_v4_wire_auth(const void *state_,
                                    const struct M7MuxIngress *ingress,
                                    SharedKnockNormalizedUnit *normal) {
  const SharedKnockCodecV4State *state = (const SharedKnockCodecV4State *)state_;
  if (!state || !normal) {
    return 0;
  }

  (void)ingress;

  normal->wire_auth = shared_knock_codec_v4_packet_nonce_accept((SharedKnockCodecV4State *)state,
                                                                  normal->timestamp,
                                                                  normal->challenge) ? 1 : 0;
  return normal->wire_auth;
}

int shared_knock_codec_v4_encode(const void *state_,
                                 const SharedKnockNormalizedUnit *normal,
                                 uint8_t *out_buf,
                                 size_t *out_len) {
  const SharedKnockCodecV4State *state = (const SharedKnockCodecV4State *)state_;
  const SharedKnockCodecContext *context = shared_knock_codec_v4_context();
  SharedKnockNormalizedUnit body = {0};
  SharedKnockCodecV4Form1Packet pkt = {0};
  uint8_t digest[32] = {0};
  uint8_t plaintext[SHARED_KNOCK_CODEC_V4_FORM1_BODY_MAX] = {0};
  uint8_t cek[SHARED_KNOCK_CODEC_V4_FORM1_CEK_SIZE] = {0};
  uint8_t ciphertext[SHARED_KNOCK_CODEC_V4_FORM1_BODY_MAX] = {0};
  uint8_t aad[SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE] = {0};
  size_t plaintext_len = sizeof(plaintext);
  size_t ciphertext_len = sizeof(ciphertext);
  size_t wrapped_cek_len = sizeof(pkt.wrapped_cek);
  size_t out_cap = 0u;
  size_t tag_len = SHARED_KNOCK_CODEC_V4_FORM1_TAG_SIZE;
  size_t total_len = 0u;

  (void)state;

  if (!normal || !out_buf || !out_len) {
    return 0;
  }

  if (normal->wire_version != WIRE_VERSION ||
      normal->wire_form != SHARED_KNOCK_CODEC_FORM1_ID) {
    return 0;
  }

  if (normal->payload_len > SHARED_KNOCK_CODEC_V4_FORM1_PAYLOAD_MAX) {
    return 0;
  }

  body = *normal;
  if (normal->wire_auth) {
    if (!context || !context->openssl_session ||
        !context->openssl_session->public_key ||
        context->openssl_session->hmac_key_len < sizeof(body.hmac)) {
      return 0;
    }

    if (!internal.digest.generate_v4_form1(normal, digest)) {
      return 0;
    }

    if (!internal.digest.lib.sign(context->openssl_session->hmac_key, digest, body.hmac)) {
      return 0;
    }
  }

  if (!shared_knock_codec_v4_pack_plaintext(&body, plaintext, &plaintext_len)) {
    return 0;
  }

  if (RAND_bytes(cek, sizeof(cek)) != 1) {
    return 0;
  }

  if (!shared_knock_codec_v4_encrypt_payload_key(cek,
                                                 sizeof(cek),
                                                 pkt.wrapped_cek,
                                                 &wrapped_cek_len)) {
    return 0;
  }

  pkt.outer.magic = SHARED_KNOCK_PREFIX_MAGIC;
  pkt.outer.version = WIRE_VERSION;
  pkt.outer.form = SHARED_KNOCK_CODEC_FORM1_ID;
  pkt.wrapped_cek_len = (uint16_t)wrapped_cek_len;
  pkt.ciphertext_len = (uint32_t)plaintext_len;

  if (RAND_bytes(pkt.nonce, sizeof(pkt.nonce)) != 1) {
    return 0;
  }

  if (!shared_knock_codec_v4_build_aad(&pkt, aad, sizeof(aad))) {
    return 0;
  }

  if (!internal.openssl.aesgcm_encrypt(cek,
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
  if (!shared_knock_codec_v4_pack(&pkt, out_buf, out_cap)) {
    return 0;
  }

  total_len = SHARED_KNOCK_CODEC_V4_FORM1_HEADER_SIZE +
              wrapped_cek_len +
              ciphertext_len +
              SHARED_KNOCK_CODEC_V4_FORM1_TAG_SIZE;
  *out_len = total_len;
  return 1;
}

const M7MuxNormalizeAdapter *shared_knock_codec_v4_get_adapter(void) {
  return &shared_knock_codec_v4_adapter;
}
