/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "v2.h"
#include "../../../../stdlib/protocol/udp/m7mux/normalize/normalize.h"
#include "../../../../stdlib/protocol/udp/m7mux/ingress/ingress.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../response.h"
#include "../../digest.h"
#include "../../../../stdlib/nonce.h"
#include "../../../../stdlib/openssl/rsa/rsa.h"
#include "v2_form1.h"

#define SHARED_KNOCK_CODEC_V2_FORM1_TIMESTAMP_FUZZ 300
#define WIRE_VERSION SHARED_KNOCK_CODEC_V2_WIRE_VERSION

static uint16_t shared_knock_codec_v2_read_u16_be(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

static uint32_t shared_knock_codec_v2_read_u32_be(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) |
         ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) |
         (uint32_t)src[3];
}

static void shared_knock_codec_v2_write_u16_be(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)((value >> 8) & 0xffu);
  dst[1] = (uint8_t)(value & 0xffu);
}

static void shared_knock_codec_v2_write_u32_be(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)((value >> 24) & 0xffu);
  dst[1] = (uint8_t)((value >> 16) & 0xffu);
  dst[2] = (uint8_t)((value >> 8) & 0xffu);
  dst[3] = (uint8_t)(value & 0xffu);
}

struct SharedKnockCodecV2State {
  NonceCache nonce;
  int nonce_ready;
};

static const SharedKnockCodecContext *g_context = NULL;
static const SharedKnockCodecContext *shared_knock_codec_v2_context(void);
static int shared_knock_codec_v2_sync_nonce_cache(SharedKnockCodecV2State *state);
static int shared_knock_codec_v2_private_decrypt(const uint8_t *input,
                                                  size_t input_len,
                                                  uint8_t *output,
                                                  size_t *output_len);
static int shared_knock_codec_v2_unpack_wire(const uint8_t *buf,
                                         size_t buflen,
                                         SharedKnockCodecV2Form1Packet *pkt);
static int shared_knock_codec_v2_validate_wire(const SharedKnockCodecV2Form1Packet *pkt);
static int shared_knock_codec_v2_deserialize_wire(const uint8_t *buf,
                                              size_t buflen,
                                              SharedKnockCodecV2Form1Packet *pkt);
static int shared_knock_codec_v2_normalize(const uint8_t *buf,
                                            size_t buflen,
                                            const char *ip,
                                            uint16_t client_port,
                                            int encrypted,
                                            SharedKnockNormalizedUnit *out);
static int shared_knock_codec_v2_packet_nonce_accept(SharedKnockCodecV2State *state,
                                                      uint32_t timestamp,
                                                      uint32_t challenge);
void shared_knock_codec_v2_destroy_state(void *state);

static const SharedKnockCodecContext *shared_knock_codec_v2_context(void) {
  return g_context;
}

static time_t shared_knock_codec_v2_nonce_ttl(void) {
  const SharedKnockCodecContext *context = shared_knock_codec_v2_context();
  time_t ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;

  if (context && context->nonce_window_ms > 0u) {
    ttl_seconds = (time_t)(context->nonce_window_ms / 1000u);
    if (ttl_seconds <= 0) {
      ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;
    }
  }

  return ttl_seconds;
}

static int shared_knock_codec_v2_sync_nonce_cache(SharedKnockCodecV2State *state) {
  NonceConfig cfg = {0};

  if (!state) {
    return 0;
  }

  cfg.capacity = NONCE_DEFAULT_CAPACITY;
  cfg.nonce_strlen = NONCE_DEFAULT_STRLEN;
  cfg.ttl_seconds = shared_knock_codec_v2_nonce_ttl();

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

static int shared_knock_codec_v2_private_decrypt(const uint8_t *input,
                                                  size_t input_len,
                                                  uint8_t *output,
                                                  size_t *output_len) {
  EVP_PKEY_CTX *pctx = NULL;
  size_t plain_len = 0u;
  int ok = 0;
  const SharedKnockCodecContext *context = shared_knock_codec_v2_context();

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

static int shared_knock_codec_v2_unpack_wire(const uint8_t *buf,
                                         size_t buflen,
                                         SharedKnockCodecV2Form1Packet *pkt) {
  if (!buf || !pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (buflen != SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memset(pkt, 0, sizeof(*pkt));

  pkt->outer.magic = shared_knock_codec_v2_read_u32_be(buf + 0);
  pkt->outer.version = shared_knock_codec_v2_read_u32_be(buf + 4);
  pkt->outer.form = buf[8];

  pkt->inner.timestamp = shared_knock_codec_v2_read_u32_be(buf + 9);
  pkt->inner.user_id = shared_knock_codec_v2_read_u16_be(buf + 13);
  pkt->inner.action_id = buf[15];
  pkt->inner.challenge = shared_knock_codec_v2_read_u32_be(buf + 16);
  memcpy(pkt->inner.hmac, buf + 20, sizeof(pkt->inner.hmac));
  pkt->inner.payload_len = shared_knock_codec_v2_read_u16_be(buf + 52);

  memcpy(pkt->payload,
         buf + SHARED_KNOCK_CODEC_V2_FORM1_OUTER_SIZE + SHARED_KNOCK_CODEC_V2_FORM1_INNER_SIZE,
         sizeof(pkt->payload));

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec_v2_validate_wire(const SharedKnockCodecV2Form1Packet *pkt) {
  time_t now = 0;

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

  if (pkt->inner.payload_len > sizeof(pkt->payload)) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  now = time(NULL);
  if (pkt->inner.timestamp > now + SHARED_KNOCK_CODEC_V2_FORM1_TIMESTAMP_FUZZ ||
      pkt->inner.timestamp < now - SHARED_KNOCK_CODEC_V2_FORM1_TIMESTAMP_FUZZ) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec_v2_deserialize_wire(const uint8_t *buf,
                                              size_t buflen,
                                              SharedKnockCodecV2Form1Packet *pkt) {
  int validate_rc = 0;

  validate_rc = shared_knock_codec_v2_unpack_wire(buf, buflen, pkt);
  if (validate_rc != SL_PAYLOAD_OK) {
    return validate_rc;
  }

  validate_rc = shared_knock_codec_v2_validate_wire(pkt);
  if (validate_rc == SL_PAYLOAD_ERR_OVERFLOW) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }
  if (validate_rc != SL_PAYLOAD_OK) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

static int shared_knock_codec_v2_normalize(const uint8_t *buf,
                                            size_t buflen,
                                            const char *ip,
                                            uint16_t client_port,
                                            int encrypted,
                                            SharedKnockNormalizedUnit *out) {
  SharedKnockCodecV2Form1Packet pkt = {0};
  int deserialize_rc = 0;
  size_t ip_len = 0;
  size_t copy_len = 0;
  int overflow = 0;

  if (!out) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  deserialize_rc = shared_knock_codec_v2_deserialize_wire(buf, buflen, &pkt);
  if (deserialize_rc != SL_PAYLOAD_OK) {
    return deserialize_rc;
  }

  overflow = (pkt.inner.payload_len > sizeof(out->payload));

  memset(out, 0, sizeof(*out));

  out->complete = 1;
  out->wire_version = WIRE_VERSION;
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

static int shared_knock_codec_v2_packet_nonce_accept(SharedKnockCodecV2State *state,
                                                      uint32_t timestamp,
                                                      uint32_t challenge) {
  char nonce_str[64] = {0};
  time_t now = time(NULL);

  if (!state) {
    return 0;
  }

  if (!shared_knock_codec_v2_sync_nonce_cache(state)) {
    return 0;
  }

  snprintf(nonce_str, sizeof(nonce_str), "%u-%u", timestamp, challenge);
  if (lib_nonce_check(&state->nonce, nonce_str, now)) {
    return 0;
  }

  lib_nonce_add(&state->nonce, nonce_str, now);
  return 1;
}

int shared_knock_codec_v2_pack(const void *pkt_,
                                uint8_t *out_buf,
                                size_t maxlen) {
  const SharedKnockCodecV2Form1Packet *pkt = (const SharedKnockCodecV2Form1Packet *)pkt_;

  if (!pkt || !out_buf) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (maxlen < SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  if (pkt->inner.payload_len > sizeof(pkt->payload)) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  memset(out_buf, 0, SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE);
  shared_knock_codec_v2_write_u32_be(out_buf + 0, pkt->outer.magic);
  shared_knock_codec_v2_write_u32_be(out_buf + 4, pkt->outer.version);
  out_buf[8] = pkt->outer.form;
  shared_knock_codec_v2_write_u32_be(out_buf + 9, pkt->inner.timestamp);
  shared_knock_codec_v2_write_u16_be(out_buf + 13, pkt->inner.user_id);
  out_buf[15] = pkt->inner.action_id;
  shared_knock_codec_v2_write_u32_be(out_buf + 16, pkt->inner.challenge);
  memcpy(out_buf + 20, pkt->inner.hmac, sizeof(pkt->inner.hmac));
  shared_knock_codec_v2_write_u16_be(out_buf + 52, pkt->inner.payload_len);
  if (pkt->inner.payload_len > 0u) {
    memcpy(out_buf + SHARED_KNOCK_CODEC_V2_FORM1_OUTER_SIZE +
           SHARED_KNOCK_CODEC_V2_FORM1_INNER_SIZE,
           pkt->payload,
           pkt->inner.payload_len);
  }

  return (int)SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE;
}

int shared_knock_codec_v2_unpack(const uint8_t *buf,
                                  size_t buflen,
                                  void *pkt_) {
  SharedKnockCodecV2Form1Packet *pkt = (SharedKnockCodecV2Form1Packet *)pkt_;

  return shared_knock_codec_v2_unpack_wire(buf, buflen, pkt);
}

int shared_knock_codec_v2_validate(const void *pkt_) {
  const SharedKnockCodecV2Form1Packet *pkt = (const SharedKnockCodecV2Form1Packet *)pkt_;

  return shared_knock_codec_v2_validate_wire(pkt);
}

int shared_knock_codec_v2_deserialize(const uint8_t *buf,
                                       size_t buflen,
                                       void *pkt_) {
  SharedKnockCodecV2Form1Packet *pkt = (SharedKnockCodecV2Form1Packet *)pkt_;

  return shared_knock_codec_v2_deserialize_wire(buf, buflen, pkt);
}

const char *shared_knock_codec_v2_deserialize_strerror(int code) {
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

static int shared_knock_codec_v2_adapter_create_state(void **out_state) {
  return shared_knock_codec_v2_create_state(out_state);
}

static void shared_knock_codec_v2_adapter_destroy_state(void *state) {
  shared_knock_codec_v2_destroy_state((SharedKnockCodecV2State *)state);
}

static int shared_knock_codec_v2_adapter_detect(const M7MuxContext *ctx,
                                                 const void *state,
                                                 const M7MuxIngress *ingress,
                                                 M7MuxIngressIdentity *identity) {
  (void)ctx;

  return shared_knock_codec_v2_detect((const SharedKnockCodecV2State *)state, ingress, identity);
}

static int shared_knock_codec_v2_adapter_decode(const M7MuxContext *ctx,
                                                 const void *state,
                                                 const M7MuxIngress *ingress,
                                                 M7MuxRecvPacket *out) {
  SharedKnockNormalizedUnit normal = {0};

  (void)ctx;

  if (!shared_knock_codec_v2_decode((const SharedKnockCodecV2State *)state, ingress, &normal)) {
    return 0;
  }

  m7mux_normalize_adapter_copy_shared_to_mux(&normal, out);
  if (out && ingress) {
    out->received_ms = ingress->received_ms;
  }

  return 1;
}

static int shared_knock_codec_v2_adapter_encode(const M7MuxContext *ctx,
                                                 const void *state,
                                                 const M7MuxSendPacket *send,
                                                 M7MuxEgressData *out) {
  SharedKnockNormalizedUnit normal = {0};
  uint8_t encoded[M7MUX_NORMALIZED_PACKET_BUFFER_SIZE] = {0};
  size_t encoded_len = sizeof(encoded);

  (void)ctx;

  if (!m7mux_normalize_adapter_copy_mux_to_shared(send, &normal)) {
    return 0;
  }

  if (!shared_knock_codec_v2_encode((const SharedKnockCodecV2State *)state,
                                    &normal,
                                    encoded,
                                    &encoded_len)) {
    return 0;
  }

  return m7mux_normalize_adapter_fill_egress(send, encoded, encoded_len, out);
}

static const M7MuxNormalizeAdapter shared_knock_codec_v2_adapter = {
  .name = "codec.v2",
  .wire_version = WIRE_VERSION,
  .create_state = shared_knock_codec_v2_adapter_create_state,
  .destroy_state = shared_knock_codec_v2_adapter_destroy_state,
  .detect = shared_knock_codec_v2_adapter_detect,
  .decode = shared_knock_codec_v2_adapter_decode,
  .encode = shared_knock_codec_v2_adapter_encode,
  .state = NULL,
  .reserved = NULL
};

int shared_knock_codec_v2_create_state(void **out_state_) {
  SharedKnockCodecV2State **out_state = (SharedKnockCodecV2State **)out_state_;
  SharedKnockCodecV2State *state = NULL;

  if (!out_state) {
    return 0;
  }

  state = (SharedKnockCodecV2State *)calloc(1u, sizeof(*state));
  if (!state) {
    return 0;
  }

  if (!shared_knock_codec_v2_sync_nonce_cache(state)) {
    shared_knock_codec_v2_destroy_state(state);
    *out_state = NULL;
    return 0;
  }

  *out_state = state;
  return 1;
}

void shared_knock_codec_v2_destroy_state(void *state_) {
  SharedKnockCodecV2State *state = (SharedKnockCodecV2State *)state_;

  if (!state) {
    return;
  }

  if (state->nonce_ready) {
    lib_nonce_cache_shutdown(&state->nonce);
    state->nonce_ready = 0;
  }

  free(state);
}

int shared_knock_codec_v2_init(const SharedKnockCodecContext *context) {
  g_context = context;
  return 1;
}

void shared_knock_codec_v2_shutdown(void) {
  g_context = NULL;
}

int shared_knock_codec_v2_detect(const void *state_,
                                 const struct M7MuxIngress *ingress,
                                 M7MuxIngressIdentity *identity) {
  const SharedKnockCodecV2State *state = (const SharedKnockCodecV2State *)state_;
  SharedKnockCodecV2Form1Packet pkt = {0};
  size_t decrypted_cap = 0u;
  const SharedKnockCodecContext *context = shared_knock_codec_v2_context();
  const uint8_t *buf = NULL;
  size_t buflen = 0u;

  if (!ingress) {
    return 0;
  }

  buf = ingress->buffer;
  buflen = ingress->len;

  if (buflen == SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE &&
      shared_knock_codec_v2_deserialize_wire(buf, buflen, &pkt) == SL_PAYLOAD_OK) {
    if (identity) {
      identity->encrypted = 0;
      identity->magic = pkt.outer.magic;
      identity->version = pkt.outer.version;
      identity->form = pkt.outer.form;
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

    if (!shared_knock_codec_v2_private_decrypt(buf, buflen, decrypted, &decrypted_len)) {
      free(decrypted);
      return 0;
    }

    if (decrypted_len != SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE) {
      free(decrypted);
      return 0;
    }

    if (shared_knock_codec_v2_deserialize_wire(decrypted, decrypted_len, &pkt) != SL_PAYLOAD_OK) {
      free(decrypted);
      return 0;
    }

    free(decrypted);
  }

  if (identity) {
    identity->encrypted = 1;
    identity->magic = pkt.outer.magic;
    identity->version = pkt.outer.version;
    identity->form = pkt.outer.form;
  }
  return 1;
}

int shared_knock_codec_v2_decode(const void *state_,
                                 const struct M7MuxIngress *ingress,
                                 SharedKnockNormalizedUnit *out) {
  const SharedKnockCodecV2State *state = (const SharedKnockCodecV2State *)state_;
  const uint8_t *payload = NULL;
  size_t payload_len = 0u;
  int should_decrypt = 0;
  int rc = 0;
  const SharedKnockCodecContext *context = shared_knock_codec_v2_context();
  const uint8_t *buf = NULL;
  size_t buflen = 0u;
  const char *ip = NULL;
  uint16_t client_port = 0u;
  int encrypted = 0;

  if (!state || !out || !ingress) {
    return 0;
  }

  buf = ingress->buffer;
  buflen = ingress->len;
  ip = ingress->ip;
  client_port = ingress->client_port;
  encrypted = ingress->encrypted;
  payload = buf;
  payload_len = buflen;

  should_decrypt = encrypted ? 1 : 0;
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
    if (!shared_knock_codec_v2_private_decrypt(buf,
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

  rc = shared_knock_codec_v2_normalize(payload, payload_len, ip, client_port, should_decrypt, out);
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

int shared_knock_codec_v2_wire_auth(const void *state_,
                                     const struct M7MuxIngress *ingress,
                                     SharedKnockNormalizedUnit *normal) {
  const SharedKnockCodecV2State *state = (const SharedKnockCodecV2State *)state_;
  if (!state || !normal) {
    return 0;
  }

  (void)ingress;

  normal->wire_auth = shared_knock_codec_v2_packet_nonce_accept((SharedKnockCodecV2State *)state,
                                                                 normal->timestamp,
                                                                 normal->challenge) ? 1 : 0;
  return normal->wire_auth;
}

int shared_knock_codec_v2_encode(const void *state_,
                                  const SharedKnockNormalizedUnit *normal,
                                  uint8_t *out_buf,
                                  size_t *out_len) {
  const SharedKnockCodecV2State *state = (const SharedKnockCodecV2State *)state_;
  SharedKnockCodecV2Form1Packet wire_pkt = {0};
  const SharedKnockCodecContext *context = shared_knock_codec_v2_context();
  SiglatchOpenSSLSession *session = NULL;
  uint8_t digest[32] = {0};
  uint8_t packed[SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE] = {0};
  size_t capacity = 0u;
  size_t packed_len = 0u;
  size_t encrypted_cap = 0u;
  int should_encrypt = 0;

  (void)state;

  if (!normal || !out_buf || !out_len) {
    return 0;
  }

  capacity = *out_len;
  if (capacity < SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE) {
    return 0;
  }

  if (normal->payload_len > SHARED_KNOCK_CODEC_V2_FORM1_PAYLOAD_MAX) {
    return 0;
  }

  if (!context || !context->openssl_session || context->openssl_session->hmac_key_len < 32u) {
    return 0;
  }

  session = context->openssl_session;

  wire_pkt.outer.magic = SHARED_KNOCK_PREFIX_MAGIC;
  wire_pkt.outer.version = WIRE_VERSION;
  wire_pkt.outer.form = SHARED_KNOCK_CODEC_FORM1_ID;
  wire_pkt.inner.timestamp = normal->timestamp;
  wire_pkt.inner.user_id = normal->user_id;
  wire_pkt.inner.action_id = SL_KNOCK_RESPONSE_ACTION_ID;
  wire_pkt.inner.challenge = normal->challenge;
  wire_pkt.inner.payload_len = (uint16_t)normal->payload_len;

  if (normal->payload_len > 0u) {
    memcpy(wire_pkt.payload, normal->payload, normal->payload_len);
  }

  if (!shared_knock_digest_generate_v2_form1(&wire_pkt, digest)) {
    return 0;
  }

  if (!shared_knock_digest_sign(context->openssl_session->hmac_key, digest, wire_pkt.inner.hmac)) {
    return 0;
  }

  if (shared_knock_codec_v2_pack(&wire_pkt, packed, sizeof(packed)) < 0) {
    return 0;
  }

  packed_len = sizeof(packed);
  should_encrypt = normal->encrypted ? 1 : 0;
  if (!should_encrypt) {
    if (capacity < packed_len) {
      return 0;
    }

    memcpy(out_buf, packed, packed_len);
    *out_len = packed_len;
    return 1;
  }

  if (!session || !session->public_key) {
    return 0;
  }

  encrypted_cap = (size_t)EVP_PKEY_get_size(session->public_key);
  if (encrypted_cap <= 11u || capacity < encrypted_cap || packed_len > (encrypted_cap - 11u)) {
    return 0;
  }

  *out_len = capacity;
  if (!siglatch_openssl_session_encrypt(session, packed, packed_len, out_buf, out_len)) {
    return 0;
  }

  return 1;
}

const M7MuxNormalizeAdapter *shared_knock_codec_v2_get_adapter(void) {
  return &shared_knock_codec_v2_adapter;
}
