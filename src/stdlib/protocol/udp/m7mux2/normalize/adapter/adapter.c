/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../ingress/ingress.h"
#include "../normalize.h"
#include "../../../../../openssl.h"
#include "../../../../../../shared/knock/codec3/codec.h"
#include "../../../../../../shared/knock/codec3/v1/v1.h"
#include "../../../../../../shared/knock/codec3/v2/v2.h"

#define M7MUX2_MAX_NORMALIZE_ADAPTERS 16u

static M7Mux2Context g_ctx = {0};
static M7Mux2NormalizeAdapter g_adapters[M7MUX2_MAX_NORMALIZE_ADAPTERS] = {0};
static size_t g_adapter_count = 0;

static int m7mux2_normalize_adapter_codec3_v1_create_state(void **out_state);
static void m7mux2_normalize_adapter_codec3_v1_destroy_state(void *state);
static int m7mux2_normalize_adapter_codec3_v1_detect(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2Ingress *ingress);
static int m7mux2_normalize_adapter_codec3_v1_decode(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2Ingress *ingress,
                                                    M7Mux2RecvPacket *out);
static int m7mux2_normalize_adapter_codec3_v1_encode(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2SendPacket *send,
                                                    M7Mux2EgressData *out);
static int m7mux2_normalize_adapter_codec3_v2_create_state(void **out_state);
static void m7mux2_normalize_adapter_codec3_v2_destroy_state(void *state);
static int m7mux2_normalize_adapter_codec3_v2_detect(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2Ingress *ingress);
static int m7mux2_normalize_adapter_codec3_v2_decode(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2Ingress *ingress,
                                                    M7Mux2RecvPacket *out);
static int m7mux2_normalize_adapter_codec3_v2_encode(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2SendPacket *send,
                                                    M7Mux2EgressData *out);

static const M7Mux2NormalizeAdapter g_builtin_adapters[] = {
  {
    .name = "codec3.v1",
    .create_state = m7mux2_normalize_adapter_codec3_v1_create_state,
    .destroy_state = m7mux2_normalize_adapter_codec3_v1_destroy_state,
    .detect = m7mux2_normalize_adapter_codec3_v1_detect,
    .decode = m7mux2_normalize_adapter_codec3_v1_decode,
    .encode = m7mux2_normalize_adapter_codec3_v1_encode,
    .state = NULL,
    .reserved = NULL
  },
  {
    .name = "codec3.v2",
    .create_state = m7mux2_normalize_adapter_codec3_v2_create_state,
    .destroy_state = m7mux2_normalize_adapter_codec3_v2_destroy_state,
    .detect = m7mux2_normalize_adapter_codec3_v2_detect,
    .decode = m7mux2_normalize_adapter_codec3_v2_decode,
    .encode = m7mux2_normalize_adapter_codec3_v2_encode,
    .state = NULL,
    .reserved = NULL
  }
};

static int m7mux2_normalize_adapter_register_builtin_adapters(void);
static void m7mux2_normalize_adapter_destroy_slot(M7Mux2NormalizeAdapter *adapter);
static void m7mux2_normalize_adapter_copy_shared_to_mux(const SharedKnockNormalizedUnit *src,
                                                       M7Mux2RecvPacket *dst);
static int m7mux2_normalize_adapter_copy_mux_to_shared(const M7Mux2SendPacket *src,
                                                      SharedKnockNormalizedUnit *dst);
static int m7mux2_normalize_adapter_fill_egress(const M7Mux2SendPacket *src,
                                                const uint8_t *payload,
                                                size_t payload_len,
                                                M7Mux2EgressData *dst);

static int m7mux2_name_matches(const char *lhs, const char *rhs) {
  return strcmp(lhs, rhs) == 0;
}

static void m7mux2_normalize_adapter_reset_registry(void) {
  size_t i = 0;

  for (i = 0; i < g_adapter_count; ++i) {
    m7mux2_normalize_adapter_destroy_slot(&g_adapters[i]);
  }
  memset(g_adapters, 0, sizeof(g_adapters));
  g_adapter_count = 0;
}

static int m7mux2_normalize_adapter_apply_context(const M7Mux2Context *ctx) {
  if (!ctx) {
    return 0;
  }

  g_ctx = *ctx;
  return 1;
}

static int m7mux2_normalize_adapter_init(void) {
  m7mux2_normalize_adapter_reset_registry();
  return 1;
}

static int m7mux2_normalize_adapter_set_context(const M7Mux2Context *ctx) {
  if (!m7mux2_normalize_adapter_apply_context(ctx)) {
    return 0;
  }

  if (!g_ctx.codec_context) {
    return 1;
  }

  if (g_adapter_count == 0u) {
    if (!m7mux2_normalize_adapter_register_builtin_adapters()) {
      m7mux2_normalize_adapter_reset_registry();
      return 0;
    }
  }

  return 1;
}

static void m7mux2_normalize_adapter_shutdown(void) {
  m7mux2_normalize_adapter_reset_registry();
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static int m7mux2_normalize_adapter_register(const M7Mux2NormalizeAdapter *adapter) {
  M7Mux2NormalizeAdapter stored = {0};
  size_t i = 0;

  if (!adapter || !adapter->name || !adapter->detect ||
      !adapter->decode || !adapter->encode) {
    return 0;
  }

  for (i = 0; i < g_adapter_count; ++i) {
    if (m7mux2_name_matches(g_adapters[i].name, adapter->name)) {
      return 0;
    }
  }

  if (g_adapter_count >= M7MUX2_MAX_NORMALIZE_ADAPTERS) {
    return 0;
  }

  stored = *adapter;
  stored.state = NULL;
  if (stored.create_state && !stored.create_state(&stored.state)) {
    return 0;
  }

  g_adapters[g_adapter_count++] = stored;
  return 1;
}

static int m7mux2_normalize_adapter_unregister(const char *name) {
  size_t i = 0;
  size_t j = 0;

  if (!name) {
    return 0;
  }

  for (i = 0; i < g_adapter_count; ++i) {
    if (m7mux2_name_matches(g_adapters[i].name, name)) {
      m7mux2_normalize_adapter_destroy_slot(&g_adapters[i]);
      for (j = i; j + 1 < g_adapter_count; ++j) {
        g_adapters[j] = g_adapters[j + 1];
      }

      memset(&g_adapters[g_adapter_count - 1], 0, sizeof(g_adapters[0]));
      --g_adapter_count;
      return 1;
    }
  }

  return 0;
}

static const M7Mux2NormalizeAdapter *m7mux2_normalize_adapter_lookup(const char *name) {
  size_t i = 0;

  if (!name) {
    return NULL;
  }

  for (i = 0; i < g_adapter_count; ++i) {
    if (m7mux2_name_matches(g_adapters[i].name, name)) {
      return &g_adapters[i];
    }
  }

  return NULL;
}

static const M7Mux2NormalizeAdapter *m7mux2_normalize_adapter_demux(const M7Mux2Context *ctx,
                                                                   const M7Mux2Ingress *ingress) {
  size_t i = 0;

  if (!ctx || !ingress) {
    return NULL;
  }

  for (i = 0; i < g_adapter_count; ++i) {
    const M7Mux2NormalizeAdapter *adapter = &g_adapters[i];

    if (!adapter->detect) {
      continue;
    }

    if (adapter->detect(ctx, adapter->state, ingress)) {
      return adapter;
    }
  }

  return NULL;
}

static int m7mux2_normalize_adapter_decode(const M7Mux2Context *ctx,
                                          const M7Mux2NormalizeAdapter *adapter,
                                          const M7Mux2Ingress *ingress,
                                          M7Mux2RecvPacket *out) {
  if (!ctx || !adapter || !adapter->decode) {
    return 0;
  }

  return adapter->decode(ctx, adapter->state, ingress, out);
}

static int m7mux2_normalize_adapter_encode(const M7Mux2Context *ctx,
                                          const M7Mux2NormalizeAdapter *adapter,
                                          const M7Mux2SendPacket *send,
                                          M7Mux2EgressData *out) {
  if (!ctx || !adapter || !adapter->encode) {
    return 0;
  }

  return adapter->encode(ctx, adapter->state, send, out);
}

static size_t m7mux2_normalize_adapter_count(void) {
  return g_adapter_count;
}

static void m7mux2_normalize_adapter_destroy_slot(M7Mux2NormalizeAdapter *adapter) {
  if (!adapter) {
    return;
  }

  if (adapter->destroy_state && adapter->state) {
    adapter->destroy_state(adapter->state);
  }

  memset(adapter, 0, sizeof(*adapter));
}

static int m7mux2_normalize_adapter_register_builtin_adapters(void) {
  size_t i = 0;

  for (i = 0; i < sizeof(g_builtin_adapters) / sizeof(g_builtin_adapters[0]); ++i) {
    if (!m7mux2_normalize_adapter_register(&g_builtin_adapters[i])) {
      return 0;
    }
  }

  return 1;
}

static int m7mux2_normalize_adapter_codec3_v1_create_state(void **out_state) {
  return shared_knock_codec3_v1_create_state((SharedKnockCodec3V1State **)out_state);
}

static void m7mux2_normalize_adapter_codec3_v1_destroy_state(void *state) {
  shared_knock_codec3_v1_destroy_state((SharedKnockCodec3V1State *)state);
}

static int m7mux2_normalize_adapter_codec3_v1_detect(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2Ingress *ingress) {
  (void)ctx;
  return shared_knock_codec3_v1_detect((const SharedKnockCodec3V1State *)state,
                                       ingress ? ingress->buffer : NULL,
                                       ingress ? ingress->len : 0u);
}

static int m7mux2_normalize_adapter_codec3_v1_decode(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2Ingress *ingress,
                                                    M7Mux2RecvPacket *out) {
  SharedKnockNormalizedUnit shared = {0};

  (void)ctx;
  if (!shared_knock_codec3_v1_decode((const SharedKnockCodec3V1State *)state,
                                     ingress ? ingress->buffer : NULL,
                                     ingress ? ingress->len : 0u,
                                     ingress ? ingress->ip : NULL,
                                     ingress ? ingress->client_port : 0u,
                                     ingress ? ingress->encrypted : 0,
                                     &shared)) {
    return 0;
  }

  shared.wire_auth = shared_knock_codec3_v1_wire_auth((const SharedKnockCodec3V1State *)state,
                                                      ingress ? ingress->buffer : NULL,
                                                      ingress ? ingress->len : 0u,
                                                      ingress ? ingress->ip : NULL,
                                                      ingress ? ingress->client_port : 0u,
                                                      ingress ? ingress->encrypted : 0,
                                                      &shared) ? 1 : 0;
  shared.wire_decode = 1;
  if (!shared.wire_auth && g_ctx.enforce_wire_auth) {
    return 0;
  }
  m7mux2_normalize_adapter_copy_shared_to_mux(&shared, out);
  out->received_ms = ingress ? ingress->received_ms : 0u;
  snprintf(out->label, sizeof(out->label), "codec3.v1");
  return 1;
}

static int m7mux2_normalize_adapter_codec3_v1_encode(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2SendPacket *send,
                                                    M7Mux2EgressData *out) {
  SharedKnockNormalizedUnit shared = {0};
  const SiglatchOpenSSL_Lib *openssl = NULL;
  uint8_t encoded[SHARED_KNOCK_CODEC3_PACKET_MAX_SIZE] = {0};
  uint8_t *encrypted = NULL;
  size_t encoded_len = sizeof(encoded);
  size_t final_len = 0u;
  size_t encrypted_cap = 0u;
  const uint8_t *final_bytes = encoded;

  (void)ctx;
  if (!send || !out) {
    return 0;
  }

  if (!m7mux2_normalize_adapter_copy_mux_to_shared(send, &shared)) {
    return 0;
  }

  if (!shared_knock_codec3_v1_encode((const SharedKnockCodec3V1State *)state,
                                     &shared,
                                     encoded,
                                     &encoded_len)) {
    return 0;
  }

  final_len = encoded_len;
  if (g_ctx.codec_context && g_ctx.codec_context->server_secure) {
    openssl = get_siglatch_openssl();
    if (!openssl || !openssl->session_encrypt) {
      return 0;
    }

    if (!g_ctx.codec_context->openssl_session ||
        !g_ctx.codec_context->openssl_session->public_key) {
      return 0;
    }

    encrypted_cap = (size_t)EVP_PKEY_get_size(g_ctx.codec_context->openssl_session->public_key);
    if (encrypted_cap == 0u) {
      return 0;
    }

    encrypted = (uint8_t *)calloc(1u, encrypted_cap);
    if (!encrypted) {
      return 0;
    }

    final_len = encrypted_cap;
    if (!openssl->session_encrypt(g_ctx.codec_context->openssl_session,
                                  (const unsigned char *)encoded,
                                  encoded_len,
                                  encrypted,
                                  &final_len)) {
      free(encrypted);
      return 0;
    }

    final_bytes = encrypted;
  }

  if (!m7mux2_normalize_adapter_fill_egress(send, final_bytes, final_len, out)) {
    if (encrypted) {
      free(encrypted);
    }
    return 0;
  }

  if (encrypted) {
    free(encrypted);
  }

  return 1;
}

static int m7mux2_normalize_adapter_codec3_v2_create_state(void **out_state) {
  return shared_knock_codec3_v2_create_state((SharedKnockCodec3V2State **)out_state);
}

static void m7mux2_normalize_adapter_codec3_v2_destroy_state(void *state) {
  shared_knock_codec3_v2_destroy_state((SharedKnockCodec3V2State *)state);
}

static int m7mux2_normalize_adapter_codec3_v2_detect(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2Ingress *ingress) {
  (void)ctx;
  return shared_knock_codec3_v2_detect((const SharedKnockCodec3V2State *)state,
                                       ingress ? ingress->buffer : NULL,
                                       ingress ? ingress->len : 0u);
}

static int m7mux2_normalize_adapter_codec3_v2_decode(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2Ingress *ingress,
                                                    M7Mux2RecvPacket *out) {
  SharedKnockNormalizedUnit shared = {0};

  (void)ctx;
  if (!shared_knock_codec3_v2_decode((const SharedKnockCodec3V2State *)state,
                                     ingress ? ingress->buffer : NULL,
                                     ingress ? ingress->len : 0u,
                                     ingress ? ingress->ip : NULL,
                                     ingress ? ingress->client_port : 0u,
                                     ingress ? ingress->encrypted : 0,
                                     &shared)) {
    return 0;
  }

  shared.wire_auth = shared_knock_codec3_v2_wire_auth((const SharedKnockCodec3V2State *)state,
                                                      ingress ? ingress->buffer : NULL,
                                                      ingress ? ingress->len : 0u,
                                                      ingress ? ingress->ip : NULL,
                                                      ingress ? ingress->client_port : 0u,
                                                      ingress ? ingress->encrypted : 0,
                                                      &shared) ? 1 : 0;
  shared.wire_decode = 1;
  if (!shared.wire_auth && g_ctx.enforce_wire_auth) {
    return 0;
  }
  m7mux2_normalize_adapter_copy_shared_to_mux(&shared, out);
  out->received_ms = ingress ? ingress->received_ms : 0u;
  snprintf(out->label, sizeof(out->label), "codec3.v2");
  return 1;
}

static int m7mux2_normalize_adapter_codec3_v2_encode(const M7Mux2Context *ctx,
                                                    const void *state,
                                                    const M7Mux2SendPacket *send,
                                                    M7Mux2EgressData *out) {
  SharedKnockNormalizedUnit shared = {0};
  const SiglatchOpenSSL_Lib *openssl = NULL;
  uint8_t encoded[SHARED_KNOCK_CODEC3_PACKET_MAX_SIZE] = {0};
  uint8_t *encrypted = NULL;
  size_t encoded_len = sizeof(encoded);
  size_t final_len = 0u;
  size_t encrypted_cap = 0u;
  const uint8_t *final_bytes = encoded;

  (void)ctx;
  if (!send || !out) {
    return 0;
  }

  if (!m7mux2_normalize_adapter_copy_mux_to_shared(send, &shared)) {
    return 0;
  }

  if (!shared_knock_codec3_v2_encode((const SharedKnockCodec3V2State *)state,
                                     &shared,
                                     encoded,
                                     &encoded_len)) {
    return 0;
  }

  final_len = encoded_len;
  if (g_ctx.codec_context && g_ctx.codec_context->server_secure) {
    openssl = get_siglatch_openssl();
    if (!openssl || !openssl->session_encrypt) {
      return 0;
    }

    if (!g_ctx.codec_context->openssl_session ||
        !g_ctx.codec_context->openssl_session->public_key) {
      return 0;
    }

    encrypted_cap = (size_t)EVP_PKEY_get_size(g_ctx.codec_context->openssl_session->public_key);
    if (encrypted_cap == 0u) {
      return 0;
    }

    encrypted = (uint8_t *)calloc(1u, encrypted_cap);
    if (!encrypted) {
      return 0;
    }

    final_len = encrypted_cap;
    if (!openssl->session_encrypt(g_ctx.codec_context->openssl_session,
                                  (const unsigned char *)encoded,
                                  encoded_len,
                                  encrypted,
                                  &final_len)) {
      free(encrypted);
      return 0;
    }

    final_bytes = encrypted;
  }

  if (!m7mux2_normalize_adapter_fill_egress(send, final_bytes, final_len, out)) {
    if (encrypted) {
      free(encrypted);
    }
    return 0;
  }

  if (encrypted) {
    free(encrypted);
  }

  return 1;
}

static void m7mux2_normalize_adapter_copy_shared_to_mux(const SharedKnockNormalizedUnit *src,
                                                       M7Mux2RecvPacket *dst) {
  if (!src || !dst) {
    return;
  }

  memset(dst, 0, sizeof(*dst));
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
  dst->user = *src;
}

static int m7mux2_normalize_adapter_copy_mux_to_shared(const M7Mux2SendPacket *src,
                                                      SharedKnockNormalizedUnit *dst) {
  const SharedKnockNormalizedUnit *user = NULL;

  if (!src || !dst || !src->user) {
    return 0;
  }

  user = src->user;
  if (user->payload_len > sizeof(dst->payload)) {
    return 0;
  }

  memset(dst, 0, sizeof(*dst));
  dst->complete = src->complete;
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

static int m7mux2_normalize_adapter_fill_egress(const M7Mux2SendPacket *src,
                                                const uint8_t *payload,
                                                size_t payload_len,
                                                M7Mux2EgressData *dst) {
  if (!src || !payload || !dst || payload_len > sizeof(dst->egress_buffer)) {
    return 0;
  }

  memset(dst, 0, sizeof(*dst));
  dst->complete = src->complete;
  dst->should_reply = src->should_reply;
  dst->available = 1;
  dst->trace_id = src->trace_id;
  memcpy(dst->label, src->label, sizeof(dst->label));
  dst->wire_version = src->wire_version;
  dst->wire_form = src->wire_form;
  dst->received_ms = src->received_ms;
  dst->session_id = src->session_id;
  dst->message_id = src->message_id;
  dst->stream_id = src->stream_id;
  dst->fragment_index = src->fragment_index;
  dst->fragment_count = src->fragment_count;
  dst->timestamp = src->timestamp;
  memcpy(dst->ip, src->ip, sizeof(dst->ip));
  dst->client_port = src->client_port;
  dst->encrypted = src->encrypted;
  dst->wire_auth = src->wire_auth;
  dst->egress_len = payload_len;
  if (payload_len > 0u) {
    memcpy(dst->egress_buffer, payload, payload_len);
  }

  return 1;
}

static const M7Mux2NormalizeAdapterLib _instance = {
  .init = m7mux2_normalize_adapter_init,
  .set_context = m7mux2_normalize_adapter_set_context,
  .shutdown = m7mux2_normalize_adapter_shutdown,
  .register_adapter = m7mux2_normalize_adapter_register,
  .unregister_adapter = m7mux2_normalize_adapter_unregister,
  .lookup_adapter = m7mux2_normalize_adapter_lookup,
  .demux = m7mux2_normalize_adapter_demux,
  .decode = m7mux2_normalize_adapter_decode,
  .encode = m7mux2_normalize_adapter_encode,
  .count = m7mux2_normalize_adapter_count
};

const M7Mux2NormalizeAdapterLib *get_protocol_udp_m7mux2_normalize_adapter_lib(void) {
  return &_instance;
}
