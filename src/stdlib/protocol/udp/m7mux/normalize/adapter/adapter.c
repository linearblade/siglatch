/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "adapter.h"

#include <string.h>

#include "../../ingress/ingress.h"
#include "../normalize.h"
#include "../../../../../../shared/knock/codec2/v1/v1.h"
#include "../../../../../../shared/knock/codec2/v2/v2.h"

#define M7MUX_MAX_NORMALIZE_ADAPTERS 16u

static M7MuxContext g_ctx = {0};
static M7MuxNormalizeAdapter g_adapters[M7MUX_MAX_NORMALIZE_ADAPTERS] = {0};
static size_t g_adapter_count = 0;

static int m7mux_normalize_adapter_codec2_v1_create_state(void **out_state);
static void m7mux_normalize_adapter_codec2_v1_destroy_state(void *state);
static int m7mux_normalize_adapter_codec2_v1_detect(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxIngress *ingress);
static int m7mux_normalize_adapter_codec2_v1_decode(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxIngress *ingress,
                                                    M7MuxNormalizedPacket *out);
static int m7mux_normalize_adapter_codec2_v1_encode(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxNormalizedPacket *normal,
                                                    uint8_t *out,
                                                    size_t *out_len);
static int m7mux_normalize_adapter_codec2_v2_create_state(void **out_state);
static void m7mux_normalize_adapter_codec2_v2_destroy_state(void *state);
static int m7mux_normalize_adapter_codec2_v2_detect(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxIngress *ingress);
static int m7mux_normalize_adapter_codec2_v2_decode(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxIngress *ingress,
                                                    M7MuxNormalizedPacket *out);
static int m7mux_normalize_adapter_codec2_v2_encode(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxNormalizedPacket *normal,
                                                    uint8_t *out,
                                                    size_t *out_len);

static const M7MuxNormalizeAdapter g_builtin_adapters[] = {
  {
    .name = "codec2.v1",
    .create_state = m7mux_normalize_adapter_codec2_v1_create_state,
    .destroy_state = m7mux_normalize_adapter_codec2_v1_destroy_state,
    .detect = m7mux_normalize_adapter_codec2_v1_detect,
    .decode = m7mux_normalize_adapter_codec2_v1_decode,
    .encode = m7mux_normalize_adapter_codec2_v1_encode,
    .state = NULL,
    .reserved = NULL
  },
  {
    .name = "codec2.v2",
    .create_state = m7mux_normalize_adapter_codec2_v2_create_state,
    .destroy_state = m7mux_normalize_adapter_codec2_v2_destroy_state,
    .detect = m7mux_normalize_adapter_codec2_v2_detect,
    .decode = m7mux_normalize_adapter_codec2_v2_decode,
    .encode = m7mux_normalize_adapter_codec2_v2_encode,
    .state = NULL,
    .reserved = NULL
  }
};

static int m7mux_normalize_adapter_register_builtin_adapters(void);
static void m7mux_normalize_adapter_destroy_slot(M7MuxNormalizeAdapter *adapter);
static void m7mux_normalize_adapter_copy_shared_to_mux(const SharedKnockNormalizedUnit *src,
                                                       M7MuxNormalizedPacket *dst);
static int m7mux_normalize_adapter_copy_mux_to_shared(const M7MuxNormalizedPacket *src,
                                                      SharedKnockNormalizedUnit *dst);

static int m7mux_name_matches(const char *lhs, const char *rhs) {
  return strcmp(lhs, rhs) == 0;
}

static void m7mux_normalize_adapter_reset_registry(void) {
  size_t i = 0;

  for (i = 0; i < g_adapter_count; ++i) {
    m7mux_normalize_adapter_destroy_slot(&g_adapters[i]);
  }
  memset(g_adapters, 0, sizeof(g_adapters));
  g_adapter_count = 0;
}

static int m7mux_normalize_adapter_apply_context(const M7MuxContext *ctx) {
  if (!ctx) {
    return 0;
  }

  g_ctx = *ctx;
  return 1;
}

static int m7mux_normalize_adapter_init(void) {
  m7mux_normalize_adapter_reset_registry();
  return 1;
}

static int m7mux_normalize_adapter_set_context(const M7MuxContext *ctx) {
  if (!m7mux_normalize_adapter_apply_context(ctx)) {
    return 0;
  }

  if (!g_ctx.codec_context) {
    return 1;
  }

  if (g_adapter_count == 0u) {
    if (!m7mux_normalize_adapter_register_builtin_adapters()) {
      m7mux_normalize_adapter_reset_registry();
      return 0;
    }
  }

  return 1;
}

static void m7mux_normalize_adapter_shutdown(void) {
  m7mux_normalize_adapter_reset_registry();
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static int m7mux_normalize_adapter_register(const M7MuxNormalizeAdapter *adapter) {
  M7MuxNormalizeAdapter stored = {0};
  size_t i = 0;

  if (!adapter || !adapter->name || !adapter->detect || !adapter->decode) {
    return 0;
  }

  for (i = 0; i < g_adapter_count; ++i) {
    if (m7mux_name_matches(g_adapters[i].name, adapter->name)) {
      return 0;
    }
  }

  if (g_adapter_count >= M7MUX_MAX_NORMALIZE_ADAPTERS) {
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

static int m7mux_normalize_adapter_unregister(const char *name) {
  size_t i = 0;
  size_t j = 0;

  if (!name) {
    return 0;
  }

  for (i = 0; i < g_adapter_count; ++i) {
    if (m7mux_name_matches(g_adapters[i].name, name)) {
      m7mux_normalize_adapter_destroy_slot(&g_adapters[i]);
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

static const M7MuxNormalizeAdapter *m7mux_normalize_adapter_lookup(const char *name) {
  size_t i = 0;

  if (!name) {
    return NULL;
  }

  for (i = 0; i < g_adapter_count; ++i) {
    if (m7mux_name_matches(g_adapters[i].name, name)) {
      return &g_adapters[i];
    }
  }

  return NULL;
}

static const M7MuxNormalizeAdapter *m7mux_normalize_adapter_demux(const M7MuxContext *ctx,
                                                                   const M7MuxIngress *ingress) {
  size_t i = 0;

  if (!ctx || !ingress) {
    return NULL;
  }

  for (i = 0; i < g_adapter_count; ++i) {
    const M7MuxNormalizeAdapter *adapter = &g_adapters[i];

    if (!adapter->detect) {
      continue;
    }

    if (adapter->detect(ctx, adapter->state, ingress)) {
      return adapter;
    }
  }

  return NULL;
}

static int m7mux_normalize_adapter_decode(const M7MuxContext *ctx,
                                          const M7MuxNormalizeAdapter *adapter,
                                          const M7MuxIngress *ingress,
                                          M7MuxNormalizedPacket *out) {
  if (!ctx || !adapter || !adapter->decode) {
    return 0;
  }

  return adapter->decode(ctx, adapter->state, ingress, out);
}

static int m7mux_normalize_adapter_encode(const M7MuxContext *ctx,
                                          const M7MuxNormalizeAdapter *adapter,
                                          const M7MuxNormalizedPacket *normal,
                                          uint8_t *out,
                                          size_t *out_len) {
  if (!ctx || !adapter || !adapter->encode) {
    return 0;
  }

  return adapter->encode(ctx, adapter->state, normal, out, out_len);
}

static size_t m7mux_normalize_adapter_count(void) {
  return g_adapter_count;
}

static void m7mux_normalize_adapter_destroy_slot(M7MuxNormalizeAdapter *adapter) {
  if (!adapter) {
    return;
  }

  if (adapter->destroy_state && adapter->state) {
    adapter->destroy_state(adapter->state);
  }

  memset(adapter, 0, sizeof(*adapter));
}

static int m7mux_normalize_adapter_register_builtin_adapters(void) {
  size_t i = 0;

  for (i = 0; i < sizeof(g_builtin_adapters) / sizeof(g_builtin_adapters[0]); ++i) {
    if (!m7mux_normalize_adapter_register(&g_builtin_adapters[i])) {
      return 0;
    }
  }

  return 1;
}

static int m7mux_normalize_adapter_codec2_v1_create_state(void **out_state) {
  return shared_knock_codec2_v1_create_state((SharedKnockCodec2V1State **)out_state);
}

static void m7mux_normalize_adapter_codec2_v1_destroy_state(void *state) {
  shared_knock_codec2_v1_destroy_state((SharedKnockCodec2V1State *)state);
}

static int m7mux_normalize_adapter_codec2_v1_detect(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxIngress *ingress) {
  (void)ctx;
  return shared_knock_codec2_v1_detect((const SharedKnockCodec2V1State *)state,
                                       ingress ? ingress->buffer : NULL,
                                       ingress ? ingress->len : 0u);
}

static int m7mux_normalize_adapter_codec2_v1_decode(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxIngress *ingress,
                                                    M7MuxNormalizedPacket *out) {
  SharedKnockNormalizedUnit shared = {0};

  (void)ctx;
  if (!shared_knock_codec2_v1_decode((const SharedKnockCodec2V1State *)state,
                                     ingress ? ingress->buffer : NULL,
                                     ingress ? ingress->len : 0u,
                                     ingress ? ingress->ip : NULL,
                                     ingress ? ingress->client_port : 0u,
                                     ingress ? ingress->encrypted : 0,
                                     &shared)) {
    return 0;
  }

  m7mux_normalize_adapter_copy_shared_to_mux(&shared, out);
  out->received_ms = ingress ? ingress->received_ms : 0u;
  return 1;
}

static int m7mux_normalize_adapter_codec2_v1_encode(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxNormalizedPacket *normal,
                                                    uint8_t *out,
                                                    size_t *out_len) {
  SharedKnockNormalizedUnit shared = {0};

  (void)ctx;
  if (!m7mux_normalize_adapter_copy_mux_to_shared(normal, &shared)) {
    return 0;
  }
  return shared_knock_codec2_v1_encode((const SharedKnockCodec2V1State *)state,
                                       &shared,
                                       out,
                                       out_len);
}

static int m7mux_normalize_adapter_codec2_v2_create_state(void **out_state) {
  return shared_knock_codec2_v2_create_state((SharedKnockCodec2V2State **)out_state);
}

static void m7mux_normalize_adapter_codec2_v2_destroy_state(void *state) {
  shared_knock_codec2_v2_destroy_state((SharedKnockCodec2V2State *)state);
}

static int m7mux_normalize_adapter_codec2_v2_detect(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxIngress *ingress) {
  (void)ctx;
  return shared_knock_codec2_v2_detect((const SharedKnockCodec2V2State *)state,
                                       ingress ? ingress->buffer : NULL,
                                       ingress ? ingress->len : 0u);
}

static int m7mux_normalize_adapter_codec2_v2_decode(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxIngress *ingress,
                                                    M7MuxNormalizedPacket *out) {
  SharedKnockNormalizedUnit shared = {0};

  (void)ctx;
  if (!shared_knock_codec2_v2_decode((const SharedKnockCodec2V2State *)state,
                                     ingress ? ingress->buffer : NULL,
                                     ingress ? ingress->len : 0u,
                                     ingress ? ingress->ip : NULL,
                                     ingress ? ingress->client_port : 0u,
                                     ingress ? ingress->encrypted : 0,
                                     &shared)) {
    return 0;
  }

  m7mux_normalize_adapter_copy_shared_to_mux(&shared, out);
  out->received_ms = ingress ? ingress->received_ms : 0u;
  return 1;
}

static int m7mux_normalize_adapter_codec2_v2_encode(const M7MuxContext *ctx,
                                                    const void *state,
                                                    const M7MuxNormalizedPacket *normal,
                                                    uint8_t *out,
                                                    size_t *out_len) {
  SharedKnockNormalizedUnit shared = {0};

  (void)ctx;
  if (!m7mux_normalize_adapter_copy_mux_to_shared(normal, &shared)) {
    return 0;
  }
  return shared_knock_codec2_v2_encode((const SharedKnockCodec2V2State *)state,
                                       &shared,
                                       out,
                                       out_len);
}

static void m7mux_normalize_adapter_copy_shared_to_mux(const SharedKnockNormalizedUnit *src,
                                                       M7MuxNormalizedPacket *dst) {
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
  dst->user_id = src->user_id;
  dst->action_id = src->action_id;
  dst->challenge = src->challenge;
  memcpy(dst->hmac, src->hmac, sizeof(dst->hmac));
  memcpy(dst->ip, src->ip, sizeof(dst->ip));
  dst->client_port = src->client_port;
  dst->encrypted = src->encrypted;
  dst->authorized = src->authorized;
  dst->payload_len = src->payload_len;
  if (src->payload_len > 0u) {
    memcpy(dst->payload_buffer, src->payload, src->payload_len);
  }
}

static int m7mux_normalize_adapter_copy_mux_to_shared(const M7MuxNormalizedPacket *src,
                                                      SharedKnockNormalizedUnit *dst) {
  const uint8_t *payload = NULL;
  size_t payload_len = 0u;

  if (!src || !dst) {
    return 0;
  }

  if (src->response_len > 0u) {
    payload = src->response_buffer;
    payload_len = src->response_len;
  } else {
    payload = src->payload_buffer;
    payload_len = src->payload_len;
  }

  if (payload_len > sizeof(dst->payload)) {
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
  dst->user_id = src->user_id;
  dst->action_id = src->action_id;
  dst->challenge = src->challenge;
  memcpy(dst->hmac, src->hmac, sizeof(dst->hmac));
  memcpy(dst->ip, src->ip, sizeof(dst->ip));
  dst->client_port = src->client_port;
  dst->encrypted = src->encrypted;
  dst->authorized = src->authorized;
  dst->payload_len = payload_len;
  if (payload_len > 0u) {
    memcpy(dst->payload, payload, payload_len);
  }

  return 1;
}

static const M7MuxNormalizeAdapterLib _instance = {
  .init = m7mux_normalize_adapter_init,
  .set_context = m7mux_normalize_adapter_set_context,
  .shutdown = m7mux_normalize_adapter_shutdown,
  .register_adapter = m7mux_normalize_adapter_register,
  .unregister_adapter = m7mux_normalize_adapter_unregister,
  .lookup_adapter = m7mux_normalize_adapter_lookup,
  .demux = m7mux_normalize_adapter_demux,
  .decode = m7mux_normalize_adapter_decode,
  .encode = m7mux_normalize_adapter_encode,
  .count = m7mux_normalize_adapter_count
};

const M7MuxNormalizeAdapterLib *get_protocol_udp_m7mux_normalize_adapter_lib(void) {
  return &_instance;
}
