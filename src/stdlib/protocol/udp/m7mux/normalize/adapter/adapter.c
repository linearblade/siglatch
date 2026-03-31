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
#include "../../../../../openssl/openssl.h"

#define M7MUX_MAX_NORMALIZE_ADAPTERS 16u

static M7MuxContext g_ctx = {0};
static M7MuxNormalizeAdapter g_adapters[M7MUX_MAX_NORMALIZE_ADAPTERS] = {0};
static size_t g_adapter_count = 0;
static void m7mux_normalize_adapter_destroy_slot(M7MuxNormalizeAdapter *adapter);

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

  return 1;
}

static void m7mux_normalize_adapter_shutdown(void) {
  m7mux_normalize_adapter_reset_registry();
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static int m7mux_normalize_adapter_register(const M7MuxNormalizeAdapter *adapter) {
  M7MuxNormalizeAdapter stored = {0};
  size_t i = 0;

  if (!adapter || !adapter->name || !adapter->detect ||
      !adapter->decode || !adapter->encode) {
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

static const M7MuxNormalizeAdapter *m7mux_normalize_adapter_lookup_wire_version(uint32_t wire_version) {
  size_t i = 0;

  for (i = 0; i < g_adapter_count; ++i) {
    if (g_adapters[i].wire_version == wire_version) {
      return &g_adapters[i];
    }
  }

  return NULL;
}

static const M7MuxNormalizeAdapter *m7mux_normalize_adapter_demux(const M7MuxContext *ctx,
                                                                   const M7MuxIngress *ingress,
                                                                   M7MuxIngressIdentity *identity) {
  size_t i = 0;

  if (!ctx || !ingress) {
    return NULL;
  }

  for (i = 0; i < g_adapter_count; ++i) {
    const M7MuxNormalizeAdapter *adapter = &g_adapters[i];

    if (identity) {
      memset(identity, 0, sizeof(*identity));
    }

    if (!adapter->detect) {
      continue;
    }

    if (adapter->detect(ctx, adapter->state, ingress, identity)) {
      return adapter;
    }
  }

  return NULL;
}

static int m7mux_normalize_adapter_decode(const M7MuxContext *ctx,
                                          const M7MuxNormalizeAdapter *adapter,
                                          const M7MuxIngress *ingress,
                                          M7MuxRecvPacket *out) {
  if (!ctx || !adapter || !adapter->decode) {
    return 0;
  }

  return adapter->decode(ctx, adapter->state, ingress, out);
}

static int m7mux_normalize_adapter_encode(const M7MuxContext *ctx,
                                          const M7MuxNormalizeAdapter *adapter,
                                          const M7MuxSendPacket *send,
                                          M7MuxEgressData *out) {
  if (!ctx || !adapter || !adapter->encode) {
    return 0;
  }

  return adapter->encode(ctx, adapter->state, send, out);
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

void m7mux_normalize_adapter_copy_shared_to_mux(const SharedKnockNormalizedUnit *src,
                                                M7MuxRecvPacket *dst) {
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

int m7mux_normalize_adapter_copy_mux_to_shared(const M7MuxSendPacket *src,
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

int m7mux_normalize_adapter_fill_egress(const M7MuxSendPacket *src,
                                        const uint8_t *payload,
                                        size_t payload_len,
                                        M7MuxEgressData *dst) {
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

static const M7MuxNormalizeAdapterLib _instance = {
  .init = m7mux_normalize_adapter_init,
  .set_context = m7mux_normalize_adapter_set_context,
  .shutdown = m7mux_normalize_adapter_shutdown,
  .register_adapter = m7mux_normalize_adapter_register,
  .unregister_adapter = m7mux_normalize_adapter_unregister,
  .lookup_adapter = m7mux_normalize_adapter_lookup,
  .lookup_adapter_wire_version = m7mux_normalize_adapter_lookup_wire_version,
  .demux = m7mux_normalize_adapter_demux,
  .decode = m7mux_normalize_adapter_decode,
  .encode = m7mux_normalize_adapter_encode,
  .count = m7mux_normalize_adapter_count
};

const M7MuxNormalizeAdapterLib *get_protocol_udp_m7mux_normalize_adapter_lib(void) {
  return &_instance;
}
