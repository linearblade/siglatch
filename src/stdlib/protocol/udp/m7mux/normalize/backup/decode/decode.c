/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "decode.h"

#include <string.h>

#define M7MUX_MAX_ADAPTERS 16u

#include "../../../../../../../shared/knock/codec/normalized.h"
#include "../../../../../../../shared/knock/codec/v1/v1.h"
#include "../../../../../../../shared/knock/codec/v2/v2.h"

static M7MuxContext g_ctx = {0};
static M7MuxAdapter g_adapters[M7MUX_MAX_ADAPTERS] = {0};
static size_t g_adapter_count = 0;

static int m7mux_decode_register_adapter(const M7MuxAdapter *adapter);
static int m7mux_decode_unregister_adapter(const char *name);

static void m7mux_decode_copy_shared_unit(const SharedKnockNormalizedUnit *src,
                                          const uint8_t *input,
                                          M7MuxRecvContext *out) {
  memset(out, 0, sizeof(*out));
  out->complete = src->complete;
  out->wire_version = src->wire_version;
  out->wire_form = src->wire_form;
  out->session_id = src->session_id;
  out->message_id = src->message_id;
  out->stream_id = src->stream_id;
  out->fragment_index = src->fragment_index;
  out->fragment_count = src->fragment_count;
  out->timestamp = src->timestamp;
  out->user_id = src->user_id;
  out->action_id = src->action_id;
  out->challenge = src->challenge;
  memcpy(out->hmac, src->hmac, sizeof(out->hmac));
  memcpy(out->ip, src->ip, sizeof(out->ip));
  out->port = src->client_port;
  out->flags = 0;
  out->encrypted = src->encrypted;
  out->payload = input;
  out->payload_len = src->payload_len;
  out->final = 1;
}

static int m7mux_decode_v1_normalize(const void *route,
                                     size_t route_len,
                                     const uint8_t *input,
                                     size_t input_len,
                                     const char *ip,
                                     uint16_t port,
                                     int encrypted,
                                     M7MuxRecvContext *out) {
  SharedKnockNormalizedUnit shared = {0};
  int rc = 0;

  (void)route;
  (void)route_len;

  rc = shared_knock_v1_codec_normalize(input, input_len, ip, port, encrypted, &shared);
  if (rc != SL_PAYLOAD_OK && rc != SL_PAYLOAD_ERR_OVERFLOW) {
    return 0;
  }

  m7mux_decode_copy_shared_unit(&shared, input, out);
  return rc;
}

static int m7mux_decode_v2_normalize(const void *route,
                                     size_t route_len,
                                     const uint8_t *input,
                                     size_t input_len,
                                     const char *ip,
                                     uint16_t port,
                                     int encrypted,
                                     M7MuxRecvContext *out) {
  SharedKnockNormalizedUnit shared = {0};
  int rc = 0;

  (void)route;
  (void)route_len;

  rc = shared_knock_v2_form1_codec_normalize(input, input_len, ip, port, encrypted, &shared);
  if (rc != SL_PAYLOAD_OK && rc != SL_PAYLOAD_ERR_OVERFLOW) {
    return 0;
  }

  m7mux_decode_copy_shared_unit(&shared, input, out);
  return rc;
}

static const M7MuxAdapter g_builtin_adapters[] = {
  {
    .name = "v1",
    .normalize = m7mux_decode_v1_normalize,
    .reserved = NULL
  },
  {
    .name = "v2",
    .normalize = m7mux_decode_v2_normalize,
    .reserved = NULL
  }
};

static void m7mux_decode_reset_context(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static void m7mux_decode_reset_registry(void) {
  memset(g_adapters, 0, sizeof(g_adapters));
  g_adapter_count = 0;
}

static int m7mux_decode_apply_context(const M7MuxContext *ctx) {
  g_ctx = *ctx;
  return 1;
}

static int m7mux_name_matches(const char *lhs, const char *rhs) {
  return strcmp(lhs, rhs) == 0;
}

static const M7MuxAdapter *m7mux_decode_lookup(const char *name) {
  size_t i = 0;

  for (i = 0; i < g_adapter_count; ++i) {
    if (m7mux_name_matches(g_adapters[i].name, name)) {
      return &g_adapters[i];
    }
  }

  return NULL;
}

static int m7mux_decode_init(const M7MuxContext *ctx) {
  m7mux_decode_apply_context(ctx);
  m7mux_decode_reset_registry();
  for (size_t i = 0; i < sizeof(g_builtin_adapters) / sizeof(g_builtin_adapters[0]); ++i) {
    (void)m7mux_decode_register_adapter(&g_builtin_adapters[i]);
  }
  return 1;
}

static int m7mux_decode_set_context(const M7MuxContext *ctx) {
  return m7mux_decode_apply_context(ctx);
}

static void m7mux_decode_shutdown(void) {
  m7mux_decode_reset_registry();
  m7mux_decode_reset_context();
}

static int m7mux_decode_register_adapter(const M7MuxAdapter *adapter) {
  size_t i = 0;

  for (i = 0; i < g_adapter_count; ++i) {
    if (m7mux_name_matches(g_adapters[i].name, adapter->name)) {
      return 0;
    }
  }

  if (g_adapter_count >= M7MUX_MAX_ADAPTERS) {
    return 0;
  }

  g_adapters[g_adapter_count++] = *adapter;
  return 1;
}

static int m7mux_decode_unregister_adapter(const char *name) {
  size_t i = 0;
  size_t j = 0;

  for (i = 0; i < g_adapter_count; ++i) {
    if (m7mux_name_matches(g_adapters[i].name, name)) {
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

static const M7MuxAdapter *m7mux_decode_lookup_adapter_fn(const char *name) {
  return m7mux_decode_lookup(name);
}

static const M7MuxDecodeLib g_decode_lib = {
  .init = m7mux_decode_init,
  .set_context = m7mux_decode_set_context,
  .shutdown = m7mux_decode_shutdown,
  .register_adapter = m7mux_decode_register_adapter,
  .unregister_adapter = m7mux_decode_unregister_adapter,
  .lookup_adapter = m7mux_decode_lookup_adapter_fn
};

const M7MuxDecodeLib *get_lib_m7mux_decode(void) {
  return &g_decode_lib;
}
