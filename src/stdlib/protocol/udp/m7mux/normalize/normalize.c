/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "normalize.h"
#include "../ingress/ingress.h"

#include <string.h>

static M7MuxContext g_ctx = {0};

static int m7mux_normalize_init(const M7MuxContext *ctx);
static int m7mux_normalize_set_context(const M7MuxContext *ctx);
static void m7mux_normalize_shutdown(void);
static int m7mux_normalize_packet(const M7MuxIngress *ingress, M7MuxNormalizedPacket *out);

static M7MuxNormalizeLib _instance = {
  .adapter = {0},
  .init = m7mux_normalize_init,
  .set_context = m7mux_normalize_set_context,
  .shutdown = m7mux_normalize_shutdown,
  .normalize = m7mux_normalize_packet
};

static void m7mux_normalize_reset_context(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static int m7mux_normalize_apply_context(const M7MuxContext *ctx) {
  if (!ctx) {
    return 0;
  }

  g_ctx = *ctx;
  return 1;
}

static int m7mux_normalize_raw_copy(const M7MuxIngress *ingress, M7MuxNormalizedPacket *out) {
  if (ingress->len > sizeof(out->payload_buffer)) {
    return 0;
  }

  memset(out, 0, sizeof(*out));
  out->complete = 1;
  out->received_ms = ingress->received_ms;
  out->payload_len = ingress->len;
  memcpy(out->ip, ingress->ip, sizeof(out->ip));
  out->client_port = ingress->client_port;
  out->encrypted = ingress->encrypted;
  memcpy(out->payload_buffer, ingress->buffer, ingress->len);
  return 1;
}

static int m7mux_normalize_init(const M7MuxContext *ctx) {
  const M7MuxNormalizeAdapterLib *adapter_lib = NULL;

  adapter_lib = get_protocol_udp_m7mux_normalize_adapter_lib();

  if (!adapter_lib || !adapter_lib->init || !adapter_lib->set_context ||
      !adapter_lib->shutdown || !adapter_lib->register_adapter ||
      !adapter_lib->unregister_adapter || !adapter_lib->lookup_adapter ||
      !adapter_lib->demux || !adapter_lib->decode ||
      !adapter_lib->encode || !adapter_lib->count) {
    return 0;
  }

  if (!adapter_lib->init()) {
    return 0;
  }

  if (!adapter_lib->set_context(ctx)) {
    adapter_lib->shutdown();
    _instance.adapter = (M7MuxNormalizeAdapterLib){0};
    return 0;
  }

  if (!m7mux_normalize_apply_context(ctx)) {
    adapter_lib->shutdown();
    _instance.adapter = (M7MuxNormalizeAdapterLib){0};
    return 0;
  }

  _instance.adapter = *adapter_lib;
  return 1;
}

static int m7mux_normalize_set_context(const M7MuxContext *ctx) {
  if (!_instance.adapter.set_context) {
    return 0;
  }

  if (!_instance.adapter.set_context(ctx)) {
    return 0;
  }

  return m7mux_normalize_apply_context(ctx);
}

static void m7mux_normalize_shutdown(void) {
  if (_instance.adapter.shutdown) {
    _instance.adapter.shutdown();
  }

  _instance.adapter = (M7MuxNormalizeAdapterLib){0};
  m7mux_normalize_reset_context();
}

static int m7mux_normalize_packet(const M7MuxIngress *ingress, M7MuxNormalizedPacket *out) {
  const M7MuxNormalizeAdapter *adapter = NULL;

  if (!ingress || !out || !_instance.adapter.demux ||
      !_instance.adapter.decode || !_instance.adapter.count) {
    return 0;
  }

  if (_instance.adapter.count() == 0u) {
    return m7mux_normalize_raw_copy(ingress, out);
  }

  adapter = _instance.adapter.demux(&g_ctx, ingress);
  if (!adapter) {
    return m7mux_normalize_raw_copy(ingress, out);
  }

  if (!_instance.adapter.decode(&g_ctx, adapter, ingress, out)) {
    return 0;
  }

  return 1;
}

const M7MuxNormalizeLib *get_protocol_udp_m7mux_normalize_lib(void) {
  return &_instance;
}
