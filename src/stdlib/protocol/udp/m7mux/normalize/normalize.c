/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "../internal.h"

#include <stdio.h>
#include <string.h>

static M7MuxContext g_ctx = {0};

static int m7mux_normalize_init(const M7MuxContext *ctx);
static int m7mux_normalize_set_context(const M7MuxContext *ctx);
static void m7mux_normalize_shutdown(void);
static int m7mux_normalize_packet(const M7MuxState *state,
                                  const M7MuxIngress *ingress,
                                  M7MuxRecvPacket *out);
static int m7mux_normalize_encryption_allowed(const M7MuxState *state, int encrypted);
static void m7mux_normalize_configure_ingress_identity(const M7MuxState *state,
                                                       const M7MuxNormalizeAdapter *adapter,
                                                       M7MuxIngress *ingress,
                                                       M7MuxIngressIdentity *identity);

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

static int m7mux_normalize_encryption_allowed(const M7MuxState *state, int encrypted) {
  if (state) {
    switch (state->policy_enforce_encryption) {
      case M7MUX_POLICY_ENFORCE_ENCRYPTION_YES:
        return encrypted ? 1 : 0;
      case M7MUX_POLICY_ENFORCE_ENCRYPTION_NO:
        return encrypted ? 0 : 1;
      case M7MUX_POLICY_ENFORCE_ENCRYPTION_ANY:
      default:
        break;
    }
  }

  if (g_ctx.codec_context && g_ctx.codec_context->server_secure) {
    return encrypted ? 1 : 0;
  }

  return 1;
}

static int m7mux_normalize_raw_copy(const M7MuxState *state,
                                    const M7MuxIngress *ingress,
                                    M7MuxRecvPacket *out) {
  if (ingress->len > sizeof(out->user.payload)) {
    return 0;
  }

  if (!m7mux_normalize_encryption_allowed(state, ingress->encrypted)) {
    fprintf(stderr,
            "[m7mux.normalize] raw/unstructured fallback rejected by policy ip=%s port=%u encrypted=%d bytes=%zu\n",
            ingress->ip,
            (unsigned)ingress->client_port,
            ingress->encrypted,
            ingress->len);
    return 0;
  }

  memset(out, 0, sizeof(*out));
  out->complete = 1;
  out->received_ms = ingress->received_ms;
  snprintf(out->label, sizeof(out->label), "raw");
  out->user.complete = 1;
  out->user.wire_decode = 0;
  out->user.wire_auth = 0;
  out->user.encrypted = ingress->encrypted;
  memcpy(out->user.ip, ingress->ip, sizeof(out->user.ip));
  out->user.client_port = ingress->client_port;
  out->user.payload_len = ingress->len;
  memcpy(out->user.payload, ingress->buffer, ingress->len);
  fprintf(stderr,
          "[m7mux.normalize] raw/unstructured fallback ip=%s port=%u encrypted=%d bytes=%zu\n",
          out->user.ip,
          (unsigned)out->user.client_port,
          out->user.encrypted,
          out->user.payload_len);
  return 1;
}

static void m7mux_normalize_configure_ingress_identity(const M7MuxState *state,
                                                       const M7MuxNormalizeAdapter *adapter,
                                                       M7MuxIngress *ingress,
                                                       M7MuxIngressIdentity *identity) {
  (void)state;
  (void)adapter;

  if (!ingress || !identity) {
    return;
  }

  ingress->encrypted = identity->encrypted ? 1 : 0;
  ingress->magic = identity->magic;
  ingress->version = identity->version;
  ingress->form = identity->form;
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

static int m7mux_normalize_packet(const M7MuxState *state,
                                  const M7MuxIngress *ingress,
                                  M7MuxRecvPacket *out) {
  const M7MuxNormalizeAdapter *adapter = NULL;
  M7MuxIngressIdentity identity = {0};

  if (!ingress || !out || !_instance.adapter.demux ||
      !_instance.adapter.decode || !_instance.adapter.count) {
    return 0;
  }

  if (_instance.adapter.count() == 0u) {
    fprintf(stderr,
            "[m7mux.normalize] adapter registry empty; using raw/unstructured path\n");
    if (g_ctx.enforce_wire_decode) {
      fprintf(stderr,
              "[m7mux.normalize] raw/unstructured fallback rejected by policy\n");
      return 0;
    }
    return m7mux_normalize_raw_copy(state, ingress, out);
  }

  adapter = _instance.adapter.demux(&g_ctx, ingress, &identity);
  if (!adapter) {
    fprintf(stderr,
            "[m7mux.normalize] no adapter matched; using raw/unstructured path ip=%s port=%u encrypted=%d bytes=%zu\n",
            ingress->ip,
            (unsigned)ingress->client_port,
            ingress->encrypted,
            ingress->len);
    if (g_ctx.enforce_wire_decode) {
      fprintf(stderr,
              "[m7mux.normalize] raw/unstructured fallback rejected by policy ip=%s port=%u encrypted=%d bytes=%zu\n",
              ingress->ip,
              (unsigned)ingress->client_port,
              ingress->encrypted,
              ingress->len);
      return 0;
    }
    return m7mux_normalize_raw_copy(state, ingress, out);
  }

  M7MuxIngress configured_ingress = *ingress;

  m7mux_normalize_configure_ingress_identity(state, adapter, &configured_ingress, &identity);

  fprintf(stderr,
          "[m7mux.normalize] demux selected adapter=%s ip=%s port=%u encrypted=%d bytes=%zu\n",
          adapter->name,
          configured_ingress.ip,
          (unsigned)configured_ingress.client_port,
          configured_ingress.encrypted,
          configured_ingress.len);
  if (!_instance.adapter.decode(&g_ctx, adapter, &configured_ingress, out)) {
    fprintf(stderr,
            "[m7mux.normalize] adapter decode failed for adapter=%s ip=%s port=%u bytes=%zu\n",
            adapter->name,
            configured_ingress.ip,
            (unsigned)configured_ingress.client_port,
            configured_ingress.len);
    return 0;
  }

  if (!m7mux_normalize_encryption_allowed(state, out->user.encrypted)) {
    fprintf(stderr,
            "[m7mux.normalize] structured decode rejected by policy adapter=%s ip=%s port=%u encrypted=%d bytes=%zu\n",
            adapter->name,
            configured_ingress.ip,
            (unsigned)configured_ingress.client_port,
            out->user.encrypted,
            configured_ingress.len);
    return 0;
  }

  /*
   * TODO: route this through the eventual codec/mux log hook instead of
   * emitting directly to stderr.
   *
   * fprintf(stderr,
   *         "[m7mux.normalize] structured decode complete via %s label=%s session=%llu stream=%u message=%llu payload=%zu wire_auth=%d\n",
   *         adapter->name,
   *         out->label,
   *         (unsigned long long)out->session_id,
   *         out->stream_id,
   *         (unsigned long long)out->message_id,
   *         out->user.payload_len,
   *         out->user.wire_auth);
   */
  return 1;
}

const M7MuxNormalizeLib *get_protocol_udp_m7mux_normalize_lib(void) {
  return &_instance;
}
