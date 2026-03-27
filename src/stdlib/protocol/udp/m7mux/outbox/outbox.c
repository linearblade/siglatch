/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "outbox.h"

#include "../internal.h"

#include <stdlib.h>
#include <string.h>

#include "../../../../../shared/knock/codec2/codec.h"
#include "../../../../../shared/knock/response.h"
#include "../../../../openssl.h"

static M7MuxContext g_ctx = {0};

static void m7mux_outbox_reset_context(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static int m7mux_outbox_init(const M7MuxContext *ctx) {
  if (!ctx || !ctx->internal || !ctx->internal->egress) {
    m7mux_outbox_reset_context();
    return 0;
  }

  g_ctx = *ctx;
  return 1;
}

static int m7mux_outbox_set_context(const M7MuxContext *ctx) {
  return m7mux_outbox_init(ctx);
}

static void m7mux_outbox_shutdown(void) {
  m7mux_outbox_reset_context();
}

static int m7mux_outbox_state_init(M7MuxState *state) {
  if (!state) {
    return 0;
  }

  if (!g_ctx.internal->egress->state_init(&state->egress)) {
    return 0;
  }

  return 1;
}

static void m7mux_outbox_state_reset(M7MuxState *state) {
  if (!state) {
    return;
  }

  g_ctx.internal->egress->state_reset(&state->egress);
}

static int m7mux_outbox_has_pending(const M7MuxState *state) {
  if (!state) {
    return 0;
  }

  return g_ctx.internal->egress->has_pending(&state->egress);
}

static const M7MuxNormalizeAdapter *m7mux_outbox_select_adapter(const M7MuxNormalizedPacket *normal) {
  if (!normal || !g_ctx.internal || !g_ctx.internal->normalize ||
      !g_ctx.internal->normalize->adapter.lookup_adapter) {
    return NULL;
  }

  if (normal->wire_version == SHARED_KNOCK_V2_WIRE_VERSION) {
    const M7MuxNormalizeAdapter *adapter =
        g_ctx.internal->normalize->adapter.lookup_adapter("codec2.v2");
    if (adapter) {
      return adapter;
    }
  }

  return g_ctx.internal->normalize->adapter.lookup_adapter("codec2.v1");
}

static int m7mux_outbox_stage(M7MuxState *state, const M7MuxNormalizedPacket *normal) {
  const M7MuxNormalizeAdapter *adapter = NULL;
  const SiglatchOpenSSL_Lib *openssl = NULL;
  SharedKnockNormalizedUnit codec_unit = {0};
  M7MuxNormalizedPacket wire_normal = {0};
  M7MuxNormalizedPacket serialized = {0};
  uint8_t encoded[SHARED_KNOCK_CODEC2_PACKET_MAX_SIZE] = {0};
  uint8_t *encrypted = NULL;
  size_t encoded_len = sizeof(encoded);
  size_t final_len = 0u;
  size_t encrypted_cap = 0u;

  if (!state || !normal) {
    return 0;
  }

  if (!normal->complete) {
    return 0;
  }

  if (!normal->should_reply && normal->payload_len == 0u && normal->response_len == 0u) {
    return 1;
  }

  if (!g_ctx.time || !g_ctx.codec_context || !g_ctx.internal || !g_ctx.internal->normalize ||
      !g_ctx.internal->normalize->adapter.encode) {
    return 0;
  }

  adapter = m7mux_outbox_select_adapter(normal);
  if (!adapter) {
    return 0;
  }

  if (normal->payload_len > sizeof(codec_unit.payload)) {
    return 0;
  }

  codec_unit.complete = normal->complete;
  codec_unit.wire_version = normal->wire_version;
  codec_unit.wire_form = normal->wire_form;
  codec_unit.session_id = normal->session_id;
  codec_unit.message_id = normal->message_id;
  codec_unit.stream_id = normal->stream_id;
  codec_unit.fragment_index = normal->fragment_index;
  codec_unit.fragment_count = normal->fragment_count;
  codec_unit.timestamp = (uint32_t)g_ctx.time->unix_ts();
  codec_unit.user_id = normal->user_id;
  codec_unit.action_id = SL_KNOCK_RESPONSE_ACTION_ID;
  codec_unit.challenge = normal->challenge;
  memcpy(codec_unit.ip, normal->ip, sizeof(codec_unit.ip));
  codec_unit.ip[sizeof(codec_unit.ip) - 1] = '\0';
  codec_unit.client_port = normal->client_port;
  codec_unit.encrypted = normal->encrypted;
  codec_unit.payload_len = normal->payload_len;
  if (normal->payload_len > 0u) {
    memcpy(codec_unit.payload, normal->payload_buffer, normal->payload_len);
  }

  wire_normal = *normal;
  wire_normal.timestamp = codec_unit.timestamp;
  wire_normal.action_id = SL_KNOCK_RESPONSE_ACTION_ID;
  wire_normal.response_len = 0u;
  memset(wire_normal.response_buffer, 0, sizeof(wire_normal.response_buffer));

  if (!g_ctx.internal->normalize->adapter.encode(&g_ctx, adapter, &wire_normal, encoded, &encoded_len)) {
    return 0;
  }

  serialized = wire_normal;
  serialized.action_id = SL_KNOCK_RESPONSE_ACTION_ID;
  serialized.timestamp = codec_unit.timestamp;
  serialized.response_len = encoded_len;
  memcpy(serialized.response_buffer, encoded, encoded_len);

  if (g_ctx.codec_context->server_secure) {
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

    serialized.response_len = final_len;
    memcpy(serialized.response_buffer, encrypted, final_len);
    free(encrypted);
  }

  return g_ctx.internal->egress->stage(&state->egress, &serialized);
}

static int m7mux_outbox_flush(M7MuxState *state, int sock, uint64_t now_ms) {
  if (!state) {
    return 0;
  }

  return g_ctx.internal->egress->flush(&state->egress, sock, now_ms);
}

static const M7MuxOutboxLib _instance = {
  .init = m7mux_outbox_init,
  .set_context = m7mux_outbox_set_context,
  .shutdown = m7mux_outbox_shutdown,
  .state_init = m7mux_outbox_state_init,
  .state_reset = m7mux_outbox_state_reset,
  .has_pending = m7mux_outbox_has_pending,
  .stage = m7mux_outbox_stage,
  .flush = m7mux_outbox_flush
};

const M7MuxOutboxLib *get_protocol_udp_m7mux_outbox_lib(void) {
  return &_instance;
}
