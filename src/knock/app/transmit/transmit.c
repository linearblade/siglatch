/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "transmit.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../../../shared/shared.h"
#include "../../../shared/knock/response.h"
#include "../../../shared/knock/codec/user.h"
#include "../../../stdlib/protocol/udp/m7mux/ingress/ingress.h"
#include "../../../stdlib/protocol/udp/m7mux/outbox/outbox.h"
#include "../../../stdlib/protocol/udp/m7mux/normalize/normalize.h"
#include "../../../stdlib/utils.h"
#include "../../lib.h"
#include "helper.h"

#define KNOCKER_RESPONSE_TIMEOUT_MS 1500
#define KNOCKER_RESPONSE_BUFFER_SIZE SHARED_KNOCK_CODEC_PACKET_MAX_SIZE

#define FAIL_SINGLE_PACKET(...)                                                \
  if (1) {                                                                     \
    if (lib.log.emit) {                                                        \
      lib.log.emit(LOG_ERROR, 1, __VA_ARGS__);                                 \
    }                                                                          \
    break;                                                                     \
  }

static int app_transmit_response_validate_signature(const Opts *opts,
                                                    SiglatchOpenSSLSession *session,
                                                    const KnockPacket *pkt) {
  uint8_t digest[32] = {0};
  uint8_t dummy_hmac[sizeof(pkt->hmac)] = {0};

  if (!opts || !session || !pkt) {
    return 0;
  }

  switch (opts->hmac_mode) {
    case HMAC_MODE_NORMAL:
      if (!shared.knock.digest.generate(pkt, digest)) {
        return 0;
      }
      return shared.knock.digest.validate(session->hmac_key, digest, pkt->hmac);

    case HMAC_MODE_DUMMY:
      memset(dummy_hmac, 0x42, sizeof(dummy_hmac));
      return memcmp(pkt->hmac, dummy_hmac, sizeof(dummy_hmac)) == 0;

    case HMAC_MODE_NONE:
      return 1;

    default:
      break;
  }

  return 0;
}

static void app_transmit_response_copy_text(char *out,
                                            size_t out_size,
                                            const uint8_t *input,
                                            size_t input_len) {
  size_t i = 0;
  size_t copy_len = 0;

  if (!out || out_size == 0) {
    return;
  }

  out[0] = '\0';

  if (!input || input_len == 0) {
    return;
  }

  copy_len = input_len;
  if (copy_len >= out_size) {
    copy_len = out_size - 1;
  }

  for (i = 0; i < copy_len; ++i) {
    unsigned char ch = input[i];

    if (ch == '\r' || ch == '\n' || ch == '\t') {
      out[i] = ' ';
      continue;
    }

    out[i] = isprint(ch) ? (char)ch : '?';
  }

  out[copy_len] = '\0';
}

static const char *app_transmit_protocol_name(KnockProtocol protocol) {
  switch (protocol) {
    case KNOCK_PROTOCOL_V1:
      return "v1";
    case KNOCK_PROTOCOL_V2:
      return "v2";
    case KNOCK_PROTOCOL_V3:
      return "v3";
    case KNOCK_PROTOCOL_V4:
      return "v4";
    default:
      return "unknown";
  }
}

static int app_transmit_response_print_payload(const uint8_t *payload,
                                              size_t payload_len,
                                              int *out_status) {
  const char *status_name = "UNKNOWN";
  char text[KNOCKER_RESPONSE_BUFFER_SIZE] = {0};
  uint8_t status = 0;
  uint8_t flags = 0;
  size_t text_len = 0;

  if (!payload || !out_status) {
    return 0;
  }

  if (payload_len < SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response packet with short payload (%u bytes)\n",
                   (unsigned int)payload_len);
    }
    return 0;
  }

  status = payload[0];
  flags = payload[2];
  text_len = payload_len - SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE;

  switch (status) {
    case SL_KNOCK_RESPONSE_STATUS_OK:
      status_name = "OK";
      *out_status = 0;
      break;
    case SL_KNOCK_RESPONSE_STATUS_ERROR:
      status_name = "ERROR";
      *out_status = 2;
      break;
    default:
      if (lib.log.emit) {
        lib.log.emit(LOG_ERROR, 1, "Received response packet with unknown status: %u\n",
                     (unsigned int)status);
      }
      return 0;
  }

  app_transmit_response_copy_text(text, sizeof(text),
                                  payload + SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE,
                                  text_len);

  if (text[0] != '\0') {
    if (flags & SL_KNOCK_RESPONSE_FLAG_TRUNCATED) {
      lib.print.uc_printf(NULL, "%s %s [truncated]\n", status_name, text);
    } else {
      lib.print.uc_printf(NULL, "%s %s\n", status_name, text);
    }
  } else if (flags & SL_KNOCK_RESPONSE_FLAG_TRUNCATED) {
    lib.print.uc_printf(NULL, "%s [truncated]\n", status_name);
  } else {
    lib.print.uc_printf(NULL, "%s\n", status_name);
  }

  return 1;
}

static int app_transmit_response_print(const KnockPacket *reply_pkt, int *out_status) {
  if (!reply_pkt) {
    return 0;
  }

  return app_transmit_response_print_payload(reply_pkt->payload, reply_pkt->payload_len, out_status);
}

static void app_transmit_dead_drop_print_raw_response(const M7MuxRecvPacket *reply) {
  if (!reply) {
    return;
  }

  if (reply->raw_bytes_len > 0u) {
    (void)fwrite(reply->raw_bytes, 1u, reply->raw_bytes_len, stdout);
    if (reply->raw_bytes[reply->raw_bytes_len - 1u] != '\n') {
      fputc('\n', stdout);
    }
  }
}

static int app_transmit_m7mux_rehydrate_v1(const M7MuxRecvPacket *reply,
                                           const M7MuxUserRecvData *user,
                                           KnockPacket *out_pkt);
static int app_transmit_m7mux_rehydrate_v2(const M7MuxRecvPacket *reply,
                                           const M7MuxUserRecvData *user,
                                           SharedKnockCodecV2Form1Packet *out_pkt);
static int app_transmit_m7mux_rehydrate_v3(const M7MuxRecvPacket *reply,
                                           const M7MuxUserRecvData *user,
                                           SharedKnockNormalizedUnit *out_normal);
static int app_transmit_v2_response_validate_signature(const Opts *opts,
                                                       SiglatchOpenSSLSession *session,
                                                       const SharedKnockCodecV2Form1Packet *pkt);
static int app_transmit_v2_response_print(const SharedKnockCodecV2Form1Packet *reply_pkt,
                                          int *out_status);
static int app_transmit_v3_response_validate_signature(const Opts *opts,
                                                       SiglatchOpenSSLSession *session,
                                                       const SharedKnockNormalizedUnit *normal);
static int app_transmit_v3_response_print(const SharedKnockNormalizedUnit *reply,
                                          int *out_status);
static int app_transmit_v4_response_validate_signature(const Opts *opts,
                                                       SiglatchOpenSSLSession *session,
                                                       const SharedKnockNormalizedUnit *normal);

static int app_transmit_process_mux_response(const Opts *effective,
                                             SiglatchOpenSSLSession *session,
                                             const M7MuxRecvPacket *reply,
                                             const M7MuxUserSendData *send_user,
                                             const M7MuxUserRecvData *reply_user,
                                             int *out_response_status) {
#define RESPONSE_FAIL(...)                                                     \
  do {                                                                         \
    if (lib.log.emit) {                                                        \
      lib.log.emit(LOG_ERROR, 1, __VA_ARGS__);                                 \
    }                                                                          \
    return 0;                                                                  \
  } while (0)

  if (!effective || !session || !reply || !send_user || !out_response_status) {
    return 0;
  }

  if (effective->dead_drop) {
    if (reply->wire_version != 0u) {
      RESPONSE_FAIL("Received structured packet on dead-drop channel (wire=%u)\n",
                    (unsigned int)reply->wire_version);
    }

    LOGI("Received response on raw dead-drop channel\n");
    app_transmit_dead_drop_print_raw_response(reply);
    *out_response_status = 0;
    return 1;
  }

  switch (effective->protocol) {
    case KNOCK_PROTOCOL_V1: {
      KnockPacket reply_pkt = {0};

      if (!reply_user) {
        RESPONSE_FAIL("Missing reply user buffer for v1 response\n");
      }

      if (!app_transmit_m7mux_rehydrate_v1(reply, reply_user, &reply_pkt)) {
        RESPONSE_FAIL("Failed to rehydrate v1 response packet\n");
      }

      if (reply_pkt.action_id != SL_KNOCK_RESPONSE_ACTION_ID) {
        RESPONSE_FAIL("Received non-response packet on reply channel (action=%u)\n",
                      (unsigned int)reply_pkt.action_id);
      }

      if (reply_pkt.user_id != send_user->user_id) {
        RESPONSE_FAIL("Received response for unexpected user_id=%u\n",
                      (unsigned int)reply_pkt.user_id);
      }

      if (reply_pkt.challenge != send_user->challenge) {
        RESPONSE_FAIL("Received response for unexpected challenge=%u\n",
                      (unsigned int)reply_pkt.challenge);
      }

      if (reply_pkt.payload_len < SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE) {
        RESPONSE_FAIL("Received malformed response payload\n");
      }

      if (reply_pkt.payload[1] != send_user->action_id) {
        RESPONSE_FAIL("Received response for unexpected request action=%u\n",
                      (unsigned int)reply_pkt.payload[1]);
      }

      if (!app_transmit_response_validate_signature(effective, session, &reply_pkt)) {
        RESPONSE_FAIL("Response signature validation failed\n");
      }

      LOGI("Received response on %s (%d)\n",
           app_transmit_protocol_name(effective->protocol),
           (int)effective->protocol);
      if (!app_transmit_response_print(&reply_pkt, out_response_status)) {
        FAIL_SINGLE_PACKET("Failed to print response packet\n");
      }
      return 1;
    }
    case KNOCK_PROTOCOL_V2: {
      SharedKnockCodecV2Form1Packet reply_pkt = {0};

      if (!reply_user) {
        RESPONSE_FAIL("Missing reply user buffer for v2 response\n");
      }

      if (!app_transmit_m7mux_rehydrate_v2(reply, reply_user, &reply_pkt)) {
        RESPONSE_FAIL("Failed to rehydrate v2 response packet\n");
      }

      if (reply_pkt.inner.action_id != SL_KNOCK_RESPONSE_ACTION_ID) {
        RESPONSE_FAIL("Received non-response packet on reply channel (action=%u)\n",
                      (unsigned int)reply_pkt.inner.action_id);
      }

      if (reply_pkt.inner.user_id != send_user->user_id) {
        RESPONSE_FAIL("Received response for unexpected user_id=%u\n",
                      (unsigned int)reply_pkt.inner.user_id);
      }

      if (reply_pkt.inner.challenge != send_user->challenge) {
        RESPONSE_FAIL("Received response for unexpected challenge=%u\n",
                      (unsigned int)reply_pkt.inner.challenge);
      }

      if (reply_pkt.inner.payload_len < SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE) {
        RESPONSE_FAIL("Received malformed response payload\n");
      }

      if (reply_pkt.payload[1] != send_user->action_id) {
        RESPONSE_FAIL("Received response for unexpected request action=%u\n",
                      (unsigned int)reply_pkt.payload[1]);
      }

      if (!app_transmit_v2_response_validate_signature(effective, session, &reply_pkt)) {
        RESPONSE_FAIL("Response signature validation failed\n");
      }

      LOGI("Received response on %s (%d)\n",
           app_transmit_protocol_name(effective->protocol),
           (int)effective->protocol);
      if (!app_transmit_v2_response_print(&reply_pkt, out_response_status)) {
        FAIL_SINGLE_PACKET("Failed to print response packet\n");
      }
      return 1;
    }
    case KNOCK_PROTOCOL_V3: {
      SharedKnockNormalizedUnit reply_normal = {0};

      if (!reply_user) {
        RESPONSE_FAIL("Missing reply user buffer for v3 response\n");
      }

      if (!app_transmit_m7mux_rehydrate_v3(reply, reply_user, &reply_normal)) {
        RESPONSE_FAIL("Failed to rehydrate v3 response packet\n");
      }

      if (reply_normal.action_id != SL_KNOCK_RESPONSE_ACTION_ID) {
        RESPONSE_FAIL("Received non-response packet on reply channel (action=%u)\n",
                      (unsigned int)reply_normal.action_id);
      }

      if (reply_normal.user_id != send_user->user_id) {
        RESPONSE_FAIL("Received response for unexpected user_id=%u\n",
                      (unsigned int)reply_normal.user_id);
      }

      if (reply_normal.challenge != send_user->challenge) {
        RESPONSE_FAIL("Received response for unexpected challenge=%u\n",
                      (unsigned int)reply_normal.challenge);
      }

      if (reply_normal.payload_len < SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE) {
        RESPONSE_FAIL("Received malformed response payload\n");
      }

      if (reply_normal.payload[1] != send_user->action_id) {
        RESPONSE_FAIL("Received response for unexpected request action=%u\n",
                      (unsigned int)reply_normal.payload[1]);
      }

      if (!app_transmit_v3_response_validate_signature(effective, session, &reply_normal)) {
        RESPONSE_FAIL("Response signature validation failed\n");
      }

      LOGI("Received response on %s (%d)\n",
           app_transmit_protocol_name(effective->protocol),
           (int)effective->protocol);
      if (!app_transmit_v3_response_print(&reply_normal, out_response_status)) {
        FAIL_SINGLE_PACKET("Failed to print response packet\n");
      }
      return 1;
    }
    case KNOCK_PROTOCOL_V4: {
      SharedKnockNormalizedUnit reply_normal = {0};

      if (!reply_user) {
        RESPONSE_FAIL("Missing reply user buffer for v4 response\n");
      }

      if (!app_transmit_m7mux_rehydrate_v3(reply, reply_user, &reply_normal)) {
        RESPONSE_FAIL("Failed to rehydrate v4 response packet\n");
      }

      if (reply_normal.action_id != SL_KNOCK_RESPONSE_ACTION_ID) {
        RESPONSE_FAIL("Received non-response packet on reply channel (action=%u)\n",
                      (unsigned int)reply_normal.action_id);
      }

      if (reply_normal.user_id != send_user->user_id) {
        RESPONSE_FAIL("Received response for unexpected user_id=%u\n",
                      (unsigned int)reply_normal.user_id);
      }

      if (reply_normal.challenge != send_user->challenge) {
        RESPONSE_FAIL("Received response for unexpected challenge=%u\n",
                      (unsigned int)reply_normal.challenge);
      }

      if (reply_normal.payload_len < SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE) {
        RESPONSE_FAIL("Received malformed response payload\n");
      }

      if (reply_normal.payload[1] != send_user->action_id) {
        RESPONSE_FAIL("Received response for unexpected request action=%u\n",
                      (unsigned int)reply_normal.payload[1]);
      }

      if (!app_transmit_v4_response_validate_signature(effective, session, &reply_normal)) {
        RESPONSE_FAIL("Response signature validation failed\n");
      }

      LOGI("Received response on %s (%d)\n",
           app_transmit_protocol_name(effective->protocol),
           (int)effective->protocol);
      if (!app_transmit_v3_response_print(&reply_normal, out_response_status)) {
        FAIL_SINGLE_PACKET("Failed to print response packet\n");
      }
      return 1;
    }
    default:
      RESPONSE_FAIL("Unknown protocol selected\n");
  }
#undef RESPONSE_FAIL

  return 0;
}

static int app_transmit_ensure_response_private_key(const Opts *opts,
                                                    SiglatchOpenSSLSession *session) {
  if (!opts || !session) {
    return 0;
  }

  if (!opts->encrypt) {
    return 1;
  }

  if (session->private_key) {
    return 1;
  }

  if (opts->client_privkey_path[0] == '\0') {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1,
                   "Encrypted response requested but no client private key is configured\n");
    }
    return 0;
  }

  if (!session->parent_ctx && !lib.openssl.session_init(session)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to initialize OpenSSL session for response decryption\n");
    }
    return 0;
  }

  if (!lib.openssl.session_readPrivateKey(session, opts->client_privkey_path)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to load client private key from %s\n",
                   opts->client_privkey_path);
    }
    return 0;
  }

  return 1;
}

static int app_transmit_init(void) {
  return 1;
}

static void app_transmit_shutdown(void) {
}

static int app_transmit_resolve_payload(Opts *opts) {
  if (!opts) {
    return 0;
  }

  if (opts->stdin_requested) {
    opts->payload_len = 0;
    if (!lib.stdin.read_multiline(opts->payload, sizeof(opts->payload), &opts->payload_len)) {
      if (lib.log.emit) {
        lib.log.emit(LOG_ERROR, 1, "Failed to read payload from stdin (--stdin)");
      }
      return 0;
    }
  } else if (opts->payload_len == 0 && lib.stdin.has_piped_input()) {
    opts->payload_len = 0;
    if (!lib.stdin.attach_if_piped(opts->payload, sizeof(opts->payload), &opts->payload_len)) {
      if (lib.log.emit) {
        lib.log.emit(LOG_ERROR, 1, "Failed to read payload from piped stdin");
      }
      return 0;
    }
  }

  if (opts->dead_drop && opts->payload_len == 0) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Dead drop payload is required");
    }
    return 0;
  }

  return 1;
}

static uint32_t app_transmit_protocol_wire_version(KnockProtocol protocol) {
  switch (protocol) {
    case KNOCK_PROTOCOL_V1:
      return SHARED_KNOCK_CODEC_V1_VERSION;
    case KNOCK_PROTOCOL_V2:
      return SHARED_KNOCK_CODEC_V2_WIRE_VERSION;
    case KNOCK_PROTOCOL_V3:
      return SHARED_KNOCK_CODEC_V3_WIRE_VERSION;
    case KNOCK_PROTOCOL_V4:
      return SHARED_KNOCK_CODEC_V4_WIRE_VERSION;
    default:
      return SHARED_KNOCK_CODEC_V1_VERSION;
  }
}

static uint8_t app_transmit_protocol_wire_form(KnockProtocol protocol) {
  switch (protocol) {
    case KNOCK_PROTOCOL_V1:
      return 0u;
    case KNOCK_PROTOCOL_V2:
    case KNOCK_PROTOCOL_V3:
    case KNOCK_PROTOCOL_V4:
      return SHARED_KNOCK_CODEC_FORM1_ID;
    default:
      return SHARED_KNOCK_CODEC_FORM1_ID;
  }
}

static const M7MuxNormalizeAdapter *app_transmit_protocol_adapter(KnockProtocol protocol) {
  switch (protocol) {
    case KNOCK_PROTOCOL_V1:
      return shared.knock.codec.v1 ? shared.knock.codec.v1() : NULL;
    case KNOCK_PROTOCOL_V2:
      return shared.knock.codec.v2 ? shared.knock.codec.v2() : NULL;
    case KNOCK_PROTOCOL_V3:
      return shared.knock.codec.v3 ? shared.knock.codec.v3() : NULL;
    case KNOCK_PROTOCOL_V4:
      return shared.knock.codec.v4 ? shared.knock.codec.v4() : NULL;
    default:
      break;
  }

  return NULL;
}

static int app_transmit_register_m7mux_adapters(void) {
  const M7MuxNormalizeAdapterLib *normalize = NULL;
  const M7MuxNormalizeAdapter *adapter = NULL;

  normalize = get_protocol_udp_m7mux_normalize_adapter_lib();
  if (!normalize || !normalize->register_adapter || !normalize->count) {
    return 0;
  }

  if (normalize->count() > 0u) {
    return 1;
  }

  adapter = app_transmit_protocol_adapter(KNOCK_PROTOCOL_V1);
  if (!adapter || !normalize->register_adapter(adapter)) {
    return 0;
  }

  adapter = app_transmit_protocol_adapter(KNOCK_PROTOCOL_V2);
  if (!adapter || !normalize->register_adapter(adapter)) {
    return 0;
  }

  adapter = app_transmit_protocol_adapter(KNOCK_PROTOCOL_V3);
  if (!adapter || !normalize->register_adapter(adapter)) {
    return 0;
  }

  adapter = app_transmit_protocol_adapter(KNOCK_PROTOCOL_V4);
  if (!adapter || !normalize->register_adapter(adapter)) {
    return 0;
  }

  return 1;
}

static int app_transmit_m7mux_prepare_runtime(const Opts *opts,
                                              SiglatchOpenSSLSession *session,
                                              SharedKnockCodecContext **out_codec_context) {
  const SharedKnockCodecContextLib *codec_context_lib = NULL;
  SharedKnockCodecContext *codec_context = NULL;
  SharedKnockCodecServerKey server_key = {0};
  M7MuxContext m7mux_ctx = {0};

  if (!opts || !session || !out_codec_context) {
    return 0;
  }

  codec_context_lib = &shared.knock.codec.context;
  if (!codec_context_lib->init || !codec_context_lib->create ||
      !codec_context_lib->destroy || !codec_context_lib->set_server_key ||
      !codec_context_lib->clear_server_key || !codec_context_lib->set_openssl_session ||
      !codec_context_lib->clear_openssl_session) {
    return 0;
  }

  if (!codec_context_lib->init()) {
    return 0;
  }

  if (!codec_context_lib->create(&codec_context)) {
    codec_context_lib->shutdown();
    return 0;
  }

  if (!codec_context_lib->set_openssl_session(codec_context, session)) {
    codec_context_lib->destroy(codec_context);
    codec_context_lib->shutdown();
    return 0;
  }

  codec_context->server_secure = opts->encrypt ? 1 : 0;

  if (opts->encrypt) {
    if (!app_transmit_ensure_response_private_key(opts, session)) {
      codec_context_lib->clear_openssl_session(codec_context);
      codec_context_lib->destroy(codec_context);
      codec_context_lib->shutdown();
      return 0;
    }

    if (session->private_key) {
      server_key.name = "client";
      server_key.public_key = session->public_key;
      server_key.private_key = session->private_key;
      server_key.hmac_key = session->hmac_key;
      server_key.hmac_key_len = session->hmac_key_len;

      if (!codec_context_lib->set_server_key(codec_context, &server_key)) {
        codec_context_lib->clear_openssl_session(codec_context);
        codec_context_lib->destroy(codec_context);
        codec_context_lib->shutdown();
        return 0;
      }
    }
  }

  if (!shared_knock_codec_v1_init(codec_context) ||
      !shared_knock_codec_v2_init(codec_context) ||
      !shared_knock_codec_v3_init(codec_context) ||
      !shared_knock_codec_v4_init(codec_context)) {
    shared_knock_codec_v4_shutdown();
    shared_knock_codec_v3_shutdown();
    shared_knock_codec_v2_shutdown();
    shared_knock_codec_v1_shutdown();
    if (codec_context->has_server_key) {
      codec_context_lib->clear_server_key(codec_context);
    }
    codec_context_lib->clear_openssl_session(codec_context);
    codec_context_lib->destroy(codec_context);
    codec_context_lib->shutdown();
    return 0;
  }

  m7mux_ctx.socket = &lib.net.socket;
  m7mux_ctx.udp = &lib.net.udp;
  m7mux_ctx.time = &lib.time;
  m7mux_ctx.codec_context = codec_context;
  m7mux_ctx.enforce_wire_decode = 1;
  m7mux_ctx.enforce_wire_auth = 0;

  if (!lib.m7mux.set_context(&m7mux_ctx)) {
    shared_knock_codec_v4_shutdown();
    shared_knock_codec_v3_shutdown();
    shared_knock_codec_v2_shutdown();
    shared_knock_codec_v1_shutdown();
    if (codec_context->has_server_key) {
      codec_context_lib->clear_server_key(codec_context);
    }
    codec_context_lib->clear_openssl_session(codec_context);
    codec_context_lib->destroy(codec_context);
    codec_context_lib->shutdown();
    return 0;
  }

  *out_codec_context = codec_context;
  return 1;
}

static void app_transmit_m7mux_release_runtime(SharedKnockCodecContext *codec_context) {
  const SharedKnockCodecContextLib *codec_context_lib = NULL;

  codec_context_lib = &shared.knock.codec.context;

  shared_knock_codec_v4_shutdown();
  shared_knock_codec_v3_shutdown();
  shared_knock_codec_v2_shutdown();
  shared_knock_codec_v1_shutdown();

  if (!codec_context) {
    if (codec_context_lib->shutdown) {
      codec_context_lib->shutdown();
    }
    return;
  }

  if (codec_context_lib->clear_server_key) {
    codec_context_lib->clear_server_key(codec_context);
  }
  if (codec_context_lib->clear_openssl_session) {
    codec_context_lib->clear_openssl_session(codec_context);
  }
  if (codec_context_lib->destroy) {
    codec_context_lib->destroy(codec_context);
  }
  if (codec_context_lib->shutdown) {
    codec_context_lib->shutdown();
  }
}

static int app_transmit_build_m7mux_send_packet(const Opts *opts,
                                                KnockProtocol protocol,
                                                const char *target_ip,
                                                uint16_t target_port,
                                                M7MuxSendPacket *out_send,
                                                M7MuxUserSendData *out_user) {
  size_t payload_len = 0u;
  size_t copy_len = 0u;

  if (!opts || !target_ip || !out_send || !out_user) {
    return 0;
  }

  memset(out_send, 0, sizeof(*out_send));
  memset(out_user, 0, sizeof(*out_user));

  out_send->trace_id = 0u;
  memcpy(out_send->label, "knocker", sizeof("knocker"));
  out_send->wire_version = app_transmit_protocol_wire_version(protocol);
  out_send->wire_form = app_transmit_protocol_wire_form(protocol);
  out_send->received_ms = lib.time.monotonic_ms();
  out_send->session_id = (protocol == KNOCK_PROTOCOL_V4) ? 1u : 0u;
  out_send->message_id = (protocol == KNOCK_PROTOCOL_V4) ? 1u : 0u;
  out_send->stream_id = (protocol == KNOCK_PROTOCOL_V4) ? 1u : 0u;
  out_send->fragment_index = 0u;
  out_send->fragment_count = opts->fragment_count;
  out_send->timestamp = (uint32_t)lib.time.unix_ts();
  memcpy(out_send->ip, target_ip, sizeof(out_send->ip));
  out_send->ip[sizeof(out_send->ip) - 1u] = '\0';
  out_send->client_port = target_port;
  out_send->encrypted = opts->encrypt ? 1 : 0;
  out_send->wire_auth = (opts->hmac_mode == HMAC_MODE_NORMAL) ? 1 : 0;

  out_user->user_id = (uint16_t)opts->user_id;
  out_user->action_id = (uint8_t)opts->action_id;
  out_user->challenge = lib.random.challenge();
  payload_len = opts->payload_len;
  if (payload_len > sizeof(out_user->payload)) {
    payload_len = sizeof(out_user->payload);
  }

  copy_len = payload_len;
  if (copy_len > 0u) {
    memcpy(out_user->payload, opts->payload, copy_len);
  }
  out_user->payload_len = (uint16_t)copy_len;

  switch (opts->hmac_mode) {
    case HMAC_MODE_DUMMY:
      memset(out_user->hmac, 0x42, sizeof(out_user->hmac));
      break;
    case HMAC_MODE_NONE:
      memset(out_user->hmac, 0, sizeof(out_user->hmac));
      break;
    case HMAC_MODE_NORMAL:
      memset(out_user->hmac, 0, sizeof(out_user->hmac));
      break;
    default:
      return 0;
  }

  out_send->user = out_user;
  return 1;
}

static int app_transmit_m7mux_rehydrate_v1(const M7MuxRecvPacket *reply,
                                           const M7MuxUserRecvData *user,
                                           KnockPacket *out_pkt) {
  if (!reply || !user || !out_pkt) {
    return 0;
  }

  memset(out_pkt, 0, sizeof(*out_pkt));
  out_pkt->version = (uint8_t)reply->wire_version;
  out_pkt->timestamp = reply->timestamp;
  out_pkt->user_id = user->user_id;
  out_pkt->action_id = user->action_id;
  out_pkt->challenge = user->challenge;
  memcpy(out_pkt->hmac, user->hmac, sizeof(out_pkt->hmac));
  out_pkt->payload_len = user->payload_len;
  if (user->payload_len > 0u) {
    memcpy(out_pkt->payload, user->payload, user->payload_len);
  }

  return 1;
}

static int app_transmit_m7mux_rehydrate_v2(const M7MuxRecvPacket *reply,
                                           const M7MuxUserRecvData *user,
                                           SharedKnockCodecV2Form1Packet *out_pkt) {
  if (!reply || !user || !out_pkt) {
    return 0;
  }

  memset(out_pkt, 0, sizeof(*out_pkt));
  out_pkt->outer.magic = SHARED_KNOCK_PREFIX_MAGIC;
  out_pkt->outer.version = reply->wire_version;
  out_pkt->outer.form = reply->wire_form;
  out_pkt->inner.timestamp = reply->timestamp;
  out_pkt->inner.user_id = user->user_id;
  out_pkt->inner.action_id = user->action_id;
  out_pkt->inner.challenge = user->challenge;
  memcpy(out_pkt->inner.hmac, user->hmac, sizeof(out_pkt->inner.hmac));
  out_pkt->inner.payload_len = user->payload_len;
  if (user->payload_len > 0u) {
    memcpy(out_pkt->payload, user->payload, user->payload_len);
  }

  return 1;
}

static int app_transmit_m7mux_rehydrate_v3(const M7MuxRecvPacket *reply,
                                           const M7MuxUserRecvData *user,
                                           SharedKnockNormalizedUnit *out_normal) {
  if (!reply || !user || !out_normal) {
    return 0;
  }

  memset(out_normal, 0, sizeof(*out_normal));
  out_normal->complete = reply->complete;
  out_normal->wire_version = reply->wire_version;
  out_normal->wire_form = reply->wire_form;
  out_normal->session_id = reply->session_id;
  out_normal->message_id = reply->message_id;
  out_normal->stream_id = reply->stream_id;
  out_normal->fragment_index = reply->fragment_index;
  out_normal->fragment_count = reply->fragment_count;
  out_normal->timestamp = reply->timestamp;
  memcpy(out_normal->ip, reply->ip, sizeof(out_normal->ip));
  out_normal->client_port = reply->client_port;
  out_normal->encrypted = reply->encrypted;
  out_normal->wire_decode = reply->wire_decode;
  out_normal->wire_auth = reply->wire_auth;
  out_normal->user_id = user->user_id;
  out_normal->action_id = user->action_id;
  out_normal->challenge = user->challenge;
  memcpy(out_normal->hmac, user->hmac, sizeof(out_normal->hmac));
  out_normal->payload_len = user->payload_len;
  if (user->payload_len > 0u) {
    memcpy(out_normal->payload, user->payload, user->payload_len);
  }

  return 1;
}

static int app_transmit_single_packet_m7mux(const Opts *opts) {
  int status = 1;
  int response_status = 0;
  size_t response_count = 0u;
  int udp_fd = -1;
  M7MuxState *mux_state = NULL;
  SiglatchOpenSSLSession session = {0};
  SharedKnockCodecContext *codec_context = NULL;
  Opts runtime_opts = {0};
  const Opts *effective = NULL;
  M7MuxSendPacket send = {0};
  M7MuxUserSendData send_user = {0};
  M7MuxRecvPacket reply = {0};
  M7MuxUserRecvData reply_user = {0};
  char ip[INET6_ADDRSTRLEN] = {0};
  unsigned char raw_out[SHARED_KNOCK_CODEC_PACKET_MAX_SIZE] = {0};
  size_t raw_out_len = 0u;
  M7MuxSendBytesPacket raw_send = {0};
  const uint8_t *raw_payload = NULL;
  size_t raw_payload_len = 0u;

  if (!opts) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Transmit requested with NULL opts\n");
    }
    return status;
  }

  runtime_opts = *opts;
  effective = &runtime_opts;

  do {
    if (!app_transmit_resolve_payload(&runtime_opts)) {
      FAIL_SINGLE_PACKET("Failed to resolve payload input\n");
    }

    if (!init_user_openssl_session(effective, &session)) {
      FAIL_SINGLE_PACKET("Failed to initialize OpenSSL session\n");
    }
    if (effective->dead_drop) {
      raw_payload = effective->payload;
      raw_payload_len = effective->payload_len;
    }

    char ip_local[INET6_ADDRSTRLEN];
    int host_rv = lib.net.addr.resolve_host_to_ip(effective->host, ip_local, sizeof(ip_local));

    switch (host_rv) {
      case 1:
        break;
      case -2:
        FAIL_SINGLE_PACKET("Hostname is NULL\n");
        break;
      case -3:
        FAIL_SINGLE_PACKET("Output buffer is NULL\n");
        break;
      default:
        FAIL_SINGLE_PACKET("Could not resolve hostname: %s\n", effective->host);
        break;
    }

    memcpy(ip, ip_local, sizeof(ip));
    ip[sizeof(ip) - 1u] = '\0';

    if (effective->send_from_ip[0] != '\0' && lib.net.addr.is_ipv6(ip)) {
      FAIL_SINGLE_PACKET("Client source bind (--send-from) currently supports only IPv4 targets; resolved %s to %s\n",
                         effective->host, ip);
    }

    if (effective->send_from_ip[0] != '\0') {
      udp_fd = lib.net.udp.open_bound_auto(ip, effective->send_from_ip, 0, NULL);
      if (udp_fd < 0) {
        FAIL_SINGLE_PACKET("Failed to open UDP socket for target %s using source %s\n",
                           ip, effective->send_from_ip);
      }
    } else {
      udp_fd = lib.net.udp.open_auto(ip);
      if (udp_fd < 0) {
        FAIL_SINGLE_PACKET("Failed to open UDP socket for target %s\n", ip);
      }
    }

    if (effective->send_from_ip[0] != '\0' && lib.log.emit) {
      lib.log.emit(LOG_INFO, 1,
                   "Sending UDP packet to %s:%u from %s",
                   ip, (unsigned int)effective->port, effective->send_from_ip);
    }

    if (effective->dead_drop) {
      if (!encryptWrapper(effective, &session, raw_payload, raw_payload_len, raw_out, &raw_out_len)) {
        FAIL_SINGLE_PACKET("Failed to prepare dead-drop payload\n");
      }

      raw_send.trace_id = 0u;
      memcpy(raw_send.label, "knocker", sizeof("knocker"));
      memcpy(raw_send.ip, ip, sizeof(raw_send.ip));
      raw_send.ip[sizeof(raw_send.ip) - 1u] = '\0';
      raw_send.client_port = effective->port;
      raw_send.received_ms = lib.time.monotonic_ms();
      raw_send.bytes = raw_out;
      raw_send.bytes_len = raw_out_len;

      mux_state = lib.m7mux.connect.connect_socket(udp_fd);
      if (!mux_state) {
        FAIL_SINGLE_PACKET("Failed to attach UDP socket to mux state for dead-drop\n");
      }

      if (!lib.m7mux.outbox.stage_bytes(mux_state, &raw_send)) {
        FAIL_SINGLE_PACKET("Failed to stage dead-drop payload into mux outbox\n");
      }

      LOGI("Sending request on %s (%d)\n",
           app_transmit_protocol_name(effective->protocol),
           (int)effective->protocol);

      if (lib.m7mux.pump(mux_state, 0u) < 0) {
        FAIL_SINGLE_PACKET("Failed to flush mux dead-drop payload\n");
      }
    }

    if (!effective->dead_drop) {
    if (!app_transmit_m7mux_prepare_runtime(effective, &session, &codec_context)) {
      FAIL_SINGLE_PACKET("Failed to prepare mux runtime\n");
    }

    if (!app_transmit_register_m7mux_adapters()) {
      FAIL_SINGLE_PACKET("Failed to register mux adapters\n");
    }

    mux_state = lib.m7mux.connect.connect_socket(udp_fd);
    if (!mux_state) {
      FAIL_SINGLE_PACKET("Failed to attach UDP socket to mux state\n");
    }

    if (!app_transmit_build_m7mux_send_packet(effective,
                                              effective->protocol,
                                              ip,
                                              effective->port,
                                              &send,
                                              &send_user)) {
      FAIL_SINGLE_PACKET("Failed to prepare mux send packet\n");
    }

    if (effective->fragment_count > 1u && lib.log.emit) {
      lib.log.emit(LOG_INFO, 1,
                   "Fragmenting request into %u fragments\n",
                   (unsigned)effective->fragment_count);
    }

    if (effective->fragment_count > 1u) {
      if (!lib.m7mux.outbox.stage_fragments(mux_state, &send, effective->fragment_count)) {
        FAIL_SINGLE_PACKET("Failed to stage fragmented request into mux outbox\n");
      }
    } else {
      if (!lib.m7mux.outbox.stage(mux_state, &send)) {
        FAIL_SINGLE_PACKET("Failed to stage request into mux outbox\n");
      }
    }

    if (effective->send_from_ip[0] != '\0' && lib.log.emit) {
      lib.log.emit(LOG_INFO, 1,
                   "Sending UDP packet to %s:%u from %s",
                   ip,
                   (unsigned int)effective->port,
                   effective->send_from_ip);
    }

    LOGI("Sending request on %s (%d)\n",
         app_transmit_protocol_name(effective->protocol),
         (int)effective->protocol);

    if (lib.m7mux.pump(mux_state, 0u) < 0) {
      FAIL_SINGLE_PACKET("Failed to flush mux request\n");
    }
    }

    {
      uint64_t response_deadline = lib.time.monotonic_ms() + KNOCKER_RESPONSE_TIMEOUT_MS;

      while (1) {
        uint64_t now_ms = lib.time.monotonic_ms();
        uint64_t remaining_ms = 0u;

        if (now_ms >= response_deadline) {
          break;
        }

        remaining_ms = response_deadline - now_ms;
        if (lib.m7mux.pump(mux_state, remaining_ms) < 0) {
          FAIL_SINGLE_PACKET("Failed to pump mux while waiting for response\n");
        }

        while (lib.m7mux.inbox.has_pending(mux_state)) {
          memset(&reply, 0, sizeof(reply));
          memset(&reply_user, 0, sizeof(reply_user));
          if (!effective->dead_drop) {
            reply.user = &reply_user;
          }

          if (!lib.m7mux.inbox.drain(mux_state, &reply)) {
            FAIL_SINGLE_PACKET("Failed to drain mux response\n");
          }

          response_count++;
          if (!app_transmit_process_mux_response(effective,
                                                 &session,
                                                 &reply,
                                                 &send_user,
                                                 effective->dead_drop ? NULL : &reply_user,
                                                 &response_status)) {
            FAIL_SINGLE_PACKET("Failed to process mux response\n");
          }

          status = response_status;
        }
      }
    }

    if (response_count == 0u) {
      lib.print.uc_printf(NULL, "No response from host\n");
      status = 0;
      break;
    }
  } while (0);

  if (mux_state) {
    lib.m7mux.connect.disconnect(mux_state);
  }
  if (udp_fd >= 0) {
    lib.net.udp.close(udp_fd);
  }

  app_transmit_m7mux_release_runtime(codec_context);
  lib.openssl.session_free(&session);
  return status;
}

static int app_transmit_v2_response_validate_signature(const Opts *opts,
                                                       SiglatchOpenSSLSession *session,
                                                       const SharedKnockCodecV2Form1Packet *pkt) {
  uint8_t digest[32] = {0};
  uint8_t dummy_hmac[sizeof(pkt->inner.hmac)] = {0};

  if (!opts || !session || !pkt) {
    return 0;
  }

  switch (opts->hmac_mode) {
    case HMAC_MODE_NORMAL:
      if (!shared_knock_digest_generate_v2_form1(pkt, digest)) {
        return 0;
      }
      return shared.knock.digest.validate(session->hmac_key, digest, pkt->inner.hmac);

    case HMAC_MODE_DUMMY:
      memset(dummy_hmac, 0x42, sizeof(dummy_hmac));
      return memcmp(pkt->inner.hmac, dummy_hmac, sizeof(dummy_hmac)) == 0;

    case HMAC_MODE_NONE:
      return 1;

    default:
      break;
  }

  return 0;
}

static int app_transmit_v2_response_print(const SharedKnockCodecV2Form1Packet *reply_pkt,
                                          int *out_status) {
  if (!reply_pkt) {
    return 0;
  }

  return app_transmit_response_print_payload(reply_pkt->payload,
                                             reply_pkt->inner.payload_len,
                                             out_status);
}
static int app_transmit_v3_response_validate_signature(const Opts *opts,
                                                       SiglatchOpenSSLSession *session,
                                                       const SharedKnockNormalizedUnit *normal) {
  uint8_t digest[32] = {0};
  uint8_t dummy_hmac[sizeof(normal->hmac)] = {0};

  if (!opts || !session || !normal) {
    return 0;
  }

  switch (opts->hmac_mode) {
    case HMAC_MODE_NORMAL:
      if (!shared_knock_digest_generate_v3_form1(normal, digest)) {
        return 0;
      }
      return shared.knock.digest.validate(session->hmac_key, digest, normal->hmac);

    case HMAC_MODE_DUMMY:
      memset(dummy_hmac, 0x42, sizeof(dummy_hmac));
      return memcmp(normal->hmac, dummy_hmac, sizeof(dummy_hmac)) == 0;

    case HMAC_MODE_NONE:
      return 1;

    default:
      break;
  }

  return 0;
}

static int app_transmit_v4_response_validate_signature(const Opts *opts,
                                                       SiglatchOpenSSLSession *session,
                                                       const SharedKnockNormalizedUnit *normal) {
  uint8_t digest[32] = {0};
  uint8_t dummy_hmac[sizeof(normal->hmac)] = {0};

  if (!opts || !session || !normal) {
    return 0;
  }

  switch (opts->hmac_mode) {
    case HMAC_MODE_NORMAL:
      if (!shared_knock_digest_generate_v4_form1(normal, digest)) {
        return 0;
      }
      return shared.knock.digest.validate(session->hmac_key, digest, normal->hmac);

    case HMAC_MODE_DUMMY:
      memset(dummy_hmac, 0x42, sizeof(dummy_hmac));
      return memcmp(normal->hmac, dummy_hmac, sizeof(dummy_hmac)) == 0;

    case HMAC_MODE_NONE:
      return 1;

    default:
      break;
  }

  return 0;
}

static int app_transmit_v3_response_print(const SharedKnockNormalizedUnit *reply,
                                          int *out_status) {
  if (!reply) {
    return 0;
  }

  return app_transmit_response_print_payload(reply->payload, reply->payload_len, out_status);
}

static int app_transmit_single_packet(const Opts *opts) {
  int status = 1;
  Opts runtime_opts = {0};
  const Opts *effective = NULL;

  if (!opts) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Transmit requested with NULL opts");
    }
    return status;
  }

  runtime_opts = *opts;
  effective = &runtime_opts;

  LOGI("Selected protocol %s (%d)\n",
       app_transmit_protocol_name(effective->protocol),
       (int)effective->protocol);

  (void)runtime_opts;
  (void)status;
  return app_transmit_single_packet_m7mux(effective);
}

static const AppTransmitLib app_transmit_instance = {
  .init = app_transmit_init,
  .shutdown = app_transmit_shutdown,
  .singlePacket = app_transmit_single_packet
};

const AppTransmitLib *get_app_transmit_lib(void) {
  return &app_transmit_instance;
}
