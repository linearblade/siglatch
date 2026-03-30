/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "transmit.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "../../../shared/shared.h"
#include "../../../shared/knock/response.h"
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

static int app_transmit_wait_for_response(int udp_fd,
                                          const Opts *opts,
                                          const KnockPacket *request_pkt,
                                          SiglatchOpenSSLSession *session,
                                          int *out_status) {
  uint8_t received[KNOCKER_RESPONSE_BUFFER_SIZE] = {0};
  uint8_t decrypted[KNOCKER_RESPONSE_BUFFER_SIZE] = {0};
  const uint8_t *reply_buf = received;
  size_t received_len = 0;
  size_t reply_len = 0;
  struct sockaddr_storage peer = {0};
  KnockPacket reply_pkt = {0};
  int wait_rc = 0;

  if (!opts || !request_pkt || !session || !out_status) {
    return 0;
  }

  *out_status = 0;

  wait_rc = lib.net.socket.wait_readable(udp_fd, KNOCKER_RESPONSE_TIMEOUT_MS);
  if (wait_rc == 0) {
    lib.print.uc_printf(NULL, "No response from host\n");
    return 1;
  }

  if (wait_rc < 0) {
    if (errno == EINTR) {
      return 0;
    }
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed while waiting for server response\n");
    }
    return 0;
  }

  if (!lib.net.udp.recv(udp_fd, received, sizeof(received), &peer, &received_len)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to receive server response datagram\n");
    }
    return 0;
  }

  reply_len = received_len;

  if (opts->encrypt) {
    int decrypt_rc = 0;
    size_t decrypted_len = sizeof(decrypted);

    if (!app_transmit_ensure_response_private_key(opts, session)) {
      return 0;
    }

    decrypt_rc = lib.openssl.session_decrypt(session,
                                             received, received_len,
                                             decrypted, &decrypted_len);
    if (decrypt_rc != SL_SSL_DECRYPT_OK) {
      if (lib.log.emit) {
        lib.log.emit(LOG_ERROR, 1, "Failed to decrypt server response: %s\n",
                     lib.openssl.session_decrypt_strerror(decrypt_rc));
      }
      return 0;
    }

    reply_buf = decrypted;
    reply_len = decrypted_len;
  }

  if (shared.knock.codec.v1.deserialize(reply_buf, reply_len, &reply_pkt) != SL_PAYLOAD_OK) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to deserialize server response packet\n");
    }
    return 0;
  }

  if (reply_pkt.action_id != SL_KNOCK_RESPONSE_ACTION_ID) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received non-response packet on reply channel (action=%u)\n",
                   (unsigned int)reply_pkt.action_id);
    }
    return 0;
  }

  if (reply_pkt.user_id != request_pkt->user_id) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response for unexpected user_id=%u\n",
                   (unsigned int)reply_pkt.user_id);
    }
    return 0;
  }

  if (reply_pkt.challenge != request_pkt->challenge) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response for unexpected challenge=%u\n",
                   (unsigned int)reply_pkt.challenge);
    }
    return 0;
  }

  if (reply_pkt.payload_len < SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received malformed response payload\n");
    }
    return 0;
  }

  if (reply_pkt.payload[1] != request_pkt->action_id) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response for unexpected request action=%u\n",
                   (unsigned int)reply_pkt.payload[1]);
    }
    return 0;
  }

  if (!app_transmit_response_validate_signature(opts, session, &reply_pkt)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Response signature validation failed\n");
    }
    return 0;
  }

  LOGI("Received response on %s (%d)\n",
       app_transmit_protocol_name(opts->protocol),
       (int)opts->protocol);
  return app_transmit_response_print(&reply_pkt, out_status);
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

static int app_transmit_v2_structure_packet(SharedKnockCodecV2Form1Packet *pkt_out,
                                            const uint8_t *payload,
                                            size_t len,
                                            uint16_t user_id,
                                            uint8_t action_id) {
  if (!pkt_out || !payload) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "structurePacketV2: Invalid input\n");
    }
    return 0;
  }

  memset(pkt_out, 0, sizeof(*pkt_out));

  pkt_out->outer.magic = SHARED_KNOCK_PREFIX_MAGIC;
  pkt_out->outer.version = SHARED_KNOCK_CODEC_V2_WIRE_VERSION;
  pkt_out->outer.form = SHARED_KNOCK_CODEC_FORM1_ID;
  pkt_out->inner.timestamp = (uint32_t)lib.time.unix_ts();
  pkt_out->inner.user_id = user_id;
  pkt_out->inner.action_id = action_id;
  pkt_out->inner.challenge = lib.random.challenge();

  if (len > sizeof(pkt_out->payload)) {
    len = sizeof(pkt_out->payload);
  }

  memcpy(pkt_out->payload, payload, len);
  pkt_out->inner.payload_len = (uint16_t)len;

  return 1;
}

static int app_transmit_v2_sign_packet(SiglatchOpenSSLSession *session,
                                       SharedKnockCodecV2Form1Packet *pkt) {
  uint8_t digest[32] = {0};

  if (!session || !pkt) {
    return 0;
  }

  if (!shared_knock_digest_generate_v2_form1(pkt, digest)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to generate v2 digest\n");
    }
    return 0;
  }

  dumpDigest("Client-computed Digest", digest, sizeof(digest));

  if (!lib.openssl.sign(session, digest, pkt->inner.hmac)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to sign v2 digest\n");
    }
    return 0;
  }

  return 1;
}

static int app_transmit_v2_sign_wrapper(const Opts *opts,
                                        SiglatchOpenSSLSession *session,
                                        SharedKnockCodecV2Form1Packet *pkt) {
  if (!opts || !session || !pkt) {
    return 0;
  }

  switch (opts->hmac_mode) {
    case HMAC_MODE_NORMAL:
      return app_transmit_v2_sign_packet(session, pkt);

    case HMAC_MODE_DUMMY:
      memset(pkt->inner.hmac, 0x42, sizeof(pkt->inner.hmac));
      LOGD("Using dummy HMAC (0x42 padded)\n");
      return 1;

    case HMAC_MODE_NONE:
      memset(pkt->inner.hmac, 0, sizeof(pkt->inner.hmac));
      LOGD("HMAC signing disabled\n");
      return 1;

    default:
      if (lib.log.emit) {
        lib.log.emit(LOG_ERROR, 1, "Unknown HMAC mode: %d\n", opts->hmac_mode);
      }
      return 0;
  }
}

static int app_transmit_v2_structure_or_dead_drop(const Opts *opts,
                                                  const SharedKnockCodecV2Form1Packet *pkt,
                                                  uint8_t *packed,
                                                  int *packed_len) {
  if (!opts || !pkt || !packed || !packed_len) {
    return 0;
  }

  if (opts->dead_drop) {
    if (opts->payload_len == 0) {
      if (lib.log.emit) {
        lib.log.emit(LOG_ERROR, 1, "Dead drop mode requires non-empty payload\n");
      }
      return 0;
    }

    memcpy(packed, opts->payload, opts->payload_len);
    *packed_len = (int)opts->payload_len;

    LOGD("Prepared dead-drop payload (%d bytes)", *packed_len);
    return 1;
  }

  *packed_len = shared.knock.codec.v2.pack(pkt, packed, SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE);
  if (*packed_len <= 0) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to pack structured v2 payload\n");
    }
    return 0;
  }

  LOGD("Packed structured KnockPacket V2 (%d bytes)", *packed_len);
  return 1;
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

static int app_transmit_wait_for_response_v2(int udp_fd,
                                             const Opts *opts,
                                             const SharedKnockCodecV2Form1Packet *request_pkt,
                                             SiglatchOpenSSLSession *session,
                                             int *out_status) {
  uint8_t received[KNOCKER_RESPONSE_BUFFER_SIZE] = {0};
  uint8_t decrypted[KNOCKER_RESPONSE_BUFFER_SIZE] = {0};
  const uint8_t *reply_buf = received;
  size_t received_len = 0;
  size_t reply_len = 0;
  struct sockaddr_storage peer = {0};
  SharedKnockCodecV2Form1Packet reply_pkt = {0};
  int wait_rc = 0;

  if (!opts || !request_pkt || !session || !out_status) {
    return 0;
  }

  *out_status = 0;

  wait_rc = lib.net.socket.wait_readable(udp_fd, KNOCKER_RESPONSE_TIMEOUT_MS);
  if (wait_rc == 0) {
    lib.print.uc_printf(NULL, "No response from host\n");
    return 1;
  }

  if (wait_rc < 0) {
    if (errno == EINTR) {
      return 0;
    }
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed while waiting for server response\n");
    }
    return 0;
  }

  if (!lib.net.udp.recv(udp_fd, received, sizeof(received), &peer, &received_len)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to receive server response datagram\n");
    }
    return 0;
  }

  reply_len = received_len;

  if (opts->encrypt) {
    int decrypt_rc = 0;
    size_t decrypted_len = sizeof(decrypted);

    if (!app_transmit_ensure_response_private_key(opts, session)) {
      return 0;
    }

    decrypt_rc = lib.openssl.session_decrypt(session,
                                             received, received_len,
                                             decrypted, &decrypted_len);
    if (decrypt_rc != SL_SSL_DECRYPT_OK) {
      if (lib.log.emit) {
        lib.log.emit(LOG_ERROR, 1, "Failed to decrypt server response: %s\n",
                     lib.openssl.session_decrypt_strerror(decrypt_rc));
      }
      return 0;
    }

    reply_buf = decrypted;
    reply_len = decrypted_len;
  }

  if (shared.knock.codec.v2.deserialize(reply_buf, reply_len, &reply_pkt) != SL_PAYLOAD_OK) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to deserialize server response packet\n");
    }
    return 0;
  }

  if (reply_pkt.inner.action_id != SL_KNOCK_RESPONSE_ACTION_ID) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received non-response packet on reply channel (action=%u)\n",
                   (unsigned int)reply_pkt.inner.action_id);
    }
    return 0;
  }

  if (reply_pkt.inner.user_id != request_pkt->inner.user_id) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response for unexpected user_id=%u\n",
                   (unsigned int)reply_pkt.inner.user_id);
    }
    return 0;
  }

  if (reply_pkt.inner.challenge != request_pkt->inner.challenge) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response for unexpected challenge=%u\n",
                   (unsigned int)reply_pkt.inner.challenge);
    }
    return 0;
  }

  if (reply_pkt.inner.payload_len < SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received malformed response payload\n");
    }
    return 0;
  }

  if (reply_pkt.payload[1] != request_pkt->inner.action_id) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response for unexpected request action=%u\n",
                   (unsigned int)reply_pkt.payload[1]);
    }
    return 0;
  }

  if (!app_transmit_v2_response_validate_signature(opts, session, &reply_pkt)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Response signature validation failed\n");
    }
    return 0;
  }

  LOGI("Received response on %s (%d)\n",
       app_transmit_protocol_name(opts->protocol),
       (int)opts->protocol);
  return app_transmit_v2_response_print(&reply_pkt, out_status);
}

static int app_transmit_single_packet_v2(const Opts *opts) {
  int status = 1;
  int response_status = 0;
  int udp_fd = -1;
  SiglatchOpenSSLSession session = {0};
  Opts runtime_opts = {0};
  const Opts *effective = NULL;

  if (!opts) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Transmit requested with NULL opts\n");
    }
    return status;
  }

  runtime_opts = *opts;
  effective = &runtime_opts;

  do {
    SharedKnockCodecV2Form1Packet pkt = {0};

    if (!app_transmit_resolve_payload(&runtime_opts)) {
      FAIL_SINGLE_PACKET("Failed to resolve payload input\n");
    }

    if (!app_transmit_v2_structure_packet(&pkt,
                                          effective->payload,
                                          effective->payload_len,
                                          (uint16_t)effective->user_id,
                                          (uint8_t)effective->action_id)) {
      FAIL_SINGLE_PACKET("Failed to structure v2 packet\n");
    }

    if (!init_user_openssl_session(effective, &session)) {
      FAIL_SINGLE_PACKET("Failed to initialize OpenSSL session\n");
    }

    if (!app_transmit_v2_sign_wrapper(effective, &session, &pkt)) {
      FAIL_SINGLE_PACKET("Failed to sign v2 packet\n");
    }

    uint8_t packed[SHARED_KNOCK_CODEC_V2_FORM1_PACKET_SIZE] = {0};
    int packed_len = 0;
    if (!app_transmit_v2_structure_or_dead_drop(effective, &pkt, packed, &packed_len)) {
      FAIL_SINGLE_PACKET("Failed to prepare v2 payload (structured or dead-drop)\n");
    }

    unsigned char data[512] = {0};
    size_t data_len = 0;

    if (!encryptWrapper(effective, &session, packed, (size_t)packed_len, data, &data_len)) {
      FAIL_SINGLE_PACKET("Failed to prepare v2 payload (encryption or raw mode)\n");
    }

    char ip[INET6_ADDRSTRLEN];
    int rv = lib.net.addr.resolve_host_to_ip(effective->host, ip, sizeof(ip));

    switch (rv) {
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

    LOGI("Sending request on %s (%d)\n",
         app_transmit_protocol_name(effective->protocol),
         (int)effective->protocol);

    if (!lib.net.udp.send(udp_fd, ip, effective->port, data, data_len)) {
      FAIL_SINGLE_PACKET("Failed to send UDP packet\n");
    }

    if (effective->dead_drop) {
      status = 0;
      break;
    }

    if (!app_transmit_wait_for_response_v2(udp_fd, effective, &pkt, &session, &response_status)) {
      break;
    }

    status = response_status;
  } while (0);

  if (udp_fd >= 0) {
    lib.net.udp.close(udp_fd);
  }

  lib.openssl.session_free(&session);
  return status;
}

static uint16_t app_transmit_peer_port(const struct sockaddr_storage *peer) {
  if (!peer) {
    return 0;
  }

  if (peer->ss_family == AF_INET) {
    const struct sockaddr_in *addr = (const struct sockaddr_in *)peer;
    return ntohs(addr->sin_port);
  }

  if (peer->ss_family == AF_INET6) {
    const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)peer;
    return ntohs(addr->sin6_port);
  }

  return 0;
}

static int app_transmit_v3_structure_packet(SharedKnockNormalizedUnit *normal,
                                            const uint8_t *payload,
                                            size_t len,
                                            uint16_t user_id,
                                            uint8_t action_id) {
  uint8_t digest[32] = {0};

  if (!normal || !payload) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "structurePacketV3: Invalid input\n");
    }
    return 0;
  }

  memset(normal, 0, sizeof(*normal));

  normal->complete = 1;
  normal->wire_version = SHARED_KNOCK_CODEC_V3_WIRE_VERSION;
  normal->wire_form = SHARED_KNOCK_CODEC_FORM1_ID;
  normal->timestamp = (uint32_t)lib.time.unix_ts();
  normal->user_id = user_id;
  normal->action_id = action_id;
  normal->challenge = lib.random.challenge();
  normal->fragment_count = 1;
  normal->wire_decode = 1;
  normal->wire_auth = 0;
  normal->encrypted = 1;

  if (len > sizeof(normal->payload)) {
    len = sizeof(normal->payload);
  }

  memcpy(normal->payload, payload, len);
  normal->payload_len = len;

  if (!shared_knock_digest_generate_v3_form1(normal, digest)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to generate v3 digest\n");
    }
    return 0;
  }

  dumpDigest("Client-computed Digest", digest, sizeof(digest));
  return 1;
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

static int app_transmit_v3_response_print(const SharedKnockNormalizedUnit *reply,
                                          int *out_status) {
  if (!reply) {
    return 0;
  }

  return app_transmit_response_print_payload(reply->payload, reply->payload_len, out_status);
}

static int app_transmit_v3_codec_prepare(SiglatchOpenSSLSession *session,
                                         SharedKnockCodecContext **out_context,
                                         SharedKnockCodecV3State **out_state) {
  SharedKnockCodecContext *codec_context = NULL;
  SharedKnockCodecV3State *codec_state = NULL;

  if (!session || !out_context || !out_state) {
    return 0;
  }

  if (!shared.knock.codec.context.init()) {
    return 0;
  }

  if (!shared.knock.codec.context.create(&codec_context)) {
    shared.knock.codec.context.shutdown();
    return 0;
  }

  if (!shared.knock.codec.context.set_openssl_session(codec_context, session)) {
    shared.knock.codec.context.destroy(codec_context);
    shared.knock.codec.context.shutdown();
    return 0;
  }

  if (!shared.knock.codec.v3.init(codec_context)) {
    shared.knock.codec.context.clear_openssl_session(codec_context);
    shared.knock.codec.context.destroy(codec_context);
    shared.knock.codec.context.shutdown();
    return 0;
  }

  if (!shared.knock.codec.v3.create_state(&codec_state)) {
    shared.knock.codec.v3.shutdown();
    shared.knock.codec.context.clear_openssl_session(codec_context);
    shared.knock.codec.context.destroy(codec_context);
    shared.knock.codec.context.shutdown();
    return 0;
  }

  *out_context = codec_context;
  *out_state = codec_state;
  return 1;
}

static void app_transmit_v3_codec_release(SharedKnockCodecContext *codec_context,
                                          SharedKnockCodecV3State *codec_state) {
  if (codec_state) {
    shared.knock.codec.v3.destroy_state(codec_state);
  }

  shared.knock.codec.v3.shutdown();

  if (codec_context) {
    shared.knock.codec.context.clear_openssl_session(codec_context);
    shared.knock.codec.context.destroy(codec_context);
  }

  shared.knock.codec.context.shutdown();
}

static int app_transmit_wait_for_response_v3(int udp_fd,
                                             const Opts *opts,
                                             const SharedKnockNormalizedUnit *request,
                                             const SharedKnockCodecV3State *codec_state,
                                             SiglatchOpenSSLSession *session,
                                             int *out_status) {
  uint8_t received[KNOCKER_RESPONSE_BUFFER_SIZE] = {0};
  const uint8_t *reply_buf = received;
  size_t received_len = 0;
  size_t reply_len = 0;
  struct sockaddr_storage peer = {0};
  SharedKnockNormalizedUnit reply = {0};
  int wait_rc = 0;
  char peer_ip[INET6_ADDRSTRLEN] = {0};
  uint16_t peer_port = 0;

  if (!opts || !request || !codec_state || !session || !out_status) {
    return 0;
  }

  *out_status = 0;

  wait_rc = lib.net.socket.wait_readable(udp_fd, KNOCKER_RESPONSE_TIMEOUT_MS);
  if (wait_rc == 0) {
    lib.print.uc_printf(NULL, "No response from host\n");
    return 1;
  }

  if (wait_rc < 0) {
    if (errno == EINTR) {
      return 0;
    }
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed while waiting for server response\n");
    }
    return 0;
  }

  if (!lib.net.udp.recv(udp_fd, received, sizeof(received), &peer, &received_len)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to receive server response datagram\n");
    }
    return 0;
  }

  reply_len = received_len;
  if (!lib.net.addr.sock_to_ip(&peer, peer_ip, sizeof(peer_ip))) {
    peer_ip[0] = '\0';
  }
  peer_port = app_transmit_peer_port(&peer);

  if (!app_transmit_ensure_response_private_key(opts, session)) {
    return 0;
  }

  if (!shared.knock.codec.v3.decode(codec_state,
                                     reply_buf,
                                     reply_len,
                                     peer_ip[0] ? peer_ip : NULL,
                                     peer_port,
                                     1,
                                     &reply)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Failed to decode server response packet\n");
    }
    return 0;
  }

  if (!shared.knock.codec.v3.wire_auth(codec_state,
                                        reply_buf,
                                        reply_len,
                                        peer_ip[0] ? peer_ip : NULL,
                                        peer_port,
                                        1,
                                        &reply)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Response wire auth failed\n");
    }
    return 0;
  }

  if (reply.action_id != SL_KNOCK_RESPONSE_ACTION_ID) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received non-response packet on reply channel (action=%u)\n",
                   (unsigned int)reply.action_id);
    }
    return 0;
  }

  if (reply.user_id != request->user_id) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response for unexpected user_id=%u\n",
                   (unsigned int)reply.user_id);
    }
    return 0;
  }

  if (reply.challenge != request->challenge) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response for unexpected challenge=%u\n",
                   (unsigned int)reply.challenge);
    }
    return 0;
  }

  if (reply.payload_len < SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received malformed response payload\n");
    }
    return 0;
  }

  if (reply.payload[1] != request->action_id) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response for unexpected request action=%u\n",
                   (unsigned int)reply.payload[1]);
    }
    return 0;
  }

  if (!app_transmit_v3_response_validate_signature(opts, session, &reply)) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Response signature validation failed\n");
    }
    return 0;
  }

  LOGI("Received response on %s (%d)\n",
       app_transmit_protocol_name(opts->protocol),
       (int)opts->protocol);
  return app_transmit_v3_response_print(&reply, out_status);
}

static int app_transmit_single_packet_v3(const Opts *opts) {
  int status = 1;
  int response_status = 0;
  int udp_fd = -1;
  SiglatchOpenSSLSession session = {0};
  SharedKnockCodecContext *codec_context = NULL;
  SharedKnockCodecV3State *codec_state = NULL;
  Opts runtime_opts = {0};
  const Opts *effective = NULL;

  if (!opts) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Transmit requested with NULL opts\n");
    }
    return status;
  }

  runtime_opts = *opts;
  effective = &runtime_opts;

  do {
    SharedKnockNormalizedUnit request = {0};
    uint8_t encoded[SHARED_KNOCK_CODEC_PACKET_MAX_SIZE] = {0};
    size_t encoded_len = sizeof(encoded);

    if (!app_transmit_resolve_payload(&runtime_opts)) {
      FAIL_SINGLE_PACKET("Failed to resolve payload input\n");
    }

    if (!app_transmit_v3_structure_packet(&request,
                                          effective->payload,
                                          effective->payload_len,
                                          (uint16_t)effective->user_id,
                                          (uint8_t)effective->action_id)) {
      FAIL_SINGLE_PACKET("Failed to structure v3 packet\n");
    }

    if (!init_user_openssl_session(effective, &session)) {
      FAIL_SINGLE_PACKET("Failed to initialize OpenSSL session\n");
    }

    if (!app_transmit_v3_codec_prepare(&session, &codec_context, &codec_state)) {
      FAIL_SINGLE_PACKET("Failed to prepare codec.v3 state\n");
    }

    if (!shared.knock.codec.v3.encode(codec_state, &request, encoded, &encoded_len)) {
      FAIL_SINGLE_PACKET("Failed to encode v3 packet\n");
    }
    if (lib.log.emit) {
      lib.log.emit(LOG_INFO, 1, "v3 encoded packet length: %zu\n", encoded_len);
    }

    char ip[INET6_ADDRSTRLEN];
    int rv = lib.net.addr.resolve_host_to_ip(effective->host, ip, sizeof(ip));

    switch (rv) {
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

    LOGI("Sending request on %s (%d)\n",
         app_transmit_protocol_name(effective->protocol),
         (int)effective->protocol);

    if (!lib.net.udp.send(udp_fd, ip, effective->port, encoded, encoded_len)) {
      if (lib.log.emit) {
        lib.log.emit(LOG_ERROR, 1,
                     "Failed to send UDP packet to %s:%u (%zu bytes, errno=%d)\n",
                     ip,
                     (unsigned int)effective->port,
                     encoded_len,
                     errno);
      }
      FAIL_SINGLE_PACKET("Failed to send UDP packet\n");
    }

    if (!app_transmit_wait_for_response_v3(udp_fd,
                                           effective,
                                           &request,
                                           codec_state,
                                           &session,
                                           &response_status)) {
      break;
    }

    status = response_status;
  } while (0);

  if (udp_fd >= 0) {
    lib.net.udp.close(udp_fd);
  }

  app_transmit_v3_codec_release(codec_context, codec_state);
  lib.openssl.session_free(&session);
  return status;
}

static int app_transmit_single_packet(const Opts *opts) {
  int status = 1;
  int response_status = 0;
  int udp_fd = -1;
  SiglatchOpenSSLSession session = {0};
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

  if (effective->protocol == KNOCK_PROTOCOL_V3) {
    return app_transmit_single_packet_v3(effective);
  }

  if (effective->protocol == KNOCK_PROTOCOL_V2) {
    return app_transmit_single_packet_v2(effective);
  }

  do {
    KnockPacket pkt = {0};
    if (!app_transmit_resolve_payload(&runtime_opts)) {
      FAIL_SINGLE_PACKET("Failed to resolve payload input\n");
    }

    if (!structurePacket(&pkt, effective->payload, effective->payload_len,
                         effective->user_id, effective->action_id)) {
      FAIL_SINGLE_PACKET("Failed to structure packet\n");
    }

    if (!init_user_openssl_session(effective, &session)) {
      FAIL_SINGLE_PACKET("Failed to initialize OpenSSL session\n");
    }

    if (!signWrapper(effective, &session, &pkt)) {
      FAIL_SINGLE_PACKET("Failed to sign packet\n");
    }

    uint8_t packed[512] = {0};
    int packed_len = shared.knock.codec.v1.pack(&pkt, packed, sizeof(packed));
    if (!structureOrDeadDrop(effective, &pkt, packed, &packed_len)) {
      FAIL_SINGLE_PACKET("Failed to prepare payload (structured or dead-drop)\n");
    }

    unsigned char data[512] = {0};
    size_t data_len = 0;

    if (!encryptWrapper(effective, &session, packed, packed_len, data, &data_len)) {
      FAIL_SINGLE_PACKET("Failed to prepare payload (encryption or raw mode)\n");
    }
    char ip[INET6_ADDRSTRLEN];
    int rv = lib.net.addr.resolve_host_to_ip(effective->host, ip, sizeof(ip));

    switch (rv) {
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

    LOGI("Sending request on %s (%d)\n",
         app_transmit_protocol_name(effective->protocol),
         (int)effective->protocol);

    if (!lib.net.udp.send(udp_fd, ip, effective->port, data, data_len)) {
      FAIL_SINGLE_PACKET("Failed to send UDP packet\n");
    }

    if (effective->dead_drop) {
      status = 0;
      break;
    }

    if (!app_transmit_wait_for_response(udp_fd, effective, &pkt, &session, &response_status)) {
      break;
    }

    status = response_status;
  } while (0);

  if (udp_fd >= 0) {
    lib.net.udp.close(udp_fd);
  }

  lib.openssl.session_free(&session);
  return status;
}

static const AppTransmitLib app_transmit_instance = {
  .init = app_transmit_init,
  .shutdown = app_transmit_shutdown,
  .singlePacket = app_transmit_single_packet
};

const AppTransmitLib *get_app_transmit_lib(void) {
  return &app_transmit_instance;
}
