/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "transmit.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include "../../../shared/shared.h"
#include "../../../shared/knock/response.h"
#include "../../lib.h"
#include "helper.h"

#define KNOCKER_RESPONSE_TIMEOUT_MS 1500
#define KNOCKER_RESPONSE_BUFFER_SIZE 512

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

static int app_transmit_response_print(const KnockPacket *reply_pkt, int *out_status) {
  const uint8_t *payload = NULL;
  const char *status_name = "UNKNOWN";
  char text[sizeof(reply_pkt->payload)] = {0};
  uint8_t status = 0;
  uint8_t flags = 0;
  size_t text_len = 0;

  if (!reply_pkt || !out_status) {
    return 0;
  }

  if (reply_pkt->payload_len < SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Received response packet with short payload (%u bytes)\n",
                   (unsigned int)reply_pkt->payload_len);
    }
    return 0;
  }

  payload = reply_pkt->payload;
  status = payload[0];
  flags = payload[2];
  text_len = reply_pkt->payload_len - SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE;

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

  if (shared.knock.codec.deserialize(reply_buf, reply_len, &reply_pkt) != SL_PAYLOAD_OK) {
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
    int packed_len = shared.knock.codec.pack(&pkt, packed, sizeof(packed));
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
