/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "transmit.h"

#include <arpa/inet.h>
#include <stdint.h>

#include "../lib.h"
#include "../main_helpers.h"

#define FAIL_SINGLE_PACKET(...)                                                \
  if (1) {                                                                     \
    if (lib.log.emit) {                                                        \
      lib.log.emit(LOG_ERROR, 1, __VA_ARGS__);                                 \
    }                                                                          \
    break;                                                                     \
  }

static int app_transmit_init(void) {
  return 1;
}

static void app_transmit_shutdown(void) {
}

static int app_transmit_single_packet(const Opts *opts) {
  int status = 1;
  SiglatchOpenSSLSession session = {0};

  if (!opts) {
    if (lib.log.emit) {
      lib.log.emit(LOG_ERROR, 1, "Transmit requested with NULL opts");
    }
    return status;
  }

  do {
    KnockPacket pkt = {0};
    if (!structurePacket(&pkt, opts->payload, opts->payload_len, opts->user_id, opts->action_id)) {
      FAIL_SINGLE_PACKET("Failed to structure packet");
    }

    if (!init_user_openssl_session(opts, &session)) {
      FAIL_SINGLE_PACKET("Failed to initialize OpenSSL session\n");
    }

    if (!signWrapper(opts, &session, &pkt)) {
      FAIL_SINGLE_PACKET("Failed to sign packet\n");
    }

    uint8_t packed[512] = {0};
    int packed_len = lib.payload.pack(&pkt, packed, sizeof(packed));
    if (!structureOrDeadDrop(opts, &pkt, packed, &packed_len)) {
      FAIL_SINGLE_PACKET("Failed to prepare payload (structured or dead-drop)");
    }

    unsigned char data[512] = {0};
    size_t data_len = 0;

    if (!encryptWrapper(opts, &session, packed, packed_len, data, &data_len)) {
      FAIL_SINGLE_PACKET("Failed to prepare payload (encryption or raw mode)");
    }

    char ip[INET_ADDRSTRLEN];
    int rv = lib.net.resolve_host_to_ip(opts->host, ip, sizeof(ip));

    switch (rv) {
      case 1:
        break;
      case -2:
        FAIL_SINGLE_PACKET("Hostname is NULL");
        break;
      case -3:
        FAIL_SINGLE_PACKET("Output buffer is NULL");
        break;
      default:
        FAIL_SINGLE_PACKET("Could not resolve hostname: %s", opts->host);
        break;
    }

    if (!lib.udp.send(ip, opts->port, data, data_len)) {
      FAIL_SINGLE_PACKET("Failed to send UDP packet\n");
    }

    status = 0;
  } while (0);

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
