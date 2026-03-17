/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "transmit.h"

#include <arpa/inet.h>
#include <stdint.h>

#include "../../../shared/shared.h"
#include "../../lib.h"
#include "helper.h"

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

    udp_fd = lib.net.udp.open_auto(ip);
    if (udp_fd < 0) {
      FAIL_SINGLE_PACKET("Failed to open UDP socket for target %s\n", ip);
    }

    if (!lib.net.udp.send(udp_fd, ip, effective->port, data, data_len)) {
      FAIL_SINGLE_PACKET("Failed to send UDP packet\n");
    }

    status = 0;
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
