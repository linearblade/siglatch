/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "inbound.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../lib.h"

#define SL_EXIT_ERR_NETWORK_FATAL 3

static int app_inbound_init(void) {
  return app_inbound_crypto_init();
}

static void app_inbound_shutdown(void) {
  app_inbound_crypto_shutdown();
}

static ssize_t app_inbound_receive_valid_data(
    AppRuntimeListenerState *listener,
    char *buffer,
    size_t bufsize,
    struct sockaddr_in *client,
    char *ip_out,
    int ip_len) {
  socklen_t len = sizeof(*client);
  ssize_t n = -1;
  const char *timestr = lib.time.human(0);
  int rv = 0;

  if (!listener) {
    return -1;
  }

  n = recvfrom(listener->sock, buffer, bufsize - 1, 0, (struct sockaddr *)client, &len);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return -1;
    }
    LOGPERR("recvfrom failed");
    LOGE("[%s] recvfrom error (client maybe unreachable)\n", timestr);
    return -1;
  }

  rv = lib.net.addr.sock_to_ipv4(client, ip_out, ip_len);
  switch (rv) {
  case 1:
    break;
  case -2:
    LOGE("FATAL: ip_out was NULL in receiveValidData() - cannot record client address");
    exit(SL_EXIT_ERR_NETWORK_FATAL);
    break;
  case -1:
    LOGE("FATAL: client was NULL in receiveValidData() - cannot record client address");
    exit(SL_EXIT_ERR_NETWORK_FATAL);
    break;
  default:
    LOGPERR("inet_ntop");
    return -1;
  }

  if ((size_t)n >= bufsize) {
    LOGE("Dropping oversized packet (%zd bytes)\n", n);
    return -1;
  }

  if (++listener->packet_count % 100 == 0) {
    LOGD("[%s] Processed %lu candidate packets so far\n", timestr, listener->packet_count);
  }

  return n;
}

static int app_inbound_normalize_payload(
    SiglatchOpenSSLSession *session,
    const uint8_t *input,
    size_t input_len,
    uint8_t *normalized_out,
    size_t *normalized_len) {
  int rc = 0;
  const char *msg = NULL;

  if (!session || !input || !normalized_out || !normalized_len) {
    return 0;
  }

  LOGT("Attempting to decrypt incoming packet...\n");

  rc = lib.openssl.session_decrypt(
      session,
      input,
      input_len,
      normalized_out,
      normalized_len);

  if (rc == SL_SSL_DECRYPT_OK) {
    return 1;
  }

  msg = lib.openssl.session_decrypt_strerror
            ? lib.openssl.session_decrypt_strerror(rc)
            : "Unknown decrypt error";

  LOGE("[decrypt] Decryption failed (rc=%d): %s\n", rc, msg);
  return 0;
}

static const AppInboundLib app_inbound_instance = {
  .init = app_inbound_init,
  .shutdown = app_inbound_shutdown,
  .receive_valid_data = app_inbound_receive_valid_data,
  .normalize_payload = app_inbound_normalize_payload,
  .crypto = {
    .init = app_inbound_crypto_init,
    .shutdown = app_inbound_crypto_shutdown,
    .init_session_for_server = app_inbound_crypto_init_session_for_server,
    .assign_session_to_user = app_inbound_crypto_assign_session_to_user,
    .validate_signature = app_inbound_crypto_validate_signature
  }
};

const AppInboundLib *get_app_inbound_lib(void) {
  return &app_inbound_instance;
}
