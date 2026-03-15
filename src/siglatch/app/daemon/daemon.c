/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "daemon.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "../app.h"
#include "../../lib.h"

#define APP_DAEMON_BUFFER_SIZE 1024

static int app_daemon_init(void) {
  return 1;
}

static void app_daemon_shutdown(void) {
}

static void app_daemon_run(AppRuntimeListenerState *listener) {
  char buffer[APP_DAEMON_BUFFER_SIZE];
  char ip[INET_ADDRSTRLEN];
  struct sockaddr_in client;
  SiglatchOpenSSLSession session = {0};
  const siglatch_server *server_conf = NULL;
  int is_encrypted = 0;

  if (!listener) {
    LOGE("No listener state provided; refusing to start daemon loop\n");
    return;
  }

  server_conf = listener->server;
  if (!server_conf) {
    LOGE("No current server selected; refusing to start daemon loop\n");
    return;
  }

  if (!app.inbound.crypto.init_session_for_server(server_conf, &session)) {
    LOGE("Failed to initialize OpenSSL session for server\n");
    return;
  }

  is_encrypted = server_conf->secure;

  while (!app.signal.should_exit(listener->process)) {
    uint8_t normalized_buffer[512] = {0};
    size_t normalized_len = 0;
    ssize_t n = app.inbound.receive_valid_data(
        listener, buffer, sizeof(buffer), &client, ip, sizeof(ip));

    if (n <= 0) {
      continue;
    }

    lib.log.console("RECEIVED SOMETHING\n");
    LOGT("%zd bytes from %s\n", n, ip);

    if (is_encrypted) {
      if (!app.inbound.normalize_payload(
              &session,
              (const uint8_t *)buffer,
              (size_t)n,
              normalized_buffer,
              &normalized_len)) {
        continue;
      }
    } else {
      size_t copy_len = ((size_t)n < sizeof(normalized_buffer))
                            ? (size_t)n
                            : sizeof(normalized_buffer);
      memcpy(normalized_buffer, buffer, copy_len);
      normalized_len = copy_len;
    }

    app.packet.consume_normalized(
        listener,
        normalized_buffer,
        normalized_len,
        &session,
        ip,
        is_encrypted);
  }
}

static const AppDaemonLib app_daemon_instance = {
  .init = app_daemon_init,
  .shutdown = app_daemon_shutdown,
  .run = app_daemon_run
};

const AppDaemonLib *get_app_daemon_lib(void) {
  return &app_daemon_instance;
}
