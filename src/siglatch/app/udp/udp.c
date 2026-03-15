/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "udp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "../app.h"
#include "../../lib.h"

#define APP_UDP_TIMEOUT_SEC 5

static int app_udp_init(void) {
  return 1;
}

static void app_udp_shutdown(void) {
}

static int app_udp_start_listener(AppRuntimeListenerState *listener) {
  int sock = -1;
  struct sockaddr_in server_addr;
  const siglatch_server *server_conf = NULL;

  if (!listener) {
    LOGE("No listener state provided; refusing to bind UDP listener\n");
    return -1;
  }

  server_conf = listener->server;

  if (!server_conf) {
    LOGE("No current server selected; refusing to bind UDP listener\n");
    return -1;
  }

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    LOGPERR("Socket creation failed");
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(server_conf->port);

  if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    LOGPERR("Bind failed");
    close(sock);
    return -1;
  }

  {
    struct timeval tv = {APP_UDP_TIMEOUT_SEC, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }

  LOGW("Daemon started on UDP port %d\n", server_conf->port);
  listener->sock = sock;
  return sock;
}

static const AppUdpLib app_udp_instance = {
  .init = app_udp_init,
  .shutdown = app_udp_shutdown,
  .start_listener = app_udp_start_listener
};

const AppUdpLib *get_app_udp_lib(void) {
  return &app_udp_instance;
}
