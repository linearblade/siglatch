/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "udp.h"

#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "../app.h"
#include "../../lib.h"

#define APP_UDP_TIMEOUT_SEC 5

static int app_udp_open_bound_socket(const siglatch_server *server_conf,
                                     int *out_bound_port);
static const char *app_udp_effective_bind_ip(const siglatch_server *server_conf);
static int app_udp_same_binding(const AppRuntimeListenerState *listener,
                                const siglatch_server *server);
static int app_udp_probe_bind(const AppRuntimeListenerState *listener,
                              const siglatch_server *server);
static int app_udp_rebind_listener(AppRuntimeListenerState *listener,
                                   const siglatch_server *server);

static int app_udp_init(void) {
  return 1;
}

static void app_udp_shutdown(void) {
}

static const char *app_udp_effective_bind_ip(const siglatch_server *server_conf) {
  if (!server_conf || server_conf->bind_ip[0] == '\0') {
    return "";
  }

  return server_conf->bind_ip;
}

static int app_udp_same_binding(const AppRuntimeListenerState *listener,
                                const siglatch_server *server) {
  const char *current_ip = NULL;
  const char *target_ip = "";

  if (!listener || !server || listener->sock < 0) {
    return 0;
  }

  current_ip = listener->bound_ip;
  target_ip = app_udp_effective_bind_ip(server);

  return listener->bound_port == server->port &&
         strcmp(current_ip, target_ip) == 0;
}

static int app_udp_open_bound_socket(const siglatch_server *server_conf,
                                     int *out_bound_port) {
  int sock = -1;
  uint16_t bound_port = 0;
  const char *bind_ip = NULL;

  if (!server_conf) {
    LOGE("No server config provided; refusing to bind UDP listener\n");
    return -1;
  }

  bind_ip = (server_conf->bind_ip[0] != '\0')
                ? server_conf->bind_ip
                : NULL;

  sock = lib.net.udp.open_bound_ipv4(bind_ip,
                                     (uint16_t)server_conf->port,
                                     &bound_port);
  if (sock < 0) {
    LOGE("UDP bind failed for %s:%d\n",
         bind_ip ? bind_ip : "0.0.0.0",
         server_conf->port);
    return -1;
  }

  {
    struct timeval tv = {APP_UDP_TIMEOUT_SEC, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }

  if (out_bound_port) {
    *out_bound_port = (bound_port > 0)
                          ? (int)bound_port
                          : server_conf->port;
  }

  return sock;
}

static int app_udp_start_listener(AppRuntimeListenerState *listener) {
  int sock = -1;
  int bound_port = 0;
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

  sock = app_udp_open_bound_socket(server_conf, &bound_port);
  if (sock < 0) {
    return -1;
  }

  listener->sock = sock;
  listener->bound_port = bound_port;
  lib.str.lcpy(listener->bound_ip,
               app_udp_effective_bind_ip(server_conf),
               sizeof(listener->bound_ip));

  if (listener->bound_ip[0] != '\0') {
    LOGW("Daemon started on UDP %s:%d\n",
         listener->bound_ip,
         listener->bound_port);
  } else {
    LOGW("Daemon started on UDP port %d\n", listener->bound_port);
  }

  return sock;
}

static int app_udp_probe_bind(const AppRuntimeListenerState *listener,
                              const siglatch_server *server) {
  int probe_sock = -1;

  if (!listener || !server) {
    LOGE("[udp:probe_bind] Missing listener or server context\n");
    return 0;
  }

  /*
   * A probe against the currently active listener settings is already
   * satisfied by the live socket; opening a second socket on the same port
   * would fail against ourselves and would not tell us anything useful.
   */
  if (app_udp_same_binding(listener, server)) {
    return 1;
  }

  probe_sock = app_udp_open_bound_socket(server, NULL);
  if (probe_sock < 0) {
    return 0;
  }

  close(probe_sock);
  return 1;
}

static int app_udp_rebind_listener(AppRuntimeListenerState *listener,
                                   const siglatch_server *server) {
  int new_sock = -1;
  int old_sock = -1;
  int old_port = 0;
  char old_ip[MAX_IP_RANGE_LEN] = {0};
  int new_bound_port = 0;

  if (!listener || !server) {
    LOGE("[udp:rebind_listener] Missing listener or server context\n");
    return 0;
  }

  if (app_udp_same_binding(listener, server)) {
    return 1;
  }

  new_sock = app_udp_open_bound_socket(server, &new_bound_port);
  if (new_sock < 0) {
    return 0;
  }

  old_sock = listener->sock;
  old_port = listener->bound_port;
  lib.str.lcpy(old_ip, listener->bound_ip, sizeof(old_ip));
  listener->sock = new_sock;
  listener->bound_port = new_bound_port;
  lib.str.lcpy(listener->bound_ip,
               app_udp_effective_bind_ip(server),
               sizeof(listener->bound_ip));

  if (old_sock >= 0) {
    close(old_sock);
  }

  if (old_ip[0] != '\0' || listener->bound_ip[0] != '\0') {
    LOGW("Daemon rebound UDP %s:%d -> %s:%d\n",
         old_ip[0] != '\0' ? old_ip : "0.0.0.0",
         old_port,
         listener->bound_ip[0] != '\0' ? listener->bound_ip : "0.0.0.0",
         listener->bound_port);
  } else {
    LOGW("Daemon rebound UDP port %d -> %d\n", old_port, server->port);
  }
  return 1;
}

static const AppUdpLib app_udp_instance = {
  .init = app_udp_init,
  .shutdown = app_udp_shutdown,
  .start_listener = app_udp_start_listener,
  .probe_bind = app_udp_probe_bind,
  .rebind_listener = app_udp_rebind_listener
};

const AppUdpLib *get_app_udp_lib(void) {
  return &app_udp_instance;
}
