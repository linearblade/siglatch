/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "net.h"

#include <stdio.h>
#include <string.h>

static int net_wire_children(void);
static int net_init(void);
static void net_shutdown(void);

static NetLib g_net = {
  .init = net_init,
  .shutdown = net_shutdown,
  .addr = {0},
  .socket = {0},
  .udp = {0}
};

static int g_net_initialized = 0;
static int g_net_wired = 0;

static int net_wire_children(void)
{
  const NetAddrLib *addr = NULL;
  const NetIpLib *ip = NULL;
  const SocketLib *socket = NULL;
  const UdpLib *udp = NULL;

  if (g_net_wired) {
    return 1;
  }

  addr = get_lib_net_addr();
  ip = get_lib_net_ip();
  socket = get_lib_socket();
  udp = get_lib_udp();

  if (!addr || !ip || !socket || !udp) {
    fprintf(stderr, "Failed to wire stdlib.net barrel: child provider unavailable\n");
    return 0;
  }

  g_net.addr = *addr;
  g_net.ip = *ip;
  g_net.socket = *socket;
  g_net.udp = *udp;

  if (!g_net.addr.init || !g_net.addr.shutdown ||
      !g_net.ip.init || !g_net.ip.shutdown ||
      !g_net.socket.init || !g_net.socket.shutdown ||
      !g_net.udp.init || !g_net.udp.shutdown || !g_net.udp.set_context) {
    fprintf(stderr, "Failed to wire stdlib.net barrel: incomplete child wiring\n");
    memset(&g_net.addr, 0, sizeof(g_net.addr));
    memset(&g_net.ip, 0, sizeof(g_net.ip));
    memset(&g_net.socket, 0, sizeof(g_net.socket));
    memset(&g_net.udp, 0, sizeof(g_net.udp));
    return 0;
  }

  g_net_wired = 1;
  return 1;
}

static int net_init(void)
{
  UdpContext udp_ctx = {0};
  int addr_initialized = 0;
  int ip_initialized = 0;
  int socket_initialized = 0;

  if (g_net_initialized) {
    return 1;
  }

  if (!net_wire_children()) {
    return 0;
  }

  g_net.addr.init();
  addr_initialized = 1;

  if (!g_net.ip.init()) {
    fprintf(stderr, "Failed to initialize stdlib.net.ip\n");
    if (addr_initialized) {
      g_net.addr.shutdown();
    }
    return 0;
  }
  ip_initialized = 1;

  g_net.socket.init();
  socket_initialized = 1;

  udp_ctx.socket = &g_net.socket;
  udp_ctx.addr = &g_net.addr;

  if (!g_net.udp.init(&udp_ctx)) {
    fprintf(stderr, "Failed to initialize stdlib.net.udp\n");
    if (socket_initialized) {
      g_net.socket.shutdown();
    }
    if (ip_initialized) {
      g_net.ip.shutdown();
    }
    if (addr_initialized) {
      g_net.addr.shutdown();
    }
    return 0;
  }

  g_net_initialized = 1;
  return 1;
}

static void net_shutdown(void)
{
  if (!g_net_initialized) {
    return;
  }

  g_net.udp.shutdown();
  g_net.socket.shutdown();
  g_net.ip.shutdown();
  g_net.addr.shutdown();
  g_net_initialized = 0;
}

const NetLib *get_lib_net(void)
{
  if (!net_wire_children()) {
    return NULL;
  }

  return &g_net;
}
