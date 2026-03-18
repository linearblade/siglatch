/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "ip.h"

#include <stdio.h>
#include <string.h>

static int net_ip_wire_children(void);
static int net_ip_init(void);
static void net_ip_shutdown(void);

static NetIpLib g_net_ip = {
  .init = net_ip_init,
  .shutdown = net_ip_shutdown,
  .range = {0}
};

static int g_net_ip_initialized = 0;
static int g_net_ip_wired = 0;

static int net_ip_wire_children(void) {
  const NetIpRangeLib *range = NULL;

  if (g_net_ip_wired) {
    return 1;
  }

  range = get_lib_net_ip_range();
  if (!range) {
    fprintf(stderr, "Failed to wire stdlib.net.ip barrel: range provider unavailable\n");
    return 0;
  }

  g_net_ip.range = *range;

  if (!g_net_ip.range.init || !g_net_ip.range.shutdown ||
      !g_net_ip.range.is_single_ipv4 || !g_net_ip.range.is_cidr_ipv4 ||
      !g_net_ip.range.contains_cidr_ipv4 || !g_net_ip.range.contains_spec_ipv4 ||
      !g_net_ip.range.contains_any_ipv4) {
    fprintf(stderr, "Failed to wire stdlib.net.ip barrel: incomplete child wiring\n");
    memset(&g_net_ip.range, 0, sizeof(g_net_ip.range));
    return 0;
  }

  g_net_ip_wired = 1;
  return 1;
}

static int net_ip_init(void) {
  if (g_net_ip_initialized) {
    return 1;
  }

  if (!net_ip_wire_children()) {
    return 0;
  }

  g_net_ip.range.init();
  g_net_ip_initialized = 1;
  return 1;
}

static void net_ip_shutdown(void) {
  if (!g_net_ip_initialized) {
    return;
  }

  g_net_ip.range.shutdown();
  g_net_ip_initialized = 0;
}

const NetIpLib *get_lib_net_ip(void) {
  if (!net_ip_wire_children()) {
    return NULL;
  }

  return &g_net_ip;
}
