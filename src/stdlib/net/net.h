/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_NET_BARREL_H
#define SIGLATCH_NET_BARREL_H

#include "addr/addr.h"
#include "ip/ip.h"
#include "socket/socket.h"
#include "udp/udp.h"

/**
 * @file net.h
 * @brief Barrel for the future stdlib net tree.
 *
 * This module does not provide standalone network helpers of its own.
 * It exists to assemble the net subtree into one fully wired object:
 *
 *   - addr
 *   - ip
 *   - socket
 *   - udp
 *
 * The intended long-term use is to install this object into `lib.net` once
 * the subtree fully replaces the older top-level `src/stdlib/net.c` surface.
 */

typedef struct {
  /**
   * @brief Initialize the net subtree and wire child dependencies.
   *
   * This initializes `addr` and `socket`, then initializes `udp` with a
   * context built from those child libs.
   *
   * @return 1 on success, 0 on failure
   */
  int (*init)(void);

  /**
   * @brief Shutdown the net subtree in reverse dependency order.
   */
  void (*shutdown)(void);

  NetAddrLib addr;
  NetIpLib ip;
  SocketLib socket;
  UdpLib udp;
} NetLib;

/**
 * @brief Access the future net barrel.
 *
 * This is not wired into the active runtime yet. It exists so the new
 * subtree can be stabilized independently before replacing the older
 * top-level `stdlib/net.c` surface.
 *
 * @return Pointer to the assembled net barrel, or NULL on wiring failure
 */
const NetLib *get_lib_net(void);

#endif /* SIGLATCH_NET_BARREL_H */
