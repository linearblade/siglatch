/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_NET_IP_H
#define SIGLATCH_NET_IP_H

#include "range/range.h"

/**
 * @file ip.h
 * @brief IP-family barrel for the stdlib net tree.
 *
 * This module groups IP-layer helper families under a single namespace so the
 * net subtree can grow cleanly over time.
 *
 * Current children:
 *   - range
 *
 * Expected future children:
 *   - parse
 *   - packet
 */

typedef struct {
  /**
   * @brief Initialize the IP helper family.
   *
   * Initializes all IP-family child modules.
   *
   * @return 1 on success, 0 on failure
   */
  int (*init)(void);

  /**
   * @brief Shutdown the IP helper family in reverse dependency order.
   */
  void (*shutdown)(void);

  NetIpRangeLib range;
} NetIpLib;

const NetIpLib *get_lib_net_ip(void);

#endif /* SIGLATCH_NET_IP_H */
