/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_NET_IP_RANGE_H
#define SIGLATCH_NET_IP_RANGE_H

#include <stdint.h>

/**
 * @file range.h
 * @brief IP range helper surface.
 *
 * This module provides policy-oriented IPv4 helpers for:
 *
 *   - validating single IPv4 literals
 *   - validating IPv4 CIDR expressions
 *   - checking whether an IPv4 literal falls inside a CIDR
 *   - checking whether an IPv4 literal matches either a single IP or CIDR
 *   - evaluating comma-separated IPv4 allowlist expressions
 */

typedef struct {
  /**
   * @brief Initialize IP range helper state.
   *
   * Currently a no-op kept for lifecycle consistency.
   */
  void (*init)(void);

  /**
   * @brief Shutdown IP range helper state.
   *
   * Currently a no-op kept for lifecycle consistency.
   */
  void (*shutdown)(void);

  /**
   * @brief Check whether a string is a valid IPv4 literal.
   *
   * Bare IPv4 only. CIDR expressions are rejected.
   *
   * @param spec Input string
   * @return 1 if valid, 0 otherwise
   */
  int (*is_single_ipv4)(const char *spec);

  /**
   * @brief Check whether a string is a valid IPv4 CIDR expression.
   *
   * Example valid inputs:
   *   - `127.0.0.1/32`
   *   - `10.0.0.0/8`
   *
   * @param spec Input string
   * @return 1 if valid, 0 otherwise
   */
  int (*is_cidr_ipv4)(const char *spec);

  /**
   * @brief Check whether an IPv4 literal falls inside a CIDR.
   *
   * @param cidr IPv4 CIDR expression
   * @param ip   IPv4 literal to test
   * @return 1 if contained, 0 otherwise
   */
  int (*contains_cidr_ipv4)(const char *cidr, const char *ip);

  /**
   * @brief Check whether an IPv4 literal matches a single-IP or CIDR spec.
   *
   * Accepted spec forms:
   *   - `127.0.0.1`
   *   - `127.0.0.1/32`
   *   - `10.0.0.0/8`
   *
   * @param spec Single IPv4 literal or CIDR expression
   * @param ip   IPv4 literal to test
   * @return 1 if matched, 0 otherwise
   */
  int (*contains_spec_ipv4)(const char *spec, const char *ip);

  /**
   * @brief Check whether an IPv4 literal matches any spec in a CSV list.
   *
   * Example:
   *   - `127.0.0.1,10.0.0.0/8,192.168.1.0/24`
   *
   * Empty list entries are ignored.
   *
   * @param spec_list Comma-separated IPv4/CIDR specs
   * @param ip        IPv4 literal to test
   * @return 1 if any spec matches, 0 otherwise
   */
  int (*contains_any_ipv4)(const char *spec_list, const char *ip);
} NetIpRangeLib;

const NetIpRangeLib *get_lib_net_ip_range(void);

#endif /* SIGLATCH_NET_IP_RANGE_H */
