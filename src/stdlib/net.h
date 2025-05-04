/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_NET_H
#define SIGLATCH_NET_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/**
 * @file net.h
 * @brief Generic network base utilities (init, resolver, IP tools)
 *
 * This library provides non-protocol-specific tools such as DNS resolution,
 * IP string formatting, and lifecycle setup. It is designed to be used by
 * higher-level protocols like UDP, TCP, or secure transports.
 *
 * Usage:
 *   1. Place net.c and net.h in your stdlib directory
 *   2. Include net.h where needed
 *   3. Call `get_lib_net()` once to access the `NetLib` object
 */

typedef struct {
  void (*init)(void);  ///< Optional startup hook
  void (*shutdown)(void);  ///< Optional cleanup hook

  /// Resolve a host:port to a sockaddr_in structure
  /// Returns 0 on success, -1 on failure
  int (*resolve_host_to_sock)(const char *hostname, uint16_t port, struct sockaddr_in *out);
  // host to ip string
  int (*resolve_host_to_ip)(const char *hostname, char *out, size_t outlen);
  //extract the ip address from a sock
  
  int (*sock_to_ip)(const struct sockaddr_in *addr, char *out, size_t outlen);

} NetLib;

const NetLib *get_lib_net(void);

#endif // SIGLATCH_NET_H
