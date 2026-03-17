/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_NET_ADDR_H
#define SIGLATCH_NET_ADDR_H

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>

/**
 * @file addr.h
 * @brief Address and hostname resolution helpers.
 *
 * This module provides helpers for:
 *   - resolving hostnames to socket address structures
 *   - resolving hostnames to printable IP strings
 *   - converting socket address structures to printable IP strings
 *   - checking whether a string is a valid IPv4 or IPv6 literal
 */

typedef struct {
  /**
   * @brief Optional startup hook.
   */
  void (*init)(void);

  /**
   * @brief Optional cleanup hook.
   */
  void (*shutdown)(void);

  /**
   * @brief Resolve a host:port to either IPv4 or IPv6 socket storage.
   *
   * @param hostname Hostname or numeric address
   * @param port     Port number
   * @param out      Output socket storage
   * @return 0 on success, -1 on failure
   */
  int (*resolve_host_to_sock)(const char *hostname, uint16_t port, struct sockaddr_storage *out);

  /**
   * @brief Resolve a host:port to an IPv4 socket address.
   *
   * @param hostname Hostname or numeric IPv4 address
   * @param port     Port number
   * @param out      Output IPv4 socket address
   * @return 0 on success, -1 on failure
   */
  int (*resolve_host_to_sock_ipv4)(const char *hostname, uint16_t port, struct sockaddr_in *out);

  /**
   * @brief Resolve a host:port to an IPv6 socket address.
   *
   * @param hostname Hostname or numeric IPv6 address
   * @param port     Port number
   * @param out      Output IPv6 socket address
   * @return 0 on success, -1 on failure
   */
  int (*resolve_host_to_sock_ipv6)(const char *hostname, uint16_t port, struct sockaddr_in6 *out);

  /**
   * @brief Resolve a host to a printable IP string, auto family.
   *
   * @param hostname Hostname or numeric IP
   * @param out      Output buffer
   * @param outlen   Output buffer length
   * @return 1 on success, -3 if out is NULL, -2 if hostname is NULL,
   *         -1 if resolution failed, 0 if conversion failed
   */
  int (*resolve_host_to_ip)(const char *hostname, char *out, size_t outlen);

  /**
   * @brief Resolve a host to a printable IPv4 string.
   *
   * @param hostname Hostname or numeric IPv4
   * @param out      Output buffer
   * @param outlen   Output buffer length
   * @return 1 on success, -3 if out is NULL, -2 if hostname is NULL,
   *         -1 if resolution failed, 0 if conversion failed
   */
  int (*resolve_host_to_ipv4)(const char *hostname, char *out, size_t outlen);

  /**
   * @brief Resolve a host to a printable IPv6 string.
   *
   * @param hostname Hostname or numeric IPv6
   * @param out      Output buffer
   * @param outlen   Output buffer length
   * @return 1 on success, -3 if out is NULL, -2 if hostname is NULL,
   *         -1 if resolution failed, 0 if conversion failed
   */
  int (*resolve_host_to_ipv6)(const char *hostname, char *out, size_t outlen);

  /**
   * @brief Convert a generic socket address to a printable IP string.
   *
   * @param addr     Input socket storage
   * @param out      Output buffer
   * @param outlen   Output buffer length
   * @return 1 on success, -2 if out is NULL, -1 if addr is NULL,
   *         0 if conversion failed
   */
  int (*sock_to_ip)(const struct sockaddr_storage *addr, char *out, size_t outlen);

  /**
   * @brief Convert an IPv4 socket address to a printable IPv4 string.
   *
   * @param addr     Input IPv4 socket address
   * @param out      Output buffer
   * @param outlen   Output buffer length
   * @return 1 on success, -2 if out is NULL, -1 if addr is NULL,
   *         0 if conversion failed
   */
  int (*sock_to_ipv4)(const struct sockaddr_in *addr, char *out, size_t outlen);

  /**
   * @brief Check whether a string is a valid IPv4 literal.
   *
   * @param ip Input string
   * @return 1 if valid IPv4, 0 otherwise
   */
  int (*is_ipv4)(const char *ip);

  /**
   * @brief Check whether a string is a valid IPv6 literal.
   *
   * @param ip Input string
   * @return 1 if valid IPv6, 0 otherwise
   */
  int (*is_ipv6)(const char *ip);

} NetAddrLib;

/**
 * @brief Access the singleton address helper library.
 *
 * @return Pointer to the NetAddrLib instance
 */
const NetAddrLib *get_lib_net_addr(void);

#endif /* SIGLATCH_NET_ADDR_H */
