/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_UDP_H
#define SIGLATCH_UDP_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#include "../addr/addr.h"
#include "../socket/socket.h"

/**
 * @file udp.h
 * @brief Generic UDP helpers.
 *
 * This module holds UDP-specific helpers built on top of the socket layer.
 */

typedef struct {
  const SocketLib *socket;
  const NetAddrLib *addr;
} UdpContext;

typedef struct {
  /**
   * @brief Initialize UDP library state.
   *
   * @param ctx UDP context providing dependent libraries
   * @return 1 on success, 0 on failure
   */
  int (*init)(const UdpContext *ctx);

  /**
   * @brief Shutdown UDP library state.
   */
  void (*shutdown)(void);

  /**
   * @brief Set or reset UDP library context.
   *
   * @param ctx UDP context providing dependent libraries
   * @return 1 on success, 0 on failure
   */
  int (*set_context)(const UdpContext *ctx);

  /**
   * @brief Open a UDP socket for the requested address family.
   *
   * @param family Socket family such as `AF_INET` or `AF_INET6`
   * @return socket fd on success, or -1 on failure
   */
  int (*open)(int family);

  /**
   * @brief Open an IPv4 UDP socket.
   *
   * @return socket fd on success, or -1 on failure
   */
  int (*open_ipv4)(void);

  /**
   * @brief Open an IPv6 UDP socket.
   *
   * @return socket fd on success, or -1 on failure
   */
  int (*open_ipv6)(void);

  /**
   * @brief Open a UDP socket by inferring family from an IP hint.
   *
   * @param hint IPv4 or IPv6 string literal
   * @return socket fd on success, or -1 on failure
   */
  int (*open_auto)(const char *hint);

  /**
   * @brief Open and optionally bind an IPv4 UDP socket.
   *
   * This is a convenience wrapper over `open_ipv4()` plus the socket-layer
   * bind helper. If both bind arguments are omitted (`bind_ip` empty/NULL and
   * `bind_port == 0`), the bind step is treated as a no-op and the socket is
   * returned unbound, preserving the current convenience behavior.
   *
   * @param bind_ip     Optional local IPv4 literal, or NULL
   * @param bind_port   Optional local UDP port, or 0
   * @param bound_port  Optional output for the actual bound port
   * @return socket fd on success, or -1 on failure
   */
  int (*open_bound_ipv4)(const char *bind_ip, uint16_t bind_port, uint16_t *bound_port);

  /**
   * @brief Open and optionally bind a UDP socket using the destination hint.
   *
   * For IPv4 hints, this opens an IPv4 socket and applies the optional local
   * bind settings. For IPv6 hints, this currently supports only the existing
   * unbound convenience path; explicit local bind parameters are rejected until
   * the underlying socket bind helper grows IPv6 support.
   *
   * @param hint        Destination IPv4 or IPv6 literal
   * @param bind_ip     Optional local IPv4 literal, or NULL
   * @param bind_port   Optional local UDP port, or 0
   * @param bound_port  Optional output for the actual bound port
   * @return socket fd on success, or -1 on failure
   */
  int (*open_bound_auto)(const char *hint, const char *bind_ip,
                         uint16_t bind_port, uint16_t *bound_port);

  /**
   * @brief Close a UDP socket.
   *
   * This is a thin alias to the socket layer close helper.
   *
   * @param fd Socket file descriptor
   */
  void (*close)(int fd);


  /**
 * @brief Send a UDP datagram (auto IPv4/IPv6).
 *
 * Dispatches to IPv4 or IPv6 send based on the destination address string.
 *
 * @param fd    UDP socket file descriptor
 * @param ip    Destination IP address (IPv4 or IPv6 string)
 * @param port  Destination port (host byte order)
 * @param buf   Data buffer to send
 * @param len   Number of bytes to send
 *
 * @return 1 on success (all bytes sent), 0 on failure
 */
int (*send)(int fd, const char *ip, uint16_t port, const void *buf, size_t len);
  
  /**
   * @brief Send one UDP datagram to an IPv4 endpoint.
   *
   * @param fd    Socket file descriptor
   * @param ip    Destination IPv4 address string
   * @param port  Destination UDP port
   * @param buf   Payload buffer
   * @param len   Payload length
   * @return 1 on success, 0 on failure
   */
  int (*send_ipv4)(int fd, const char *ip, uint16_t port, const void *buf, size_t len);
/**
 * @brief Send a UDP datagram to an IPv6 address.
 *
 * @param fd    UDP socket file descriptor (must be AF_INET6)
 * @param ip    Destination IPv6 address (string form, e.g. "2001:db8::1")
 * @param port  Destination port (host byte order)
 * @param buf   Data buffer to send
 * @param len   Number of bytes to send
 *
 * @return 1 on success (all bytes sent), 0 on failure
 */
  int (*send_ipv6)(int fd, const char *ip, uint16_t port, const void *buf, size_t len);

/**
 * @brief Receive a UDP datagram (auto IPv4/IPv6).
 *
 * Receives from the socket and returns the sender address in a generic
 * sockaddr_storage structure, supporting both IPv4 and IPv6.
 *
 * @param fd            UDP socket file descriptor
 * @param buf           Buffer to store received data
 * @param buf_len       Size of the buffer
 * @param peer          Optional output for sender address (sockaddr_storage)
 * @param received_len  Output number of bytes received
 *
 * @return 1 on success, 0 on failure
 */
int (*recv)(int fd, void *buf, size_t buf_len, struct sockaddr_storage *peer, size_t *received_len);
  
    /**
   * @brief Receive one UDP datagram from an IPv4 peer.
   *
   * @param fd            Socket file descriptor
   * @param buf           Destination buffer
   * @param buf_len       Buffer capacity
   * @param peer          Optional output for source peer address
   * @param received_len  Output for bytes received
   * @return 1 on success, 0 on failure
   */
  int (*recv_ipv4)(int fd, void *buf, size_t buf_len,
                   struct sockaddr_in *peer, size_t *received_len);

  /**
 * @brief Receive a UDP datagram from an IPv6 socket.
 *
 * @param fd            UDP socket file descriptor (must be AF_INET6)
 * @param buf           Buffer to store received data
 * @param buf_len       Size of the buffer
 * @param peer          Optional output for sender's IPv6 address (may be NULL)
 * @param received_len  Output number of bytes received
 *
 * @return 1 on success, 0 on failure
 */

  int (*recv_ipv6)(int fd, void *buf, size_t buf_len,
                   struct sockaddr_in6 *peer, size_t *received_len);


  
} UdpLib;

const UdpLib *get_lib_udp(void);

#endif /* SIGLATCH_UDP_H */
