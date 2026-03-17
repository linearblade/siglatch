/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SOCKET_H
#define SIGLATCH_SOCKET_H

#include <stdint.h>

/**
 * @file socket.h
 * @brief Generic socket lifecycle and configuration helpers.
 *
 * This module wraps common socket operations used by the siglatch runtime.
 * It is intended to provide a small, reusable abstraction over the native
 * socket API for:
 *
 *   - opening sockets
 *   - closing sockets
 *   - binding sockets to a local IPv4 address/port
 *   - configuring send/receive buffer sizes
 *
 * The bind helper is intentionally IPv4-oriented for now. If no bind address
 * and no bind port are requested, the bind operation is treated as a no-op and
 * succeeds without forcing an explicit bind. In that case, the socket may still
 * receive an ephemeral port later through lazy kernel assignment.
 */

typedef struct {
  /**
   * @brief Initialize socket library state.
   *
   * Currently reserved for future use. Present for lifecycle consistency with
   * the rest of the stdlib modules.
   */
  void (*init)(void);

  /**
   * @brief Shutdown socket library state.
   *
   * Currently reserved for future use. Present for lifecycle consistency with
   * the rest of the stdlib modules.
   */
  void (*shutdown)(void);

  /**
   * @brief Open a socket.
   *
   * Thin wrapper around the native socket() call.
   *
   * @param domain    Socket domain (e.g. AF_INET)
   * @param type      Socket type (e.g. SOCK_DGRAM, SOCK_STREAM)
   * @param protocol  Protocol number, usually 0
   * @return file descriptor on success, or -1 on failure
   */
  int (*open)(int domain, int type, int protocol);

  /**
   * @brief Close a socket file descriptor if valid.
   *
   * Safe no-op when fd < 0.
   *
   * @param fd Socket file descriptor
   */
  void (*close)(int fd);

  /**
   * @brief Bind a socket to a local IPv4 address and/or port.
   *
   * If both bind_ip is NULL/empty and bind_port is 0, this function performs
   * no explicit bind and returns success. If bound_port is provided, it is set
   * to 0 in that case.
   *
   * If bind_port is 0 but a bind is requested, the kernel may assign an
   * ephemeral port. When possible, the actual bound port is returned through
   * bound_port using getsockname().
   *
   * @param fd          Socket file descriptor
   * @param bind_ip     Optional IPv4 address string, or NULL
   * @param bind_port   Local port to bind, or 0 for ephemeral
   * @param bound_port  Optional output for actual bound port
   * @return 1 on success, 0 on failure
   */
  int (*bind)(int fd, const char *bind_ip, uint16_t bind_port, uint16_t *bound_port);

  /**
   * @brief Configure socket receive/send buffer sizes.
   *
   * Buffer values <= 0 are ignored. This allows callers to pass optional
   * values without pre-filtering.
   *
   * @param fd        Socket file descriptor
   * @param recv_buf  Requested SO_RCVBUF size, or <= 0 to leave unchanged
   * @param send_buf  Requested SO_SNDBUF size, or <= 0 to leave unchanged
   * @return 1 on success, 0 on failure
   */
  int (*set_buffers)(int fd, int recv_buf, int send_buf);

  /**
   * @brief Wait until a socket becomes readable.
   *
   * Uses select() to wait for read readiness on the given file descriptor.
   *
   * @param fd          Socket file descriptor
   * @param timeout_ms  Timeout in milliseconds; values < 0 wait indefinitely unless interrupted by a signal
   * @return >0 if readable, 0 on timeout, -1 on error
   */

  int (*wait_readable)(int fd, int timeout_ms);
  
} SocketLib;

/**
 * @brief Access the singleton socket helper library.
 *
 * @return Pointer to the SocketLib instance.
 */
const SocketLib *get_lib_socket(void);

#endif /* SIGLATCH_SOCKET_H */
