/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "socket.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>

static void socket_init(void);
static void socket_shutdown(void);
static int  socket_bind(int fd, const char *bind_ip, uint16_t bind_port, uint16_t *bound_port);
static int  configure_buffers(int fd, int recv_buf, int send_buf);
static int  open_socket(int domain, int type, int protocol);
static void close_socket(int fd);
static int  wait_readable(int fd, int timeout_ms);

static void socket_init(void) {
  /* No-op on POSIX. */
}

static void socket_shutdown(void) {
  /* No-op for now. */
}

static int socket_bind(int fd,
                       const char *bind_ip,
                       uint16_t bind_port,
                       uint16_t *bound_port) {
  struct sockaddr_in addr;
  struct sockaddr_in actual;
  socklen_t actual_len = sizeof(actual);

  if (fd < 0)
    return 0;

  if ((!bind_ip || !*bind_ip) && bind_port == 0) {
    if (bound_port)
      *bound_port = 0;
    return 1;
  }

  memset(&addr, 0, sizeof(addr));
  memset(&actual, 0, sizeof(actual));

  addr.sin_family = AF_INET;
  addr.sin_port = htons(bind_port);

  if (bind_ip && *bind_ip) {
    if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1)
      return 0;
  } else {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
    return 0;

  if (getsockname(fd, (struct sockaddr *)&actual, &actual_len) == 0) {
    if (bound_port)
      *bound_port = ntohs(actual.sin_port);
  } else if (bound_port) {
    *bound_port = bind_port;
  }

  return 1;
}

static int configure_buffers(int fd, int recv_buf, int send_buf)
{
  int value = 0;

  if (fd < 0)
    return 0;

  if (recv_buf > 0) {
    value = recv_buf;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) != 0)
      return 0;
  }

  if (send_buf > 0) {
    value = send_buf;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) != 0)
      return 0;
  }

  return 1;
}

static int open_socket(int domain, int type, int protocol)
{
  int fd = socket(domain, type, protocol);
  return fd;
}

static void close_socket(int fd)
{
  if (fd >= 0)
    close(fd);
}


static int wait_readable(int fd, int timeout_ms)
{
  fd_set readfds;
  struct timeval tv;
  struct timeval *tv_ptr = NULL;
  int rc = 0;

  if (fd < 0)
    return -1;

  if (timeout_ms >= 0) {
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    tv_ptr = &tv;
  }

  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);

  rc = select(fd + 1, &readfds, NULL, NULL, tv_ptr);

  return rc;
}


static const SocketLib instance = {
  .init              = socket_init,
  .shutdown          = socket_shutdown,
  .bind              = socket_bind,
  .set_buffers       = configure_buffers,
  .open              = open_socket,
  .close             = close_socket,
  .wait_readable     = wait_readable
};

const SocketLib *get_lib_socket(void) {
  return &instance;
}
