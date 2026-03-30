/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "udp.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static UdpContext g_udp_ctx = {0};

static void _reset_context(void);
static int _apply_context(const UdpContext *ctx);
static int  udp_init(const UdpContext *ctx);
static void udp_shutdown(void);
static int  udp_set_context(const UdpContext *ctx);

static int  udp_open(int family);
static int  udp_open_ipv4(void);
static int  udp_open_ipv6(void);
static int  udp_open_auto(const char *hint);
static int  udp_open_bound(int family, const char *bind_ip,
                           uint16_t bind_port, uint16_t *bound_port);
static int  udp_open_bound_ipv4(const char *bind_ip, uint16_t bind_port,
                                uint16_t *bound_port);
static int  udp_open_bound_auto(const char *hint, const char *bind_ip,
                                uint16_t bind_port, uint16_t *bound_port);
static void udp_close(int fd);

static int  udp_send(int fd, const char *ip, uint16_t port, const void *buf, size_t len);
static int  udp_send_ipv4(int fd, const char *ip, uint16_t port, const void *buf, size_t len);
static int  udp_send_ipv6(int fd, const char *ip, uint16_t port, const void *buf, size_t len);

static int  udp_recv_ipv4(int fd, void *buf, size_t buf_len, struct sockaddr_in *peer, size_t *received_len);

static int  udp_recv_ipv6(int fd, void *buf, size_t buf_len, struct sockaddr_in6 *peer, size_t *received_len);


static int udp_recv(int fd, void *buf, size_t buf_len, struct sockaddr_storage *peer, size_t *received_len);
static void _reset_context(void)
{
  memset(&g_udp_ctx, 0, sizeof(g_udp_ctx));
}

static int _apply_context(const UdpContext *ctx)
{
  if (!ctx)
    return 0;

  _reset_context();

  if (!ctx->socket || !ctx->addr)
    return 0;

  if (!ctx->socket->open || !ctx->socket->close || !ctx->socket->bind)
    return 0;

  if (!ctx->addr->is_ipv4 || !ctx->addr->is_ipv6)
    return 0;

  g_udp_ctx = *ctx;
  return 1;
}

static int udp_init(const UdpContext *ctx)
{
  return _apply_context(ctx);
}

static int udp_set_context(const UdpContext *ctx)
{
  return _apply_context(ctx);
}

static void udp_shutdown(void)
{
  _reset_context();
}

static int udp_open(int family)
{
  if (!g_udp_ctx.socket || !g_udp_ctx.socket->open)
    return -1;

  return g_udp_ctx.socket->open(family, SOCK_DGRAM, 0);
}

static int udp_open_ipv4(void)
{
  return udp_open(AF_INET);
}

static int udp_open_ipv6(void)
{
  return udp_open(AF_INET6);
}

static int udp_open_auto(const char *hint)
{
  if (!hint || !g_udp_ctx.addr)
    return -1;

  if (g_udp_ctx.addr->is_ipv4(hint))
    return udp_open_ipv4();

  if (g_udp_ctx.addr->is_ipv6(hint))
    return udp_open_ipv6();

  return -1;
}

static int udp_open_bound(int family,
                          const char *bind_ip,
                          uint16_t bind_port,
                          uint16_t *bound_port)
{
  int fd = -1;

  if (!g_udp_ctx.socket || !g_udp_ctx.socket->bind)
    return -1;

  if (family != AF_INET) {
    if ((bind_ip && *bind_ip) || bind_port != 0)
      return -1;

    if (bound_port)
      *bound_port = 0;

    return udp_open(family);
  }

  fd = udp_open(family);
  if (fd < 0)
    return -1;

  if (!g_udp_ctx.socket->bind(fd, bind_ip, bind_port, bound_port)) {
    udp_close(fd);
    return -1;
  }

  return fd;
}

static int udp_open_bound_ipv4(const char *bind_ip,
                               uint16_t bind_port,
                               uint16_t *bound_port)
{
  return udp_open_bound(AF_INET, bind_ip, bind_port, bound_port);
}

static int udp_open_bound_auto(const char *hint,
                               const char *bind_ip,
                               uint16_t bind_port,
                               uint16_t *bound_port)
{
  if (!hint || !g_udp_ctx.addr)
    return -1;

  if (g_udp_ctx.addr->is_ipv4(hint))
    return udp_open_bound_ipv4(bind_ip, bind_port, bound_port);

  if (g_udp_ctx.addr->is_ipv6(hint)) {
    if ((bind_ip && *bind_ip) || bind_port != 0)
      return -1;

    if (bound_port)
      *bound_port = 0;

    return udp_open_ipv6();
  }

  return -1;
}

static void udp_close(int fd)
{
  if (!g_udp_ctx.socket || !g_udp_ctx.socket->close)
    return;

  g_udp_ctx.socket->close(fd);
}

static int udp_send_ipv4(int fd, const char *ip, uint16_t port, const void *buf, size_t len)
{
  struct sockaddr_in remote;
  ssize_t sent;

  if (fd < 0 || !ip || !buf)
    return 0;

  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_port = htons(port);

  if (inet_pton(AF_INET, ip, &remote.sin_addr) != 1)
    return 0;

  sent = sendto(fd,
                buf,
                len,
                0,
                (struct sockaddr *)&remote,
                sizeof(remote));

  if (sent != (ssize_t)len) {
    fprintf(stderr, "[udp.send_ipv4] sendto(%s:%u, %zu bytes) failed: errno=%d (%s)\n",
            ip, (unsigned int)port, len, errno, strerror(errno));
  }

  return sent == (ssize_t)len;
}

static int udp_send_ipv6(int fd, const char *ip, uint16_t port, const void *buf, size_t len)
{
  struct sockaddr_in6 remote;
  ssize_t sent;

  if (fd < 0 || !ip || !buf)
    return 0;

  memset(&remote, 0, sizeof(remote));
  remote.sin6_family = AF_INET6;
  remote.sin6_port = htons(port);

  if (inet_pton(AF_INET6, ip, &remote.sin6_addr) != 1)
    return 0;

  sent = sendto(fd,
                buf,
                len,
                0,
                (struct sockaddr *)&remote,
                sizeof(remote));

  if (sent != (ssize_t)len) {
    fprintf(stderr, "[udp.send_ipv6] sendto(%s:%u, %zu bytes) failed: errno=%d (%s)\n",
            ip, (unsigned int)port, len, errno, strerror(errno));
  }

  return sent == (ssize_t)len;
}

static int udp_recv_ipv4(int fd, void *buf, size_t buf_len,
                         struct sockaddr_in *peer, size_t *received_len)
{
  struct sockaddr_in remote;
  socklen_t remote_len = sizeof(remote);
  ssize_t received;

  if (fd < 0 || !buf || !received_len)
    return 0;

  memset(&remote, 0, sizeof(remote));

  received = recvfrom(fd,
                      buf,
                      buf_len,
                      0,
                      (struct sockaddr *)&remote,
                      &remote_len);

  if (received < 0)
    return 0;

  if (peer)
    *peer = remote;

  *received_len = (size_t)received;
  return 1;
}

static int udp_recv_ipv6(int fd, void *buf, size_t buf_len,
                         struct sockaddr_in6 *peer, size_t *received_len)
{
  struct sockaddr_in6 remote;
  socklen_t remote_len = sizeof(remote);
  ssize_t received;

  if (fd < 0 || !buf || !received_len)
    return 0;

  memset(&remote, 0, sizeof(remote));

  received = recvfrom(fd,
                      buf,
                      buf_len,
                      0,
                      (struct sockaddr *)&remote,
                      &remote_len);

  if (received < 0)
    return 0;

  if (peer)
    *peer = remote;

  *received_len = (size_t)received;
  return 1;
}

static int udp_send(int fd, const char *ip, uint16_t port, const void *buf, size_t len)
{
  if (!ip)
    return 0;

  if (g_udp_ctx.addr && g_udp_ctx.addr->is_ipv4(ip))
    return udp_send_ipv4(fd, ip, port, buf, len);

  if (g_udp_ctx.addr && g_udp_ctx.addr->is_ipv6(ip))
    return udp_send_ipv6(fd, ip, port, buf, len);

  return 0;
}

static int udp_recv(int fd, void *buf, size_t buf_len, struct sockaddr_storage *peer, size_t *received_len)
{
  struct sockaddr_storage remote;
  socklen_t remote_len = sizeof(remote);
  ssize_t received;

  if (fd < 0 || !buf || !received_len)
    return 0;

  memset(&remote, 0, sizeof(remote));

  received = recvfrom(fd,
                      buf,
                      buf_len,
                      0,
                      (struct sockaddr *)&remote,
                      &remote_len);

  if (received < 0)
    return 0;

  if (peer)
    *peer = remote;

  *received_len = (size_t)received;
  return 1;
}

static const UdpLib udp_instance = {
  .init        = udp_init,
  .shutdown    = udp_shutdown,
  .set_context = udp_set_context,
  .open        = udp_open,
  .open_ipv4   = udp_open_ipv4,
  .open_ipv6   = udp_open_ipv6,
  .open_auto   = udp_open_auto,
  .open_bound_ipv4 = udp_open_bound_ipv4,
  .open_bound_auto = udp_open_bound_auto,
  .close       = udp_close,
  .send        = udp_send,
  .send_ipv4   = udp_send_ipv4,
  .send_ipv6   = udp_send_ipv6,
  .recv        = udp_recv,
  .recv_ipv4   = udp_recv_ipv4,
  .recv_ipv6   = udp_recv_ipv6
};

const UdpLib *get_lib_udp(void)
{
  return &udp_instance;
}
