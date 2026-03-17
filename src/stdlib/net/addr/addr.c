/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "addr.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

static int net_resolve_host_to_sock(const char *hostname, uint16_t port, struct sockaddr_storage *out);

static int net_resolve_host_to_sock_ipv4(const char *hostname, uint16_t port, struct sockaddr_in *out);
static int net_resolve_host_to_sock_ipv6(const char *hostname, uint16_t port, struct sockaddr_in6 *out);

static int net_resolve_host_to_ipv4(const char *hostname, char *out, size_t outlen);
static int net_resolve_host_to_ipv6(const char *hostname, char *out, size_t outlen);
static int net_resolve_host_to_ip(const char *hostname, char *out, size_t outlen);

static int net_sock_to_ip(const struct sockaddr_storage *addr, char *out, size_t outlen);
static int net_sock_to_ipv4(const struct sockaddr_in *addr, char *out, size_t outlen);

static int addr_is_ipv4(const char *ip);
static int addr_is_ipv6(const char *ip);

static void net_init(void) {
    // No-op on POSIX; use WSAStartup() when we eventually get to  porting to Windows
}

static void net_shutdown(void) {
    // No-op for now
}

// -3 : out is null
// -2 : host is null
// -1 : couldnt resolve
//  0 : couldnt convert
static int net_resolve_host_to_ipv4(const char *hostname, char *out, size_t outlen)
{
    if (!out) {
        return -3;  // Output buffer is NULL
    }

    if (!hostname) {
        snprintf(out, outlen, "invalid");
        return -2;  // Hostname is NULL
    }

    struct sockaddr_in addr;
    if (net_resolve_host_to_sock_ipv4(hostname, 0, &addr) != 0) {
        snprintf(out, outlen, "unresolved");
        return -1;  // Resolution failed
    }

    if (!inet_ntop(AF_INET, &addr.sin_addr, out, outlen)) {
        snprintf(out, outlen, "conversion_failed");
        return 0;  // inet_ntop failed
    }

    return 1;  // Success
}

// -3 : out is null
// -2 : host is null
// -1 : couldnt resolve
//  0 : couldnt convert
static int net_resolve_host_to_ipv6(const char *hostname, char *out, size_t outlen)
{
    if (!out) {
        return -3;  // Output buffer is NULL
    }

    if (!hostname) {
        snprintf(out, outlen, "invalid");
        return -2;  // Hostname is NULL
    }

    struct sockaddr_in6 addr;
    if (net_resolve_host_to_sock_ipv6(hostname, 0, &addr) != 0) {
        snprintf(out, outlen, "unresolved");
        return -1;  // Resolution failed
    }

    if (!inet_ntop(AF_INET6, &addr.sin6_addr, out, outlen)) {
        snprintf(out, outlen, "conversion_failed");
        return 0;  // inet_ntop failed
    }

    return 1;  // Success
}


static int net_resolve_host_to_ip(const char *hostname, char *out, size_t outlen)
{
    int rv;

    rv = net_resolve_host_to_ipv4(hostname, out, outlen);
    if (rv == 1)
        return 1;

    rv = net_resolve_host_to_ipv6(hostname, out, outlen);
    if (rv == 1)
        return 1;

    return rv;
}

static int net_resolve_host_to_sock(const char *hostname, uint16_t port, struct sockaddr_storage *out)
{
    if (!hostname || !out) return -1;

    struct addrinfo hints = {0};
    struct addrinfo *res = NULL;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int err = getaddrinfo(hostname, port_str, &hints, &res);
    if (err != 0 || !res) return -1;

    memcpy(out, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return 0;
}


static int net_resolve_host_to_sock_ipv4(const char *hostname, uint16_t port, struct sockaddr_in *out) {
    if (!hostname || !out) return -1;

    struct addrinfo hints = {0};
    struct addrinfo *res = NULL;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int err = getaddrinfo(hostname, port_str, &hints, &res);
    if (err != 0 || !res) return -1;

    memcpy(out, res->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(res);
    return 0;
}


static int net_resolve_host_to_sock_ipv6(const char *hostname, uint16_t port, struct sockaddr_in6 *out) {
  if (!hostname || !out) return -1;

  struct addrinfo hints = {0};
  struct addrinfo *res = NULL;

  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;

  char port_str[6];
  snprintf(port_str, sizeof(port_str), "%u", port);

  int err = getaddrinfo(hostname, port_str, &hints, &res);
  if (err != 0 || !res) return -1;

  memcpy(out, res->ai_addr, sizeof(struct sockaddr_in6));
  freeaddrinfo(res);
  return 0;
}


// Returns:
//  1  - Success
//  0  - inet_ntop() failed
// -1  - addr was NULL
// -2  - out was NULL

static int net_sock_to_ip(const struct sockaddr_storage *addr, char *out, size_t outlen)
{
  const struct sockaddr *sa;

  if (!out)
    return -2;

  if (!addr) {
    snprintf(out, outlen, "invalid");
    return -1;
  }

  sa = (const struct sockaddr *)addr;

  if (sa->sa_family == AF_INET) {
    const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
    if (!inet_ntop(AF_INET, &addr4->sin_addr, out, outlen)) {
      snprintf(out, outlen, "unknown");
      return 0;
    }
    return 1;
  }

  if (sa->sa_family == AF_INET6) {
    const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
    if (!inet_ntop(AF_INET6, &addr6->sin6_addr, out, outlen)) {
      snprintf(out, outlen, "unknown");
      return 0;
    }
    return 1;
  }

  snprintf(out, outlen, "unknown");
  return 0;
}


static int net_sock_to_ipv4(const struct sockaddr_in *addr, char *out, size_t outlen)
{
  if (!out){
    return -2;
  }
  
  if (!addr) {
    snprintf(out, outlen, "invalid");
    return -1;
  }

  char ip[INET_ADDRSTRLEN];
  if (!inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip))) {
    snprintf(out, outlen, "unknown");
    return 0;
  }

  snprintf(out, outlen, "%s", ip);
  return 1;
}


static int addr_is_ipv4(const char *ip)
{
    struct in_addr a;
    return ip && inet_pton(AF_INET, ip, &a) == 1;
}

static int addr_is_ipv6(const char *ip)
{
    struct in6_addr a;
    return ip && inet_pton(AF_INET6, ip, &a) == 1;
}


static const NetAddrLib net_addr_instance = {
    .init                       = net_init,
    .shutdown                   = net_shutdown,

    .resolve_host_to_sock       = net_resolve_host_to_sock,
    .resolve_host_to_sock_ipv4  = net_resolve_host_to_sock_ipv4,
    .resolve_host_to_sock_ipv6  = net_resolve_host_to_sock_ipv6,

    .resolve_host_to_ip         = net_resolve_host_to_ip,
    .resolve_host_to_ipv4       = net_resolve_host_to_ipv4,
    .resolve_host_to_ipv6       = net_resolve_host_to_ipv6,

    .sock_to_ip                 = net_sock_to_ip,
    .sock_to_ipv4               = net_sock_to_ipv4,

    .is_ipv4                    = addr_is_ipv4,
    .is_ipv6                    = addr_is_ipv6
};

const NetAddrLib *get_lib_net_addr(void) {
    return &net_addr_instance;
}
