/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "range.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int net_ip_range_is_single_ipv4(const char *spec);
static int net_ip_range_is_cidr_ipv4(const char *spec);
static int net_ip_range_contains_cidr_ipv4(const char *cidr, const char *ip);
static int net_ip_range_contains_spec_ipv4(const char *spec, const char *ip);
static int net_ip_range_contains_any_ipv4(const char *spec_list, const char *ip);

static int net_ip_range_trim_copy(const char *input, char *out, size_t out_len);
static int net_ip_range_parse_ipv4_literal(const char *text, uint32_t *out_addr);
static int net_ip_range_parse_ipv4_spec(const char *spec,
                                        uint32_t *out_network,
                                        uint32_t *out_mask,
                                        int *out_is_cidr);
static uint32_t net_ip_range_prefix_mask(unsigned int prefix_len);

static void net_ip_range_init(void) {
}

static void net_ip_range_shutdown(void) {
}

static int net_ip_range_is_single_ipv4(const char *spec) {
  uint32_t addr = 0;
  char trimmed[64] = {0};

  if (!net_ip_range_trim_copy(spec, trimmed, sizeof(trimmed))) {
    return 0;
  }

  if (strchr(trimmed, '/')) {
    return 0;
  }

  return net_ip_range_parse_ipv4_literal(trimmed, &addr);
}

static int net_ip_range_is_cidr_ipv4(const char *spec) {
  uint32_t network = 0;
  uint32_t mask = 0;
  int is_cidr = 0;

  if (!net_ip_range_parse_ipv4_spec(spec, &network, &mask, &is_cidr)) {
    return 0;
  }

  return is_cidr;
}

static int net_ip_range_contains_cidr_ipv4(const char *cidr, const char *ip) {
  uint32_t network = 0;
  uint32_t mask = 0;
  uint32_t addr = 0;
  int is_cidr = 0;

  if (!net_ip_range_parse_ipv4_spec(cidr, &network, &mask, &is_cidr) || !is_cidr) {
    return 0;
  }

  if (!net_ip_range_parse_ipv4_literal(ip, &addr)) {
    return 0;
  }

  return (addr & mask) == network;
}

static int net_ip_range_contains_spec_ipv4(const char *spec, const char *ip) {
  uint32_t network = 0;
  uint32_t mask = 0;
  uint32_t addr = 0;
  int is_cidr = 0;

  if (!net_ip_range_parse_ipv4_spec(spec, &network, &mask, &is_cidr)) {
    return 0;
  }

  if (!net_ip_range_parse_ipv4_literal(ip, &addr)) {
    return 0;
  }

  if (!is_cidr) {
    return addr == network;
  }

  return (addr & mask) == network;
}

static int net_ip_range_contains_any_ipv4(const char *spec_list, const char *ip) {
  size_t start = 0;
  size_t i = 0;
  size_t len = 0;

  if (!spec_list || !ip) {
    return 0;
  }

  len = strlen(spec_list);
  for (i = 0; i <= len; ++i) {
    if (spec_list[i] == ',' || spec_list[i] == '\0') {
      char part[128] = {0};
      size_t part_len = 0;

      if (i > start) {
        part_len = i - start;
        if (part_len >= sizeof(part)) {
          return 0;
        }

        memcpy(part, spec_list + start, part_len);
        part[part_len] = '\0';

        if (net_ip_range_contains_spec_ipv4(part, ip)) {
          return 1;
        }
      }

      start = i + 1;
    }
  }

  return 0;
}

static int net_ip_range_trim_copy(const char *input, char *out, size_t out_len) {
  size_t start = 0;
  size_t end = 0;
  size_t len = 0;

  if (!input || !out || out_len == 0) {
    return 0;
  }

  len = strlen(input);
  while (start < len && isspace((unsigned char)input[start])) {
    start++;
  }

  end = len;
  while (end > start && isspace((unsigned char)input[end - 1])) {
    end--;
  }

  if (end <= start) {
    return 0;
  }

  if ((end - start) >= out_len) {
    return 0;
  }

  memcpy(out, input + start, end - start);
  out[end - start] = '\0';
  return 1;
}

static int net_ip_range_parse_ipv4_literal(const char *text, uint32_t *out_addr) {
  struct in_addr addr = {0};

  if (!text || !out_addr) {
    return 0;
  }

  if (inet_pton(AF_INET, text, &addr) != 1) {
    return 0;
  }

  *out_addr = ntohl(addr.s_addr);
  return 1;
}

static int net_ip_range_parse_ipv4_spec(const char *spec,
                                        uint32_t *out_network,
                                        uint32_t *out_mask,
                                        int *out_is_cidr) {
  char trimmed[128] = {0};
  char *slash = NULL;
  uint32_t addr = 0;

  if (!out_network || !out_mask || !out_is_cidr) {
    return 0;
  }

  if (!net_ip_range_trim_copy(spec, trimmed, sizeof(trimmed))) {
    return 0;
  }

  slash = strchr(trimmed, '/');
  if (!slash) {
    if (!net_ip_range_parse_ipv4_literal(trimmed, &addr)) {
      return 0;
    }

    *out_network = addr;
    *out_mask = 0xFFFFFFFFu;
    *out_is_cidr = 0;
    return 1;
  }

  if (strchr(slash + 1, '/')) {
    return 0;
  }

  *slash = '\0';
  slash++;

  {
    unsigned long prefix_len = 0;
    char *parse_end = NULL;
    uint32_t mask = 0;

    if (!net_ip_range_parse_ipv4_literal(trimmed, &addr)) {
      return 0;
    }

    prefix_len = strtoul(slash, &parse_end, 10);
    if (!parse_end || *parse_end != '\0' || prefix_len > 32UL) {
      return 0;
    }

    mask = net_ip_range_prefix_mask((unsigned int)prefix_len);
    *out_network = addr & mask;
    *out_mask = mask;
    *out_is_cidr = 1;
    return 1;
  }
}

static uint32_t net_ip_range_prefix_mask(unsigned int prefix_len) {
  if (prefix_len == 0U) {
    return 0U;
  }

  if (prefix_len >= 32U) {
    return 0xFFFFFFFFu;
  }

  return 0xFFFFFFFFu << (32U - prefix_len);
}

static const NetIpRangeLib net_ip_range_instance = {
  .init = net_ip_range_init,
  .shutdown = net_ip_range_shutdown,
  .is_single_ipv4 = net_ip_range_is_single_ipv4,
  .is_cidr_ipv4 = net_ip_range_is_cidr_ipv4,
  .contains_cidr_ipv4 = net_ip_range_contains_cidr_ipv4,
  .contains_spec_ipv4 = net_ip_range_contains_spec_ipv4,
  .contains_any_ipv4 = net_ip_range_contains_any_ipv4
};

const NetIpRangeLib *get_lib_net_ip_range(void) {
  return &net_ip_range_instance;
}
