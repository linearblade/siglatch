/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "bind_target.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../app.h"
#include "../../lib.h"

static int app_builtin_parse_port_text(const char *text, int *out_port);
static int app_builtin_is_all_digits(const char *text);
static int app_builtin_is_ip_literal(const char *text);

int app_builtin_parse_bind_target(const AppConnectionJob *job,
                                  AppBuiltinBindTarget *out_target) {
  char payload[128] = {0};
  char *text = payload;
  size_t copy_len = 0;
  size_t text_len = 0;

  if (!out_target) {
    return 0;
  }

  memset(out_target, 0, sizeof(*out_target));

  if (!job || job->request.payload_len == 0) {
    return 1;
  }

  if (!job->request.payload_buffer) {
    return 0;
  }

  if (job->request.payload_len >= sizeof(payload)) {
    return 0;
  }

  copy_len = job->request.payload_len;
  memcpy(payload, job->request.payload_buffer, copy_len);
  payload[copy_len] = '\0';

  while (*text && isspace((unsigned char)*text)) {
    text++;
  }

  text_len = strlen(text);
  while (text_len > 0 && isspace((unsigned char)text[text_len - 1])) {
    text[--text_len] = '\0';
  }

  if (text_len == 0) {
    return 1;
  }

  if (text[0] == '[') {
    char *close = strchr(text + 1, ']');
    char host[MAX_IP_RANGE_LEN] = {0};

    if (!close || close == text + 1 || close[1] != ':') {
      return 0;
    }

    if ((size_t)(close - (text + 1)) >= sizeof(host)) {
      return 0;
    }

    memcpy(host, text + 1, (size_t)(close - (text + 1)));
    host[close - (text + 1)] = '\0';

    if (!app_builtin_is_ip_literal(host)) {
      return 0;
    }

    if (!app_builtin_parse_port_text(close + 2, &out_target->port)) {
      return 0;
    }

    lib.str.lcpy(out_target->bind_ip, host, sizeof(out_target->bind_ip));
    out_target->has_ip_override = 1;
    out_target->has_port_override = 1;
    return 1;
  }

  if (app_builtin_is_all_digits(text)) {
    if (!app_builtin_parse_port_text(text, &out_target->port)) {
      return 0;
    }

    out_target->has_port_override = 1;
    return 1;
  }

  if (!app_builtin_is_ip_literal(text)) {
    return 0;
  }

  lib.str.lcpy(out_target->bind_ip, text, sizeof(out_target->bind_ip));
  out_target->has_ip_override = 1;
  return 1;
}

void app_builtin_format_binding(const char *bind_ip, int port,
                                char *out, size_t outlen) {
  const char *ip = (bind_ip && bind_ip[0] != '\0') ? bind_ip : "0.0.0.0";

  if (!out || outlen == 0) {
    return;
  }

  if (lib.net.addr.is_ipv6 && lib.net.addr.is_ipv6(ip)) {
    snprintf(out, outlen, "[%s]:%d", ip, port);
  } else {
    snprintf(out, outlen, "%s:%d", ip, port);
  }
}

static int app_builtin_parse_port_text(const char *text, int *out_port) {
  unsigned long port_ul = 0;
  char *parse_end = NULL;

  if (!text || !*text || !out_port) {
    return 0;
  }

  port_ul = strtoul(text, &parse_end, 10);
  if (!parse_end || *parse_end != '\0') {
    return 0;
  }

  if (port_ul == 0 || port_ul > 65535UL) {
    return 0;
  }

  *out_port = (int)port_ul;
  return 1;
}

static int app_builtin_is_all_digits(const char *text) {
  size_t i = 0;

  if (!text || text[0] == '\0') {
    return 0;
  }

  for (i = 0; text[i] != '\0'; ++i) {
    if (!isdigit((unsigned char)text[i])) {
      return 0;
    }
  }

  return 1;
}

static int app_builtin_is_ip_literal(const char *text) {
  if (!text || text[0] == '\0') {
    return 0;
  }

  if (lib.net.addr.is_ipv4 && lib.net.addr.is_ipv4(text)) {
    return 1;
  }

  if (lib.net.addr.is_ipv6 && lib.net.addr.is_ipv6(text)) {
    return 1;
  }

  return 0;
}
