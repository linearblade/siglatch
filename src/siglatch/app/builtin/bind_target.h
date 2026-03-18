/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_BUILTIN_BIND_TARGET_H
#define SIGLATCH_SERVER_APP_BUILTIN_BIND_TARGET_H

#include <stddef.h>

#include "types.h"

typedef struct {
  int has_ip_override;
  int has_port_override;
  char bind_ip[MAX_IP_RANGE_LEN];
  int port;
} AppBuiltinBindTarget;

int app_builtin_parse_bind_target(const KnockPacket *packet,
                                  AppBuiltinBindTarget *out_target);
void app_builtin_format_binding(const char *bind_ip, int port,
                                char *out, size_t outlen);

#endif
