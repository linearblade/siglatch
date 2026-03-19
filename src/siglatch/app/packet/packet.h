/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_PACKET_H
#define SIGLATCH_SERVER_APP_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "../runtime/runtime.h"
#include "../../../stdlib/openssl_session.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*consume_normalized)(
      AppRuntimeListenerState *listener,
      const uint8_t *normalized_buffer,
      size_t normalized_len,
      SiglatchOpenSSLSession *session,
      const char *ip,
      uint16_t client_port,
      int is_encrypted);
} AppPacketLib;

const AppPacketLib *get_app_packet_lib(void);

#endif
