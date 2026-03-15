/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_INBOUND_H
#define SIGLATCH_SERVER_APP_INBOUND_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "crypto/crypto.h"
#include "../runtime/runtime.h"
#include "../../../stdlib/openssl_session.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  ssize_t (*receive_valid_data)(
      AppRuntimeListenerState *listener,
      char *buffer,
      size_t bufsize,
      struct sockaddr_in *client,
      char *ip_out,
      int ip_len);
  int (*normalize_payload)(
      SiglatchOpenSSLSession *session,
      const uint8_t *input,
      size_t input_len,
      uint8_t *normalized_out,
      size_t *normalized_len);
  AppInboundCryptoLib crypto;
} AppInboundLib;

const AppInboundLib *get_app_inbound_lib(void);

#endif
