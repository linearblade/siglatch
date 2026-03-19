/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_PAYLOAD_STRUCTURED_H
#define SIGLATCH_SERVER_APP_PAYLOAD_STRUCTURED_H

#include <stdint.h>

#include "../runtime/runtime.h"
#include "../../../stdlib/openssl_session.h"
#include "codec/codec.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*handle)(
      AppRuntimeListenerState *listener,
      const KnockPacket *pkt,
      SiglatchOpenSSLSession *session,
      const char *ip,
      uint16_t client_port);
} AppPayloadStructuredLib;

int app_payload_structured_init(void);
void app_payload_structured_shutdown(void);
void app_payload_structured_handle(
    AppRuntimeListenerState *listener,
    const KnockPacket *pkt,
    SiglatchOpenSSLSession *session,
    const char *ip,
    uint16_t client_port);

#endif
