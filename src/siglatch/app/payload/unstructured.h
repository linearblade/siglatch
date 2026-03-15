/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_PAYLOAD_UNSTRUCTURED_H
#define SIGLATCH_SERVER_APP_PAYLOAD_UNSTRUCTURED_H

#include <stddef.h>
#include <stdint.h>

#include "../runtime/runtime.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*handle)(
      const AppRuntimeListenerState *listener,
      const uint8_t *payload,
      size_t payload_len,
      const char *ip);
} AppPayloadUnstructuredLib;

int app_payload_unstructured_init(void);
void app_payload_unstructured_shutdown(void);
void app_payload_unstructured_handle(
    const AppRuntimeListenerState *listener,
    const uint8_t *payload,
    size_t payload_len,
    const char *ip);

#endif
