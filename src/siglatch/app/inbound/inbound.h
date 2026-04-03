/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_INBOUND_H
#define SIGLATCH_SERVER_APP_INBOUND_H

#include "crypto/crypto.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  AppInboundCryptoLib crypto;
} AppInboundLib;

const AppInboundLib *get_app_inbound_lib(void);

#endif
