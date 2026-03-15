/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_KEYS_HMAC_H
#define SIGLATCH_SERVER_APP_KEYS_HMAC_H

#include "../config/config.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*load_all)(siglatch_config *cfg);
} AppKeysHmacLib;

int app_keys_hmac_init(void);
void app_keys_hmac_shutdown(void);
int app_keys_hmac_load_all(siglatch_config *cfg);

#endif
