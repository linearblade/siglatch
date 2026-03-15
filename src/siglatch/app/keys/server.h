/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_KEYS_SERVER_H
#define SIGLATCH_SERVER_APP_KEYS_SERVER_H

#include "../config/config.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*load_all)(siglatch_config *cfg);
} AppKeysServerLib;

int app_keys_server_init(void);
void app_keys_server_shutdown(void);
int app_keys_server_load_all(siglatch_config *cfg);

#endif
