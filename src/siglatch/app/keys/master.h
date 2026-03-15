/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_KEYS_MASTER_H
#define SIGLATCH_SERVER_APP_KEYS_MASTER_H

#include "../config/config.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*load)(siglatch_config *cfg);
} AppKeysMasterLib;

int app_keys_master_init(void);
void app_keys_master_shutdown(void);
int app_keys_master_load(siglatch_config *cfg);

#endif
