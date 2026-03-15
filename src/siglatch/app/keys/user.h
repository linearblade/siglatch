/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_KEYS_USER_H
#define SIGLATCH_SERVER_APP_KEYS_USER_H

#include "../config/config.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*load_all)(siglatch_config *cfg);
} AppKeysUserLib;

int app_keys_user_init(void);
void app_keys_user_shutdown(void);
int app_keys_user_load_all(siglatch_config *cfg);

#endif
