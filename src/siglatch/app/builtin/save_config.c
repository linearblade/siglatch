/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "save_config.h"

int app_builtin_save_config_init(void) {
  return 1;
}

void app_builtin_save_config_shutdown(void) {
}

int app_builtin_save_config_handle(const AppBuiltinContext *ctx) {
  (void)ctx;
  return 0;
}
