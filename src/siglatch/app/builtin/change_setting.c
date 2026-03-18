/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "change_setting.h"

int app_builtin_change_setting_init(void) {
  return 1;
}

void app_builtin_change_setting_shutdown(void) {
}

int app_builtin_change_setting_handle(const AppBuiltinContext *ctx) {
  (void)ctx;
  return 0;
}
