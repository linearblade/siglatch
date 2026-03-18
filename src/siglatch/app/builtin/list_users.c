/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "list_users.h"

int app_builtin_list_users_init(void) {
  return 1;
}

void app_builtin_list_users_shutdown(void) {
}

int app_builtin_list_users_handle(const AppBuiltinContext *ctx) {
  (void)ctx;
  return 0;
}
