/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "load_config.h"

int app_builtin_load_config_init(void) {
  return 1;
}

void app_builtin_load_config_shutdown(void) {
}

int app_builtin_load_config_handle(const AppBuiltinContext *ctx, AppActionReply *reply) {
  (void)ctx;
  app_action_reply_set(reply, 0, "UNIMPLEMENTED load_config");
  return 0;
}
