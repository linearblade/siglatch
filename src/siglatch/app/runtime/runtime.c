/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "runtime.h"

static int app_runtime_init(void) {
  return 1;
}

static void app_runtime_shutdown(void) {
}

static const AppRuntimeLib app_runtime_instance = {
  .init = app_runtime_init,
  .shutdown = app_runtime_shutdown
};

const AppRuntimeLib *get_app_runtime_lib(void) {
  return &app_runtime_instance;
}
