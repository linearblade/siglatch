/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "app_opts.h"

static int app_opts_init(const AppOptsContext *ctx) {
  (void)ctx;
  return 1;
}

static void app_opts_shutdown(void) {
}

static const AppOptsLib app_opts_instance = {
  .init = app_opts_init,
  .shutdown = app_opts_shutdown
};

const AppOptsLib *get_app_opts_lib(void) {
  return &app_opts_instance;
}
