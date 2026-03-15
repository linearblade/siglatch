/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>

#include "app/app.h"
#include "../shared/shared.h"
#include "lib.h"
#include "lifecycle.h"

static int g_lifecycle_lib_initialized = 0;
static int g_lifecycle_shared_initialized = 0;
static int g_lifecycle_app_initialized = 0;

int siglatch_boot(void) {
  if (g_lifecycle_lib_initialized && g_lifecycle_app_initialized) {
    return 1;
  }

  if (!g_lifecycle_lib_initialized) {
    if (!init_lib()) {
      fprintf(stderr, "Failed to initialize siglatchd library runtime\n");
      goto fail;
    }
    g_lifecycle_lib_initialized = 1;
  }

  if (!g_lifecycle_app_initialized) {
    SharedContext shared_ctx = {
      .log = &lib.log,
      .openssl = &lib.openssl,
      .print = &lib.print
    };

    if (!g_lifecycle_shared_initialized) {
      if (!init_shared(&shared_ctx)) {
        fprintf(stderr, "Failed to initialize siglatchd shared runtime\n");
        goto fail;
      }
      g_lifecycle_shared_initialized = 1;
    }

    if (!init_app()) {
      fprintf(stderr, "Failed to initialize siglatchd app runtime\n");
      goto fail;
    }
    g_lifecycle_app_initialized = 1;
  }

  return 1;

fail:
  siglatch_shutdown();
  return 0;
}

void siglatch_shutdown(void) {
  if (g_lifecycle_app_initialized) {
    shutdown_app();
    g_lifecycle_app_initialized = 0;
  }

  if (g_lifecycle_shared_initialized) {
    shutdown_shared();
    g_lifecycle_shared_initialized = 0;
  }

  if (g_lifecycle_lib_initialized) {
    shutdown_lib();
    g_lifecycle_lib_initialized = 0;
  }
}

void siglatch_report_config_error(void) {
  LOGE("Failed to load config\n");
}

void siglatch_report_shutdown_complete(void) {
  LOGW("Shutdown complete\n");
}
