/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>

#include "keys.h"
#include "../../lib.h"

static int keys_init(void) {
  int master_initialized = 0;
  int user_initialized = 0;
  int server_initialized = 0;
  int hmac_initialized = 0;

  if (!app_keys_master_init()) {
    fprintf(stderr, "Failed to initialize app.keys.master\n");
    goto fail;
  }
  master_initialized = 1;

  if (!app_keys_user_init()) {
    fprintf(stderr, "Failed to initialize app.keys.user\n");
    goto fail;
  }
  user_initialized = 1;

  if (!app_keys_server_init()) {
    fprintf(stderr, "Failed to initialize app.keys.server\n");
    goto fail;
  }
  server_initialized = 1;

  if (!app_keys_hmac_init()) {
    fprintf(stderr, "Failed to initialize app.keys.hmac\n");
    goto fail;
  }
  hmac_initialized = 1;

  return 1;

fail:
  if (hmac_initialized) {
    app_keys_hmac_shutdown();
  }
  if (server_initialized) {
    app_keys_server_shutdown();
  }
  if (user_initialized) {
    app_keys_user_shutdown();
  }
  if (master_initialized) {
    app_keys_master_shutdown();
  }
  return 0;
}

static void keys_shutdown(void) {
  app_keys_hmac_shutdown();
  app_keys_server_shutdown();
  app_keys_user_shutdown();
  app_keys_master_shutdown();
}

static int keys_load(siglatch_config *cfg) {
  if (!cfg) {
    return 0;
  }

  if (!app_keys_master_load(cfg)) {
    return 0;
  }

  if (!app_keys_user_load_all(cfg)) {
    LOGE("Failed to load user keys\n");
    return 0;
  }

  if (!app_keys_server_load_all(cfg)) {
    LOGE("Failed to load server keys\n");
    return 0;
  }

  if (!app_keys_hmac_load_all(cfg)) {
    LOGE("Failed to load user HMAC keys\n");
    return 0;
  }

  return 1;
}

static const AppKeysLib keys_instance = {
  .init = keys_init,
  .shutdown = keys_shutdown,
  .load = keys_load,
  .master = {
    .init = app_keys_master_init,
    .shutdown = app_keys_master_shutdown,
    .load = app_keys_master_load,
  },
  .user = {
    .init = app_keys_user_init,
    .shutdown = app_keys_user_shutdown,
    .load_all = app_keys_user_load_all,
  },
  .server = {
    .init = app_keys_server_init,
    .shutdown = app_keys_server_shutdown,
    .load_all = app_keys_server_load_all,
  },
  .hmac = {
    .init = app_keys_hmac_init,
    .shutdown = app_keys_hmac_shutdown,
    .load_all = app_keys_hmac_load_all,
  },
};

const AppKeysLib *get_app_keys_lib(void) {
  return &keys_instance;
}
