/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "inbound.h"

#include "../../lib.h"

static int app_inbound_init(void) {
  return app_inbound_crypto_init();
}

static void app_inbound_shutdown(void) {
  app_inbound_crypto_shutdown();
}

static const AppInboundLib app_inbound_instance = {
  .init = app_inbound_init,
  .shutdown = app_inbound_shutdown,
  .crypto = {
    .init = app_inbound_crypto_init,
    .shutdown = app_inbound_crypto_shutdown,
    .init_session_for_server = app_inbound_crypto_init_session_for_server,
    .assign_session_to_user = app_inbound_crypto_assign_session_to_user,
    .validate_signature = app_inbound_crypto_validate_signature
  }
};

const AppInboundLib *get_app_inbound_lib(void) {
  return &app_inbound_instance;
}
