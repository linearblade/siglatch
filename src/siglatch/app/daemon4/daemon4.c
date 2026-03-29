/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "daemon4.h"

static int app_daemon4_init(void) {
  return 1;
}

static void app_daemon4_shutdown(void) {
}

static void app_daemon4_process(AppRuntimeListenerState *listener) {
  if (!listener) {
    return;
  }

  get_app_daemon4_runner_lib()->run(listener);
}

const AppDaemon4 *get_app_daemon4_lib(void) {
  static AppDaemon4 lib = {0};

  lib.init = app_daemon4_init;
  lib.shutdown = app_daemon4_shutdown;
  lib.process = app_daemon4_process;
  lib.helper = *get_app_daemon4_helper_lib();
  lib.auth = *get_app_daemon4_auth_lib();
  lib.request = *get_app_daemon4_request_lib();
  lib.policy = *get_app_daemon4_policy_lib();
  lib.runner = *get_app_daemon4_runner_lib();
  lib.job = *get_app_daemon4_job_lib();
  lib.payload = *get_app_daemon4_payload_lib();
  lib.tick = *get_app_daemon4_tick_lib();

  return &lib;
}
