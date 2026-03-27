/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "daemon3.h"

static int app_daemon3_init(void) {
  return 1;
}

static void app_daemon3_shutdown(void) {
}

static void app_daemon3_process(AppRuntimeListenerState *listener) {
  if (!listener) {
    return;
  }

  get_app_daemon3_runner_lib()->run(listener);
}

const AppDaemon3 *get_app_daemon3_lib(void) {
  static AppDaemon3 lib = {0};

  lib.init = app_daemon3_init;
  lib.shutdown = app_daemon3_shutdown;
  lib.process = app_daemon3_process;
  lib.helper = *get_app_daemon3_helper_lib();
  lib.request = *get_app_daemon3_request_lib();
  lib.policy = *get_app_daemon3_policy_lib();
  lib.runner = *get_app_daemon3_runner_lib();
  lib.job = *get_app_daemon3_job_lib();
  lib.payload = *get_app_daemon3_payload_lib();
  lib.tick = *get_app_daemon3_tick_lib();

  return &lib;
}
