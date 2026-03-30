/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "daemon.h"

static int app_daemon_init(void) {
  return 1;
}

static void app_daemon_shutdown(void) {
}

static void app_daemon_process(AppRuntimeListenerState *listener) {
  if (!listener) {
    return;
  }

  get_app_daemon_runner_lib()->run(listener);
}

const AppDaemon *get_app_daemon_lib(void) {
  static AppDaemon lib = {0};

  lib.init = app_daemon_init;
  lib.shutdown = app_daemon_shutdown;
  lib.process = app_daemon_process;
  lib.helper = *get_app_daemon_helper_lib();
  lib.auth = *get_app_daemon_auth_lib();
  lib.request = *get_app_daemon_request_lib();
  lib.policy = *get_app_daemon_policy_lib();
  lib.runner = *get_app_daemon_runner_lib();
  lib.job = *get_app_daemon_job_lib();
  lib.payload = *get_app_daemon_payload_lib();
  lib.tick = *get_app_daemon_tick_lib();

  return &lib;
}
