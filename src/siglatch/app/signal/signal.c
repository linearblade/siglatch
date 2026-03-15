/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "signal.h"

#include "../../lib.h"

static const int app_signal_default_set[] = {SIGINT, SIGTERM};

static int app_signal_init(void) {
  return 1;
}

static void app_signal_shutdown(void) {
  lib.signal.uninstall();
}

static void app_signal_install(AppRuntimeProcessState *process) {
  SignalInstallConfig cfg = {
    .signals = app_signal_default_set,
    .signal_count = sizeof(app_signal_default_set) / sizeof(app_signal_default_set[0]),
    .set_should_exit = 1,
    .wake_write_fd = -1,
    .policy = LIB_SIGNAL_POLICY_GRACEFUL_THEN_HARD
  };

  if (!process) {
    return;
  }

  lib.signal.state_reset(&process->signal);
  if (!lib.signal.install(&process->signal, &cfg)) {
    LOGE("Failed to install process signal handlers\n");
  }
}

static int app_signal_should_exit(const AppRuntimeProcessState *process) {
  if (!process) {
    return 0;
  }

  return lib.signal.should_exit(&process->signal);
}

static void app_signal_request_exit(AppRuntimeProcessState *process) {
  if (process) {
    lib.signal.request_exit(&process->signal);
  }
}

static const AppSignalLib app_signal_instance = {
  .init = app_signal_init,
  .shutdown = app_signal_shutdown,
  .install = app_signal_install,
  .should_exit = app_signal_should_exit,
  .request_exit = app_signal_request_exit
};

const AppSignalLib *get_app_signal_lib(void) {
  return &app_signal_instance;
}
