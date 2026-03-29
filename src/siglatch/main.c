/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>      
#include <stdlib.h>     
#include <unistd.h>

#include "app/app.h"
#include "lib.h"
#include "lifecycle.h"

int main(int argc, char *argv[]) {
  int status = EXIT_FAILURE;
  int shutdown_signal = 0;
  int should_log_shutdown = 0;
  AppStartupState startup = {0};

  if (!siglatch_boot()) {
    goto cleanup;
  }

  if (!app.startup.prepare(argc, argv, &startup)) {
    status = startup.exit_code ? startup.exit_code : EXIT_FAILURE;
    goto cleanup;
  }

  if (startup.should_exit) {
    status = startup.exit_code;
    goto cleanup;
  }

  if (app.udp.start_listener(&startup.listener) < 0) {
    LOGPERR("Socket creation failed");
    status = EXIT_FAILURE;
    goto cleanup;
  }

  app.daemon4.runner.run(&startup.listener);
  should_log_shutdown = 1;
  status = 0;

cleanup:
  if (startup.listener.sock >= 0) {
    close(startup.listener.sock);
  }
  lib.nonce.cache_shutdown(&startup.listener.nonce);
  shutdown_signal = lib.signal.take_last_signal(&startup.process.signal);
  if (shutdown_signal) {
    LOGT("Caught signal %d - shutting down...\n", shutdown_signal);
  }
  if (should_log_shutdown) {
    siglatch_report_shutdown_complete();
  }
  siglatch_shutdown();
  return status;
}
