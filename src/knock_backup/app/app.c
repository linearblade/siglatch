/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "app.h"
#include <stddef.h>
#include <stdio.h>

App app = {
  .opts = {0},
  .env = {0},
  .alias = {0},
  .output_mode = {0},
  .help = {0},
  .error_argv = {0},
  .transmit = {0}
};

int init_app(void) {
  int opts_initialized = 0;
  int env_initialized = 0;
  int alias_initialized = 0;
  int output_mode_initialized = 0;
  int help_initialized = 0;
  int error_argv_initialized = 0;
  int transmit_initialized = 0;

  app.opts = *get_app_opts_lib();
  app.env = *get_app_env_lib();
  app.alias = *get_app_alias_lib();
  app.output_mode = *get_app_output_mode_lib();
  app.help = *get_app_help_lib();
  app.error_argv = *get_app_error_argv_lib();
  app.transmit = *get_app_transmit_lib();

  /*
   * Wiring contract (intentional): app module factories are all-or-nothing.
   * If init/shutdown callbacks are present and init_app() succeeds, the
   * execution callbacks consumed by main are expected to be valid as part of
   * that module's factory contract.
   */
  if (!app.opts.init || !app.opts.shutdown ||
      !app.env.init || !app.env.shutdown ||
      !app.env.load_host_user_send_from_ip ||
      !app.env.save_host_user_send_from_ip ||
      !app.env.clear_host_user_send_from_ip ||
      !app.alias.init || !app.alias.shutdown ||
      !app.output_mode.init || !app.output_mode.shutdown ||
      !app.help.init || !app.help.shutdown ||
      !app.error_argv.init || !app.error_argv.shutdown ||
      !app.transmit.init || !app.transmit.shutdown) {
    fprintf(stderr, "Knocker app wiring is incomplete\n");
    return 0;
  }

  if (!app.opts.init(NULL)) {
    fprintf(stderr, "Failed to initialize app.opts\n");
    goto fail;
  }
  opts_initialized = 1;

  if (!app.env.init()) {
    fprintf(stderr, "Failed to initialize app.env\n");
    goto fail;
  }
  env_initialized = 1;

  if (!app.alias.init()) {
    fprintf(stderr, "Failed to initialize app.alias\n");
    goto fail;
  }
  alias_initialized = 1;

  if (!app.output_mode.init()) {
    fprintf(stderr, "Failed to initialize app.output_mode\n");
    goto fail;
  }
  output_mode_initialized = 1;

  if (!app.help.init()) {
    fprintf(stderr, "Failed to initialize app.help\n");
    goto fail;
  }
  help_initialized = 1;

  if (!app.error_argv.init()) {
    fprintf(stderr, "Failed to initialize app.error_argv\n");
    goto fail;
  }
  error_argv_initialized = 1;

  if (!app.transmit.init()) {
    fprintf(stderr, "Failed to initialize app.transmit\n");
    goto fail;
  }
  transmit_initialized = 1;

  return 1;

fail:
  if (transmit_initialized) {
    app.transmit.shutdown();
  }
  if (error_argv_initialized) {
    app.error_argv.shutdown();
  }
  if (help_initialized) {
    app.help.shutdown();
  }
  if (output_mode_initialized) {
    app.output_mode.shutdown();
  }
  if (alias_initialized) {
    app.alias.shutdown();
  }
  if (env_initialized) {
    app.env.shutdown();
  }
  if (opts_initialized) {
    app.opts.shutdown();
  }

  return 0;
}

void shutdown_app(void) {
  app.transmit.shutdown();
  app.error_argv.shutdown();
  app.help.shutdown();
  app.output_mode.shutdown();
  app.alias.shutdown();
  app.env.shutdown();
  app.opts.shutdown();
}
