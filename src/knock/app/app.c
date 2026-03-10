/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "app.h"
#include <stddef.h>

App app = {
  .opts = {0},
  .env = {0},
  .alias = {0},
  .output_mode = {0},
  .help = {0},
  .error_argv = {0},
  .transmit = {0}
};

void init_app(void) {
  app.opts = *get_app_opts_lib();
  app.env = *get_app_env_lib();
  app.alias = *get_app_alias_lib();
  app.output_mode = *get_app_output_mode_lib();
  app.help = *get_app_help_lib();
  app.error_argv = *get_app_error_argv_lib();
  app.transmit = *get_app_transmit_lib();

  app.opts.init(NULL);
  app.env.init();
  app.alias.init();
  app.output_mode.init();
  app.help.init();
  app.error_argv.init();
  app.transmit.init();
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
