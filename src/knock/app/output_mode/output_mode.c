/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "output_mode.h"

#include <stdio.h>
#include <stdlib.h>

#include "../app.h"
#include "../../lib.h"

static int app_output_mode_init(void) {
  return 1;
}

static void app_output_mode_shutdown(void) {
}

static void app_output_mode_set_from_config(void) {
  int config_output_mode = app.env.load_output_mode_default();

  if (config_output_mode) {
    lib.print.output_set_mode(config_output_mode);
  }
}

static void app_output_mode_set_from_env(void) {
  const char *env_output_value = getenv("SIGLATCH_OUTPUT_MODE");
  int env_output_mode = lib.print.output_parse_mode(env_output_value);
  if (env_output_mode) {
    lib.print.output_set_mode(env_output_mode);
  } else if (env_output_value && *env_output_value) {
    fprintf(stderr,
            "Invalid SIGLATCH_OUTPUT_MODE '%s' (expected 'unicode' or 'ascii')\n",
            env_output_value);
  }
}

static void app_output_mode_set_from_opts(const Opts *opts) {
  if (!opts) {
    return;
  }

  if (opts->output_mode) {
    lib.print.output_set_mode(opts->output_mode);
  }
}

static const AppOutputModeLib app_output_mode_instance = {
  .init = app_output_mode_init,
  .shutdown = app_output_mode_shutdown,
  .set_from_config = app_output_mode_set_from_config,
  .set_from_env = app_output_mode_set_from_env,
  .set_from_opts = app_output_mode_set_from_opts
};

const AppOutputModeLib *get_app_output_mode_lib(void) {
  return &app_output_mode_instance;
}
