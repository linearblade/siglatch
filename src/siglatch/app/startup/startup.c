/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "startup.h"

#include <stdio.h>
#include <stdlib.h>

#include "../app.h"
#include "../../lifecycle.h"
#include "../../lib.h"

#ifndef SL_CONFIG_PATH_DEFAULT
#define SL_CONFIG_PATH_DEFAULT "/etc/siglatch/server.conf"
#endif

static int app_startup_init(void) {
  return 1;
}

static void app_startup_shutdown(void) {
}

static void app_startup_reset_state(AppStartupState *state) {
  if (!state) {
    return;
  }

  if (lib.nonce.cache_shutdown) {
    lib.nonce.cache_shutdown(&state->listener.nonce);
  }

  *state = (AppStartupState){0};
  state->listener.sock = -1;
  state->listener.process = &state->process;
  state->exit_code = EXIT_FAILURE;
}

static int app_startup_select_server(const AppParsedOpts *parsed,
                                     const siglatch_config *cfg,
                                     AppRuntimeListenerState *listener_out) {
  const char *cli_server_name = NULL;
  const char *env_server_name = NULL;
  const char *selected_server_name = NULL;
  const char *selected_server_source = NULL;

  if (!parsed || !cfg || !listener_out) {
    return 0;
  }

  cli_server_name = parsed->values.server_name[0] ? parsed->values.server_name : NULL;
  env_server_name = getenv("SIGLATCH_SERVER");

  if (cli_server_name) {
    selected_server_name = cli_server_name;
    selected_server_source = "cli";
  } else if (env_server_name && env_server_name[0] != '\0') {
    selected_server_name = env_server_name;
    selected_server_source = "env";
  } else if (cfg->default_server[0] != '\0') {
    selected_server_name = cfg->default_server;
    selected_server_source = "config";
  } else {
    selected_server_name = "secure";
    selected_server_source = "fallback";
  }

  listener_out->server = app.server.select(selected_server_name);
  if (!listener_out->server) {
    const siglatch_server *candidate_server = app.config.server_by_name(selected_server_name);
    if (candidate_server && !candidate_server->enabled) {
      LOGE("Server block '%s' is disabled in config\n", selected_server_name);
    } else {
      LOGE("Server block '%s' not found in config\n", selected_server_name);
    }
    siglatch_report_config_error();
    return 0;
  }

  LOGD("[startup] Selected server '%s' (source=%s)\n",
       selected_server_name,
       selected_server_source);

  return listener_out->server != NULL;
}

static void app_startup_resolve_output_mode(const AppStartupState *state) {
  const char *env_output_value = NULL;
  int env_output_mode = 0;
  int config_output_mode = 0;

  if (!state || !state->cfg) {
    return;
  }

  if (state->parsed.values.output_mode) {
    lib.print.output_set_mode(state->parsed.values.output_mode);
    return;
  }

  env_output_value = getenv("SIGLATCH_OUTPUT_MODE");
  env_output_mode = lib.print.output_parse_mode(env_output_value);
  if (env_output_mode) {
    lib.print.output_set_mode(env_output_mode);
    return;
  }

  if (env_output_value && *env_output_value) {
    LOGW("Invalid SIGLATCH_OUTPUT_MODE='%s' (expected 'unicode' or 'ascii')\n",
         env_output_value);
  }

  if (state->listener.server && state->listener.server->output_mode) {
    config_output_mode = state->listener.server->output_mode;
  } else if (state->cfg->output_mode) {
    config_output_mode = state->cfg->output_mode;
  }

  if (config_output_mode) {
    lib.print.output_set_mode(config_output_mode);
  }
}

static void app_startup_apply_logging(const AppStartupState *state) {
  if (!state || !state->listener.server) {
    LOGW("LOG FILE NOT DEFINED IN CONFIG - logging disabled.\n");
    lib.log.set_enabled(0);
    return;
  }

  if (*state->listener.server->log_file) {
    lib.log.open(state->listener.server->log_file);
    return;
  }

  LOGW("LOG FILE NOT DEFINED IN CONFIG - logging disabled.\n");
  lib.log.set_enabled(0);
}

static int app_startup_prepare(int argc, char *argv[], AppStartupState *state) {
  const char *config_path = NULL;

  app_startup_reset_state(state);

  if (!state) {
    return 0;
  }

  if (!app.opts.parse(argc, argv, &state->parsed)) {
    if (state->parsed.error[0] != '\0') {
      fprintf(stderr, "%s\n", state->parsed.error);
    }
    app.help.show(argc, argv);
    state->should_exit = 1;
    state->exit_code = state->parsed.exit_code ? state->parsed.exit_code : 2;
    return 1;
  }

  if (state->parsed.values.help_requested) {
    app.help.show(argc, argv);
    state->should_exit = 1;
    state->exit_code = 0;
    return 1;
  }

  app.signal.install(&state->process);
  lib.log.set_enabled(1);
  lib.log.set_debug(1);
  lib.log.set_level(LOG_TRACE);

  LOGE("Launching...\n");
  config_path = state->parsed.values.config_path[0]
                    ? state->parsed.values.config_path
                    : SL_CONFIG_PATH_DEFAULT;

  LOGD("[startup] Loading config from %s\n", config_path);
  if (!app.config.load(config_path)) {
    siglatch_report_config_error();
    return 0;
  }

  state->cfg = app.config.get();
  if (!state->cfg) {
    siglatch_report_config_error();
    return 0;
  }

  if (!app_startup_select_server(&state->parsed, state->cfg, &state->listener)) {
    return 0;
  }

  if (!lib.nonce.cache_init(&state->listener.nonce, NULL)) {
    LOGE("Failed to initialize listener nonce cache\n");
    return 0;
  }

  if (state->parsed.values.dump_config_requested) {
    app.config.dump();
    state->should_exit = 1;
    state->exit_code = 0;
    return 1;
  }

  app_startup_resolve_output_mode(state);

  LOGT("loaded config\n");
  app_startup_apply_logging(state);

  state->exit_code = 0;
  return 1;
}

static const AppStartupLib app_startup_instance = {
  .init = app_startup_init,
  .shutdown = app_startup_shutdown,
  .prepare = app_startup_prepare
};

const AppStartupLib *get_app_startup_lib(void) {
  return &app_startup_instance;
}
