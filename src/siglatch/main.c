/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>      
#include <stdlib.h>     
#include <string.h>     
#include <signal.h>     

#include "config.h"
//#include "config_debug.h"
#include "udp_listener.h"
#include "decrypt.h"
#include "shutdown.h"
#include "signal.h"
#include "daemon.h"
#include "start_opts.h"
#include "help.h"
#include "lib.h"

volatile sig_atomic_t should_exit = 0;

static const char *find_cli_server_override(int argc, char *argv[]) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (strcmp(argv[i], "--server") == 0) {
      if (argv[i + 1] && argv[i + 1][0] != '\0') {
        return argv[i + 1];
      }
      return NULL;
    }
  }

  return NULL;
}

static int has_cli_output_override(int argc, char *argv[]) {
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--output-mode") == 0) {
      return 1;
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--help") == 0) {
      init_lib();
      siglatch_help(argc, argv);
      shutdown_lib();
      return 0;
    }
  }

  init_signals();
  init_lib();
  lib.log.set_enabled(1);
  lib.log.set_debug(1);
  lib.log.set_level(LOG_TRACE);

  LOGE("Launching...\n");
  //siglatch_config *cfg = NULL;//    load_config("/etc/siglatch/config");
  
  lib.config.load("/etc/siglatch/server.conf");
  //lib.config.dump();
  siglatch_config * cfg = (siglatch_config*) lib.config.get();

  if (!cfg){
    shutdown_config_error();
    exit(EXIT_FAILURE);
  }
  {
    const char *cli_server_name = find_cli_server_override(argc, argv);
    const char *env_server_name = getenv("SIGLATCH_SERVER");
    const char *selected_server_name = NULL;
    const char *selected_server_source = NULL;

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

    if (!lib.config.set_current_server(selected_server_name)) {
      const siglatch_server *candidate_server = lib.config.server_by_name(selected_server_name);
      if (candidate_server && !candidate_server->enabled) {
        LOGE("Server block '%s' is disabled in config\n", selected_server_name);
      } else {
        LOGE("Server block '%s' not found in config\n", selected_server_name);
      }
      shutdown_config_error();
      exit(EXIT_FAILURE);
    }

    LOGD("[startup] Selected server '%s' (source=%s)\n",
         selected_server_name,
         selected_server_source);
  }

  if (!start_opts(argc, argv, cfg) )
    exit(0);

  /*
   * Resolve output mode only after startup options have been applied so
   * server-scoped defaults use the final selected server.
   * Precedence: CLI (--output-mode) > SIGLATCH_OUTPUT_MODE > server/global config.
   */
  if (!has_cli_output_override(argc, argv)) {
    const char *env_output_value = getenv("SIGLATCH_OUTPUT_MODE");
    int env_output_mode = lib.print.output_parse_mode(env_output_value);
    if (env_output_mode) {
      lib.print.output_set_mode(env_output_mode);
    } else {
      int config_output_mode = 0;
      if (env_output_value && *env_output_value) {
        LOGW("Invalid SIGLATCH_OUTPUT_MODE='%s' (expected 'unicode' or 'ascii')\n",
             env_output_value);
      }

      if (cfg->current_server && cfg->current_server->output_mode) {
        config_output_mode = cfg->current_server->output_mode;
      } else if (cfg->output_mode) {
        config_output_mode = cfg->output_mode;
      }

      if (config_output_mode) {
        lib.print.output_set_mode(config_output_mode);
      }
    }
  }

  LOGT("loaded config\n");

  if (cfg && cfg->current_server && *cfg->current_server->log_file) {
    lib.log.open(cfg->current_server->log_file);
  }else {
    LOGW("LOG FILE NOT DEFINED IN CONFIG - logging disabled.\n");
    lib.log.set_enabled(0);
  }

  int sock = start_udp_listener(cfg);
  if (sock < 0) shutdown_socket_error(cfg);
  siglatch_daemon(cfg, sock);
  
  return shutdown_OK(cfg,sock);
}
