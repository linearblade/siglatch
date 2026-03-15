/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "lib.h"
#include "app/app.h"
#include "../shared/shared.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
  int status = 1;
  int lib_initialized = 0;
  int shared_initialized = 0;
  int app_initialized = 0;
  AppCommand cmd = {0};

  if (!init_lib()) {
    fprintf(stderr, "Failed to initialize knocker library runtime\n");
    goto cleanup;
  }
  lib_initialized = 1;

  {
    SharedContext shared_ctx = {
      .log = &lib.log,
      .openssl = &lib.openssl,
      .print = &lib.print
    };

    if (!init_shared(&shared_ctx)) {
      fprintf(stderr, "Failed to initialize knocker shared runtime\n");
      goto cleanup;
    }
  }
  shared_initialized = 1;

  if (!init_app()) {
    fprintf(stderr, "Failed to initialize knocker app runtime\n");
    goto cleanup;
  }
  app_initialized = 1;

  app.output_mode.set_from_config();
  app.output_mode.set_from_env();

  if (!app.opts.parse_command || !app.opts.parse_command(argc, argv, &cmd)) {
    if (cmd.error[0] != '\0') {
      lib.print.uc_fprintf(stderr, "err", "%s\n", cmd.error);
    }
    app.help.errorMessage();
    status = cmd.exit_code ? cmd.exit_code : 2;
    goto cleanup;
  }

  if (cmd.type == APP_CMD_TRANSMIT) {
    app.output_mode.set_from_opts(&cmd.as.transmit);
  } else if (cmd.type == APP_CMD_ALIAS && cmd.as.alias.output_mode) {
    lib.print.output_set_mode(cmd.as.alias.output_mode);
  }

  if (cmd.dump_requested) {
    if (app.opts.dump_command) {
      app.opts.dump_command(&cmd);
      status = 0;
    } else {
      lib.print.uc_fprintf(stderr, "err", "Dump requested but dump handler is unavailable\n");
      status = 2;
    }
    goto cleanup;
  }

  switch (cmd.type) {
    case APP_CMD_HELP:
      app.help.printHelp();
      status = 0;
      break;
    case APP_CMD_OUTPUT_MODE_DEFAULT: {
      const char *mode_name = lib.print.output_mode_name(cmd.as.outdef.mode);
      if (!mode_name || strcmp(mode_name, "unknown") == 0) {
        lib.print.uc_fprintf(stderr, "err", "Invalid output mode command payload\n");
        status = 2;
        break;
      }
      status = app.env.save_output_mode_default(mode_name) ? 0 : 2;
      break;
    }
    case APP_CMD_ALIAS:
      status = app.alias.execute(&cmd.as.alias) ? 0 : 2;
      break;
    case APP_CMD_TRANSMIT:
      lib.log.open(cmd.as.transmit.log_file);
      lib.log.set_debug(cmd.as.transmit.verbose ? 1 : 0);
      lib.log.set_level(cmd.as.transmit.verbose);
      status = app.transmit.singlePacket(&cmd.as.transmit);
      break;
    case APP_CMD_ERROR:
    default:
      if (cmd.error[0] != '\0') {
        lib.print.uc_fprintf(stderr, "err", "%s\n", cmd.error);
      }
      app.help.errorMessage();
      status = cmd.exit_code ? cmd.exit_code : 2;
      break;
  }

cleanup:
  if (app_initialized) {
    shutdown_app();
  }
  if (shared_initialized) {
    shutdown_shared();
  }
  if (lib_initialized) {
    shutdown_lib();
  }
  return status;
}
