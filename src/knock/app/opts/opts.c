/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "opts.h"
#include "alias.h"
#include "transmit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../lib.h"

static AppOptsAliasLib app_opts_alias = {0};
static AppOptsTransmitLib app_opts_transmit = {0};

static int app_opts_init(const AppOptsContext *ctx) {
  (void)ctx;
  app_opts_alias = *get_app_opts_alias_lib();
  app_opts_transmit = *get_app_opts_transmit_lib();
  if (!app_opts_alias.init()) {
    return 0;
  }

  if (!app_opts_transmit.init()) {
    app_opts_alias.shutdown();
    return 0;
  }

  return 1;
}

static void app_opts_shutdown(void) {
  app_opts_transmit.shutdown();
  app_opts_alias.shutdown();
}

typedef enum {
  APP_OPTS_PARSE_MODE_HELP = 0,
  APP_OPTS_PARSE_MODE_OUTPUT_MODE_DEFAULT,
  APP_OPTS_PARSE_MODE_ALIAS,
  APP_OPTS_PARSE_MODE_TRANSMIT
} AppOptsParseMode;

static int app_opts_set_error(AppCommand *out, int exit_code, const char *message) {
  if (!out) {
    return 0;
  }

  out->type = APP_CMD_ERROR;
  out->ok = 0;
  out->exit_code = exit_code;

  if (message && *message) {
    snprintf(out->error, sizeof(out->error), "%s", message);
  } else {
    out->error[0] = '\0';
  }
  return 0;
}

static AppOptsParseMode app_opts_get_parse_mode(int argc, char *argv[]) {
  if (argc < 2 || !argv || !argv[1]) {
    return APP_OPTS_PARSE_MODE_HELP;
  }

  if (strcmp(argv[1], "--output-mode-default") == 0) {
    return APP_OPTS_PARSE_MODE_OUTPUT_MODE_DEFAULT;
  }

  if (strcmp(argv[1], "--help") == 0) {
    return APP_OPTS_PARSE_MODE_HELP;
  }

  if (strncmp(argv[1], "--alias", 7) == 0) {
    return APP_OPTS_PARSE_MODE_ALIAS;
  }

  return APP_OPTS_PARSE_MODE_TRANSMIT;
}

static int app_opts_parse_output_mode_default(int argc, char *argv[], AppCommand *out) {
  int mode = 0;
  char message[256];

  if (argc < 3) {
    return app_opts_set_error(out, 2,
                              "Not enough arguments for --output-mode-default (expected 'unicode' or 'ascii')");
  }

  mode = lib.print.output_parse_mode(argv[2]);
  if (!mode) {
    snprintf(message, sizeof(message),
             "Invalid output mode default: %s (expected 'unicode' or 'ascii')",
             argv[2] ? argv[2] : "(null)");
    return app_opts_set_error(out, 2, message);
  }

  out->type = APP_CMD_OUTPUT_MODE_DEFAULT;
  out->ok = 1;
  out->exit_code = 0;
  out->as.outdef.mode = mode;
  return 1;
}

static int app_opts_parse_command(int argc, char *argv[], AppCommand *out) {
  AppOptsParseMode parse_mode = APP_OPTS_PARSE_MODE_TRANSMIT;

  if (!out) {
    return 0;
  }

  memset(out, 0, sizeof(*out));
  out->type = APP_CMD_ERROR;
  out->ok = 0;
  out->exit_code = 2;

  parse_mode = app_opts_get_parse_mode(argc, argv);
  switch (parse_mode) {
    case APP_OPTS_PARSE_MODE_HELP:
      out->type = APP_CMD_HELP;
      out->ok = 1;
      out->exit_code = 0;
      return 1;
    case APP_OPTS_PARSE_MODE_OUTPUT_MODE_DEFAULT:
      return app_opts_parse_output_mode_default(argc, argv, out);
    case APP_OPTS_PARSE_MODE_ALIAS:
      return app_opts_alias.parse(argc, argv, out);
    case APP_OPTS_PARSE_MODE_TRANSMIT:
      out->type = APP_CMD_TRANSMIT;
      if (!app_opts_transmit.parse(argc, argv, &out->as.transmit, &out->dump_requested)) {
        out->type = APP_CMD_ERROR;
        out->ok = 0;
        out->exit_code = 2;
        return 0;
      }
      out->ok = 1;
      out->exit_code = 0;
      return 1;
    default:
      return app_opts_set_error(out, 2, "Unknown parse mode");
  }
}

static void app_opts_dump_command(const AppCommand *cmd) {
  if (!cmd) {
    lib.print.uc_fprintf(stderr, "err", "Dump requested with NULL command\n");
    return;
  }

  switch (cmd->type) {
    case APP_CMD_TRANSMIT:
      app_opts_transmit.dump(&cmd->as.transmit);
      break;
    case APP_CMD_ALIAS:
      app_opts_alias.dump(&cmd->as.alias);
      break;
    case APP_CMD_OUTPUT_MODE_DEFAULT:
      lib.print.uc_printf("debug", "Dumping Output Mode Default Command:\n");
      lib.print.uc_printf(NULL, "  Mode             : %s (%d)\n",
                          lib.print.output_mode_name(cmd->as.outdef.mode),
                          cmd->as.outdef.mode);
      break;
    case APP_CMD_HELP:
      lib.print.uc_printf("debug", "Dumping Help Command:\n");
      lib.print.uc_printf(NULL, "  Type             : help\n");
      break;
    case APP_CMD_ERROR:
    default:
      lib.print.uc_printf("debug", "Dumping Error Command:\n");
      lib.print.uc_printf(NULL, "  Exit Code        : %d\n", cmd->exit_code);
      lib.print.uc_printf(NULL, "  Error            : %s\n",
                          cmd->error[0] ? cmd->error : "(none)");
      break;
  }
}

static const AppOptsLib app_opts_instance = {
  .init = app_opts_init,
  .shutdown = app_opts_shutdown,
  .parse_command = app_opts_parse_command,
  .dump_command = app_opts_dump_command
};

const AppOptsLib *get_app_opts_lib(void) {
  return &app_opts_instance;
}
