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
#include "../app.h"

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

typedef int (*AppOptsModeParseFn)(const char *mode_selector, const ArgvParsed *parsed, AppCommand *out);

typedef struct {
  int argv_offset;
  const ArgvOptionSpec *spec;
  AppOptsModeParseFn parse;
} AppOptsModeParser;

enum {
  OPT_ID_OUTPUT_MODE_DEFAULT = 1,
  OPT_ID_OUTPUT_MODE_DEFAULT_DUMP
};

static const ArgvOptionSpec output_mode_default_specs[] = {
  { "--output-mode-default", OPT_ID_OUTPUT_MODE_DEFAULT,      1, ARGV_OPT_KEYED, 1, 0, 1 },
  { "--opts-dump", OPT_ID_OUTPUT_MODE_DEFAULT_DUMP, 0, ARGV_OPT_FLAG, 0, 0, 1 },
  { NULL, 0, 0, ARGV_OPT_FLAG, 0, 0, 0 }
};

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

static int app_opts_set_argv_error(AppCommand *out, const ArgvParsed *parsed) {
  char message[256];

  if (app.error_argv.shape && app.error_argv.shape(parsed, message, sizeof(message))) {
    return app_opts_set_error(out, 2, message);
  }

  return app_opts_set_error(out, 2, "Argument parse error");
}

static int app_opts_set_typed_error(AppCommand *out, const ArgvParsedOption *opt, const ArgvError *err) {
  char message[256];

  if (app.error_argv.shape_typed && app.error_argv.shape_typed(opt, err, message, sizeof(message))) {
    return app_opts_set_error(out, 2, message);
  }

  return app_opts_set_error(out, 2, "Invalid option value");
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

static int app_opts_parse_output_mode_default(const char *mode_selector, const ArgvParsed *parsed, AppCommand *out) {
  static const ArgvEnumMap output_mode_map[] = {
    { "unicode", SL_OUTPUT_MODE_UNICODE },
    { "ascii", SL_OUTPUT_MODE_ASCII }
  };
  const ArgvParsedOption *mode_opt = NULL;
  ArgvError parse_err = {0};
  char message[256];
  int mode = 0;

  (void)mode_selector;

  if (!parsed || !out) {
    return 0;
  }

  mode_opt = lib.argv.find_first_by_id(parsed, OPT_ID_OUTPUT_MODE_DEFAULT);
  if (!mode_opt) {
    return app_opts_set_error(out, 2, "Missing --output-mode-default parse payload");
  }

  if (parsed->num_positionals > 0) {
    snprintf(message, sizeof(message),
             "Too many positional arguments for --output-mode-default");
    return app_opts_set_error(out, 2, message);
  }

  if (!lib.argv.get_enum(mode_opt, 0, output_mode_map,
                         sizeof(output_mode_map) / sizeof(output_mode_map[0]),
                         &mode, &parse_err)) {
    return app_opts_set_typed_error(out, mode_opt, &parse_err);
  }

  out->type = APP_CMD_OUTPUT_MODE_DEFAULT;
  out->ok = 1;
  out->exit_code = 0;
  out->dump_requested = lib.argv.has(parsed, "--opts-dump") ? 1 : 0;
  out->as.outdef.mode = mode;
  return 1;
}

static int app_opts_get_mode_parser(AppOptsParseMode parse_mode, AppOptsModeParser *out) {
  if (!out) {
    return 0;
  }

  memset(out, 0, sizeof(*out));

  switch (parse_mode) {
    case APP_OPTS_PARSE_MODE_OUTPUT_MODE_DEFAULT:
      out->argv_offset = 0;
      out->spec = output_mode_default_specs;
      out->parse = app_opts_parse_output_mode_default;
      return 1;
    case APP_OPTS_PARSE_MODE_ALIAS:
      out->argv_offset = 1;
      out->spec = app_opts_alias.spec ? app_opts_alias.spec() : NULL;
      out->parse = app_opts_alias.parse;
      return 1;
    case APP_OPTS_PARSE_MODE_TRANSMIT:
      out->argv_offset = 0;
      out->spec = app_opts_transmit.spec ? app_opts_transmit.spec() : NULL;
      out->parse = app_opts_transmit.parse;
      return 1;
    case APP_OPTS_PARSE_MODE_HELP:
    default:
      return 0;
  }
}

static int app_opts_parse_command(int argc, char *argv[], AppCommand *out) {
  AppOptsParseMode parse_mode = APP_OPTS_PARSE_MODE_TRANSMIT;
  AppOptsModeParser mode_parser = {0};
  ArgvParsed parsed = {0};
  const char *mode_selector = NULL;
  int parse_argc = 0;
  char **parse_argv = NULL;

  if (!out) {
    return 0;
  }

  memset(out, 0, sizeof(*out));
  out->type = APP_CMD_ERROR;
  out->ok = 0;
  out->exit_code = 2;

  parse_mode = app_opts_get_parse_mode(argc, argv);
  mode_selector = (argc > 1 && argv && argv[1]) ? argv[1] : NULL;
  switch (parse_mode) {
    case APP_OPTS_PARSE_MODE_HELP:
      out->type = APP_CMD_HELP;
      out->ok = 1;
      out->exit_code = 0;
      return 1;
    case APP_OPTS_PARSE_MODE_OUTPUT_MODE_DEFAULT:
    case APP_OPTS_PARSE_MODE_ALIAS:
    case APP_OPTS_PARSE_MODE_TRANSMIT:
      break;
    default:
      return app_opts_set_error(out, 2, "Unknown parse mode");
  }

  if (!app_opts_get_mode_parser(parse_mode, &mode_parser) ||
      !mode_parser.spec || !mode_parser.parse) {
    return app_opts_set_error(out, 2, "Parser mode wiring is incomplete");
  }

  parse_argc = argc - mode_parser.argv_offset;
  parse_argv = argv + mode_parser.argv_offset;
  if (parse_argc < 1 || !parse_argv) {
    return app_opts_set_error(out, 2, "Invalid parser argv state");
  }

  if (!lib.argv.parse(parse_argc, parse_argv, &parsed, mode_parser.spec)) {
    return app_opts_set_argv_error(out, &parsed);
  }

  if (!mode_parser.parse(mode_selector, &parsed, out)) {
    if (!out->error[0]) {
      app_opts_set_error(out, 2, "Invalid command arguments");
    }
    return 0;
  }

  return 1;
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
