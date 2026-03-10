/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "help.h"

#include <stdio.h>
#include <string.h>

#include "../print_help.h"

static int app_help_init(void) {
  return 1;
}

static void app_help_shutdown(void) {
}

static int app_help_is_help(int argc, char *argv[]) {
  if (argc < 2) {
    return 1;
  }

  if (argc > 1 && argv && argv[1] && strcmp(argv[1], "--help") == 0) {
    return 1;
  }

  return 0;
}

static void app_help_print_help(void) {
  printHelp();
}

static void app_help_error_message(void) {
  fprintf(stderr, "Use --help for usage.\n");
}

static void app_help_handle_parse_result(int argc, char *argv[], const Opts *opts) {
  if (opts && opts->response_type == OPTS_RESPONSE_HELP) {
    app_help_print_help();
    return;
  }

  if (app_help_is_help(argc, argv)) {
    app_help_print_help();
    return;
  }

  app_help_error_message();
}

static const AppHelpLib app_help_instance = {
  .init = app_help_init,
  .shutdown = app_help_shutdown,
  .isHelp = app_help_is_help,
  .printHelp = app_help_print_help,
  .errorMessage = app_help_error_message,
  .handleParseResult = app_help_handle_parse_result
};

const AppHelpLib *get_app_help_lib(void) {
  return &app_help_instance;
}
