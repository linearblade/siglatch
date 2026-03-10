/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "argv.h"

#include <stdio.h>

#include "../../lib.h"

static int app_error_argv_init(void) {
  return 1;
}

static void app_error_argv_shutdown(void) {
}

static int app_error_argv_parse(const ArgvParsed *parsed) {
  char detail[256];
  const ArgvError *err = NULL;

  if (!parsed) {
    lib.print.uc_fprintf(stderr, "err", "Argument parse failed\n");
    return 0;
  }

  err = &parsed->error;
  switch (err->code) {
    case ARGV_ERR_UNKNOWN_OPTION:
      lib.print.uc_fprintf(stderr, "err", "Unknown option: %s\n", err->arg_value ? err->arg_value : "(null)");
      return 0;
    case ARGV_ERR_NOT_ENOUGH_OPTION_ARGS:
      lib.print.uc_fprintf(stderr, "err", "Not enough arguments for option: %s\n",
                           err->arg_value ? err->arg_value :
                           (err->option_name ? err->option_name : "(null)"));
      return 0;
    case ARGV_ERR_TOO_MANY_OPTIONS:
      lib.print.uc_fprintf(stderr, "err", "Too many options (max %d)\n", ARGV_MAX_OPTIONS);
      return 0;
    case ARGV_ERR_TOO_MANY_POSITIONALS:
      lib.print.uc_fprintf(stderr, "err", "Too many positional arguments (max %d)\n", ARGV_MAX_POSITIONALS);
      return 0;
    case ARGV_ERR_DUPLICATE_OPTION:
      lib.print.uc_fprintf(stderr, "err", "Duplicate option not allowed: %s\n",
                           err->option_name ? err->option_name : "(null)");
      return 0;
    case ARGV_ERR_EQUALS_FORM_NOT_ALLOWED:
      lib.print.uc_fprintf(stderr, "err", "Option does not accept --key=value form: %s\n",
                           err->option_name ? err->option_name : "(null)");
      return 0;
    default:
      break;
  }

  if (lib.argv.format_error && lib.argv.format_error(err, detail, sizeof(detail))) {
    lib.print.uc_fprintf(stderr, "err", "Argument parse error: %s\n", detail);
  } else {
    lib.print.uc_fprintf(stderr, "err", "Argument parse error\n");
  }

  return 0;
}

static int app_error_argv_typed(const ArgvParsedOption *opt, const ArgvError *err) {
  const char *option_name = "(unknown)";
  const char *value = NULL;

  if (opt && opt->spec && opt->spec->name) {
    option_name = opt->spec->name;
  }

  if (lib.argv.option_value) {
    value = lib.argv.option_value(opt, 0);
  }

  switch (err ? err->code : ARGV_ERR_NONE) {
    case ARGV_ERR_BAD_INTEGER:
      lib.print.uc_fprintf(stderr, "err", "Invalid numeric value for %s: %s\n",
                           option_name, value ? value : "(null)");
      return 0;
    case ARGV_ERR_INTEGER_OUT_OF_RANGE:
      lib.print.uc_fprintf(stderr, "err", "Out-of-range value for %s: %s\n",
                           option_name, value ? value : "(null)");
      return 0;
    case ARGV_ERR_BAD_ENUM:
      lib.print.uc_fprintf(stderr, "err", "Invalid value for %s: %s\n",
                           option_name, value ? value : "(null)");
      return 0;
    default:
      lib.print.uc_fprintf(stderr, "err", "Invalid option value for %s\n", option_name);
      return 0;
  }
}

static const AppErrorArgvLib app_error_argv_instance = {
  .init = app_error_argv_init,
  .shutdown = app_error_argv_shutdown,
  .parse = app_error_argv_parse,
  .typed = app_error_argv_typed
};

const AppErrorArgvLib *get_app_error_argv_lib(void) {
  return &app_error_argv_instance;
}
