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

static int app_error_argv_shape_typed(const ArgvParsedOption *opt, const ArgvError *err,
                                      char *out, size_t out_size) {
  const char *option_name = "(unknown)";
  const char *value = NULL;
  int written = 0;

  if (!out || out_size == 0) {
    return 0;
  }

  out[0] = '\0';

  if (opt && opt->spec && opt->spec->name && *opt->spec->name) {
    option_name = opt->spec->name;
  }

  if (lib.argv.option_value) {
    value = lib.argv.option_value(opt, 0);
  }

  switch (err ? err->code : ARGV_ERR_NONE) {
    case ARGV_ERR_BAD_INTEGER:
      written = snprintf(out, out_size, "Invalid numeric value for %s: %s",
                         option_name, value ? value : "(null)");
      break;
    case ARGV_ERR_INTEGER_OUT_OF_RANGE:
      written = snprintf(out, out_size, "Out-of-range value for %s: %s",
                         option_name, value ? value : "(null)");
      break;
    case ARGV_ERR_BAD_ENUM:
      written = snprintf(out, out_size, "Invalid value for %s: %s",
                         option_name, value ? value : "(null)");
      break;
    default:
      written = snprintf(out, out_size, "Invalid option value for %s", option_name);
      break;
  }

  if (written < 0 || (size_t)written >= out_size) {
    return 0;
  }

  return 1;
}

static int app_error_argv_shape(const ArgvParsed *parsed, char *out, size_t out_size) {
  char detail[256];
  const ArgvError *err = NULL;
  int written = 0;

  if (!out || out_size == 0) {
    return 0;
  }

  out[0] = '\0';
  if (!parsed) {
    written = snprintf(out, out_size, "Argument parse failed");
    return written >= 0 && (size_t)written < out_size;
  }

  err = &parsed->error;
  switch (err->code) {
    case ARGV_ERR_UNKNOWN_OPTION:
      written = snprintf(out, out_size, "Unknown option: %s",
                         err->arg_value ? err->arg_value : "(null)");
      break;
    case ARGV_ERR_NOT_ENOUGH_OPTION_ARGS:
      written = snprintf(out, out_size, "Not enough arguments for option: %s",
                         err->arg_value ? err->arg_value :
                         (err->option_name ? err->option_name : "(null)"));
      break;
    case ARGV_ERR_TOO_MANY_OPTIONS:
      written = snprintf(out, out_size, "Too many options (max %d)", ARGV_MAX_OPTIONS);
      break;
    case ARGV_ERR_TOO_MANY_POSITIONALS:
      written = snprintf(out, out_size, "Too many positional arguments (max %d)", ARGV_MAX_POSITIONALS);
      break;
    case ARGV_ERR_DUPLICATE_OPTION:
      written = snprintf(out, out_size, "Duplicate option not allowed: %s",
                         err->option_name ? err->option_name : "(null)");
      break;
    case ARGV_ERR_EQUALS_FORM_NOT_ALLOWED:
      written = snprintf(out, out_size, "Option does not accept --key=value form: %s",
                         err->option_name ? err->option_name : "(null)");
      break;
    default:
      if (lib.argv.format_error && lib.argv.format_error(err, detail, sizeof(detail))) {
        written = snprintf(out, out_size, "Argument parse error: %s", detail);
      } else {
        written = snprintf(out, out_size, "Argument parse error");
      }
      break;
  }

  if (written < 0 || (size_t)written >= out_size) {
    return 0;
  }

  return 1;
}

static const AppErrorArgvLib app_error_argv_instance = {
  .init = app_error_argv_init,
  .shutdown = app_error_argv_shutdown,
  .shape = app_error_argv_shape,
  .shape_typed = app_error_argv_shape_typed
};

const AppErrorArgvLib *get_app_error_argv_lib(void) {
  return &app_error_argv_instance;
}
