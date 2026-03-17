/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "opts.h"

#include <stdio.h>
#include <string.h>

#include "../../lib.h"

enum {
  OPT_ID_HELP = 1,
  OPT_ID_DUMP_CONFIG,
  OPT_ID_OUTPUT_MODE,
  OPT_ID_CONFIG,
  OPT_ID_SERVER
};

static const ArgvOptionSpec app_opts_specs[] = {
  { "--help", OPT_ID_HELP, 0, ARGV_OPT_FLAG, 0, 1, 1 },
  { "--dump-config", OPT_ID_DUMP_CONFIG, 0, ARGV_OPT_FLAG, 0, 1, 1 },
  { "--output-mode", OPT_ID_OUTPUT_MODE, 1, ARGV_OPT_KEYED, 0, 1, 1 },
  { "--config", OPT_ID_CONFIG, 1, ARGV_OPT_KEYED, 0, 1, 1 },
  { "--server", OPT_ID_SERVER, 1, ARGV_OPT_KEYED, 0, 1, 1 },
  { NULL, 0, 0, ARGV_OPT_FLAG, 0, 0, 0 }
};

static const ArgvEnumMap output_mode_map[] = {
  { "unicode", SL_OUTPUT_MODE_UNICODE },
  { "ascii", SL_OUTPUT_MODE_ASCII }
};

static int app_opts_init(const AppOptsContext *ctx) {
  (void)ctx;
  return 1;
}

static void app_opts_shutdown(void) {
}

static int app_opts_set_error(AppParsedOpts *out, int exit_code, const char *message) {
  if (!out) {
    return 0;
  }

  out->ok = 0;
  out->exit_code = exit_code;

  if (message && *message) {
    snprintf(out->error, sizeof(out->error), "%s", message);
  } else {
    out->error[0] = '\0';
  }

  return 0;
}

static int app_opts_set_argv_error(AppParsedOpts *out, const ArgvParsed *parsed) {
  const ArgvError *err = NULL;
  char message[256];

  if (!out) {
    return 0;
  }

  if (!parsed) {
    return app_opts_set_error(out, 2, "Argument parse error");
  }

  err = &parsed->error;
  switch (err->code) {
    case ARGV_ERR_UNKNOWN_OPTION:
      snprintf(message, sizeof(message), "Unknown option: %s",
               err->arg_value ? err->arg_value : "(null)");
      return app_opts_set_error(out, 2, message);
    case ARGV_ERR_NOT_ENOUGH_OPTION_ARGS:
      snprintf(message, sizeof(message), "Not enough arguments for option: %s",
               err->arg_value ? err->arg_value :
               (err->option_name ? err->option_name : "(null)"));
      return app_opts_set_error(out, 2, message);
    case ARGV_ERR_TOO_MANY_OPTIONS:
      snprintf(message, sizeof(message), "Too many options (max %d)", ARGV_MAX_OPTIONS);
      return app_opts_set_error(out, 2, message);
    case ARGV_ERR_TOO_MANY_POSITIONALS:
      snprintf(message, sizeof(message), "Too many positional arguments (max %d)", ARGV_MAX_POSITIONALS);
      return app_opts_set_error(out, 2, message);
    case ARGV_ERR_DUPLICATE_OPTION:
      snprintf(message, sizeof(message), "Duplicate option not allowed: %s",
               err->option_name ? err->option_name : "(null)");
      return app_opts_set_error(out, 2, message);
    case ARGV_ERR_EQUALS_FORM_NOT_ALLOWED:
      snprintf(message, sizeof(message), "Option does not accept --key=value form: %s",
               err->option_name ? err->option_name : "(null)");
      return app_opts_set_error(out, 2, message);
    default:
      break;
  }

  if (parsed && lib.argv.format_error &&
      lib.argv.format_error(&parsed->error, message, sizeof(message))) {
    return app_opts_set_error(out, 2, message);
  }

  return app_opts_set_error(out, 2, "Argument parse error");
}

static int app_opts_set_typed_error(AppParsedOpts *out, const ArgvParsedOption *opt, const ArgvError *err) {
  const char *option_name = "--option";
  const char *value = NULL;
  char message[256];

  if (!out) {
    return 0;
  }

  if (opt && opt->spec && opt->spec->name && *opt->spec->name) {
    option_name = opt->spec->name;
  }
  if (opt && lib.argv.option_value) {
    value = lib.argv.option_value(opt, 0);
  }

  switch (err ? err->code : ARGV_ERR_NONE) {
    case ARGV_ERR_BAD_ENUM:
      snprintf(message, sizeof(message), "Invalid value for %s: %s",
               option_name, value ? value : "(null)");
      break;
    default:
      snprintf(message, sizeof(message), "Invalid option value for %s",
               option_name);
      break;
  }

  return app_opts_set_error(out, 2, message);
}

static int app_opts_help_requested(int argc, char *argv[]) {
  int i;

  if (!argv) {
    return 0;
  }

  for (i = 1; i < argc; ++i) {
    if (argv[i] && strcmp(argv[i], "--help") == 0) {
      return 1;
    }
  }

  return 0;
}

static int app_opts_reject_positionals(AppParsedOpts *out, const ArgvParsed *parsed) {
  char message[256];

  if (!parsed || parsed->num_positionals == 0) {
    return 1;
  }

  snprintf(message, sizeof(message), "Unexpected positional argument: %s",
           parsed->positionals[0] ? parsed->positionals[0] : "(null)");
  return app_opts_set_error(out, 2, message);
}

static int app_opts_reject_equals_form(AppParsedOpts *out,
                                       const ArgvParsedOption *opt,
                                       int argc,
                                       char *argv[]) {
  const char *raw_arg = NULL;
  const char *option_name = "--option";
  char message[256];

  if (!opt) {
    return 1;
  }

  if (opt->spec && opt->spec->name && *opt->spec->name) {
    option_name = opt->spec->name;
  }

  if (opt->source_index < 0 || opt->source_index >= argc || !argv) {
    return 1;
  }

  raw_arg = argv[opt->source_index];
  if (!raw_arg || !strchr(raw_arg, '=')) {
    return 1;
  }

  snprintf(message, sizeof(message), "Option does not accept --key=value form: %s",
           option_name);
  return app_opts_set_error(out, 2, message);
}

static int app_opts_copy_server_name(AppParsedOpts *out, const char *value) {
  int written = 0;

  if (!out || !value) {
    return app_opts_set_error(out, 2, "Invalid --server value");
  }

  if (value[0] == '\0') {
    return app_opts_set_error(out, 2, "Invalid --server value (empty)");
  }

  written = snprintf(out->values.server_name, sizeof(out->values.server_name), "%s", value);
  if (written < 0 || (size_t)written >= sizeof(out->values.server_name)) {
    return app_opts_set_error(out, 2, "Server name is too long");
  }

  return 1;
}

static int app_opts_copy_config_path(AppParsedOpts *out, const char *value) {
  int written = 0;

  if (!out || !value) {
    return app_opts_set_error(out, 2, "Invalid --config value");
  }

  if (value[0] == '\0') {
    return app_opts_set_error(out, 2, "Invalid --config value (empty)");
  }

  written = snprintf(out->values.config_path, sizeof(out->values.config_path), "%s", value);
  if (written < 0 || (size_t)written >= sizeof(out->values.config_path)) {
    return app_opts_set_error(out, 2, "Config path is too long");
  }

  return 1;
}

static int app_opts_parse(int argc, char *argv[], AppParsedOpts *out) {
  ArgvParsed parsed = {0};
  const ArgvParsedOption *output_mode_opt = NULL;
  const ArgvParsedOption *config_opt = NULL;
  const ArgvParsedOption *server_opt = NULL;
  ArgvError parse_err = {0};
  const char *config_path = NULL;
  const char *server_name = NULL;

  if (!out) {
    return 0;
  }

  memset(out, 0, sizeof(*out));
  out->exit_code = 2;

  if (argc < 1 || !argv) {
    return app_opts_set_error(out, 2, "Invalid argv state");
  }

  if (app_opts_help_requested(argc, argv)) {
    out->ok = 1;
    out->exit_code = 0;
    out->values.help_requested = 1;
    return 1;
  }

  if (!lib.argv.parse(argc, argv, &parsed, app_opts_specs)) {
    return app_opts_set_argv_error(out, &parsed);
  }

  if (!app_opts_reject_positionals(out, &parsed)) {
    return 0;
  }

  output_mode_opt = lib.argv.find_last_by_id(&parsed, OPT_ID_OUTPUT_MODE);
  if (output_mode_opt) {
    if (!app_opts_reject_equals_form(out, output_mode_opt, argc, argv)) {
      return 0;
    }

    if (!lib.argv.get_enum(output_mode_opt, 0,
                           output_mode_map,
                           sizeof(output_mode_map) / sizeof(output_mode_map[0]),
                           &out->values.output_mode,
                           &parse_err)) {
      return app_opts_set_typed_error(out, output_mode_opt, &parse_err);
    }
  }

  config_opt = lib.argv.find_last_by_id(&parsed, OPT_ID_CONFIG);
  if (config_opt) {
    if (!app_opts_reject_equals_form(out, config_opt, argc, argv)) {
      return 0;
    }

    config_path = lib.argv.option_value ? lib.argv.option_value(config_opt, 0) : NULL;
    if (!app_opts_copy_config_path(out, config_path)) {
      return 0;
    }
  }

  server_opt = lib.argv.find_last_by_id(&parsed, OPT_ID_SERVER);
  if (server_opt) {
    if (!app_opts_reject_equals_form(out, server_opt, argc, argv)) {
      return 0;
    }

    server_name = lib.argv.option_value ? lib.argv.option_value(server_opt, 0) : NULL;
    if (!app_opts_copy_server_name(out, server_name)) {
      return 0;
    }
  }

  out->ok = 1;
  out->exit_code = 0;
  out->values.dump_config_requested = lib.argv.has(&parsed, "--dump-config") ? 1 : 0;
  return 1;
}

static void app_opts_dump(const AppParsedOpts *parsed) {
  if (!parsed) {
    lib.print.uc_fprintf(stderr, "err", "Dump requested with NULL parsed opts\n");
    return;
  }

  lib.print.uc_printf("debug", "Dumping Server Options:\n");
  lib.print.uc_printf(NULL, "  Help Requested   : %s\n",
                      parsed->values.help_requested ? "yes" : "no");
  lib.print.uc_printf(NULL, "  Dump Config      : %s\n",
                      parsed->values.dump_config_requested ? "yes" : "no");
  lib.print.uc_printf(NULL, "  Output Mode      : %s (%d)\n",
                      lib.print.output_mode_name(parsed->values.output_mode),
                      parsed->values.output_mode);
  lib.print.uc_printf(NULL, "  Config Path      : %s\n",
                      parsed->values.config_path[0] ? parsed->values.config_path : "(default)");
  lib.print.uc_printf(NULL, "  Server Name      : %s\n",
                      parsed->values.server_name[0] ? parsed->values.server_name : "(unset)");
}

static const AppOptsLib app_opts_instance = {
  .init = app_opts_init,
  .shutdown = app_opts_shutdown,
  .parse = app_opts_parse,
  .dump = app_opts_dump
};

const AppOptsLib *get_app_opts_lib(void) {
  return &app_opts_instance;
}
