/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <string.h>
#include "parse_argv.h"

// Internal context (defaults to non-strict)
static ParseArgvContext g_parse_argv_ctx = {
  .strict = 0,
  .quiet_errors = 0,
  .log = NULL,
  .print = NULL
};

// Internal lookup
static const OptionSpec* find_option_spec(const char *arg, const OptionSpec *spec_table) {
  for (const OptionSpec *spec = spec_table; spec->name != NULL; spec++) {
    if (strcmp(arg, spec->name) == 0) {
      return spec;
    }
  }
  return NULL;
}

static void parse_argv_set_context(const ParseArgvContext *ctx) {
  if (ctx) {
    g_parse_argv_ctx = *ctx;
  }
}

static void parse_argv_init(const ParseArgvContext *ctx) {
  parse_argv_set_context(ctx);
}
static void parse_argv_shutdown(void){
  g_parse_argv_ctx.strict = 0;
  g_parse_argv_ctx.quiet_errors = 0;
  g_parse_argv_ctx.log = NULL;
  g_parse_argv_ctx.print = NULL;
}

static void parse_argv_print(const char *marker, const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    if (g_parse_argv_ctx.print && g_parse_argv_ctx.print->uc_vfprintf) {
        (void)g_parse_argv_ctx.print->uc_vfprintf(stdout, marker, fmt, args);
    } else {
        (void)vprintf(fmt, args);
    }
    va_end(args);
}

static void log_error(const char *fmt, ...) {
    if (g_parse_argv_ctx.quiet_errors) {
        return;
    }

    va_list args;
    va_start(args, fmt);

    if (g_parse_argv_ctx.log && g_parse_argv_ctx.log->emit) {
        char buffer[512];
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        g_parse_argv_ctx.log->emit(LOG_ERROR, 1, "%s", buffer);
    } else {
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    }

    va_end(args);
}

static int parse_argv(const int argc, char *argv[], ParsedArgv *parsed_out, const OptionSpec *spec_table) {
  int i = 1;
  const int max_options = (int)(sizeof(parsed_out->options) / sizeof(parsed_out->options[0]));
  const int max_positionals = (int)(sizeof(parsed_out->positionals) / sizeof(parsed_out->positionals[0]));
  parsed_out->num_options = 0;
  parsed_out->num_positionals = 0;
  parsed_out->spec = spec_table;

  while (i < argc) {
    if (strncmp(argv[i], "--", 2) != 0) break;

    const OptionSpec *opt = find_option_spec(argv[i], spec_table);
    if (!opt) {
      if (g_parse_argv_ctx.strict) {
        log_error( "Unknown option: %s\n", argv[i]);
        return 0;
      } else {
        break; // Treat as positional start
      }
    }

    if (opt->num_args < 0) {
      log_error("Invalid option spec for %s: negative arg count\n", opt->name);
      return 0;
    }

    if (opt->num_args > (argc - i - 1)) {
      log_error( "Not enough arguments for option: %s\n", argv[i]);
      return 0;
    }

    if (parsed_out->num_options >= max_options) {
      log_error("Too many options (max %d)\n", max_options);
      return 0;
    }

    ParsedOption *po = &parsed_out->options[parsed_out->num_options++];
    po->spec = opt;
    po->num_args = 1 + opt->num_args;

    {
      const int max_opt_args = (int)(sizeof(po->args) / sizeof(po->args[0]));
      if (po->num_args > max_opt_args) {
        log_error("Too many arguments for option: %s (max %d)\n", opt->name, max_opt_args - 1);
        return 0;
      }
    }

    for (int j = 0; j < po->num_args; j++) {
      po->args[j] = argv[i + j];
    }

    i += po->num_args;
  }

  while (i < argc) {
    if (parsed_out->num_positionals >= max_positionals) {
      log_error("Too many positional arguments (max %d)\n", max_positionals);
      return 0;
    }
    parsed_out->positionals[parsed_out->num_positionals++] = argv[i++];
  }

  return 1;
}

static int parse_argv_has(const ParsedArgv *parsed, const char *flag) {
  for (int i = 0; i < parsed->num_options; i++) {
    if (strcmp(parsed->options[i].args[0], flag) == 0) {
      return 1;
    }
  }
  return 0;
}

static void parse_argv_dump(const ParsedArgv *parsed) {
  parse_argv_print("debug", "Parsed Options (%d):\n", parsed->num_options);
  for (int i = 0; i < parsed->num_options; i++) {
    const ParsedOption *po = &parsed->options[i];
    printf("  - %s", po->args[0]);
    for (int j = 1; j < po->num_args; j++) {
      printf(" %s", po->args[j]);
    }
    printf("\n");
  }

  parse_argv_print("box", "\nPositional Arguments (%d):\n", parsed->num_positionals);
  for (int i = 0; i < parsed->num_positionals; i++) {
    printf("  [%d] %s\n", i, parsed->positionals[i]);
  }
}

// Singleton object
static const ParseArgvLib parse_argv_lib = {
  .init         = parse_argv_init,
  .shutdown     = parse_argv_shutdown,
  .set_context  = parse_argv_set_context,
  .parse        = parse_argv,
  .has          = parse_argv_has,
  .dump         = parse_argv_dump
};

const ParseArgvLib *get_lib_parse_argv(void) {
  return &parse_argv_lib;
}
