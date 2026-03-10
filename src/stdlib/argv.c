/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "argv.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ArgvContext g_argv_ctx = {
  .strict = 1
};

static void argv_set_error(ArgvError *err,
                           ArgvErrorCode code,
                           int arg_index,
                           const char *arg_value,
                           int option_id,
                           const char *option_name) {
  if (!err) {
    return;
  }

  err->code = code;
  err->arg_index = arg_index;
  err->arg_value = arg_value;
  err->option_id = option_id;
  err->option_name = option_name;
}

static void argv_clear_error(ArgvError *err) {
  argv_set_error(err, ARGV_ERR_NONE, -1, NULL, 0, NULL);
}

static const ArgvOptionSpec *argv_find_spec_exact(const char *name, const ArgvOptionSpec *spec_table) {
  const ArgvOptionSpec *spec = spec_table;

  if (!name || !spec_table) {
    return NULL;
  }

  while (spec->name != NULL) {
    if (strcmp(name, spec->name) == 0) {
      return spec;
    }
    spec++;
  }

  return NULL;
}

static int argv_find_option_index_by_id(const ArgvParsed *parsed, int option_id) {
  int i;

  if (!parsed) {
    return -1;
  }

  for (i = 0; i < parsed->num_options; i++) {
    if (parsed->options[i].spec && parsed->options[i].spec->id == option_id) {
      return i;
    }
  }

  return -1;
}

static int argv_append_positional(ArgvParsed *parsed_out, const char *value, int arg_index) {
  if (parsed_out->num_positionals >= ARGV_MAX_POSITIONALS) {
    argv_set_error(&parsed_out->error,
                   ARGV_ERR_TOO_MANY_POSITIONALS,
                   arg_index,
                   value,
                   0,
                   NULL);
    return 0;
  }

  parsed_out->positionals[parsed_out->num_positionals] = value;
  parsed_out->positional_indices[parsed_out->num_positionals] = arg_index;
  parsed_out->num_positionals++;
  return 1;
}

static int argv_store_option(ArgvParsed *parsed_out,
                             const ArgvOptionSpec *opt,
                             const char *spelling,
                             int source_index,
                             int value_count,
                             const char *const *values) {
  int existing_index;
  ArgvParsedOption *po;
  int j;

  if (!parsed_out || !opt || !spelling) {
    if (parsed_out) {
      argv_set_error(&parsed_out->error,
                     ARGV_ERR_INVALID_INPUT,
                     source_index,
                     spelling,
                     0,
                     NULL);
    }
    return 0;
  }

  if (value_count < 0) {
    argv_set_error(&parsed_out->error,
                   ARGV_ERR_INVALID_INPUT,
                   source_index,
                   spelling,
                   opt->id,
                   opt->name);
    return 0;
  }

  if (1 + value_count > ARGV_MAX_OPTION_ARGS) {
    argv_set_error(&parsed_out->error,
                   ARGV_ERR_TOO_MANY_OPTION_ARGS,
                   source_index,
                   spelling,
                   opt->id,
                   opt->name);
    return 0;
  }

  existing_index = argv_find_option_index_by_id(parsed_out, opt->id);
  if (existing_index >= 0 && !opt->allow_repeat) {
    if (opt->last_wins) {
      po = &parsed_out->options[existing_index];
      po->spec = opt;
      po->num_args = 1 + value_count;
      po->source_index = source_index;
      po->args[0] = spelling;
      for (j = 0; j < value_count; ++j) {
        po->args[1 + j] = values[j];
      }
      return 1;
    }

    argv_set_error(&parsed_out->error,
                   ARGV_ERR_DUPLICATE_OPTION,
                   source_index,
                   spelling,
                   opt->id,
                   opt->name);
    return 0;
  }

  if (parsed_out->num_options >= ARGV_MAX_OPTIONS) {
    argv_set_error(&parsed_out->error,
                   ARGV_ERR_TOO_MANY_OPTIONS,
                   source_index,
                   spelling,
                   opt->id,
                   opt->name);
    return 0;
  }

  po = &parsed_out->options[parsed_out->num_options++];
  po->spec = opt;
  po->num_args = 1 + value_count;
  po->source_index = source_index;
  po->args[0] = spelling;

  for (j = 0; j < value_count; ++j) {
    po->args[1 + j] = values[j];
  }

  return 1;
}

static int argv_parse_long_with_equals(const char *arg,
                                       int arg_index,
                                       ArgvParsed *parsed_out,
                                       const ArgvOptionSpec *spec_table) {
  const char *equals = strchr(arg, '=');
  char key_buf[256];
  const ArgvOptionSpec *opt;
  const char *values[1];
  size_t key_len;

  if (!equals) {
    return -1;
  }

  key_len = (size_t)(equals - arg);
  if (key_len == 0 || key_len >= sizeof(key_buf)) {
    if (g_argv_ctx.strict) {
      argv_set_error(&parsed_out->error,
                     ARGV_ERR_UNKNOWN_OPTION,
                     arg_index,
                     arg,
                     0,
                     NULL);
      return 0;
    }
    return -1;
  }

  memcpy(key_buf, arg, key_len);
  key_buf[key_len] = '\0';

  opt = argv_find_spec_exact(key_buf, spec_table);
  if (!opt) {
    if (g_argv_ctx.strict) {
      argv_set_error(&parsed_out->error,
                     ARGV_ERR_UNKNOWN_OPTION,
                     arg_index,
                     arg,
                     0,
                     NULL);
      return 0;
    }
    return -1;
  }

  if (opt->num_args != 1) {
    argv_set_error(&parsed_out->error,
                   ARGV_ERR_EQUALS_FORM_NOT_ALLOWED,
                   arg_index,
                   arg,
                   opt->id,
                   opt->name);
    return 0;
  }

  values[0] = equals + 1;
  return argv_store_option(parsed_out, opt, opt->name, arg_index, 1, values);
}

static int argv_enforce_required(const ArgvOptionSpec *spec_table, ArgvParsed *parsed_out) {
  const ArgvOptionSpec *spec = spec_table;

  if (!spec || !parsed_out) {
    return 1;
  }

  while (spec->name != NULL) {
    if (spec->required && argv_find_option_index_by_id(parsed_out, spec->id) < 0) {
      argv_set_error(&parsed_out->error,
                     ARGV_ERR_REQUIRED_OPTION_MISSING,
                     -1,
                     spec->name,
                     spec->id,
                     spec->name);
      return 0;
    }
    spec++;
  }

  return 1;
}

static void argv_set_context(const ArgvContext *ctx) {
  if (!ctx) {
    return;
  }
  g_argv_ctx = *ctx;
}

static void argv_init(const ArgvContext *ctx) {
  if (ctx) {
    argv_set_context(ctx);
  }
}

static void argv_shutdown(void) {
  g_argv_ctx.strict = 1;
}

static int argv_parse(int argc, char *argv[], ArgvParsed *parsed_out, const ArgvOptionSpec *spec_table) {
  int i = 1;
  int positional_only = 0;

  if (!parsed_out || !spec_table || argc < 0 || (argc > 0 && !argv)) {
    if (parsed_out) {
      argv_set_error(&parsed_out->error,
                     ARGV_ERR_INVALID_INPUT,
                     -1,
                     NULL,
                     0,
                     NULL);
    }
    return 0;
  }

  parsed_out->num_options = 0;
  parsed_out->num_positionals = 0;
  parsed_out->spec = spec_table;
  argv_clear_error(&parsed_out->error);

  while (i < argc) {
    const char *arg = argv[i];

    if (!arg) {
      argv_set_error(&parsed_out->error,
                     ARGV_ERR_INVALID_INPUT,
                     i,
                     NULL,
                     0,
                     NULL);
      return 0;
    }

    if (!positional_only && strcmp(arg, "--") == 0) {
      positional_only = 1;
      i++;
      continue;
    }

    if (!positional_only && strncmp(arg, "--", 2) == 0) {
      int rc = argv_parse_long_with_equals(arg, i, parsed_out, spec_table);
      if (rc >= 0) {
        if (!rc) {
          return 0;
        }
        i++;
        continue;
      }
    }

    if (!positional_only && arg[0] == '-') {
      const ArgvOptionSpec *opt = argv_find_spec_exact(arg, spec_table);
      if (opt) {
        const char *value_ptrs[ARGV_MAX_OPTION_ARGS];
        int value_count = opt->num_args;
        int j;

        if (value_count < 0) {
          argv_set_error(&parsed_out->error,
                         ARGV_ERR_INVALID_INPUT,
                         i,
                         arg,
                         opt->id,
                         opt->name);
          return 0;
        }

        if (value_count > (argc - i - 1)) {
          argv_set_error(&parsed_out->error,
                         ARGV_ERR_NOT_ENOUGH_OPTION_ARGS,
                         i,
                         arg,
                         opt->id,
                         opt->name);
          return 0;
        }

        for (j = 0; j < value_count; ++j) {
          value_ptrs[j] = argv[i + 1 + j];
        }

        if (!argv_store_option(parsed_out, opt, arg, i, value_count, value_ptrs)) {
          return 0;
        }

        i += 1 + value_count;
        continue;
      }

      if (g_argv_ctx.strict) {
        argv_set_error(&parsed_out->error,
                       ARGV_ERR_UNKNOWN_OPTION,
                       i,
                       arg,
                       0,
                       NULL);
        return 0;
      }
    }

    if (!argv_append_positional(parsed_out, arg, i)) {
      return 0;
    }
    i++;
  }

  if (!argv_enforce_required(spec_table, parsed_out)) {
    return 0;
  }

  return 1;
}

static int argv_has(const ArgvParsed *parsed, const char *option_name) {
  int i;

  if (!parsed || !option_name) {
    return 0;
  }

  for (i = 0; i < parsed->num_options; i++) {
    const ArgvParsedOption *po = &parsed->options[i];
    if (po->spec && po->spec->name && strcmp(po->spec->name, option_name) == 0) {
      return 1;
    }
  }

  return 0;
}

static void argv_dump(const ArgvParsed *parsed) {
  int i;

  if (!parsed) {
    return;
  }

  printf("Parsed Options (%d):\n", parsed->num_options);
  for (i = 0; i < parsed->num_options; i++) {
    const ArgvParsedOption *po = &parsed->options[i];
    int j;

    printf("  - %s", po->args[0] ? po->args[0] : "(null)");
    for (j = 1; j < po->num_args; j++) {
      printf(" %s", po->args[j] ? po->args[j] : "(null)");
    }
    printf("\n");
  }

  printf("\nPositional Arguments (%d):\n", parsed->num_positionals);
  for (i = 0; i < parsed->num_positionals; i++) {
    printf("  [%d] %s\n", i, parsed->positionals[i] ? parsed->positionals[i] : "(null)");
  }
}

static const ArgvParsedOption *argv_find_first_by_id(const ArgvParsed *parsed, int option_id) {
  int i;

  if (!parsed) {
    return NULL;
  }

  for (i = 0; i < parsed->num_options; i++) {
    const ArgvParsedOption *po = &parsed->options[i];
    if (po->spec && po->spec->id == option_id) {
      return po;
    }
  }

  return NULL;
}

static const ArgvParsedOption *argv_find_last_by_id(const ArgvParsed *parsed, int option_id) {
  int i;

  if (!parsed) {
    return NULL;
  }

  for (i = parsed->num_options - 1; i >= 0; i--) {
    const ArgvParsedOption *po = &parsed->options[i];
    if (po->spec && po->spec->id == option_id) {
      return po;
    }
  }

  return NULL;
}

static const ArgvParsedOption *argv_find_first_by_name(const ArgvParsed *parsed, const char *option_name) {
  int i;

  if (!parsed || !option_name) {
    return NULL;
  }

  for (i = 0; i < parsed->num_options; i++) {
    const ArgvParsedOption *po = &parsed->options[i];
    if (po->spec && po->spec->name && strcmp(po->spec->name, option_name) == 0) {
      return po;
    }
  }

  return NULL;
}

static const char *argv_option_value(const ArgvParsedOption *option, int value_index) {
  int idx;

  if (!option || value_index < 0) {
    return NULL;
  }

  idx = value_index + 1;
  if (idx >= option->num_args || idx >= ARGV_MAX_OPTION_ARGS) {
    return NULL;
  }

  return option->args[idx];
}

static void argv_set_typed_error(ArgvError *err,
                                 ArgvErrorCode code,
                                 const ArgvParsedOption *option,
                                 const char *value) {
  int option_id = 0;
  const char *option_name = NULL;
  int arg_index = -1;

  if (option && option->spec) {
    option_id = option->spec->id;
    option_name = option->spec->name;
    arg_index = option->source_index;
  }

  argv_set_error(err, code, arg_index, value, option_id, option_name);
}

static int argv_parse_long_range(const char *text,
                                 long min_value,
                                 long max_value,
                                 long *out_value) {
  char *endptr = NULL;
  long parsed = 0;

  if (!text || !*text || !out_value) {
    return 0;
  }

  errno = 0;
  parsed = strtol(text, &endptr, 10);
  if (errno == ERANGE || !endptr || *endptr != '\0') {
    return 0;
  }

  if (parsed < min_value || parsed > max_value) {
    return -1;
  }

  *out_value = parsed;
  return 1;
}

static int argv_get_i32(const ArgvParsedOption *option,
                        int value_index,
                        int min_value,
                        int max_value,
                        int *out,
                        ArgvError *err) {
  const char *text = argv_option_value(option, value_index);
  long parsed = 0;
  int rc;

  if (!out || !option) {
    argv_set_typed_error(err, ARGV_ERR_INVALID_INPUT, option, NULL);
    return 0;
  }

  rc = argv_parse_long_range(text, (long)min_value, (long)max_value, &parsed);
  if (rc == 0) {
    argv_set_typed_error(err, ARGV_ERR_BAD_INTEGER, option, text);
    return 0;
  }
  if (rc < 0) {
    argv_set_typed_error(err, ARGV_ERR_INTEGER_OUT_OF_RANGE, option, text);
    return 0;
  }

  *out = (int)parsed;
  argv_clear_error(err);
  return 1;
}

static int argv_get_u16(const ArgvParsedOption *option,
                        int value_index,
                        uint16_t *out,
                        ArgvError *err) {
  int tmp = 0;

  if (!out) {
    argv_set_typed_error(err, ARGV_ERR_INVALID_INPUT, option, NULL);
    return 0;
  }

  if (!argv_get_i32(option, value_index, 0, 65535, &tmp, err)) {
    return 0;
  }

  *out = (uint16_t)tmp;
  return 1;
}

static int argv_get_enum(const ArgvParsedOption *option,
                         int value_index,
                         const ArgvEnumMap *map,
                         size_t map_count,
                         int *out,
                         ArgvError *err) {
  const char *text = argv_option_value(option, value_index);
  size_t i;

  if (!option || !map || map_count == 0 || !out) {
    argv_set_typed_error(err, ARGV_ERR_INVALID_INPUT, option, text);
    return 0;
  }

  for (i = 0; i < map_count; ++i) {
    if (map[i].name && strcmp(map[i].name, text) == 0) {
      *out = map[i].value;
      argv_clear_error(err);
      return 1;
    }
  }

  argv_set_typed_error(err, ARGV_ERR_BAD_ENUM, option, text);
  return 0;
}

static const char *argv_error_code_name(ArgvErrorCode code) {
  switch (code) {
    case ARGV_ERR_NONE:
      return "none";
    case ARGV_ERR_INVALID_INPUT:
      return "invalid_input";
    case ARGV_ERR_UNKNOWN_OPTION:
      return "unknown_option";
    case ARGV_ERR_NOT_ENOUGH_OPTION_ARGS:
      return "not_enough_option_args";
    case ARGV_ERR_TOO_MANY_OPTIONS:
      return "too_many_options";
    case ARGV_ERR_TOO_MANY_POSITIONALS:
      return "too_many_positionals";
    case ARGV_ERR_TOO_MANY_OPTION_ARGS:
      return "too_many_option_args";
    case ARGV_ERR_EQUALS_FORM_NOT_ALLOWED:
      return "equals_form_not_allowed";
    case ARGV_ERR_DUPLICATE_OPTION:
      return "duplicate_option";
    case ARGV_ERR_REQUIRED_OPTION_MISSING:
      return "required_option_missing";
    case ARGV_ERR_BAD_INTEGER:
      return "bad_integer";
    case ARGV_ERR_INTEGER_OUT_OF_RANGE:
      return "integer_out_of_range";
    case ARGV_ERR_BAD_ENUM:
      return "bad_enum";
    default:
      return "unknown_error";
  }
}

static int argv_format_error(const ArgvError *err, char *out, size_t out_size) {
  const char *code_name;
  int written;

  if (!out || out_size == 0) {
    return 0;
  }

  out[0] = '\0';
  if (!err) {
    return 1;
  }

  code_name = argv_error_code_name(err->code);
  written = snprintf(out, out_size,
                     "code=%s arg_index=%d arg_value=%s option_id=%d option_name=%s",
                     code_name,
                     err->arg_index,
                     err->arg_value ? err->arg_value : "(null)",
                     err->option_id,
                     err->option_name ? err->option_name : "(null)");
  if (written < 0 || (size_t)written >= out_size) {
    return 0;
  }

  return 1;
}

static const ArgvLib argv_lib = {
  .init = argv_init,
  .shutdown = argv_shutdown,
  .set_context = argv_set_context,
  .parse = argv_parse,
  .has = argv_has,
  .dump = argv_dump,
  .find_first_by_id = argv_find_first_by_id,
  .find_last_by_id = argv_find_last_by_id,
  .find_first_by_name = argv_find_first_by_name,
  .option_value = argv_option_value,
  .get_i32 = argv_get_i32,
  .get_u16 = argv_get_u16,
  .get_enum = argv_get_enum,
  .error_code_name = argv_error_code_name,
  .format_error = argv_format_error
};

const ArgvLib *get_lib_argv(void) {
  return &argv_lib;
}
