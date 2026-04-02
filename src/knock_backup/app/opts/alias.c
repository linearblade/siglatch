/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "alias.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../lib.h"
#include "../app.h"

enum {
  ALIAS_OPT_ID_NONE = 0,
  ALIAS_OPT_ID_DUMP,
  ALIAS_OPT_ID_OUTPUT_MODE
};

static const ArgvOptionSpec option_specs[] = {
  { "--opts-dump",   ALIAS_OPT_ID_DUMP,        0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--output-mode", ALIAS_OPT_ID_OUTPUT_MODE, 1, ARGV_OPT_KEYED, 0, 0, 1 },
  { NULL, 0, 0, ARGV_OPT_FLAG, 0, 0, 0 }
};

static const ArgvOptionSpec *app_opts_alias_spec(void) {
  return option_specs;
}

static int app_opts_alias_init(void) {
  return 1;
}

static void app_opts_alias_shutdown(void) {
}

static int app_opts_alias_set_error(AppCommand *out, int exit_code, const char *message) {
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

static int app_opts_alias_parse_id(const char *value,
                                   uint32_t min_value,
                                   uint32_t max_value,
                                   uint32_t *out_id) {
  unsigned long parsed = 0;
  char *end = NULL;

  if (!value || !*value || !out_id || min_value > max_value) {
    return 0;
  }

  errno = 0;
  parsed = strtoul(value, &end, 10);
  if (errno != 0 || !end || *end != '\0') {
    return 0;
  }

  if (parsed < (unsigned long)min_value || parsed > (unsigned long)max_value) {
    return 0;
  }

  *out_id = (uint32_t)parsed;
  return 1;
}

static int app_opts_alias_expect_positionals(const ArgvParsed *parsed,
                                             int min_count,
                                             int max_count,
                                             AppCommand *out,
                                             const char *missing_message,
                                             const char *command_name) {
  int count = 0;
  char message[256];

  if (!parsed) {
    return app_opts_alias_set_error(out, 2, "Invalid parser state for alias command");
  }

  count = parsed->num_positionals;
  if (count < min_count) {
    return app_opts_alias_set_error(out, 2,
                                    (missing_message && *missing_message)
                                    ? missing_message
                                    : "Not enough arguments for alias command");
  }

  if (max_count >= 0 && count > max_count) {
    snprintf(message, sizeof(message), "Too many arguments for %s",
             (command_name && *command_name) ? command_name : "alias command");
    return app_opts_alias_set_error(out, 2, message);
  }

  return 1;
}

static int app_opts_alias_apply_options(const ArgvParsed *parsed, AppAliasCommand *alias, AppCommand *out) {
  static const ArgvEnumMap output_mode_map[] = {
    { "unicode", SL_OUTPUT_MODE_UNICODE },
    { "ascii", SL_OUTPUT_MODE_ASCII }
  };
  int i = 0;

  if (!parsed || !alias || !out) {
    return app_opts_alias_set_error(out, 2, "Invalid parser state for alias options");
  }

  for (i = 0; i < parsed->num_options; i++) {
    const ArgvParsedOption *opt = &parsed->options[i];

    switch (opt->spec->id) {
      case ALIAS_OPT_ID_NONE:
        break;
      case ALIAS_OPT_ID_DUMP:
        out->dump_requested = 1;
        break;
      case ALIAS_OPT_ID_OUTPUT_MODE:
        if (!lib.argv.get_enum(opt, 0, output_mode_map,
                               sizeof(output_mode_map) / sizeof(output_mode_map[0]),
                               &alias->output_mode, NULL)) {
          const char *value = lib.argv.option_value(opt, 0);
          char message[256];
          snprintf(message, sizeof(message),
                   "Invalid output mode: %s (expected 'unicode' or 'ascii')",
                   value ? value : "(null)");
          return app_opts_alias_set_error(out, 2, message);
        }
        break;
      default:
        lib.print.uc_fprintf(stderr, "warn", "Unhandled alias option id %d: %s\n",
                             opt->spec->id, opt->args[0] ? opt->args[0] : "(null)");
        break;
    }
  }

  return 1;
}

static int app_opts_alias_copy_token(char *dst, size_t dst_size, const char *src, const char *label,
                                     AppCommand *out) {
  int written = 0;
  char message[256];

  if (!dst || dst_size == 0 || !src || !*src) {
    snprintf(message, sizeof(message), "Missing %s for alias command", label ? label : "value");
    return app_opts_alias_set_error(out, 2, message);
  }

  written = snprintf(dst, dst_size, "%s", src);
  if (written < 0 || (size_t)written >= dst_size) {
    snprintf(message, sizeof(message), "Alias %s is too long", label ? label : "value");
    return app_opts_alias_set_error(out, 2, message);
  }

  return 1;
}

static int app_opts_alias_parse(const char *mode_selector, const ArgvParsed *parsed, AppCommand *out) {
  AppAliasCommand *alias = NULL;
  char message[256];

  if (!mode_selector || !*mode_selector) {
    return app_opts_alias_set_error(out, 2, "Missing alias command");
  }

  out->type = APP_CMD_ALIAS;
  out->ok = 0;
  out->exit_code = 2;
  out->dump_requested = 0;
  memset(&out->as.alias, 0, sizeof(out->as.alias));
  alias = &out->as.alias;

  if (!app_opts_alias_apply_options(parsed, alias, out)) {
    return 0;
  }

  if (strcmp(mode_selector, "--alias-user") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 3, 3, out,
                                           "Not enough arguments for --alias-user",
                                           "--alias-user")) {
      return 0;
    }
    alias->op = APP_ALIAS_OP_SET_USER;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), parsed->positionals[0], "host", out) ||
        !app_opts_alias_copy_token(alias->name, sizeof(alias->name), parsed->positionals[1], "name", out)) {
      return 0;
    }
    if (!app_opts_alias_parse_id(parsed->positionals[2], 1, UINT16_MAX, &alias->id)) {
      return app_opts_alias_set_error(out, 2,
                                      "Invalid user ID for --alias-user (expected range 1-65535)");
    }
  } else if (strcmp(mode_selector, "--alias-action") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 3, 3, out,
                                           "Not enough arguments for --alias-action",
                                           "--alias-action")) {
      return 0;
    }
    alias->op = APP_ALIAS_OP_SET_ACTION;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), parsed->positionals[0], "host", out) ||
        !app_opts_alias_copy_token(alias->name, sizeof(alias->name), parsed->positionals[1], "name", out)) {
      return 0;
    }
    if (!app_opts_alias_parse_id(parsed->positionals[2], 1, UINT8_MAX, &alias->id)) {
      return app_opts_alias_set_error(out, 2,
                                      "Invalid action ID for --alias-action (expected range 1-255)");
    }
  } else if (strcmp(mode_selector, "--alias-user-show") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 0, 1, out, NULL, "--alias-user-show")) {
      return 0;
    }
    if (parsed->num_positionals == 0) {
      alias->op = APP_ALIAS_OP_SHOW_USER_ALL;
    } else {
      alias->op = APP_ALIAS_OP_SHOW_USER;
      if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), parsed->positionals[0], "host", out)) {
        return 0;
      }
    }
  } else if (strcmp(mode_selector, "--alias-action-show") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 0, 1, out, NULL, "--alias-action-show")) {
      return 0;
    }
    if (parsed->num_positionals == 0) {
      alias->op = APP_ALIAS_OP_SHOW_ACTION_ALL;
    } else {
      alias->op = APP_ALIAS_OP_SHOW_ACTION;
      if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), parsed->positionals[0], "host", out)) {
        return 0;
      }
    }
  } else if (strcmp(mode_selector, "--alias-user-delete") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 2, 2, out,
                                           "Not enough arguments for --alias-user-delete",
                                           "--alias-user-delete")) {
      return 0;
    }
    alias->op = APP_ALIAS_OP_DELETE_USER;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), parsed->positionals[0], "host", out) ||
        !app_opts_alias_copy_token(alias->name, sizeof(alias->name), parsed->positionals[1], "name", out)) {
      return 0;
    }
  } else if (strcmp(mode_selector, "--alias-action-delete") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 2, 2, out,
                                           "Not enough arguments for --alias-action-delete",
                                           "--alias-action-delete")) {
      return 0;
    }
    alias->op = APP_ALIAS_OP_DELETE_ACTION;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), parsed->positionals[0], "host", out) ||
        !app_opts_alias_copy_token(alias->name, sizeof(alias->name), parsed->positionals[1], "name", out)) {
      return 0;
    }
  } else if (strcmp(mode_selector, "--alias-show") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 1, 1, out,
                                           "Not enough arguments for --alias-show",
                                           "--alias-show")) {
      return 0;
    }
    alias->op = APP_ALIAS_OP_SHOW_HOST;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), parsed->positionals[0], "host", out)) {
      return 0;
    }
  } else if (strcmp(mode_selector, "--alias-show-hosts") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 0, 0, out, NULL, "--alias-show-hosts")) {
      return 0;
    }
    alias->op = APP_ALIAS_OP_SHOW_HOSTS;
  } else if (strcmp(mode_selector, "--alias-delete") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 2, 2, out,
                                           "You must confirm destructive alias wipe by typing YES",
                                           "--alias-delete")) {
      return 0;
    }
    if (strcmp(parsed->positionals[1], "YES") != 0) {
      return app_opts_alias_set_error(out, 2, "You must confirm destructive alias wipe by typing YES");
    }
    alias->op = APP_ALIAS_OP_DELETE_HOST;
    alias->confirm_yes = 1;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), parsed->positionals[0], "host", out)) {
      return 0;
    }
  } else if (strcmp(mode_selector, "--alias-user-delete-map") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 2, 2, out,
                                           "You must confirm map deletion by typing YES",
                                           "--alias-user-delete-map")) {
      return 0;
    }
    if (strcmp(parsed->positionals[1], "YES") != 0) {
      return app_opts_alias_set_error(out, 2, "You must confirm map deletion by typing YES");
    }
    alias->op = APP_ALIAS_OP_DELETE_USER_MAP;
    alias->confirm_yes = 1;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), parsed->positionals[0], "host", out)) {
      return 0;
    }
  } else if (strcmp(mode_selector, "--alias-action-delete-map") == 0) {
    if (!app_opts_alias_expect_positionals(parsed, 2, 2, out,
                                           "You must confirm map deletion by typing YES",
                                           "--alias-action-delete-map")) {
      return 0;
    }
    if (strcmp(parsed->positionals[1], "YES") != 0) {
      return app_opts_alias_set_error(out, 2, "You must confirm map deletion by typing YES");
    }
    alias->op = APP_ALIAS_OP_DELETE_ACTION_MAP;
    alias->confirm_yes = 1;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), parsed->positionals[0], "host", out)) {
      return 0;
    }
  } else {
    snprintf(message, sizeof(message), "Unknown alias command: %s", mode_selector);
    return app_opts_alias_set_error(out, 2, message);
  }

  out->ok = 1;
  out->exit_code = 0;
  return 1;
}

static const char *app_opts_alias_op_name(AppAliasOp op) {
  switch (op) {
    case APP_ALIAS_OP_SET_USER:
      return "set_user";
    case APP_ALIAS_OP_SET_ACTION:
      return "set_action";
    case APP_ALIAS_OP_SHOW_USER:
      return "show_user";
    case APP_ALIAS_OP_SHOW_USER_ALL:
      return "show_user_all";
    case APP_ALIAS_OP_DELETE_USER:
      return "delete_user";
    case APP_ALIAS_OP_DELETE_USER_MAP:
      return "delete_user_map";
    case APP_ALIAS_OP_SHOW_ACTION:
      return "show_action";
    case APP_ALIAS_OP_SHOW_ACTION_ALL:
      return "show_action_all";
    case APP_ALIAS_OP_DELETE_ACTION:
      return "delete_action";
    case APP_ALIAS_OP_DELETE_ACTION_MAP:
      return "delete_action_map";
    case APP_ALIAS_OP_SHOW_HOST:
      return "show_host";
    case APP_ALIAS_OP_SHOW_HOSTS:
      return "show_hosts";
    case APP_ALIAS_OP_DELETE_HOST:
      return "delete_host";
    default:
      return "invalid";
  }
}

static void app_opts_alias_dump(const AppAliasCommand *cmd) {
  if (!cmd) {
    lib.print.uc_fprintf(stderr, "err", "Alias dump requested with NULL command\n");
    return;
  }

  lib.print.uc_printf("debug", "Dumping Parsed Alias Command:\n");
  lib.print.uc_printf(NULL, "  Operation        : %s (%d)\n",
                      app_opts_alias_op_name(cmd->op), (int)cmd->op);
  lib.print.uc_printf(NULL, "  Host             : %s\n", cmd->host[0] ? cmd->host : "(none)");
  lib.print.uc_printf(NULL, "  Name             : %s\n", cmd->name[0] ? cmd->name : "(none)");
  lib.print.uc_printf(NULL, "  ID               : %u\n", cmd->id);
  lib.print.uc_printf(NULL, "  Confirm YES      : %s\n", cmd->confirm_yes ? "yes" : "no");
  lib.print.uc_printf(NULL, "  Output Mode      : %s (%d)\n",
                      lib.print.output_mode_name(cmd->output_mode), cmd->output_mode);
}

static const AppOptsAliasLib app_opts_alias_instance = {
  .init = app_opts_alias_init,
  .shutdown = app_opts_alias_shutdown,
  .spec = app_opts_alias_spec,
  .parse = app_opts_alias_parse,
  .dump = app_opts_alias_dump
};

const AppOptsAliasLib *get_app_opts_alias_lib(void) {
  return &app_opts_alias_instance;
}
