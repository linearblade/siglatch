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

static int app_opts_alias_parse_id(const char *value, uint32_t *out_id) {
  unsigned long parsed = 0;
  char *end = NULL;

  if (!value || !*value || !out_id) {
    return 0;
  }

  errno = 0;
  parsed = strtoul(value, &end, 10);
  if (errno != 0 || !end || *end != '\0' || parsed == 0 || parsed > UINT32_MAX) {
    return 0;
  }

  *out_id = (uint32_t)parsed;
  return 1;
}

static int app_opts_alias_parse_runtime_options(int argc, char *argv[], AppCommand *out, char **filtered_argv,
                                                int *filtered_argc, int *output_mode, int *dump_requested) {
  int i = 0;
  int write_idx = 0;
  int parsed_mode = 0;
  char message[256];

  if (!argv || argc < 2 || !out || !filtered_argv || !filtered_argc || !output_mode || !dump_requested) {
    return app_opts_alias_set_error(out, 2, "Invalid parser state for alias options");
  }

  filtered_argv[write_idx++] = argv[0];
  filtered_argv[write_idx++] = argv[1];

  for (i = 2; i < argc; i++) {
    const char *arg = argv[i];

    if (!arg || !*arg) {
      continue;
    }

    if (strcmp(arg, "--opts-dump") == 0) {
      *dump_requested = 1;
      continue;
    }

    if (strcmp(arg, "--output-mode") == 0) {
      const char *mode_value = NULL;

      if (i + 1 >= argc || !argv[i + 1] || !argv[i + 1][0]) {
        return app_opts_alias_set_error(out, 2,
                                        "Missing value for --output-mode (expected 'unicode' or 'ascii')");
      }

      mode_value = argv[i + 1];
      parsed_mode = lib.print.output_parse_mode(mode_value);
      if (!parsed_mode) {
        snprintf(message, sizeof(message),
                 "Invalid output mode: %s (expected 'unicode' or 'ascii')",
                 mode_value);
        return app_opts_alias_set_error(out, 2, message);
      }

      *output_mode = parsed_mode;
      i++;
      continue;
    }

    filtered_argv[write_idx++] = argv[i];
  }

  *filtered_argc = write_idx;
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

static int app_opts_alias_parse(int argc, char *argv[], AppCommand *out) {
  AppAliasCommand *alias = NULL;
  char **filtered_argv = NULL;
  int filtered_argc = 0;
  int ok = 0;
  char message[256];

  if (argc < 2 || !argv || !argv[1]) {
    return app_opts_alias_set_error(out, 2, "Missing alias command");
  }

  out->type = APP_CMD_ALIAS;
  out->ok = 0;
  out->exit_code = 2;
  memset(&out->as.alias, 0, sizeof(out->as.alias));
  alias = &out->as.alias;

  filtered_argv = calloc((size_t)argc, sizeof(char *));
  if (!filtered_argv) {
    return app_opts_alias_set_error(out, 2, "Failed to allocate alias parse buffer");
  }

  if (!app_opts_alias_parse_runtime_options(argc, argv, out, filtered_argv, &filtered_argc,
                                            &alias->output_mode, &out->dump_requested)) {
    goto cleanup;
  }

  if (filtered_argc < 2 || !filtered_argv[1]) {
    app_opts_alias_set_error(out, 2, "Missing alias command");
    goto cleanup;
  }

  if (strcmp(filtered_argv[1], "--alias-user") == 0) {
    if (filtered_argc < 5) {
      app_opts_alias_set_error(out, 2, "Not enough arguments for --alias-user");
      goto cleanup;
    }
    alias->op = APP_ALIAS_OP_SET_USER;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), filtered_argv[2], "host", out) ||
        !app_opts_alias_copy_token(alias->name, sizeof(alias->name), filtered_argv[3], "name", out)) {
      goto cleanup;
    }
    if (!app_opts_alias_parse_id(filtered_argv[4], &alias->id)) {
      app_opts_alias_set_error(out, 2, "Invalid user ID for --alias-user");
      goto cleanup;
    }
  } else if (strcmp(filtered_argv[1], "--alias-action") == 0) {
    if (filtered_argc < 5) {
      app_opts_alias_set_error(out, 2, "Not enough arguments for --alias-action");
      goto cleanup;
    }
    alias->op = APP_ALIAS_OP_SET_ACTION;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), filtered_argv[2], "host", out) ||
        !app_opts_alias_copy_token(alias->name, sizeof(alias->name), filtered_argv[3], "name", out)) {
      goto cleanup;
    }
    if (!app_opts_alias_parse_id(filtered_argv[4], &alias->id)) {
      app_opts_alias_set_error(out, 2, "Invalid action ID for --alias-action");
      goto cleanup;
    }
  } else if (strcmp(filtered_argv[1], "--alias-user-show") == 0) {
    if (filtered_argc == 2) {
      alias->op = APP_ALIAS_OP_SHOW_USER_ALL;
    } else {
      alias->op = APP_ALIAS_OP_SHOW_USER;
      if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), filtered_argv[2], "host", out)) {
        goto cleanup;
      }
    }
  } else if (strcmp(filtered_argv[1], "--alias-action-show") == 0) {
    if (filtered_argc == 2) {
      alias->op = APP_ALIAS_OP_SHOW_ACTION_ALL;
    } else {
      alias->op = APP_ALIAS_OP_SHOW_ACTION;
      if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), filtered_argv[2], "host", out)) {
        goto cleanup;
      }
    }
  } else if (strcmp(filtered_argv[1], "--alias-user-delete") == 0) {
    if (filtered_argc < 4) {
      app_opts_alias_set_error(out, 2, "Not enough arguments for --alias-user-delete");
      goto cleanup;
    }
    alias->op = APP_ALIAS_OP_DELETE_USER;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), filtered_argv[2], "host", out) ||
        !app_opts_alias_copy_token(alias->name, sizeof(alias->name), filtered_argv[3], "name", out)) {
      goto cleanup;
    }
  } else if (strcmp(filtered_argv[1], "--alias-action-delete") == 0) {
    if (filtered_argc < 4) {
      app_opts_alias_set_error(out, 2, "Not enough arguments for --alias-action-delete");
      goto cleanup;
    }
    alias->op = APP_ALIAS_OP_DELETE_ACTION;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), filtered_argv[2], "host", out) ||
        !app_opts_alias_copy_token(alias->name, sizeof(alias->name), filtered_argv[3], "name", out)) {
      goto cleanup;
    }
  } else if (strcmp(filtered_argv[1], "--alias-show") == 0) {
    if (filtered_argc < 3) {
      app_opts_alias_set_error(out, 2, "Not enough arguments for --alias-show");
      goto cleanup;
    }
    alias->op = APP_ALIAS_OP_SHOW_HOST;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), filtered_argv[2], "host", out)) {
      goto cleanup;
    }
  } else if (strcmp(filtered_argv[1], "--alias-show-hosts") == 0) {
    alias->op = APP_ALIAS_OP_SHOW_HOSTS;
  } else if (strcmp(filtered_argv[1], "--alias-delete") == 0) {
    if (filtered_argc < 4 || strcmp(filtered_argv[3], "YES") != 0) {
      app_opts_alias_set_error(out, 2, "You must confirm destructive alias wipe by typing YES");
      goto cleanup;
    }
    alias->op = APP_ALIAS_OP_DELETE_HOST;
    alias->confirm_yes = 1;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), filtered_argv[2], "host", out)) {
      goto cleanup;
    }
  } else if (strcmp(filtered_argv[1], "--alias-user-delete-map") == 0) {
    if (filtered_argc < 4 || strcmp(filtered_argv[3], "YES") != 0) {
      app_opts_alias_set_error(out, 2, "You must confirm map deletion by typing YES");
      goto cleanup;
    }
    alias->op = APP_ALIAS_OP_DELETE_USER_MAP;
    alias->confirm_yes = 1;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), filtered_argv[2], "host", out)) {
      goto cleanup;
    }
  } else if (strcmp(filtered_argv[1], "--alias-action-delete-map") == 0) {
    if (filtered_argc < 4 || strcmp(filtered_argv[3], "YES") != 0) {
      app_opts_alias_set_error(out, 2, "You must confirm map deletion by typing YES");
      goto cleanup;
    }
    alias->op = APP_ALIAS_OP_DELETE_ACTION_MAP;
    alias->confirm_yes = 1;
    if (!app_opts_alias_copy_token(alias->host, sizeof(alias->host), filtered_argv[2], "host", out)) {
      goto cleanup;
    }
  } else {
    snprintf(message, sizeof(message), "Unknown alias command: %s", filtered_argv[1]);
    app_opts_alias_set_error(out, 2, message);
    goto cleanup;
  }

  out->ok = 1;
  out->exit_code = 0;
  ok = 1;

cleanup:
  free(filtered_argv);
  return ok;
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
  .parse = app_opts_alias_parse,
  .dump = app_opts_alias_dump
};

const AppOptsAliasLib *get_app_opts_alias_lib(void) {
  return &app_opts_alias_instance;
}
