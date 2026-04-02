/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "command.h"

#include <stdio.h>

#include "../../lib.h"
#include "ops.h"

static AppAliasOpsLib app_alias_ops = {0};

static int app_alias_command_execute(const AppAliasCommand *cmd);

static int app_alias_command_init(void) {
  app_alias_ops = *get_app_alias_ops_lib();
  return app_alias_ops.init();
}

static void app_alias_command_shutdown(void) {
  app_alias_ops.shutdown();
}

static int app_alias_command_execute(const AppAliasCommand *cmd) {
  if (!cmd) {
    lib.print.uc_fprintf(stderr, "err", "Alias command is NULL\n");
    return 0;
  }

  switch (cmd->op) {
    case APP_ALIAS_OP_SET_USER:
      if (!app_alias_ops.set_user(cmd->host, cmd->name, cmd->id)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to handle alias user\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_SET_ACTION:
      if (!app_alias_ops.set_action(cmd->host, cmd->name, cmd->id)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to handle alias action\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_SHOW_USER:
      if (!app_alias_ops.show_user(cmd->host)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to show user aliases\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_SHOW_USER_ALL:
      if (!app_alias_ops.show_user_all()) {
        lib.print.uc_fprintf(stderr, "err", "Failed to show all user aliases\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_DELETE_USER:
      if (!app_alias_ops.delete_user(cmd->host, cmd->name)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete user alias\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_DELETE_USER_MAP:
      if (cmd->confirm_yes != 1) {
        lib.print.uc_fprintf(stderr, "err", "You must confirm map deletion by typing YES\n");
        return 0;
      }
      if (!app_alias_ops.delete_user_map(cmd->host)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete user alias map file\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_SHOW_ACTION:
      if (!app_alias_ops.show_action(cmd->host)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to show action aliases\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_SHOW_ACTION_ALL:
      if (!app_alias_ops.show_action_all()) {
        lib.print.uc_fprintf(stderr, "err", "Failed to show all action aliases\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_DELETE_ACTION:
      if (!app_alias_ops.delete_action(cmd->host, cmd->name)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete action alias\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_DELETE_ACTION_MAP:
      if (cmd->confirm_yes != 1) {
        lib.print.uc_fprintf(stderr, "err", "You must confirm map deletion by typing YES\n");
        return 0;
      }
      if (!app_alias_ops.delete_action_map(cmd->host)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete action alias map file\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_SHOW_HOST:
      if (!app_alias_ops.show_host(cmd->host)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to show aliases\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_SHOW_HOSTS:
      if (!app_alias_ops.show_hosts()) {
        lib.print.uc_fprintf(stderr, "err", "Failed to show hosts\n");
        return 0;
      }
      return 1;

    case APP_ALIAS_OP_DELETE_HOST:
      if (cmd->confirm_yes != 1) {
        lib.print.uc_fprintf(stderr, "err", "You must confirm destructive alias wipe by typing YES\n");
        return 0;
      }
      if (!app_alias_ops.delete_host(cmd->host)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete all aliases\n");
        return 0;
      }
      return 1;

    default:
      lib.print.uc_fprintf(stderr, "err", "Unknown alias operation: %d\n", (int)cmd->op);
      return 0;
  }
}

static const AppAliasCommandLib app_alias_command_instance = {
  .init = app_alias_command_init,
  .shutdown = app_alias_command_shutdown,
  .execute = app_alias_command_execute
};

const AppAliasCommandLib *get_app_alias_command_lib(void) {
  return &app_alias_command_instance;
}
