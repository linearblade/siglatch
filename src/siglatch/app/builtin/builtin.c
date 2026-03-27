/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "builtin.h"

#include <string.h>

#include "../../lib.h"

static int app_builtin_supports(const char *name);
static int app_builtin_is_action(const siglatch_action *action);
static int app_builtin_build_context(
    AppBuiltinContext *out,
    AppRuntimeListenerState *listener,
    const AppConnectionJob *job,
    SiglatchOpenSSLSession *session,
    const siglatch_user *user,
    const siglatch_action *action,
    const char *ip_addr);
static int app_builtin_handle(const AppBuiltinContext *ctx, AppActionReply *reply);

static int app_builtin_init(void) {
  if (!app_builtin_probe_rebind_init()) {
    return 0;
  }

  if (!app_builtin_rebind_listener_init()) {
    app_builtin_probe_rebind_shutdown();
    return 0;
  }

  if (!app_builtin_reload_config_init()) {
    app_builtin_rebind_listener_shutdown();
    app_builtin_probe_rebind_shutdown();
    return 0;
  }

  if (!app_builtin_change_setting_init()) {
    app_builtin_reload_config_shutdown();
    app_builtin_rebind_listener_shutdown();
    app_builtin_probe_rebind_shutdown();
    return 0;
  }

  if (!app_builtin_save_config_init()) {
    app_builtin_change_setting_shutdown();
    app_builtin_reload_config_shutdown();
    app_builtin_rebind_listener_shutdown();
    app_builtin_probe_rebind_shutdown();
    return 0;
  }

  if (!app_builtin_load_config_init()) {
    app_builtin_save_config_shutdown();
    app_builtin_change_setting_shutdown();
    app_builtin_reload_config_shutdown();
    app_builtin_rebind_listener_shutdown();
    app_builtin_probe_rebind_shutdown();
    return 0;
  }

  if (!app_builtin_list_users_init()) {
    app_builtin_load_config_shutdown();
    app_builtin_save_config_shutdown();
    app_builtin_change_setting_shutdown();
    app_builtin_reload_config_shutdown();
    app_builtin_rebind_listener_shutdown();
    app_builtin_probe_rebind_shutdown();
    return 0;
  }

  if (!app_builtin_test_blurt_init()) {
    app_builtin_list_users_shutdown();
    app_builtin_load_config_shutdown();
    app_builtin_save_config_shutdown();
    app_builtin_change_setting_shutdown();
    app_builtin_reload_config_shutdown();
    app_builtin_rebind_listener_shutdown();
    app_builtin_probe_rebind_shutdown();
    return 0;
  }

  return 1;
}

static void app_builtin_shutdown(void) {
  app_builtin_test_blurt_shutdown();
  app_builtin_list_users_shutdown();
  app_builtin_load_config_shutdown();
  app_builtin_save_config_shutdown();
  app_builtin_change_setting_shutdown();
  app_builtin_reload_config_shutdown();
  app_builtin_rebind_listener_shutdown();
  app_builtin_probe_rebind_shutdown();
}

static int app_builtin_supports(const char *name) {
  if (!name || name[0] == '\0') {
    return 0;
  }

  return strcmp(name, "reload_config") == 0 ||
         strcmp(name, "probe_rebind") == 0 ||
         strcmp(name, "rebind_listener") == 0 ||
         strcmp(name, "change_setting") == 0 ||
         strcmp(name, "save_config") == 0 ||
         strcmp(name, "load_config") == 0 ||
         strcmp(name, "list_users") == 0 ||
         strcmp(name, "test_blurt") == 0;
}

static int app_builtin_is_action(const siglatch_action *action) {
  if (!action) {
    return 0;
  }

  return action->handler == SL_ACTION_HANDLER_BUILTIN &&
         action->builtin[0] != '\0';
}

static int app_builtin_build_context(
    AppBuiltinContext *out,
    AppRuntimeListenerState *listener,
    const AppConnectionJob *job,
    SiglatchOpenSSLSession *session,
    const siglatch_user *user,
    const siglatch_action *action,
    const char *ip_addr) {
  if (!out || !listener || !job || !session || !user || !action || !ip_addr) {
    return 0;
  }

  *out = (AppBuiltinContext){
    .listener = listener,
    .job = job,
    .session = session,
    .user = user,
    .action = action,
    .ip_addr = ip_addr
  };

  return 1;
}

static int app_builtin_handle(const AppBuiltinContext *ctx, AppActionReply *reply) {
  if (!ctx || !ctx->action) {
    return 0;
  }

  if (strcmp(ctx->action->builtin, "reload_config") == 0) {
    return app_builtin_reload_config_handle(ctx, reply);
  }

  if (strcmp(ctx->action->builtin, "probe_rebind") == 0) {
    return app_builtin_probe_rebind_handle(ctx, reply);
  }

  if (strcmp(ctx->action->builtin, "rebind_listener") == 0) {
    return app_builtin_rebind_listener_handle(ctx, reply);
  }

  if (strcmp(ctx->action->builtin, "change_setting") == 0) {
    return app_builtin_change_setting_handle(ctx, reply);
  }

  if (strcmp(ctx->action->builtin, "save_config") == 0) {
    return app_builtin_save_config_handle(ctx, reply);
  }

  if (strcmp(ctx->action->builtin, "load_config") == 0) {
    return app_builtin_load_config_handle(ctx, reply);
  }

  if (strcmp(ctx->action->builtin, "list_users") == 0) {
    return app_builtin_list_users_handle(ctx, reply);
  }

  if (strcmp(ctx->action->builtin, "test_blurt") == 0) {
    return app_builtin_test_blurt_handle(ctx, reply);
  }

  LOGE("Unsupported builtin action handler: %s\n", ctx->action->builtin);
  return 0;
}

static const AppBuiltinLib app_builtin_instance = {
  .init = app_builtin_init,
  .shutdown = app_builtin_shutdown,
  .supports = app_builtin_supports,
  .is_action = app_builtin_is_action,
  .build_context = app_builtin_build_context,
  .handle = app_builtin_handle,
  .probe_rebind = {
    .init = app_builtin_probe_rebind_init,
    .shutdown = app_builtin_probe_rebind_shutdown,
    .handle = app_builtin_probe_rebind_handle
  },
  .rebind_listener = {
    .init = app_builtin_rebind_listener_init,
    .shutdown = app_builtin_rebind_listener_shutdown,
    .handle = app_builtin_rebind_listener_handle
  },
  .reload_config = {
    .init = app_builtin_reload_config_init,
    .shutdown = app_builtin_reload_config_shutdown,
    .handle = app_builtin_reload_config_handle
  },
  .change_setting = {
    .init = app_builtin_change_setting_init,
    .shutdown = app_builtin_change_setting_shutdown,
    .handle = app_builtin_change_setting_handle
  },
  .save_config = {
    .init = app_builtin_save_config_init,
    .shutdown = app_builtin_save_config_shutdown,
    .handle = app_builtin_save_config_handle
  },
  .load_config = {
    .init = app_builtin_load_config_init,
    .shutdown = app_builtin_load_config_shutdown,
    .handle = app_builtin_load_config_handle
  },
  .list_users = {
    .init = app_builtin_list_users_init,
    .shutdown = app_builtin_list_users_shutdown,
    .handle = app_builtin_list_users_handle
  },
  .test_blurt = {
    .init = app_builtin_test_blurt_init,
    .shutdown = app_builtin_test_blurt_shutdown,
    .handle = app_builtin_test_blurt_handle
  }
};

const AppBuiltinLib *get_app_builtin_lib(void) {
  return &app_builtin_instance;
}
