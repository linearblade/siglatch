/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "reload_config.h"

#include "../../lib.h"
#include "../app.h"

int app_builtin_reload_config_init(void) {
  return 1;
}

void app_builtin_reload_config_shutdown(void) {
}

int app_builtin_reload_config_handle(const AppBuiltinContext *ctx, AppActionReply *reply) {
  const char *server_name = NULL;

  if (!ctx || !ctx->listener || !ctx->session || !ctx->action || !ctx->user) {
    LOGE("[builtin:reload_config] Invalid builtin context\n");
    app_action_reply_set(reply, 0, "INVALID_CONTEXT");
    return 0;
  }

  if (ctx->listener->config_path[0] == '\0') {
    LOGE("[builtin:reload_config] No active config path is available for reload\n");
    app_action_reply_set(reply, 0, "NO_CONFIG_PATH");
    return 0;
  }

  server_name = (ctx->listener->server && ctx->listener->server->name[0] != '\0')
                    ? ctx->listener->server->name
                    : NULL;

  lib.log.emit(LOG_INFO, 1,
               "[builtin:reload_config] user=%s ip=%s config=%s server=%s",
               ctx->user->name,
               ctx->ip_addr ? ctx->ip_addr : "(unknown)",
               ctx->listener->config_path,
               server_name ? server_name : "(current)");

  if (!app.runtime.reload_config(
          ctx->listener,
          ctx->session,
          ctx->listener->config_path,
          server_name)) {
    lib.log.emit(LOG_ERROR, 1,
                 "[builtin:reload_config] reload failed for config=%s",
                 ctx->listener->config_path);
    app_action_reply_set(reply, 0, "RELOAD_FAILED");
    return 0;
  }

  lib.log.emit(LOG_INFO, 1,
               "[builtin:reload_config] reload complete for config=%s",
               ctx->listener->config_path);
  app_action_reply_set(reply, 1, "RELOADED");
  return 1;
}
