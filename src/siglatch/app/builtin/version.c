/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "version.h"

#include "../version.h"
#include "../../lib.h"

int app_builtin_version_init(void) {
  return 1;
}

void app_builtin_version_shutdown(void) {
}

int app_builtin_version_handle(const AppBuiltinContext *ctx, AppActionReply *reply) {
  const char *server_name = NULL;

  if (!ctx || !ctx->listener) {
    LOGE("[builtin:version] Invalid builtin context\n");
    app_action_reply_set(reply, 0, "INVALID_CONTEXT");
    return 0;
  }

  server_name = (ctx->listener->server && ctx->listener->server->name[0] != '\0')
                    ? ctx->listener->server->name
                    : NULL;

  lib.log.emit(LOG_INFO, 1,
               "[builtin:version] user=%s ip=%s server=%s version=%s",
               (ctx->user && ctx->user->name[0] != '\0') ? ctx->user->name : "(unknown)",
               ctx->ip_addr ? ctx->ip_addr : "(unknown)",
               server_name ? server_name : "(none)",
               SIGLATCH_SERVER_VERSION);

  app_action_reply_set(reply, 1, "%s", SIGLATCH_SERVER_VERSION);
  return 1;
}
