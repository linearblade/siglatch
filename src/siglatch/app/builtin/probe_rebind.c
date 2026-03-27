/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "probe_rebind.h"

#include <string.h>

#include "bind_target.h"
#include "../app.h"
#include "../../lib.h"

int app_builtin_probe_rebind_init(void) {
  return 1;
}

void app_builtin_probe_rebind_shutdown(void) {
}

int app_builtin_probe_rebind_handle(const AppBuiltinContext *ctx, AppActionReply *reply) {
  siglatch_server target = {0};
  AppBuiltinBindTarget parsed = {0};
  char current_binding[128] = {0};
  char target_binding[128] = {0};

  if (!ctx || !ctx->listener || !ctx->action || !ctx->user) {
    LOGE("[builtin:probe_rebind] Invalid builtin context\n");
    app_action_reply_set(reply, 0, "INVALID_CONTEXT");
    return 0;
  }

  if (!ctx->listener->server) {
    LOGE("[builtin:probe_rebind] No active server is attached to the listener\n");
    app_action_reply_set(reply, 0, "NO_ACTIVE_SERVER");
    return 0;
  }

  if (!app_builtin_parse_bind_target(ctx->job, &parsed)) {
    lib.log.emit(LOG_ERROR, 1,
                 "[builtin:probe_rebind] Invalid payload; expected empty payload, PORT, IP, or [IP]:PORT");
    app_action_reply_set(reply, 0, "INVALID_BIND_TARGET");
    return 0;
  }

  target = *ctx->listener->server;
  if (parsed.has_ip_override) {
    lib.str.lcpy(target.bind_ip, parsed.bind_ip, sizeof(target.bind_ip));
  }
  if (parsed.has_port_override) {
    target.port = parsed.port;
  }

  if (target.bind_ip[0] != '\0' && lib.net.addr.is_ipv6(target.bind_ip)) {
    lib.log.emit(LOG_ERROR, 1,
                 "[builtin:probe_rebind] IPv6 bind targets are not supported yet: %s",
                 target.bind_ip);
    app_action_reply_set(reply, 0, "IPV6_BIND_UNSUPPORTED");
    return 0;
  }

  app_builtin_format_binding(ctx->listener->bound_ip,
                             ctx->listener->bound_port > 0
                                 ? ctx->listener->bound_port
                                 : ctx->listener->server->port,
                             current_binding,
                             sizeof(current_binding));
  app_builtin_format_binding(target.bind_ip,
                             target.port,
                             target_binding,
                             sizeof(target_binding));

  lib.log.emit(LOG_INFO, 1,
               "[builtin:probe_rebind] user=%s ip=%s current=%s target=%s server=%s",
               ctx->user->name,
               ctx->ip_addr ? ctx->ip_addr : "(unknown)",
               current_binding,
               target_binding,
               ctx->listener->server->name[0] != '\0'
                   ? ctx->listener->server->name
                   : "(none)");

  if (!app.udp.probe_bind(ctx->listener, &target)) {
    lib.log.emit(LOG_ERROR, 1,
                 "[builtin:probe_rebind] probe failed for target_port=%d",
                 target.port);
    app_action_reply_set(reply, 0, "PROBE_FAILED %s", target_binding);
    return 0;
  }

  if (ctx->listener->sock >= 0 &&
      target.port == ctx->listener->bound_port &&
      strcmp(target.bind_ip, ctx->listener->bound_ip) == 0) {
    lib.log.emit(LOG_INFO, 1,
                 "[builtin:probe_rebind] current listener already owns %s",
                 target_binding);
    app_action_reply_set(reply, 1, "ALREADY_BOUND %s", target_binding);
  } else {
    lib.log.emit(LOG_INFO, 1,
                 "[builtin:probe_rebind] target binding %s is bindable",
                 target_binding);
    app_action_reply_set(reply, 1, "BINDABLE %s", target_binding);
  }

  return 1;
}
