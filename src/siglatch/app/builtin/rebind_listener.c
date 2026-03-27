/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "rebind_listener.h"

#include <string.h>

#include "bind_target.h"
#include "../app.h"
#include "../../lib.h"

int app_builtin_rebind_listener_init(void) {
  return 1;
}

void app_builtin_rebind_listener_shutdown(void) {
}

int app_builtin_rebind_listener_handle(const AppBuiltinContext *ctx, AppActionReply *reply) {
  siglatch_server target = {0};
  const char *server_name = NULL;
  AppBuiltinBindTarget parsed = {0};
  int current_port = 0;
  char current_binding[128] = {0};
  char target_binding[128] = {0};

  if (!ctx || !ctx->listener || !ctx->action || !ctx->user) {
    LOGE("[builtin:rebind_listener] Invalid builtin context\n");
    app_action_reply_set(reply, 0, "INVALID_CONTEXT");
    return 0;
  }

  if (!ctx->listener->server) {
    LOGE("[builtin:rebind_listener] No active server is attached to the listener\n");
    app_action_reply_set(reply, 0, "NO_ACTIVE_SERVER");
    return 0;
  }

  server_name = (ctx->listener->server->name[0] != '\0')
                    ? ctx->listener->server->name
                    : NULL;

  if (!app_builtin_parse_bind_target(ctx->job, &parsed)) {
    lib.log.emit(LOG_ERROR, 1,
                 "[builtin:rebind_listener] Invalid payload; expected empty payload, PORT, IP, or [IP]:PORT");
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
                 "[builtin:rebind_listener] IPv6 bind targets are not supported yet: %s",
                 target.bind_ip);
    app_action_reply_set(reply, 0, "IPV6_BIND_UNSUPPORTED");
    return 0;
  }

  current_port = (ctx->listener->bound_port > 0)
                     ? ctx->listener->bound_port
                     : ctx->listener->server->port;
  app_builtin_format_binding(ctx->listener->bound_ip,
                             current_port,
                             current_binding,
                             sizeof(current_binding));
  app_builtin_format_binding(target.bind_ip,
                             target.port,
                             target_binding,
                             sizeof(target_binding));

  lib.log.emit(LOG_INFO, 1,
               "[builtin:rebind_listener] user=%s ip=%s current=%s target=%s server=%s",
               ctx->user->name,
               ctx->ip_addr ? ctx->ip_addr : "(unknown)",
               current_binding,
               target_binding,
               server_name ? server_name : "(none)");

  if (current_port == target.port &&
      strcmp(ctx->listener->bound_ip, target.bind_ip) == 0) {
    if (server_name && !app.config.server_set_binding(server_name,
                                                      target.bind_ip,
                                                      current_port)) {
      lib.log.emit(LOG_ERROR, 1,
                   "[builtin:rebind_listener] failed to reconcile config binding for server=%s",
                   server_name);
      app_action_reply_set(reply, 0, "CONFIG_BIND_SYNC_FAILED");
      return 0;
    }

    if (server_name) {
      ctx->listener->server = app.config.server_by_name(server_name);
    }

    lib.log.emit(LOG_INFO, 1,
                 "[builtin:rebind_listener] listener already bound to %s",
                 current_binding);
    app_action_reply_set(reply, 1, "ALREADY_BOUND %s", current_binding);
    return 1;
  }

  if (!app.udp.rebind_listener(ctx->listener, &target)) {
    lib.log.emit(LOG_ERROR, 1,
                 "[builtin:rebind_listener] rebind failed for target_port=%d",
                 target.port);
    app_action_reply_set(reply, 0, "REBIND_FAILED %s", target_binding);
    return 0;
  }

  if (server_name && !app.config.server_set_binding(server_name,
                                                    target.bind_ip,
                                                    target.port)) {
    lib.log.emit(LOG_ERROR, 1,
                 "[builtin:rebind_listener] listener rebound but failed to update config binding for server=%s",
                 server_name);
    app_action_reply_set(reply, 0, "CONFIG_BIND_SYNC_FAILED");
    return 0;
  }

  if (server_name) {
    ctx->listener->server = app.config.server_by_name(server_name);
  }

  app_builtin_format_binding(ctx->listener->bound_ip,
                             ctx->listener->bound_port,
                             target_binding,
                             sizeof(target_binding));
  lib.log.emit(LOG_INFO, 1,
               "[builtin:rebind_listener] listener now bound to %s",
               target_binding);
  app_action_reply_set(reply, 1, "BOUND %s", target_binding);
  return 1;
}
