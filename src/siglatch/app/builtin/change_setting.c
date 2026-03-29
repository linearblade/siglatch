/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "change_setting.h"

#include <ctype.h>
#include <string.h>

#include "../app.h"
#include "../../lib.h"

static int app_builtin_change_setting_push_wire_policy(
    const AppWorkspace *workspace,
    const siglatch_server *server,
    int enforce_wire_decode,
    int enforce_wire_auth);
static int app_builtin_change_setting_extract_kv(
    const AppBuiltinContext *ctx,
    char *key,
    size_t key_size,
    char *value,
    size_t value_size);
static int app_builtin_change_setting_set_server_wire_flag(
    const AppBuiltinContext *ctx,
    const char *key,
    int enabled,
    AppActionReply *reply);

int app_builtin_change_setting_init(void) {
  return 1;
}

void app_builtin_change_setting_shutdown(void) {
}

static int app_builtin_change_setting_push_wire_policy(
    const AppWorkspace *workspace,
    const siglatch_server *server,
    int enforce_wire_decode,
    int enforce_wire_auth) {
  M7Mux2Context m7mux2_ctx = {0};

  if (!workspace || !workspace->codec_context || !server) {
    return 0;
  }

  m7mux2_ctx.socket = &lib.net.socket;
  m7mux2_ctx.udp = &lib.net.udp;
  m7mux2_ctx.time = &lib.time;
  m7mux2_ctx.codec_context = workspace->codec_context;
  m7mux2_ctx.enforce_wire_decode = enforce_wire_decode;
  m7mux2_ctx.enforce_wire_auth = enforce_wire_auth;

  if (!lib.m7mux2.set_context(&m7mux2_ctx)) {
    LOGE("[builtin:change_setting] Failed to refresh mux wire policy for m7mux2\n");
    return 0;
  }

  return 1;
}

static int app_builtin_change_setting_extract_kv(
    const AppBuiltinContext *ctx,
    char *key,
    size_t key_size,
    char *value,
    size_t value_size) {
  char payload[256];
  char *line = NULL;
  char *parsed_key = NULL;
  char *parsed_value = NULL;
  char *space = NULL;
  size_t payload_len = 0;

  if (!ctx || !ctx->job || !ctx->job->request.payload_buffer ||
      !key || !value || key_size == 0u || value_size == 0u) {
    return 0;
  }

  payload_len = ctx->job->request.payload_len;
  if (payload_len == 0u || payload_len >= sizeof(payload)) {
    return 0;
  }

  memcpy(payload, ctx->job->request.payload_buffer, payload_len);
  payload[payload_len] = '\0';

  line = lib.str.trim(payload);
  if (!line || line[0] == '\0' || lib.str.is_blank(line)) {
    return 0;
  }

  if (!lib.str.split_kv(line, &parsed_key, &parsed_value)) {
    space = line;
    while (*space && !isspace((unsigned char)*space)) {
      space++;
    }

    if (*space == '\0') {
      return 0;
    }

    *space = '\0';
    parsed_key = lib.str.trim(line);
    parsed_value = lib.str.trim(space + 1);
  }

  if (!parsed_key || !parsed_key[0] || !parsed_value || !parsed_value[0]) {
    return 0;
  }

  if (strncmp(parsed_key, "action.", 7) == 0) {
    LOGW("[builtin:change_setting] Action-scoped wire policy is not implemented yet: %s\n",
         parsed_key);
    return 0;
  }

  if (strncmp(parsed_key, "server.", 7) == 0) {
    parsed_key += 7;
  }

  if (strcmp(parsed_key, "enforce_wire_decode") != 0 &&
      strcmp(parsed_key, "enforce_wire_auth") != 0) {
    return 0;
  }

  lib.str.lcpy(key, parsed_key, key_size);
  lib.str.lcpy(value, parsed_value, value_size);
  return 1;
}

static int app_builtin_change_setting_set_server_wire_flag(
    const AppBuiltinContext *ctx,
    const char *key,
    int enabled,
    AppActionReply *reply) {
  const siglatch_server *server = NULL;
  AppWorkspace *workspace = NULL;
  int old_decode = 0;
  int old_auth = 0;

  if (!ctx || !ctx->listener || !ctx->listener->server || !key) {
    if (reply) {
      app_action_reply_set(reply, 0, "INVALID_CONTEXT");
    }
    return 0;
  }

  if (!reply) {
    return 0;
  }

  server = ctx->listener->server;
  workspace = app.workspace.get();
  if (!workspace || !workspace->codec_context) {
    app_action_reply_set(reply, 0, "WORKSPACE_UNAVAILABLE");
    return 0;
  }

  old_decode = server->enforce_wire_decode;
  old_auth = server->enforce_wire_auth;

  if (strcmp(key, "enforce_wire_decode") == 0) {
    if (!app.config.server_set_enforce_wire_decode(server->name, enabled)) {
      app_action_reply_set(reply, 0, "SET_FAILED");
      return 0;
    }
  } else if (strcmp(key, "enforce_wire_auth") == 0) {
    if (!app.config.server_set_enforce_wire_auth(server->name, enabled)) {
      app_action_reply_set(reply, 0, "SET_FAILED");
      return 0;
    }
  } else {
    app_action_reply_set(reply, 0, "UNSUPPORTED_KEY");
    return 0;
  }

  if (!app_builtin_change_setting_push_wire_policy(
          workspace,
          server,
          server->enforce_wire_decode,
          server->enforce_wire_auth)) {
    if (strcmp(key, "enforce_wire_decode") == 0) {
      (void)app.config.server_set_enforce_wire_decode(server->name, old_decode);
    } else if (strcmp(key, "enforce_wire_auth") == 0) {
      (void)app.config.server_set_enforce_wire_auth(server->name, old_auth);
    }
    (void)app_builtin_change_setting_push_wire_policy(workspace, server, old_decode, old_auth);
    app_action_reply_set(reply, 0, "REFRESH_FAILED");
    return 0;
  }

  app_action_reply_set(reply,
                       1,
                       "%s=%s",
                       key,
                       enabled ? "yes" : "no");
  return 1;
}

int app_builtin_change_setting_handle(const AppBuiltinContext *ctx, AppActionReply *reply) {
  char key[128] = {0};
  char value[128] = {0};
  int enabled = 0;

  if (!ctx || !reply) {
    return 0;
  }

  if (!app_builtin_change_setting_extract_kv(ctx, key, sizeof(key), value, sizeof(value))) {
    app_action_reply_set(reply,
                         0,
                         "Expected payload: [server.]enforce_wire_(decode|auth) = yes|no");
    return 0;
  }

  if (!lib.str.to_bool(value, &enabled)) {
    app_action_reply_set(reply, 0, "Invalid boolean value: %s", value);
    return 0;
  }

  return app_builtin_change_setting_set_server_wire_flag(ctx, key, enabled, reply);
}
