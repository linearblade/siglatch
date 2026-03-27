/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "runtime.h"

#include <openssl/evp.h>
#include <string.h>

#include "../../../stdlib/openssl_session.h"
#include "../app.h"
#include "../../lib.h"

static const char *app_runtime_listener_bind_ip(const AppRuntimeListenerState *listener);
static int app_runtime_listener_bound_port(const AppRuntimeListenerState *listener);
static int app_runtime_listener_binding_changed(const AppRuntimeListenerState *listener,
                                                const siglatch_server *server);
static int app_runtime_listener_same_port_ip_change(const AppRuntimeListenerState *listener,
                                                    const siglatch_server *server);
static int app_runtime_sync_codec_context(const siglatch_config *cfg,
                                          const siglatch_server *server);

static int app_runtime_init(void) {
  return 1;
}

static void app_runtime_shutdown(void) {
}

static const char *app_runtime_listener_bind_ip(const AppRuntimeListenerState *listener) {
  if (!listener) {
    return "";
  }

  return listener->bound_ip;
}

static int app_runtime_listener_bound_port(const AppRuntimeListenerState *listener) {
  if (!listener) {
    return 0;
  }

  if (listener->bound_port > 0) {
    return listener->bound_port;
  }

  if (listener->server) {
    return listener->server->port;
  }

  return 0;
}

static int app_runtime_listener_binding_changed(const AppRuntimeListenerState *listener,
                                                const siglatch_server *server) {
  const char *current_ip = "";
  const char *target_ip = "";
  int current_port = 0;

  if (!listener || !server) {
    return 0;
  }

  current_ip = app_runtime_listener_bind_ip(listener);
  target_ip = server->bind_ip;
  current_port = app_runtime_listener_bound_port(listener);

  return current_port != server->port || strcmp(current_ip, target_ip) != 0;
}

static int app_runtime_listener_same_port_ip_change(const AppRuntimeListenerState *listener,
                                                    const siglatch_server *server) {
  const char *current_ip = "";
  const char *target_ip = "";
  int current_port = 0;

  if (!listener || !server) {
    return 0;
  }

  current_ip = app_runtime_listener_bind_ip(listener);
  target_ip = server->bind_ip;
  current_port = app_runtime_listener_bound_port(listener);

  return current_port == server->port && strcmp(current_ip, target_ip) != 0;
}

static void app_runtime_invalidate_config_borrows(
    AppRuntimeListenerState *listener,
    SiglatchOpenSSLSession *session) {
  if (listener) {
    listener->server = NULL;
  }

  if (!session) {
    return;
  }

  if (session->public_key_ctx) {
    EVP_PKEY_CTX_free(session->public_key_ctx);
    session->public_key_ctx = NULL;
  }

  if (session->private_key_ctx) {
    EVP_PKEY_CTX_free(session->private_key_ctx);
    session->private_key_ctx = NULL;
  }

  session->public_key = NULL;
  session->private_key = NULL;
  memset(session->hmac_key, 0, sizeof(session->hmac_key));
  session->hmac_key_len = 0;
}

static int app_runtime_sync_codec_context(const siglatch_config *cfg,
                                          const siglatch_server *server) {
  const SharedKnockCodecContextLib *codec_context_lib = NULL;
  AppWorkspace *workspace = NULL;
  M7MuxContext m7mux_ctx = {0};
  size_t i = 0;

  if (!cfg || !server) {
    return 0;
  }

  workspace = app.workspace.get();
  if (!workspace) {
    LOGE("Workspace unavailable during config reload\n");
    return 0;
  }

  codec_context_lib = get_shared_knock_codec_context_lib();
  if (!codec_context_lib || !codec_context_lib->set_server_key ||
      !codec_context_lib->clear_server_key || !codec_context_lib->add_keychain ||
      !codec_context_lib->remove_keychain || !codec_context_lib->set_openssl_session ||
      !codec_context_lib->clear_openssl_session) {
    LOGE("Codec context builder unavailable during config reload\n");
    return 0;
  }

  if (!workspace->codec_context) {
    if (!codec_context_lib->create(&workspace->codec_context)) {
      LOGE("Failed to create workspace codec context during config reload\n");
      return 0;
    }
  }

  codec_context_lib->clear_server_key(workspace->codec_context);
  workspace->codec_context->server_secure = server->secure ? 1 : 0;
  workspace->codec_context->nonce_window_ms = (uint64_t)NONCE_DEFAULT_TTL_SECONDS * 1000u;

  while (workspace->codec_context->keychain_len > 0u) {
    const char *name = workspace->codec_context->keychain[0].name;

    if (!name || !codec_context_lib->remove_keychain(workspace->codec_context, name)) {
      LOGE("Failed to clear codec keychain entry during config reload\n");
      return 0;
    }
  }

  if (server->secure && server->priv_key) {
    SharedKnockCodecServerKey server_key = {0};

    server_key.name = server->name;
    server_key.private_key = server->priv_key;

    if (!codec_context_lib->set_server_key(workspace->codec_context, &server_key)) {
      LOGE("Failed to install codec server key for '%s' during config reload\n",
           server->name);
      return 0;
    }
  }

  for (i = 0; i < (size_t)cfg->user_count; ++i) {
    const siglatch_user *user = &cfg->users[i];
    SharedKnockCodecKeyEntry entry = {0};

    if (!user->enabled) {
      continue;
    }

    entry.name = user->name;
    entry.public_key = user->pubkey;
    entry.private_key = NULL;
    entry.hmac_key = user->hmac_key;
    entry.hmac_key_len = sizeof(user->hmac_key);

    if (!codec_context_lib->add_keychain(workspace->codec_context, &entry)) {
      LOGE("Failed to add codec keychain entry for user '%s' during config reload\n",
           user->name);
      return 0;
    }
  }

  m7mux_ctx.socket = &lib.net.socket;
  m7mux_ctx.udp = &lib.net.udp;
  m7mux_ctx.time = &lib.time;
  m7mux_ctx.codec_context = workspace->codec_context;

  if (!lib.m7mux.set_context(&m7mux_ctx)) {
    LOGE("Failed to install codec context into m7mux during config reload\n");
    return 0;
  }

  return 1;
}

static int app_runtime_reload_config(
    AppRuntimeListenerState *listener,
    SiglatchOpenSSLSession *session,
    const char *config_path,
    const char *server_name) {
  char current_name[MAX_SERVER_NAME] = {0};
  char target_name[MAX_SERVER_NAME] = {0};
  siglatch_config *new_cfg = NULL;
  siglatch_config *old_cfg = NULL;
  const siglatch_server *selected_server = NULL;
  const siglatch_server *restored_server = NULL;
  SiglatchOpenSSLSession staged_session = {0};
  int binding_changed = 0;

  if (!listener || !session || !config_path || config_path[0] == '\0') {
    return 0;
  }

  if (listener->server && listener->server->name[0] != '\0') {
    lib.str.lcpy(current_name, listener->server->name, sizeof(current_name));
  }

  if (server_name && server_name[0] != '\0') {
    lib.str.lcpy(target_name, server_name, sizeof(target_name));
  } else if (current_name[0] != '\0') {
    lib.str.lcpy(target_name, current_name, sizeof(target_name));
  } else {
    LOGE("Cannot reload config: no selected server name available\n");
    return 0;
  }

  /*
   * Stage the next config first so the live runtime stays untouched unless
   * the new config parses, loads keys, and still contains a usable selected
   * server.
   */
  if (!app.config.load_detached(config_path, &new_cfg)) {
    LOGE("Failed to reload config from %s\n", config_path);
    return 0;
  }

  selected_server = app.config.server_by_name_from(new_cfg, target_name);
  if (!selected_server || !selected_server->enabled) {
    LOGE("Reloaded config does not contain an enabled server named '%s'\n", target_name);
    app.config.destroy(new_cfg);
    return 0;
  }

  if (!app.inbound.crypto.init_session_for_server(selected_server, &staged_session)) {
    LOGE("Reloaded config could not initialize a session for server '%s'\n", target_name);
    app.runtime.invalidate_config_borrows(NULL, &staged_session);
    app.config.destroy(new_cfg);
    return 0;
  }
  app.runtime.invalidate_config_borrows(NULL, &staged_session);

  binding_changed = app_runtime_listener_binding_changed(listener, selected_server);
  if (binding_changed) {
    if (app_runtime_listener_same_port_ip_change(listener, selected_server)) {
      LOGE("Hot reload cannot safely change bind_ip on the same port (%d) while the current listener is live; use rebind_listener or restart\n",
           selected_server->port);
      app.config.destroy(new_cfg);
      return 0;
    }

    if (!app.udp.probe_bind(listener, selected_server)) {
      LOGE("Reloaded config failed listener bind validation for %s:%d\n",
           selected_server->bind_ip[0] != '\0' ? selected_server->bind_ip : "0.0.0.0",
           selected_server->port);
      app.config.destroy(new_cfg);
      return 0;
    }
  }

  old_cfg = app.config.detach();
  app.runtime.invalidate_config_borrows(listener, session);
  app.config.attach(new_cfg);
  listener->server = app.config.server_by_name(target_name);

  if (!app.inbound.crypto.init_session_for_server(listener->server, session)) {
    LOGE("Failed to rebuild server session after config reload\n");

    app.runtime.invalidate_config_borrows(listener, session);

    new_cfg = app.config.detach();
    if (old_cfg) {
      app.config.attach(old_cfg);
      old_cfg = NULL;
    }

    if (new_cfg) {
      app.config.destroy(new_cfg);
    }

    if (current_name[0] != '\0') {
      restored_server = app.config.server_by_name(current_name);
    }

    if (restored_server &&
        app.inbound.crypto.init_session_for_server(restored_server, session)) {
      listener->server = restored_server;
    } else {
      app.runtime.invalidate_config_borrows(listener, session);
      LOGE("Failed to restore previous runtime bindings after config reload failure\n");
    }

    return 0;
  }

  if (binding_changed && !app.udp.rebind_listener(listener, listener->server)) {
    LOGE("Failed to apply listener rebind after config reload\n");

    app.runtime.invalidate_config_borrows(listener, session);

    new_cfg = app.config.detach();
    if (old_cfg) {
      app.config.attach(old_cfg);
      old_cfg = NULL;
    }

    if (new_cfg) {
      app.config.destroy(new_cfg);
    }

    if (current_name[0] != '\0') {
      restored_server = app.config.server_by_name(current_name);
    }

    if (restored_server &&
        app.inbound.crypto.init_session_for_server(restored_server, session)) {
      listener->server = restored_server;
    } else {
      app.runtime.invalidate_config_borrows(listener, session);
      LOGE("Failed to restore previous runtime bindings after rebind failure\n");
    }

    return 0;
  }

  if (!app_runtime_sync_codec_context(new_cfg, listener->server)) {
    LOGE("Failed to rebuild codec context after config reload\n");

    app.runtime.invalidate_config_borrows(listener, session);

    new_cfg = app.config.detach();
    if (old_cfg) {
      app.config.attach(old_cfg);
      old_cfg = NULL;
    }

    if (new_cfg) {
      app.config.destroy(new_cfg);
    }

    if (current_name[0] != '\0') {
      restored_server = app.config.server_by_name(current_name);
    }

    if (restored_server &&
        !app_runtime_sync_codec_context(old_cfg, restored_server)) {
      LOGE("Failed to restore previous codec context after reload failure\n");
    }

    if (restored_server &&
        app.inbound.crypto.init_session_for_server(restored_server, session)) {
      listener->server = restored_server;
    } else {
      app.runtime.invalidate_config_borrows(listener, session);
      LOGE("Failed to restore previous runtime bindings after codec context reload failure\n");
    }

    return 0;
  }

  if (old_cfg) {
    app.config.destroy(old_cfg);
  }

  return 1;
}

static const AppRuntimeLib app_runtime_instance = {
  .init = app_runtime_init,
  .shutdown = app_runtime_shutdown,
  .invalidate_config_borrows = app_runtime_invalidate_config_borrows,
  .reload_config = app_runtime_reload_config
};

const AppRuntimeLib *get_app_runtime_lib(void) {
  return &app_runtime_instance;
}
