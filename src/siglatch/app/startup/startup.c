/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "startup.h"

#include <stdio.h>
#include <stdlib.h>

#include "../app.h"
#include "../../lifecycle.h"
#include "../../lib.h"
#include "../../../shared/shared.h"
#include "../../../shared/knock/codec/codec.h"
#include "../../../stdlib/protocol/udp/m7mux/normalize/normalize.h"

#ifndef SL_CONFIG_PATH_DEFAULT
#define SL_CONFIG_PATH_DEFAULT "/etc/siglatch/server.conf"
#endif

static int app_startup_init(void) {
  return 1;
}

static void app_startup_shutdown(void) {
  const SharedKnockCodecLib *codec = NULL;

  codec = get_shared_knock_codec_lib();
  if (!codec) {
    return;
  }

  if (codec->v3.shutdown) {
    codec->v3.shutdown();
  }
  if (codec->v2.shutdown) {
    codec->v2.shutdown();
  }
  if (codec->v1.shutdown) {
    codec->v1.shutdown();
  }
}

static void app_startup_reset_state(AppStartupState *state) {
  if (!state) {
    return;
  }

  if (lib.nonce.cache_shutdown) {
    lib.nonce.cache_shutdown(&state->listener.nonce);
  }

  *state = (AppStartupState){0};
  state->listener.sock = -1;
  state->listener.process = &state->process;
  state->exit_code = EXIT_FAILURE;
}

static int app_startup_select_server(const AppParsedOpts *parsed,
                                     const siglatch_config *cfg,
                                     AppRuntimeListenerState *listener_out) {
  const char *cli_server_name = NULL;
  const char *env_server_name = NULL;
  const char *selected_server_name = NULL;
  const char *selected_server_source = NULL;

  if (!parsed || !cfg || !listener_out) {
    return 0;
  }

  cli_server_name = parsed->values.server_name[0] ? parsed->values.server_name : NULL;
  env_server_name = getenv("SIGLATCH_SERVER");

  if (cli_server_name) {
    selected_server_name = cli_server_name;
    selected_server_source = "cli";
  } else if (env_server_name && env_server_name[0] != '\0') {
    selected_server_name = env_server_name;
    selected_server_source = "env";
  } else if (cfg->default_server[0] != '\0') {
    selected_server_name = cfg->default_server;
    selected_server_source = "config";
  } else {
    selected_server_name = "secure";
    selected_server_source = "fallback";
  }

  listener_out->server = app.server.select(selected_server_name);
  if (!listener_out->server) {
    const siglatch_server *candidate_server = app.config.server_by_name(selected_server_name);
    if (candidate_server && !candidate_server->enabled) {
      LOGE("Server block '%s' is disabled in config\n", selected_server_name);
    } else {
      LOGE("Server block '%s' not found in config\n", selected_server_name);
    }
    siglatch_report_config_error();
    return 0;
  }

  LOGD("[startup] Selected server '%s' (source=%s)\n",
       selected_server_name,
       selected_server_source);

  return listener_out->server != NULL;
}

static void app_startup_resolve_output_mode(const AppStartupState *state) {
  const char *env_output_value = NULL;
  int env_output_mode = 0;
  int config_output_mode = 0;

  if (!state || !state->cfg) {
    return;
  }

  if (state->parsed.values.output_mode) {
    lib.print.output_set_mode(state->parsed.values.output_mode);
    return;
  }

  env_output_value = getenv("SIGLATCH_OUTPUT_MODE");
  env_output_mode = lib.print.output_parse_mode(env_output_value);
  if (env_output_mode) {
    lib.print.output_set_mode(env_output_mode);
    return;
  }

  if (env_output_value && *env_output_value) {
    LOGW("Invalid SIGLATCH_OUTPUT_MODE='%s' (expected 'unicode' or 'ascii')\n",
         env_output_value);
  }

  if (state->listener.server && state->listener.server->output_mode) {
    config_output_mode = state->listener.server->output_mode;
  } else if (state->cfg->output_mode) {
    config_output_mode = state->cfg->output_mode;
  }

  if (config_output_mode) {
    lib.print.output_set_mode(config_output_mode);
  }
}

static void app_startup_apply_logging(const AppStartupState *state) {
  if (!state || !state->listener.server) {
    LOGW("LOG FILE NOT DEFINED IN CONFIG - logging disabled.\n");
    lib.log.set_enabled(0);
    return;
  }

  if (*state->listener.server->log_file) {
    lib.log.open(state->listener.server->log_file);
    return;
  }

  LOGW("LOG FILE NOT DEFINED IN CONFIG - logging disabled.\n");
  lib.log.set_enabled(0);
}

static int app_startup_register_codec_modules(const AppWorkspace *workspace) {
  const SharedKnockCodecLib *codec = NULL;

  if (!workspace || !workspace->codec_context) {
    LOGE("Codec context unavailable for codec module registration\n");
    return 0;
  }

  codec = &shared.knock.codec;
  if (!codec || !codec->v1.init || !codec->v1.shutdown ||
      !codec->v2.init || !codec->v2.shutdown ||
      !codec->v3.init || !codec->v3.shutdown) {
    LOGE("Codec module registry unavailable\n");
    return 0;
  }

  if (!codec->v1.init(workspace->codec_context)) {
    LOGE("Failed to initialize codec.v1\n");
    return 0;
  }

  if (!codec->v2.init(workspace->codec_context)) {
    LOGE("Failed to initialize codec.v2\n");
    codec->v1.shutdown();
    return 0;
  }

  if (!codec->v3.init(workspace->codec_context)) {
    LOGE("Failed to initialize codec.v3\n");
    codec->v2.shutdown();
    codec->v1.shutdown();
    return 0;
  }

  {
    const M7MuxNormalizeLib *normalize = NULL;
    const M7MuxNormalizeAdapter *adapter = NULL;
    const char *registered_names[3] = {0};
    size_t registered_count = 0u;

    normalize = get_protocol_udp_m7mux_normalize_lib();
    if (!normalize || !normalize->adapter.register_adapter ||
        !normalize->adapter.unregister_adapter) {
      LOGE("Normalize adapter registry unavailable\n");
      codec->v3.shutdown();
      codec->v2.shutdown();
      codec->v1.shutdown();
      return 0;
    }

    adapter = codec->v1_adapter;
    if (!adapter || !normalize->adapter.register_adapter(adapter)) {
      goto fail_unregister_adapters;
    }
    registered_names[registered_count++] = adapter->name;

    adapter = codec->v2_adapter;
    if (!adapter || !normalize->adapter.register_adapter(adapter)) {
      goto fail_unregister_adapters;
    }
    registered_names[registered_count++] = adapter->name;

    adapter = codec->v3_adapter;
    if (!adapter || !normalize->adapter.register_adapter(adapter)) {
      goto fail_unregister_adapters;
    }
    registered_names[registered_count++] = adapter->name;

    return 1;

  fail_unregister_adapters:
    while (registered_count > 0u) {
      --registered_count;
      if (registered_names[registered_count]) {
        normalize->adapter.unregister_adapter(registered_names[registered_count]);
      }
    }

    codec->v3.shutdown();
    codec->v2.shutdown();
    codec->v1.shutdown();
    return 0;
  }
}

static int app_startup_sync_codec_context(const AppStartupState *state) {
  const SharedKnockCodecContextLib *codec_context_lib = NULL;
  AppWorkspace *workspace = NULL;
  M7MuxContext m7mux_ctx = {0};
  size_t i = 0;

  if (!state || !state->cfg || !state->listener.server) {
    return 0;
  }

  workspace = app.workspace.get();
  if (!workspace) {
    LOGE("Workspace unavailable for codec context\n");
    return 0;
  }

  codec_context_lib = get_shared_knock_codec_context_lib();
  if (!codec_context_lib || !codec_context_lib->set_server_key ||
      !codec_context_lib->clear_server_key || !codec_context_lib->add_keychain ||
      !codec_context_lib->remove_keychain || !codec_context_lib->set_openssl_session ||
      !codec_context_lib->clear_openssl_session) {
    LOGE("Codec context builder unavailable\n");
    return 0;
  }

  if (!workspace->codec_context) {
    if (!codec_context_lib->create(&workspace->codec_context)) {
      LOGE("Failed to create workspace codec context\n");
      return 0;
    }
  }

  codec_context_lib->clear_server_key(workspace->codec_context);
  workspace->codec_context->server_secure = state->listener.server->secure ? 1 : 0;
  workspace->codec_context->nonce_window_ms = (uint64_t)NONCE_DEFAULT_TTL_SECONDS * 1000u;

  while (workspace->codec_context->keychain_len > 0u) {
    const char *name = workspace->codec_context->keychain[0].name;

    if (!name || !codec_context_lib->remove_keychain(workspace->codec_context, name)) {
      LOGE("Failed to clear codec keychain entry\n");
      return 0;
    }
  }

  if (state->listener.server->secure && state->listener.server->priv_key) {
    SharedKnockCodecServerKey server_key = {0};

    server_key.name = state->listener.server->name;
    server_key.private_key = state->listener.server->priv_key;

    if (!codec_context_lib->set_server_key(workspace->codec_context, &server_key)) {
      LOGE("Failed to install codec server key for '%s'\n",
           state->listener.server->name);
      return 0;
    }
  }

  for (i = 0; i < (size_t)state->cfg->user_count; ++i) {
    const siglatch_user *user = &state->cfg->users[i];
    SharedKnockCodecKeyEntry entry = {0};

    if (!user->enabled) {
      continue;
    }

    entry.name = user->name;
    entry.user_id = user->id;
    entry.public_key = user->pubkey;
    entry.private_key = NULL;
    entry.hmac_key = user->hmac_key;
    entry.hmac_key_len = sizeof(user->hmac_key);

    if (!codec_context_lib->add_keychain(workspace->codec_context, &entry)) {
      LOGE("Failed to add codec keychain entry for user '%s'\n", user->name);
      return 0;
    }
  }

  if (!app_startup_register_codec_modules(workspace)) {
    return 0;
  }

  m7mux_ctx.socket = &lib.net.socket;
  m7mux_ctx.udp = &lib.net.udp;
  m7mux_ctx.time = &lib.time;
  m7mux_ctx.codec_context = workspace->codec_context;
  m7mux_ctx.enforce_wire_decode = state->listener.server->enforce_wire_decode;
  m7mux_ctx.enforce_wire_auth = state->listener.server->enforce_wire_auth;

  if (!lib.m7mux.set_context(&m7mux_ctx)) {
    LOGE("Failed to install codec context into m7mux\n");
    return 0;
  }

  return 1;
}

static int app_startup_prepare(int argc, char *argv[], AppStartupState *state) {
  const char *config_path = NULL;

  app_startup_reset_state(state);

  if (!state) {
    return 0;
  }

  if (!app.opts.parse(argc, argv, &state->parsed)) {
    if (state->parsed.error[0] != '\0') {
      fprintf(stderr, "%s\n", state->parsed.error);
    }
    app.help.show(argc, argv);
    state->should_exit = 1;
    state->exit_code = state->parsed.exit_code ? state->parsed.exit_code : 2;
    return 1;
  }

  if (state->parsed.values.help_requested) {
    app.help.show(argc, argv);
    state->should_exit = 1;
    state->exit_code = 0;
    return 1;
  }

  if (state->parsed.values.version_requested) {
    app.help.version();
    state->should_exit = 1;
    state->exit_code = 0;
    return 1;
  }

  app.signal.install(&state->process);
  lib.log.set_enabled(1);
  lib.log.set_debug(1);
  lib.log.set_level(LOG_TRACE);

  LOGE("Launching...\n");
  config_path = state->parsed.values.config_path[0]
                    ? state->parsed.values.config_path
                    : SL_CONFIG_PATH_DEFAULT;
  lib.str.lcpy(state->listener.config_path,
               config_path,
               sizeof(state->listener.config_path));

  LOGD("[startup] Loading config from %s\n", config_path);
  if (!app.config.load(config_path)) {
    siglatch_report_config_error();
    return 0;
  }

  state->cfg = app.config.get();
  if (!state->cfg) {
    siglatch_report_config_error();
    return 0;
  }

  if (!app_startup_select_server(&state->parsed, state->cfg, &state->listener)) {
    return 0;
  }

  if (!lib.nonce.cache_init(&state->listener.nonce, NULL)) {
    LOGE("Failed to initialize listener nonce cache\n");
    return 0;
  }

  if (state->parsed.values.dump_config_requested) {
    app.config.dump();
    state->should_exit = 1;
    state->exit_code = 0;
    return 1;
  }

  app_startup_resolve_output_mode(state);

  if (!app_startup_sync_codec_context(state)) {
    return 0;
  }

  LOGT("loaded config\n");
  app_startup_apply_logging(state);

  state->exit_code = 0;
  return 1;
}

static const AppStartupLib app_startup_instance = {
  .init = app_startup_init,
  .shutdown = app_startup_shutdown,
  .prepare = app_startup_prepare
};

const AppStartupLib *get_app_startup_lib(void) {
  return &app_startup_instance;
}
