/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "app.h"

#include <stdio.h>

App app = {
  .builtin = {0},
  .config = {0},
  .daemon4 = {0},
  .help = {0},
  .inbound = {0},
  .keys = {0},
  .object = {0},
  .opts = {0},
  .payload = {0},
  .policy = {0},
  .runtime = {0},
  .server = {0},
  .signal = {0},
  .workspace = {0},
  .startup = {0},
  .udp = {0}
};

static int g_app_initialized = 0;

int init_app(void) {
  int builtin_initialized = 0;
  int config_initialized = 0;
  int daemon4_initialized = 0;
  int daemon4_helper_initialized = 0;
  int daemon4_auth_initialized = 0;
  int daemon4_request_initialized = 0;
  int daemon4_policy_initialized = 0;
  int daemon4_payload_initialized = 0;
  int help_initialized = 0;
  int inbound_initialized = 0;
  int keys_initialized = 0;
  int object_initialized = 0;
  int opts_initialized = 0;
  int payload_initialized = 0;
  int policy_initialized = 0;
  int runtime_initialized = 0;
  int server_initialized = 0;
  int signal_initialized = 0;
  int workspace_initialized = 0;
  int startup_initialized = 0;
  int tick_initialized = 0;
  int udp_initialized = 0;

  if (g_app_initialized) {
    return 1;
  }

  app.builtin = *get_app_builtin_lib();
  app.config = *get_app_config_lib();
  app.daemon4 = *get_app_daemon4_lib();
  app.help = *get_app_help_lib();
  app.inbound = *get_app_inbound_lib();
  app.keys = *get_app_keys_lib();
  app.object = *get_app_object_lib();
  app.opts = *get_app_opts_lib();
  app.payload = *get_app_payload_lib();
  app.policy = *get_app_policy_lib();
  app.runtime = *get_app_runtime_lib();
  app.server = *get_app_server_lib();
  app.signal = *get_app_signal_lib();
  app.workspace = *get_app_workspace_lib();
  app.startup = *get_app_startup_lib();
  app.udp = *get_app_udp_lib();

  /*
   * Wiring contract (intentional): server app module factories are
   * all-or-nothing. If init_app() succeeds, the execution callbacks exposed
   * by each acquired module are expected to be valid as part of that module's
   * provider contract.
   */
  if (!app.builtin.init || !app.builtin.shutdown ||
      !app.builtin.supports || !app.builtin.is_action ||
      !app.builtin.build_context || !app.builtin.handle ||
      !app.builtin.probe_rebind.init || !app.builtin.probe_rebind.shutdown || !app.builtin.probe_rebind.handle ||
      !app.builtin.rebind_listener.init || !app.builtin.rebind_listener.shutdown || !app.builtin.rebind_listener.handle ||
      !app.builtin.reload_config.init || !app.builtin.reload_config.shutdown || !app.builtin.reload_config.handle ||
      !app.builtin.change_setting.init || !app.builtin.change_setting.shutdown || !app.builtin.change_setting.handle ||
      !app.builtin.save_config.init || !app.builtin.save_config.shutdown || !app.builtin.save_config.handle ||
      !app.builtin.load_config.init || !app.builtin.load_config.shutdown || !app.builtin.load_config.handle ||
      !app.builtin.list_users.init || !app.builtin.list_users.shutdown || !app.builtin.list_users.handle ||
      !app.builtin.test_blurt.init || !app.builtin.test_blurt.shutdown || !app.builtin.test_blurt.handle ||
      !app.config.init || !app.config.shutdown ||
      !app.config.load || !app.config.load_detached ||
      !app.config.consume || !app.config.unload ||
      !app.config.detach || !app.config.attach || !app.config.destroy ||
      !app.config.get || !app.config.set_context ||
      !app.config.dump || !app.config.dump_ptr ||
      !app.config.deaddrop_starts_with_buffer ||
      !app.config.action_available_by_user ||
      !app.config.user_by_id || !app.config.user_by_id_from ||
      !app.config.action_by_id || !app.config.action_by_id_from ||
      !app.config.server_by_name || !app.config.server_by_name_from ||
      !app.config.server_set_port || !app.config.server_set_binding ||
      !app.config.deaddrop_by_name || !app.config.deaddrop_by_name_from ||
      !app.config.username_by_id ||
      !app.daemon4.init || !app.daemon4.shutdown || !app.daemon4.process ||
      !app.daemon4.helper.init || !app.daemon4.helper.shutdown ||
      !app.daemon4.helper.copy_job_to_knock_packet ||
      !app.daemon4.helper.copy_job_reply_to_send ||
      !app.daemon4.helper.time_until_ms ||
      !app.daemon4.auth.init || !app.daemon4.auth.shutdown ||
      !app.daemon4.auth.authorize ||
      !app.daemon4.request.init || !app.daemon4.request.shutdown ||
      !app.daemon4.request.resolve_user_action ||
      !app.daemon4.request.bind_user_action ||
      !app.daemon4.policy.init || !app.daemon4.policy.shutdown ||
      !app.daemon4.policy.enforce ||
      !app.daemon4.runner.init || !app.daemon4.runner.shutdown || !app.daemon4.runner.run ||
      !app.daemon4.payload.init || !app.daemon4.payload.shutdown ||
      !app.daemon4.payload.consume ||
      !app.daemon4.job.init || !app.daemon4.job.shutdown ||
      !app.daemon4.job.state_init || !app.daemon4.job.state_reset ||
      !app.daemon4.job.enqueue || !app.daemon4.job.drain ||
      !app.daemon4.job.consume ||
      !app.daemon4.job.reserve_response ||
      !app.daemon4.job.dispose ||
      !app.daemon4.job.flush_buffer ||
      !app.daemon4.tick.init || !app.daemon4.tick.shutdown ||
      !app.daemon4.tick.next_at || !app.daemon4.tick.run ||
      !app.help.init || !app.help.shutdown || !app.help.show ||
      !app.inbound.init || !app.inbound.shutdown ||
      !app.keys.init || !app.keys.shutdown ||
      !app.object.init || !app.object.shutdown ||
      !app.object.supports_static || !app.object.supports_dynamic ||
      !app.object.build_context || !app.object.run_static || !app.object.run_dynamic ||
      !app.opts.init || !app.opts.shutdown ||
      !app.payload.init || !app.payload.shutdown ||
      !app.payload.run_shell || !app.payload.run_shell_wait ||
      !app.policy.init || !app.policy.shutdown ||
      !app.policy.server_ip_allowed || !app.policy.user_ip_allowed ||
      !app.policy.action_ip_allowed || !app.policy.request_ip_allowed ||
      !app.payload.codec.init || !app.payload.codec.shutdown ||
      !app.payload.codec.pack || !app.payload.codec.unpack ||
      !app.payload.codec.validate || !app.payload.codec.deserialize || !app.payload.codec.deserialize_strerror ||
      !app.payload.digest.init || !app.payload.digest.shutdown ||
      !app.payload.digest.generate || !app.payload.digest.generate_oneshot ||
      !app.payload.digest.sign || !app.payload.digest.validate ||
      !app.payload.reply.reset || !app.payload.reply.set ||
      !app.payload.unstructured.init || !app.payload.unstructured.shutdown || !app.payload.unstructured.handle ||
      !app.runtime.init || !app.runtime.shutdown ||
      !app.runtime.invalidate_config_borrows || !app.runtime.reload_config ||
      !app.server.init || !app.server.shutdown ||
      !app.signal.init || !app.signal.shutdown || !app.signal.install || !app.signal.should_exit || !app.signal.request_exit ||
      !app.workspace.init || !app.workspace.shutdown || !app.workspace.get ||
      !app.startup.init || !app.startup.shutdown ||
      !app.udp.init || !app.udp.shutdown ||
      !app.udp.start_listener || !app.udp.probe_bind || !app.udp.rebind_listener) {
    fprintf(stderr, "Siglatch app wiring is incomplete\n");
    return 0;
  }

  if (!app.builtin.init()) {
    fprintf(stderr, "Failed to initialize app.builtin\n");
    goto fail;
  }
  builtin_initialized = 1;

  {
    siglatch_config_context config_ctx = {0};
    if (!app.config.init(&config_ctx)) {
      fprintf(stderr, "Failed to initialize app.config\n");
      goto fail;
    }
  }
  config_initialized = 1;

  if (!app.daemon4.init()) {
    fprintf(stderr, "Failed to initialize app.daemon4\n");
    goto fail;
  }
  daemon4_initialized = 1;

  if (!app.daemon4.helper.init()) {
    fprintf(stderr, "Failed to initialize app.daemon4.helper\n");
    goto fail;
  }
  daemon4_helper_initialized = 1;

  if (!app.daemon4.auth.init()) {
    fprintf(stderr, "Failed to initialize app.daemon4.auth\n");
    goto fail;
  }
  daemon4_auth_initialized = 1;

  if (!app.daemon4.request.init()) {
    fprintf(stderr, "Failed to initialize app.daemon4.request\n");
    goto fail;
  }
  daemon4_request_initialized = 1;

  if (!app.daemon4.policy.init()) {
    fprintf(stderr, "Failed to initialize app.daemon4.policy\n");
    goto fail;
  }
  daemon4_policy_initialized = 1;

  if (!app.daemon4.payload.init()) {
    fprintf(stderr, "Failed to initialize app.daemon4.payload\n");
    goto fail;
  }
  daemon4_payload_initialized = 1;

  if (!app.help.init()) {
    fprintf(stderr, "Failed to initialize app.help\n");
    goto fail;
  }
  help_initialized = 1;

  if (!app.inbound.init()) {
    fprintf(stderr, "Failed to initialize app.inbound\n");
    goto fail;
  }
  inbound_initialized = 1;

  if (!app.keys.init()) {
    fprintf(stderr, "Failed to initialize app.keys\n");
    goto fail;
  }
  keys_initialized = 1;

  if (!app.object.init()) {
    fprintf(stderr, "Failed to initialize app.object\n");
    goto fail;
  }
  object_initialized = 1;

  if (!app.opts.init(NULL)) {
    fprintf(stderr, "Failed to initialize app.opts\n");
    goto fail;
  }
  opts_initialized = 1;

  if (!app.payload.init()) {
    fprintf(stderr, "Failed to initialize app.payload\n");
    goto fail;
  }
  payload_initialized = 1;

  if (!app.policy.init()) {
    fprintf(stderr, "Failed to initialize app.policy\n");
    goto fail;
  }
  policy_initialized = 1;

  if (!app.runtime.init()) {
    fprintf(stderr, "Failed to initialize app.runtime\n");
    goto fail;
  }
  runtime_initialized = 1;

  if (!app.server.init()) {
    fprintf(stderr, "Failed to initialize app.server\n");
    goto fail;
  }
  server_initialized = 1;

  if (!app.signal.init()) {
    fprintf(stderr, "Failed to initialize app.signal\n");
    goto fail;
  }
  signal_initialized = 1;

  if (!app.workspace.init()) {
    fprintf(stderr, "Failed to initialize app.workspace\n");
    goto fail;
  }
  workspace_initialized = 1;

  if (!app.startup.init()) {
    fprintf(stderr, "Failed to initialize app.startup\n");
    goto fail;
  }
  startup_initialized = 1;

  if (!app.daemon4.tick.init()) {
    fprintf(stderr, "Failed to initialize app.daemon4.tick\n");
    goto fail;
  }
  tick_initialized = 1;

  if (!app.udp.init()) {
    fprintf(stderr, "Failed to initialize app.udp\n");
    goto fail;
  }
  udp_initialized = 1;

  g_app_initialized = 1;
  return 1;

fail:
  if (udp_initialized) {
    app.udp.shutdown();
  }
  if (tick_initialized) {
    app.daemon4.tick.shutdown();
  }
  if (startup_initialized) {
    app.startup.shutdown();
  }
  if (server_initialized) {
    app.server.shutdown();
  }
  if (signal_initialized) {
    app.signal.shutdown();
  }
  if (workspace_initialized) {
    app.workspace.shutdown();
  }
  if (policy_initialized) {
    app.policy.shutdown();
  }
  if (runtime_initialized) {
    app.runtime.shutdown();
  }
  if (payload_initialized) {
    app.payload.shutdown();
  }
  if (opts_initialized) {
    app.opts.shutdown();
  }
  if (keys_initialized) {
    app.keys.shutdown();
  }
  if (object_initialized) {
    app.object.shutdown();
  }
  if (inbound_initialized) {
    app.inbound.shutdown();
  }
  if (daemon4_initialized) {
    if (daemon4_helper_initialized) {
      app.daemon4.helper.shutdown();
    }
    if (daemon4_auth_initialized) {
      app.daemon4.auth.shutdown();
    }
    if (daemon4_request_initialized) {
      app.daemon4.request.shutdown();
    }
    if (daemon4_policy_initialized) {
      app.daemon4.policy.shutdown();
    }
    if (daemon4_payload_initialized) {
      app.daemon4.payload.shutdown();
    }
    app.daemon4.shutdown();
  }
  if (help_initialized) {
    app.help.shutdown();
  }
  if (builtin_initialized) {
    app.builtin.shutdown();
  }
  if (config_initialized) {
    app.config.shutdown();
  }
  app.builtin = (AppBuiltinLib){0};
  app.config = (ConfigLib){0};
  app.daemon4 = (AppDaemon4){0};
  app.help = (AppHelpLib){0};
  app.inbound = (AppInboundLib){0};
  app.keys = (AppKeysLib){0};
  app.object = (AppObjectLib){0};
  app.opts = (AppOptsLib){0};
  app.payload = (AppPayloadLib){0};
  app.policy = (AppPolicyLib){0};
  app.runtime = (AppRuntimeLib){0};
  app.server = (AppServerLib){0};
  app.signal = (AppSignalLib){0};
  app.workspace = (AppWorkspaceLib){0};
  app.startup = (AppStartupLib){0};
  app.udp = (AppUdpLib){0};
  g_app_initialized = 0;
  return 0;
}

void shutdown_app(void) {
  if (!g_app_initialized) {
    return;
  }

  app.builtin.shutdown();
  app.daemon4.helper.shutdown();
  app.daemon4.auth.shutdown();
  app.daemon4.request.shutdown();
  app.daemon4.payload.shutdown();
  app.daemon4.shutdown();
  app.udp.shutdown();
  app.daemon4.tick.shutdown();
  app.startup.shutdown();
  app.server.shutdown();
  app.signal.shutdown();
  app.workspace.shutdown();
  app.runtime.shutdown();
  app.payload.shutdown();
  app.policy.shutdown();
  app.opts.shutdown();
  app.keys.shutdown();
  app.object.shutdown();
  app.inbound.shutdown();
  app.help.shutdown();
  app.config.shutdown();
  app.builtin = (AppBuiltinLib){0};
  app.config = (ConfigLib){0};
  app.daemon4 = (AppDaemon4){0};
  app.help = (AppHelpLib){0};
  app.inbound = (AppInboundLib){0};
  app.keys = (AppKeysLib){0};
  app.object = (AppObjectLib){0};
  app.opts = (AppOptsLib){0};
  app.payload = (AppPayloadLib){0};
  app.policy = (AppPolicyLib){0};
  app.runtime = (AppRuntimeLib){0};
  app.server = (AppServerLib){0};
  app.signal = (AppSignalLib){0};
  app.workspace = (AppWorkspaceLib){0};
  app.startup = (AppStartupLib){0};
  app.udp = (AppUdpLib){0};
  g_app_initialized = 0;
}
