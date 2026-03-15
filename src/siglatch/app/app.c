/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "app.h"

#include <stdio.h>

App app = {
  .config = {0},
  .daemon = {0},
  .help = {0},
  .inbound = {0},
  .keys = {0},
  .opts = {0},
  .packet = {0},
  .payload = {0},
  .runtime = {0},
  .server = {0},
  .signal = {0},
  .startup = {0},
  .udp = {0}
};

static int g_app_initialized = 0;

int init_app(void) {
  int config_initialized = 0;
  int daemon_initialized = 0;
  int help_initialized = 0;
  int inbound_initialized = 0;
  int keys_initialized = 0;
  int opts_initialized = 0;
  int packet_initialized = 0;
  int payload_initialized = 0;
  int runtime_initialized = 0;
  int server_initialized = 0;
  int signal_initialized = 0;
  int startup_initialized = 0;
  int udp_initialized = 0;

  if (g_app_initialized) {
    return 1;
  }

  app.config = *get_app_config_lib();
  app.daemon = *get_app_daemon_lib();
  app.help = *get_app_help_lib();
  app.inbound = *get_app_inbound_lib();
  app.keys = *get_app_keys_lib();
  app.opts = *get_app_opts_lib();
  app.packet = *get_app_packet_lib();
  app.payload = *get_app_payload_lib();
  app.runtime = *get_app_runtime_lib();
  app.server = *get_app_server_lib();
  app.signal = *get_app_signal_lib();
  app.startup = *get_app_startup_lib();
  app.udp = *get_app_udp_lib();

  /*
   * Wiring contract (intentional): server app module factories are
   * all-or-nothing. If init_app() succeeds, the execution callbacks exposed
   * by each acquired module are expected to be valid as part of that module's
   * provider contract.
   */
  if (!app.config.init || !app.config.shutdown ||
      !app.daemon.init || !app.daemon.shutdown || !app.daemon.run ||
      !app.help.init || !app.help.shutdown || !app.help.show ||
      !app.inbound.init || !app.inbound.shutdown ||
      !app.keys.init || !app.keys.shutdown ||
      !app.opts.init || !app.opts.shutdown ||
      !app.packet.init || !app.packet.shutdown || !app.packet.consume_normalized ||
      !app.payload.init || !app.payload.shutdown || !app.payload.run_shell ||
      !app.payload.codec.init || !app.payload.codec.shutdown ||
      !app.payload.codec.pack || !app.payload.codec.unpack ||
      !app.payload.codec.validate || !app.payload.codec.deserialize || !app.payload.codec.deserialize_strerror ||
      !app.payload.digest.init || !app.payload.digest.shutdown ||
      !app.payload.digest.generate || !app.payload.digest.generate_oneshot ||
      !app.payload.digest.sign || !app.payload.digest.validate ||
      !app.payload.structured.init || !app.payload.structured.shutdown || !app.payload.structured.handle ||
      !app.payload.unstructured.init || !app.payload.unstructured.shutdown || !app.payload.unstructured.handle ||
      !app.runtime.init || !app.runtime.shutdown ||
      !app.server.init || !app.server.shutdown ||
      !app.signal.init || !app.signal.shutdown || !app.signal.install || !app.signal.should_exit || !app.signal.request_exit ||
      !app.startup.init || !app.startup.shutdown ||
      !app.udp.init || !app.udp.shutdown) {
    fprintf(stderr, "Siglatch app wiring is incomplete\n");
    return 0;
  }

  {
    siglatch_config_context config_ctx = {0};
    if (!app.config.init(&config_ctx)) {
      fprintf(stderr, "Failed to initialize app.config\n");
      goto fail;
    }
  }
  config_initialized = 1;

  if (!app.daemon.init()) {
    fprintf(stderr, "Failed to initialize app.daemon\n");
    goto fail;
  }
  daemon_initialized = 1;

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

  if (!app.opts.init(NULL)) {
    fprintf(stderr, "Failed to initialize app.opts\n");
    goto fail;
  }
  opts_initialized = 1;

  if (!app.packet.init()) {
    fprintf(stderr, "Failed to initialize app.packet\n");
    goto fail;
  }
  packet_initialized = 1;

  if (!app.payload.init()) {
    fprintf(stderr, "Failed to initialize app.payload\n");
    goto fail;
  }
  payload_initialized = 1;

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

  if (!app.startup.init()) {
    fprintf(stderr, "Failed to initialize app.startup\n");
    goto fail;
  }
  startup_initialized = 1;

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
  if (startup_initialized) {
    app.startup.shutdown();
  }
  if (server_initialized) {
    app.server.shutdown();
  }
  if (signal_initialized) {
    app.signal.shutdown();
  }
  if (runtime_initialized) {
    app.runtime.shutdown();
  }
  if (payload_initialized) {
    app.payload.shutdown();
  }
  if (packet_initialized) {
    app.packet.shutdown();
  }
  if (opts_initialized) {
    app.opts.shutdown();
  }
  if (keys_initialized) {
    app.keys.shutdown();
  }
  if (inbound_initialized) {
    app.inbound.shutdown();
  }
  if (daemon_initialized) {
    app.daemon.shutdown();
  }
  if (help_initialized) {
    app.help.shutdown();
  }
  if (config_initialized) {
    app.config.shutdown();
  }
  app.config = (ConfigLib){0};
  app.daemon = (AppDaemonLib){0};
  app.help = (AppHelpLib){0};
  app.inbound = (AppInboundLib){0};
  app.keys = (AppKeysLib){0};
  app.opts = (AppOptsLib){0};
  app.packet = (AppPacketLib){0};
  app.payload = (AppPayloadLib){0};
  app.runtime = (AppRuntimeLib){0};
  app.server = (AppServerLib){0};
  app.signal = (AppSignalLib){0};
  app.startup = (AppStartupLib){0};
  app.udp = (AppUdpLib){0};
  g_app_initialized = 0;
  return 0;
}

void shutdown_app(void) {
  if (!g_app_initialized) {
    return;
  }

  app.udp.shutdown();
  app.startup.shutdown();
  app.server.shutdown();
  app.signal.shutdown();
  app.runtime.shutdown();
  app.payload.shutdown();
  app.packet.shutdown();
  app.opts.shutdown();
  app.keys.shutdown();
  app.inbound.shutdown();
  app.daemon.shutdown();
  app.help.shutdown();
  app.config.shutdown();
  app.config = (ConfigLib){0};
  app.daemon = (AppDaemonLib){0};
  app.help = (AppHelpLib){0};
  app.inbound = (AppInboundLib){0};
  app.keys = (AppKeysLib){0};
  app.opts = (AppOptsLib){0};
  app.packet = (AppPacketLib){0};
  app.payload = (AppPayloadLib){0};
  app.runtime = (AppRuntimeLib){0};
  app.server = (AppServerLib){0};
  app.signal = (AppSignalLib){0};
  app.startup = (AppStartupLib){0};
  app.udp = (AppUdpLib){0};
  g_app_initialized = 0;
}
