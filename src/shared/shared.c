/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "shared.h"

#include <stdio.h>

Shared shared = {
  .knock = {
    .codec = {0},
    .debug = {0},
    .detect = {0},
    .digest = {0}
  }
};

static int g_shared_initialized = 0;

int init_shared(const SharedContext *ctx) {
  SharedKnockDebugContext debug_ctx = {0};
  SharedKnockDigestContext digest_ctx = {0};

  if (g_shared_initialized) {
    return 1;
  }

  if (!ctx || !ctx->log || !ctx->openssl) {
    fprintf(stderr, "Failed to initialize shared: invalid context\n");
    return 0;
  }

  shared.knock.codec = *get_shared_knock_codec_lib();
  shared.knock.debug = *get_shared_knock_debug_lib();
  shared.knock.detect = *get_shared_knock_detect_lib();
  shared.knock.digest = *get_shared_knock_digest_lib();
  shared.knock.codec.v1_adapter = shared_knock_codec_v1_get_adapter();
  shared.knock.codec.v2_adapter = shared_knock_codec_v2_get_adapter();
  shared.knock.codec.v3_adapter = shared_knock_codec_v3_get_adapter();

  if (!shared.knock.codec.context.init || !shared.knock.codec.context.shutdown ||
      !shared.knock.codec.context.create || !shared.knock.codec.context.destroy ||
      !shared.knock.codec.context.set_server_key || !shared.knock.codec.context.clear_server_key ||
      !shared.knock.codec.context.set_openssl_session || !shared.knock.codec.context.clear_openssl_session ||
      !shared.knock.codec.context.add_keychain || !shared.knock.codec.context.remove_keychain ||
      !shared.knock.codec.v1_adapter || !shared.knock.codec.v2_adapter || !shared.knock.codec.v3_adapter ||
      !shared.knock.codec.v1.init || !shared.knock.codec.v1.shutdown ||
      !shared.knock.codec.v1.create_state || !shared.knock.codec.v1.destroy_state ||
      !shared.knock.codec.v1.detect || !shared.knock.codec.v1.decode ||
      !shared.knock.codec.v1.wire_auth || !shared.knock.codec.v1.encode ||
      !shared.knock.codec.v1.pack || !shared.knock.codec.v1.unpack ||
      !shared.knock.codec.v1.validate || !shared.knock.codec.v1.deserialize ||
      !shared.knock.codec.v1.deserialize_strerror ||
      !shared.knock.codec.v2.init || !shared.knock.codec.v2.shutdown ||
      !shared.knock.codec.v2.create_state || !shared.knock.codec.v2.destroy_state ||
      !shared.knock.codec.v2.detect || !shared.knock.codec.v2.decode ||
      !shared.knock.codec.v2.wire_auth || !shared.knock.codec.v2.encode ||
      !shared.knock.codec.v2.pack || !shared.knock.codec.v2.unpack ||
      !shared.knock.codec.v2.validate || !shared.knock.codec.v2.deserialize ||
      !shared.knock.codec.v2.deserialize_strerror ||
      !shared.knock.codec.v3.init || !shared.knock.codec.v3.shutdown ||
      !shared.knock.codec.v3.create_state || !shared.knock.codec.v3.destroy_state ||
      !shared.knock.codec.v3.detect || !shared.knock.codec.v3.decode ||
      !shared.knock.codec.v3.wire_auth || !shared.knock.codec.v3.encode ||
      !shared.knock.codec.v3.pack || !shared.knock.codec.v3.unpack ||
      !shared.knock.codec.v3.validate || !shared.knock.codec.v3.deserialize ||
      !shared.knock.codec.v3.deserialize_strerror ||
      !shared.knock.debug.init || !shared.knock.debug.shutdown ||
      !shared.knock.debug.dump_packet_fields ||
      !shared.knock.detect.init || !shared.knock.detect.shutdown ||
      !shared.knock.detect.detect_kind || !shared.knock.detect.detect ||
      !shared.knock.detect.kind_name ||
      !shared.knock.digest.init || !shared.knock.digest.shutdown ||
      !shared.knock.digest.generate || !shared.knock.digest.generate_oneshot ||
      !shared.knock.digest.sign || !shared.knock.digest.validate) {
    fprintf(stderr, "Failed to initialize shared: incomplete knock wiring\n");
    shared = (Shared){0};
    return 0;
  }

  debug_ctx.print = ctx->print;
  if (!shared.knock.debug.init(&debug_ctx)) {
    fprintf(stderr, "Failed to initialize shared.knock.debug\n");
    shared = (Shared){0};
    return 0;
  }

  if (!shared.knock.detect.init()) {
    fprintf(stderr, "Failed to initialize shared.knock.detect\n");
    shared.knock.debug.shutdown();
    shared = (Shared){0};
    return 0;
  }

  digest_ctx.log = ctx->log;
  digest_ctx.openssl = ctx->openssl;

  if (!shared.knock.digest.init(&digest_ctx)) {
    fprintf(stderr, "Failed to initialize shared.knock.digest\n");
    shared.knock.detect.shutdown();
    shared.knock.debug.shutdown();
    shared = (Shared){0};
    return 0;
  }

  g_shared_initialized = 1;
  return 1;
}

void shutdown_shared(void) {
  if (!g_shared_initialized) {
    return;
  }

  shared.knock.digest.shutdown();
  shared.knock.detect.shutdown();
  shared.knock.debug.shutdown();
  shared = (Shared){0};
  g_shared_initialized = 0;
}
