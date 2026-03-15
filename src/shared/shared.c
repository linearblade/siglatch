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
  shared.knock.digest = *get_shared_knock_digest_lib();

  if (!shared.knock.codec.init || !shared.knock.codec.shutdown ||
      !shared.knock.codec.pack || !shared.knock.codec.unpack ||
      !shared.knock.codec.validate || !shared.knock.codec.deserialize ||
      !shared.knock.codec.deserialize_strerror ||
      !shared.knock.debug.init || !shared.knock.debug.shutdown ||
      !shared.knock.debug.dump_packet_fields ||
      !shared.knock.digest.init || !shared.knock.digest.shutdown ||
      !shared.knock.digest.generate || !shared.knock.digest.generate_oneshot ||
      !shared.knock.digest.sign || !shared.knock.digest.validate) {
    fprintf(stderr, "Failed to initialize shared: incomplete knock wiring\n");
    shared = (Shared){0};
    return 0;
  }

  if (!shared.knock.codec.init()) {
    fprintf(stderr, "Failed to initialize shared.knock.codec\n");
    shared = (Shared){0};
    return 0;
  }

  debug_ctx.print = ctx->print;
  if (!shared.knock.debug.init(&debug_ctx)) {
    fprintf(stderr, "Failed to initialize shared.knock.debug\n");
    shared.knock.codec.shutdown();
    shared = (Shared){0};
    return 0;
  }

  digest_ctx.log = ctx->log;
  digest_ctx.openssl = ctx->openssl;

  if (!shared.knock.digest.init(&digest_ctx)) {
    fprintf(stderr, "Failed to initialize shared.knock.digest\n");
    shared.knock.debug.shutdown();
    shared.knock.codec.shutdown();
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
  shared.knock.debug.shutdown();
  shared.knock.codec.shutdown();
  shared = (Shared){0};
  g_shared_initialized = 0;
}
