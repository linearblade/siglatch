/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "context.h"

static SiglatchOpenSSLContext g_openssl_ctx = {0};

SiglatchOpenSSLContext *siglatch_openssl_context_current(void) {
  return &g_openssl_ctx;
}

int siglatch_openssl_init(SiglatchOpenSSLContext *ctx) {
  if (!ctx) {
    return -1;
  }
  g_openssl_ctx = *ctx;
  return 0;
}

void siglatch_openssl_shutdown(void) {
  g_openssl_ctx = (SiglatchOpenSSLContext){0};
}

void siglatch_openssl_set_context(SiglatchOpenSSLContext *ctx) {
  if (!ctx) {
    return;
  }
  g_openssl_ctx = *ctx;
}
