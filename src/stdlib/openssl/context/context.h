/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_SIGLATCH_OPENSSL_CONTEXT_MODULE_H
#define LIB_SIGLATCH_OPENSSL_CONTEXT_MODULE_H

#include "../../file.h"
#include "../../log.h"
#include "../../hmac_key.h"
#include "../../print.h"

// OpenSSL library context
typedef struct {
  const FileLib *file; ///< Pointer to file library (e.g., for reading keys from disk)
  const Logger *log;   ///< Pointer to logging library (for error reporting)
  const HMACKey *hmac; //< pointer to hmac key reader
  const PrintLib *print; ///< Pointer to print library for console/stderr output
  // Future: random number generation lib, config flags, etc.
} SiglatchOpenSSLContext;

int siglatch_openssl_init(SiglatchOpenSSLContext *ctx);
void siglatch_openssl_shutdown(void);
void siglatch_openssl_set_context(SiglatchOpenSSLContext *ctx);
SiglatchOpenSSLContext *siglatch_openssl_context_current(void);

#endif // LIB_SIGLATCH_OPENSSL_CONTEXT_MODULE_H
