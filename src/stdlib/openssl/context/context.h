/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_SIGLATCH_OPENSSL_CONTEXT_MODULE_H
#define LIB_SIGLATCH_OPENSSL_CONTEXT_MODULE_H

#include "../../openssl_context.h"

int siglatch_openssl_init(SiglatchOpenSSLContext *ctx);
void siglatch_openssl_shutdown(void);
void siglatch_openssl_set_context(SiglatchOpenSSLContext *ctx);
SiglatchOpenSSLContext *siglatch_openssl_context_current(void);

#endif // LIB_SIGLATCH_OPENSSL_CONTEXT_MODULE_H
