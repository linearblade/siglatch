/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_SIGLATCH_OPENSSL_HMAC_H
#define LIB_SIGLATCH_OPENSSL_HMAC_H

#include <stdint.h>

#include "../session/session.h"

int siglatch_openssl_sign(SiglatchOpenSSLSession *session, const uint8_t *digest, uint8_t *out_signature);

#endif // LIB_SIGLATCH_OPENSSL_HMAC_H
