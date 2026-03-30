/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_SIGLATCH_OPENSSL_SESSION_MODULE_H
#define LIB_SIGLATCH_OPENSSL_SESSION_MODULE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#include "../context/context.h"

typedef struct SiglatchOpenSSLSession {
  SiglatchOpenSSLContext *parent_ctx;
  EVP_PKEY *public_key;
  EVP_PKEY *private_key;
  EVP_PKEY_CTX *public_key_ctx;
  EVP_PKEY_CTX *private_key_ctx;
  uint8_t hmac_key[64];
  size_t hmac_key_len;
  bool owns_ctx;
} SiglatchOpenSSLSession;

int siglatch_openssl_session_init(SiglatchOpenSSLSession *session);
int siglatch_openssl_session_free(SiglatchOpenSSLSession *session);
int siglatch_openssl_session_readPrivateKey(SiglatchOpenSSLSession *session, const char *filename);
int siglatch_openssl_session_readPublicKey(SiglatchOpenSSLSession *session, const char *filename);
int siglatch_openssl_session_readHMAC(SiglatchOpenSSLSession *session, const char *filename);
int siglatch_openssl_key_fingerprint(const EVP_PKEY *key, char *out_hex, size_t out_hex_len);

#endif // LIB_SIGLATCH_OPENSSL_SESSION_MODULE_H
